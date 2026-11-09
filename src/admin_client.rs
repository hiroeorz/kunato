//! Client for the loopback admin listener.
//!
//! `kunato metrics` fetches `GET /metrics` and renders the exposition as a
//! table. `kunato maintenance on|off` sends `PUT /maintenance/on|off` to switch
//! the running proxy between maintenance mode and normal forwarding.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

use crate::cli::{
    AdminAccessAction, AdminAccessArgs, MaintenanceAction, MaintenanceArgs, MetricsArgs,
};
use crate::error::Error;
use crate::proxy::{BodyExt, Full};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_METRICS_BYTES: usize = 8 * 1024 * 1024;
const MAX_MAINTENANCE_BYTES: usize = 4 * 1024;
const MAX_ADMIN_ACCESS_BYTES: usize = 256 * 1024;
const MAX_ERROR_BYTES: usize = 4 * 1024;

type AdminClient = Client<HttpConnector, Full<Bytes>>;

/// Query the admin listener and write the rendered metrics table to stdout.
pub async fn run(args: MetricsArgs) -> Result<(), Error> {
    let body = fetch(args.listen).await?;
    let table = crate::metrics_table::render(&String::from_utf8_lossy(&body))?;
    write_stdout(table.as_bytes())
}

/// Switch maintenance mode and write the admin confirmation to stdout.
pub async fn run_maintenance(args: MaintenanceArgs) -> Result<(), Error> {
    let body = request(
        args.listen,
        Method::PUT,
        maintenance_path(args.action),
        MAX_MAINTENANCE_BYTES,
    )
    .await?;
    write_stdout(&body)
}

fn maintenance_path(action: MaintenanceAction) -> &'static str {
    match action {
        MaintenanceAction::On => "/maintenance/on",
        MaintenanceAction::Off => "/maintenance/off",
    }
}

/// Open, close, or list administrative access and write the admin response to
/// stdout.
pub async fn run_admin_access(args: AdminAccessArgs) -> Result<(), Error> {
    let (method, path) = admin_access_request(&args.action);
    let body = request(args.listen, method, &path, MAX_ADMIN_ACCESS_BYTES).await?;
    write_stdout(&body)
}

fn admin_access_request(action: &AdminAccessAction) -> (Method, String) {
    match action {
        AdminAccessAction::Status => (Method::GET, "/admin-access".to_owned()),
        AdminAccessAction::Set {
            state,
            client,
            function,
            ttl,
        } => {
            let mut path = format!("/admin-access/{}", state.as_str());
            let mut params = Vec::new();
            if let Some(client) = client {
                params.push(format!("client={client}"));
            }
            if let Some(function) = function {
                params.push(format!("function={function}"));
            }
            if let Some(ttl) = ttl {
                params.push(format!("ttl={}", ttl.as_secs()));
            }
            if !params.is_empty() {
                path.push('?');
                path.push_str(&params.join("&"));
            }
            (Method::PUT, path)
        }
    }
}

async fn fetch(listen: SocketAddr) -> Result<Vec<u8>, Error> {
    fetch_with_limit(listen, MAX_METRICS_BYTES).await
}

async fn fetch_with_limit(listen: SocketAddr, max_bytes: usize) -> Result<Vec<u8>, Error> {
    request(listen, Method::GET, "/metrics", max_bytes).await
}

async fn request(
    listen: SocketAddr,
    method: Method,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    if !listen.ip().is_loopback() {
        return Err(Error::Message(format!(
            "the admin listener must be a loopback address, got `{listen}`"
        )));
    }

    let url = format!("http://{listen}{path}");
    let client: AdminClient = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method(method)
        .uri(&url)
        .body(Full::new(Bytes::new()))
        .map_err(|err| Error::Message(format!("invalid admin request: {err}")))?;

    let response = timeout(REQUEST_TIMEOUT, client.request(request))
        .await
        .map_err(|_| Error::Message(format!("request to `{url}` timed out")))?
        .map_err(|err| Error::Message(format!("failed to reach `{url}`: {}", error_chain(&err))))?;

    let status = response.status();
    if status != StatusCode::OK {
        let detail = timeout(
            REQUEST_TIMEOUT,
            read_body(response.into_body(), &url, MAX_ERROR_BYTES),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|body| String::from_utf8_lossy(&body).trim().to_owned())
        .filter(|body| !body.is_empty());
        return Err(Error::Message(match detail {
            Some(detail) => format!("`{url}` returned {status}: {detail}"),
            None => format!("`{url}` returned {status}"),
        }));
    }

    timeout(
        REQUEST_TIMEOUT,
        read_body(response.into_body(), &url, max_bytes),
    )
    .await
    .map_err(|_| Error::Message(format!("reading `{url}` timed out")))?
}

async fn read_body(
    mut body: hyper::body::Incoming,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|err| Error::Message(format!("failed to read `{url}`: {err}")))?;
        if let Some(chunk) = frame.data_ref() {
            if bytes.len() + chunk.len() > max_bytes {
                return Err(Error::Message(format!(
                    "`{url}` exceeds the {max_bytes} byte limit"
                )));
            }
            bytes.extend_from_slice(chunk);
        }
    }
    Ok(bytes)
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn write_stdout(body: &[u8]) -> Result<(), Error> {
    let mut stdout = io::stdout().lock();
    let written = stdout.write_all(body).and_then(|()| stdout.flush());
    match written {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(Error::Message(format!(
            "failed to write admin response to stdout: {err}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::admin_access::AccessState;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_once(response: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            let _ = stream.shutdown().await;
        });
        addr
    }

    async fn serve_once_capturing(
        response: String,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local address");
        let (captured, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).await.expect("read request");
            let _ = captured.send(String::from_utf8_lossy(&request[..read]).into_owned());
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            let _ = stream.shutdown().await;
        });
        (addr, receiver)
    }

    fn response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn maintenance_paths_select_the_admin_route() {
        assert_eq!(maintenance_path(MaintenanceAction::On), "/maintenance/on");
        assert_eq!(maintenance_path(MaintenanceAction::Off), "/maintenance/off");
    }

    #[test]
    fn admin_access_requests_use_the_expected_routes() {
        assert_eq!(
            admin_access_request(&AdminAccessAction::Status),
            (Method::GET, "/admin-access".to_owned())
        );
        assert_eq!(
            admin_access_request(&AdminAccessAction::Set {
                state: AccessState::Open,
                client: None,
                function: None,
                ttl: None,
            }),
            (Method::PUT, "/admin-access/open".to_owned())
        );
        assert_eq!(
            admin_access_request(&AdminAccessAction::Set {
                state: AccessState::Close,
                client: None,
                function: None,
                ttl: Some(Duration::from_secs(600)),
            }),
            (Method::PUT, "/admin-access/close?ttl=600".to_owned())
        );
        assert_eq!(
            admin_access_request(&AdminAccessAction::Set {
                state: AccessState::Open,
                client: Some("192.0.2.10".parse().expect("ip")),
                function: Some("wordpress-admin".to_owned()),
                ttl: Some(Duration::from_secs(600)),
            }),
            (
                Method::PUT,
                "/admin-access/open?client=192.0.2.10&function=wordpress-admin&ttl=600".to_owned()
            )
        );
        assert_eq!(
            admin_access_request(&AdminAccessAction::Set {
                state: AccessState::Close,
                client: Some("192.0.2.10".parse().expect("ip")),
                function: None,
                ttl: None,
            }),
            (
                Method::PUT,
                "/admin-access/close?client=192.0.2.10".to_owned()
            )
        );
        assert_eq!(
            admin_access_request(&AdminAccessAction::Set {
                state: AccessState::Open,
                client: None,
                function: Some("admin".to_owned()),
                ttl: None,
            }),
            (Method::PUT, "/admin-access/open?function=admin".to_owned())
        );

        let (_, path) = admin_access_request(&AdminAccessAction::Set {
            state: AccessState::Open,
            client: Some("2001:db8::1".parse().expect("ip")),
            function: Some("admin".to_owned()),
            ttl: Some(Duration::from_secs(600)),
        });
        assert!(
            format!("http://127.0.0.1:9090{path}")
                .parse::<http::Uri>()
                .is_ok(),
            "the IPv6 override query must be a valid request target"
        );
    }

    #[tokio::test]
    async fn set_is_a_put_request_with_its_query() {
        let (addr, captured) = serve_once_capturing(response(
            "200 OK",
            "open client=192.0.2.10 function=admin expires_in_seconds=600\n",
        ))
        .await;

        run_admin_access(AdminAccessArgs {
            action: AdminAccessAction::Set {
                state: AccessState::Open,
                client: Some("192.0.2.10".parse().expect("ip")),
                function: Some("admin".to_owned()),
                ttl: Some(Duration::from_secs(600)),
            },
            listen: addr,
        })
        .await
        .expect("open");

        let request = captured.await.expect("captured request");
        assert!(
            request.starts_with(
                "PUT /admin-access/open?client=192.0.2.10&function=admin&ttl=600 HTTP/1.1\r\n"
            ),
            "{request}"
        );
    }

    #[tokio::test]
    async fn close_without_options_closes_everything() {
        let (addr, captured) = serve_once_capturing(response(
            "200 OK",
            "close client=* function=* expires_in_seconds=600\n",
        ))
        .await;

        run_admin_access(AdminAccessArgs {
            action: AdminAccessAction::Set {
                state: AccessState::Close,
                client: None,
                function: None,
                ttl: None,
            },
            listen: addr,
        })
        .await
        .expect("close");

        let request = captured.await.expect("captured request");
        assert!(
            request.starts_with("PUT /admin-access/close HTTP/1.1\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_rejected_admin_request_reports_the_response_body() {
        let addr = serve_once(response("400 Bad Request", "unknown function `nope`\n")).await;

        let error = request(
            addr,
            Method::PUT,
            "/admin-access/open?client=192.0.2.10&function=nope",
            MAX_ADMIN_ACCESS_BYTES,
        )
        .await
        .expect_err("400 is an error");

        assert!(error.to_string().contains("400 Bad Request"), "{error}");
        assert!(
            error.to_string().contains("unknown function `nope`"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn maintenance_is_a_put_request() {
        let (addr, captured) = serve_once_capturing(response("200 OK", "maintenance on\n")).await;

        run_maintenance(MaintenanceArgs {
            action: MaintenanceAction::On,
            listen: addr,
        })
        .await
        .expect("toggle maintenance");

        let request = captured.await.expect("captured request");
        assert!(
            request.starts_with("PUT /maintenance/on HTTP/1.1\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn returns_the_exposition_verbatim() {
        let body = "# HELP kunato_requests_total Total requests.\n\
                    # TYPE kunato_requests_total counter\n\
                    kunato_requests_total 12\n\
                    \n\
                    # A trailing value without a final newline";
        let addr = serve_once(response("200 OK", body)).await;

        let fetched = fetch(addr).await.expect("fetch");

        assert_eq!(fetched, body.as_bytes());
    }

    #[tokio::test]
    async fn reports_a_non_success_status() {
        let addr = serve_once(response("404 Not Found", "not found")).await;

        let error = fetch(addr).await.expect_err("404 is an error");

        assert!(error.to_string().contains("404 Not Found"), "{error}");
    }

    #[tokio::test]
    async fn refuses_a_non_loopback_listener() {
        let error = fetch(SocketAddr::from(([192, 0, 2, 1], 9090)))
            .await
            .expect_err("public address");

        assert!(error.to_string().contains("loopback"), "{error}");
    }

    #[tokio::test]
    async fn reports_an_unreachable_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local address");
        drop(listener);

        let error = fetch(addr).await.expect_err("nothing listens");

        assert!(
            error.to_string().contains("failed to reach"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn bounded_body_limit_is_enforced() {
        let addr = serve_once(response("200 OK", "0123456789abcdef")).await;

        let fetched = fetch_with_limit(addr, 16).await.expect("exact limit fits");
        assert_eq!(fetched, b"0123456789abcdef");

        let addr = serve_once(response("200 OK", "0123456789abcdefg")).await;
        let error = fetch_with_limit(addr, 16)
            .await
            .expect_err("oversized body");
        assert!(error.to_string().contains("byte limit"), "{error}");
    }
}
