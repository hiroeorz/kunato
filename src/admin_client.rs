//! `kunato metrics`: print the metrics served by the admin listener as a table.
//!
//! The `GET /metrics` body is fetched unchanged and rendered by
//! [`crate::metrics_table`] as two aligned columns: the metric name and its
//! value, without the Prometheus comment lines.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

use crate::cli::MetricsArgs;
use crate::error::Error;
use crate::proxy::{BodyExt, Full};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_METRICS_BYTES: usize = 8 * 1024 * 1024;

type MetricsClient = Client<HttpConnector, Full<Bytes>>;

/// Query the admin listener and write the rendered metrics table to stdout.
pub async fn run(args: MetricsArgs) -> Result<(), Error> {
    let body = fetch(args.listen).await?;
    let table = crate::metrics_table::render(&String::from_utf8_lossy(&body))?;
    write_stdout(table.as_bytes())
}

async fn fetch(listen: SocketAddr) -> Result<Vec<u8>, Error> {
    fetch_with_limit(listen, MAX_METRICS_BYTES).await
}

async fn fetch_with_limit(listen: SocketAddr, max_bytes: usize) -> Result<Vec<u8>, Error> {
    if !listen.ip().is_loopback() {
        return Err(Error::Message(format!(
            "the admin listener must be a loopback address, got `{listen}`"
        )));
    }

    let url = format!("http://{listen}/metrics");
    let client: MetricsClient = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method(Method::GET)
        .uri(&url)
        .body(Full::new(Bytes::new()))
        .map_err(|err| Error::Message(format!("invalid metrics request: {err}")))?;

    let response = timeout(REQUEST_TIMEOUT, client.request(request))
        .await
        .map_err(|_| Error::Message(format!("request to `{url}` timed out")))?
        .map_err(|err| Error::Message(format!("failed to reach `{url}`: {}", error_chain(&err))))?;

    let status = response.status();
    if status != StatusCode::OK {
        return Err(Error::Message(format!("`{url}` returned {status}")));
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
            "failed to write metrics to stdout: {err}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
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
