use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use kunato::admin::AdminServer;
use kunato::config;
use kunato::metrics::Metrics;
use kunato::proxy::server::Server;

async fn spawn_header_echo_upstream(header: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |request: Request<Incoming>| async move {
                    let value = request
                        .headers()
                        .get(header)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(value))))
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

async fn spawn_upstream(status: StatusCode, body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_request: Request<Incoming>| async move {
                    let mut response =
                        Response::new(Full::new(Bytes::from_static(body.as_bytes())));
                    *response.status_mut() = status;
                    Ok::<_, Infallible>(response)
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

struct Running {
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

async fn start_kunato(yaml: &str) -> Running {
    let compiled = config::parse(yaml).expect("valid config");
    let config = Arc::new(ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(Metrics::new());
    let server = Server::bind("127.0.0.1:0".parse().expect("address"), config, metrics)
        .await
        .expect("bind kunato");
    let addr = server.local_addr().expect("local address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown_rx));
    Running {
        addr,
        shutdown,
        task,
    }
}

async fn send(addr: SocketAddr, method: Method, path: &str, body: &str) -> (StatusCode, String) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", addr.to_string())
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("build request");

    let response = client.request(request).await.expect("request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn pass_through_forwards_to_upstream() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn block_rule_rejects_matching_request() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: sql-injection
    action: BLOCK
    rules:
      - name: union-select
        match: {{ regex: '(?i)union\\s+select', in: [query] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/?q=union%20select", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = send(running.addr, Method::GET, "/safe", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn allow_short_circuits_later_blocks() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: trusted
    action: ALLOW
    rules:
      - name: local
        match: {{ source_ip: 127.0.0.1 }}
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send(running.addr, Method::GET, "/anything", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn rule_action_overrides_log_category() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: scanners
    action: LOG
    rules:
      - name: sensitive-files
        action: BLOCK
        match: {{ path: /admin }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/admin", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(running.addr, Method::GET, "/public", "").await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::POST, "/upload", "0123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn rate_limit_returns_too_many_requests() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nprotection: {{ requests_per_second: 1, burst: 1 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (first, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(first, StatusCode::OK);

    let (second, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);

    running.stop().await;
}

#[tokio::test]
async fn body_at_limit_is_accepted() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::POST, "/exact", "12345678").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(running.addr, Method::POST, "/over", "123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn oversized_headers_are_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_header_bytes: 128 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    let request = format!(
        "GET / HTTP/1.1\r\nhost: kunato.test\r\nx-pad: {}\r\nconnection: close\r\n\r\n",
        "a".repeat(256)
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 431"),
        "unexpected response: {response}"
    );

    running.stop().await;
}

#[tokio::test]
async fn tls_termination_forwards_https_proto() {
    let upstream = spawn_header_echo_upstream("x-forwarded-proto").await;
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).expect("write key");

    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
tls:
  cert_file: {}
  key_file: {}
",
        cert_path.display(),
        key_path.display()
    );
    let running = start_kunato(&yaml).await;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certified.cert.der().clone())
        .expect("trust test certificate");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(running.addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.expect("read response");
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert!(
        response.trim_end().ends_with("https"),
        "unexpected response: {response}"
    );

    running.stop().await;
}

#[tokio::test]
async fn admin_metrics_endpoint_reports_counters() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
admin: {{ listen: 127.0.0.1:0 }}
categories:
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
    );

    let compiled = config::parse(&yaml).expect("valid config");
    let admin_config = compiled.admin.clone();
    let config = Arc::new(ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(Metrics::new());
    let server = Server::bind(
        "127.0.0.1:0".parse().expect("address"),
        config,
        metrics.clone(),
    )
    .await
    .expect("bind kunato");
    let protection = server.protection();
    let addr = server.local_addr().expect("local address");

    let admin = AdminServer::bind(&admin_config, metrics.clone(), protection)
        .await
        .expect("bind admin");
    let admin_addr = admin.local_addr().expect("admin address");

    let (shutdown, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx.clone()));
    let admin_task = tokio::spawn(admin.run(shutdown_rx.clone()));

    let (status, _) = send(addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = send(admin_addr, Method::GET, "/metrics", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("kunato_requests_total 1"), "{body}");
    assert!(body.contains("kunato_blocked_total 1"), "{body}");

    let (status, _) = send(admin_addr, Method::GET, "/other", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let _ = shutdown.send(true);
    let _ = server_task.await;
    let _ = admin_task.await;
}

#[tokio::test]
async fn unreachable_upstream_returns_bad_gateway() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temp listener");
        listener.local_addr().expect("temp address")
    };

    let running = start_kunato(&format!("listen: 127.0.0.1:0\nupstream: http://{closed}\n")).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    running.stop().await;
}
