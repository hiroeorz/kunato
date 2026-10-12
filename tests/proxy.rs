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
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use kunato::config;
use kunato::proxy::server::Server;

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
    let server = Server::bind("127.0.0.1:0".parse().expect("address"), config)
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
