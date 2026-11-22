use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use kunato::console::collector::{Collector, CollectorConfig, CollectorHealth};
use kunato::console::runtime::{ConsoleRuntime, LiveState};
use kunato::console::server::ConsoleServer;
use kunato::console::{StorageConfig, WriterConfig};
use kunato::observations::{self, Observations};
use kunato::proxy::{BodyExt, Full};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

fn fast_writer() -> WriterConfig {
    WriterConfig {
        metric_flush: Duration::from_millis(1),
        event_flush: Duration::from_millis(1),
        min_commit_interval: Duration::from_millis(1),
        ..WriterConfig::default()
    }
}

async fn requests(history: &Arc<Observations>, count: usize, rejected: bool) {
    for _ in 0..count {
        observations::observe(history.clone(), async {
            if rejected {
                observations::reject(kunato::console::model::RejectionReason::Rule);
            }
            http::Response::builder()
                .status(if rejected { 403 } else { 200 })
                .body(())
                .unwrap()
        })
        .await;
    }
}

fn console_yaml(dir: &std::path::Path, extra: &str) -> String {
    format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: {{ listen: 127.0.0.1:9090 }}
console:
  enabled: true
  listen: 127.0.0.1:0
  source: 127.0.0.1:9090
  instance: test-console
  storage_dir: {}
{extra}",
        dir.display()
    )
}

struct Running {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

async fn start(
    yaml: &str,
    live: watch::Receiver<Option<Arc<LiveState>>>,
    reader: kunato::console::HistoryReader,
) -> Running {
    let console = kunato::config::parse(yaml)
        .expect("valid console config")
        .console;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let server = ConsoleServer::bind(&console, live, reader, shutdown_rx.clone())
        .await
        .expect("bind console");
    let address = server.local_addr().expect("address");
    let task = tokio::spawn(server.run(shutdown_rx));
    Running {
        address,
        shutdown,
        task,
    }
}

type HttpClient = Client<HttpConnector, Full<Bytes>>;

fn client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn request(
    client: &HttpClient,
    address: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> (StatusCode, String, Option<String>) {
    let mut builder = Request::builder()
        .uri(format!("http://{address}{path}"))
        .method(method);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = body.map_or_else(
        || Full::new(Bytes::new()),
        |body| Full::new(Bytes::from(body.to_owned())),
    );
    let response = client
        .request(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let cookie = response
        .headers()
        .get(http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned(), cookie)
}

async fn raw(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    String::from_utf8_lossy(&response).into_owned()
}

fn http_get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
}

async fn seeded_collector(
    dir: &std::path::Path,
) -> (
    kunato::console::HistoryReader,
    kunato::observations::StatisticsSnapshot,
    CollectorHealth,
    u64,
) {
    let mut storage = StorageConfig::new(dir.join("history"));
    storage.event_retention = Duration::from_secs(3600);
    let config = CollectorConfig {
        instance: "test-console".to_owned(),
        ..CollectorConfig::default()
    };
    let mut collector = Collector::start(storage, fast_writer(), config)
        .await
        .expect("collector");
    let reader = collector.history_reader();
    let history = Arc::new(Observations::new());
    requests(&history, 4, true).await;
    let packet = history.snapshot(0).expect("snapshot");
    collector.receive(packet.clone()).await.expect("receive");
    let health = collector.health();
    let report = collector
        .shutdown(Duration::from_secs(2))
        .await
        .expect("shutdown");
    assert!(!report.timed_out);
    let minute_start = packet.buckets[0].start_ms;
    (reader, packet, health, minute_start)
}

#[tokio::test]
async fn serves_history_live_state_and_assets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, minute_start) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet.clone()),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let running = start(&console_yaml(temp.path(), ""), rx, reader).await;
    let client = client();

    let (status, body, _) = request(&client, running.address, Method::GET, "/", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Kunato console"), "{body}");
    assert!(
        body.contains(r#"<option value="604800000" selected>Last 7 days</option>"#),
        "{body}"
    );

    let (status, body, _) = request(
        &client,
        running.address,
        Method::GET,
        "/api/v1/health",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health: serde_json::Value = serde_json::from_str(&body).expect("health json");
    assert_eq!(health["version"], 1);
    assert_eq!(health["collection"]["connected"], true);
    assert_eq!(health["console"]["instance"], "test-console");

    let path = format!(
        "/api/v1/history?from_ms={minute_start}&until_ms={}&limit=10",
        packet.observed_at_ms + 60_000
    );
    let (status, body, _) = request(&client, running.address, Method::GET, &path, &[], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: serde_json::Value = serde_json::from_str(&body).expect("history json");
    assert!(
        page["buckets"]
            .as_array()
            .is_some_and(|buckets| !buckets.is_empty()),
        "{body}"
    );
    assert_eq!(page["instance"], "test-console");
    assert!(
        page["buckets"][0]["reasons"]["rule"]["sum"]
            .as_u64()
            .is_some_and(|sum| sum >= 4),
        "{body}"
    );

    let path = format!(
        "/api/v1/correlations?from_ms={minute_start}&until_ms={}",
        packet.observed_at_ms + 60_000
    );
    let (status, body, _) = request(&client, running.address, Method::GET, &path, &[], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"records\""), "{body}");

    let (status, _, _) = request(
        &client,
        running.address,
        Method::POST,
        "/api/v1/history",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn streams_the_latest_state_over_sse() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let running = start(&console_yaml(temp.path(), ""), rx, reader).await;

    let mut stream = TcpStream::connect(running.address).await.expect("connect");
    stream
        .write_all(http_get("/api/v1/live").as_bytes())
        .await
        .expect("write");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .expect("stream timeout")
            .expect("stream read");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&buffer);
        if text.contains("event: state") && text.contains("\n\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    assert!(text.contains("content-type: text/event-stream"), "{text}");
    assert!(text.contains("id: "), "{text}");
    assert!(text.contains("\"snapshot\""), "{text}");
    assert!(text.contains("\"replayed\":true"), "{text}");

    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn rejects_forwarding_markers_and_foreign_hosts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let running = start(&console_yaml(temp.path(), ""), rx, reader).await;

    let response = raw(
        running.address,
        "GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 203.0.113.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    let response = raw(
        running.address,
        "GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 421"), "{response}");

    let response = raw(
        running.address,
        "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn auth_session_flow_and_bearer_access() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let yaml = console_yaml(
        temp.path(),
        "  auth:
    enabled: true
",
    );
    let running = start(&yaml, rx, reader).await;
    let client = client();

    let (status, body, _) = request(
        &client,
        running.address,
        Method::GET,
        "/api/v1/health",
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let token_path = temp.path().join("console-token");
    let token = std::fs::read_to_string(&token_path).expect("token file");
    let token = token.trim();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let (status, _, _) = request(&client, running.address, Method::GET, "/login", &[], None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body, cookie) = request(
        &client,
        running.address,
        Method::POST,
        "/api/v1/session",
        &[("content-type", "application/json".to_owned())],
        Some(&format!("{{\"token\":\"{token}\"}}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cookie = cookie.expect("session cookie");
    assert!(cookie.starts_with("kunato_console="), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    let session = cookie.split(';').next().expect("cookie pair");

    let (status, _, _) = request(
        &client,
        running.address,
        Method::GET,
        "/api/v1/health",
        &[("cookie", session.to_owned())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = request(
        &client,
        running.address,
        Method::GET,
        "/api/v1/health",
        &[("authorization", format!("Bearer {token}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut live_stream = TcpStream::connect(running.address).await.expect("connect");
    live_stream
        .write_all(
            format!(
                "GET /api/v1/live HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: {session}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write live request");
    let mut live_bytes = Vec::new();
    let mut live_chunk = [0u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(3), live_stream.read(&mut live_chunk))
            .await
            .expect("live stream timeout")
            .expect("live stream read");
        assert!(read > 0, "the stream must open before logout");
        live_bytes.extend_from_slice(&live_chunk[..read]);
        let text = String::from_utf8_lossy(&live_bytes);
        if text.contains("event: state") && text.contains("\n\n") {
            break;
        }
    }

    let (status, _, _) = request(
        &client,
        running.address,
        Method::DELETE,
        "/api/v1/session",
        &[("cookie", session.to_owned())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let read = live_stream
                .read(&mut live_chunk)
                .await
                .expect("stream read");
            if read == 0 {
                break true;
            }
        }
    })
    .await
    .expect("the revoked stream must close");
    assert!(closed, "the SSE stream must end after session revocation");

    let (status, _, _) = request(
        &client,
        running.address,
        Method::GET,
        "/api/v1/health",
        &[("cookie", session.to_owned())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn auth_limits_repeated_failed_logins() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let yaml = console_yaml(
        temp.path(),
        "  auth:
    enabled: true
",
    );
    let running = start(&yaml, rx, reader).await;

    for attempt in 0..6 {
        let response = raw(
            running.address,
            "POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"token\":\"wrong\"}",
        )
        .await;
        if attempt < 5 {
            assert!(
                response.starts_with("HTTP/1.1 401"),
                "{attempt}: {response}"
            );
        } else {
            assert!(
                response.starts_with("HTTP/1.1 429"),
                "{attempt}: {response}"
            );
            assert!(
                response.to_lowercase().contains("retry-after:"),
                "{response}"
            );
        }
    }

    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn source_allowlist_denies_loopback_when_not_listed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));
    let yaml = console_yaml(
        temp.path(),
        "  allowed_clients: ['192.0.2.0/24']
",
    );
    let running = start(&yaml, rx, reader).await;
    let response = raw(running.address, &http_get("/")).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    running.stop().await;
    drop(tx);
}

#[tokio::test]
async fn tls_serves_a_combined_key_and_chain_bundle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (reader, packet, health, _) = seeded_collector(temp.path()).await;
    let live = LiveState {
        snapshot: Some(packet),
        health,
    };
    let (tx, rx) = watch::channel(Some(Arc::new(live)));

    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("certificate");
    let bundle = temp.path().join("combined.pem");
    let mut pem = certified.signing_key.serialize_pem();
    pem.push_str(&certified.cert.pem());
    std::fs::write(&bundle, pem).expect("bundle");

    let yaml = console_yaml(
        temp.path(),
        &format!(
            "  tls:
    cert_file: {}
",
            bundle.display()
        ),
    );
    let running = start(&yaml, rx, reader).await;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certified.cert.der().clone())
        .expect("trust anchor");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let stream = TcpStream::connect(running.address).await.expect("connect");
    let mut stream = connector.connect(name, stream).await.expect("handshake");
    stream
        .write_all(b"GET /api/v1/session HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read");
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"tls\":true"), "{response}");

    running.stop().await;
    drop(tx);
}

async fn spawn_snapshot_source(
    snapshot: kunato::observations::StatisticsSnapshot,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let json = Arc::new(serde_json::to_vec(&snapshot).expect("snapshot json"));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("source bind");
    let address = listener.local_addr().expect("source address");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let json = Arc::clone(&json);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_request| {
                    let json = Arc::clone(&json);
                    async move {
                        Ok::<_, std::convert::Infallible>(http::Response::new(
                            kunato::proxy::full_body(json.as_ref().clone()),
                        ))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn runtime_collects_from_the_loopback_snapshot_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let history = Arc::new(Observations::new());
    requests(&history, 2, false).await;
    let packet = history.snapshot(0).expect("snapshot");
    let (source, source_task) = spawn_snapshot_source(packet).await;

    let yaml = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: {{ listen: 127.0.0.1:9090 }}
console:
  enabled: true
  listen: 127.0.0.1:0
  source: {source}
  instance: runtime-test
  storage_dir: {}
",
        temp.path().join("console").display()
    );
    let console = kunato::config::parse(&yaml).expect("config").console;
    let runtime = ConsoleRuntime::start(console).await.expect("runtime");
    let address = runtime.address;
    let client = client();

    let mut connected = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, body, _) =
            request(&client, address, Method::GET, "/api/v1/health", &[], None).await;
        if status == StatusCode::OK {
            let value: serde_json::Value = serde_json::from_str(&body).expect("health");
            if value["collection"]["connected"] == true {
                connected = true;
                break;
            }
        }
    }
    assert!(connected, "console did not connect to the snapshot source");
    runtime.shutdown().await.expect("shutdown");
    source_task.abort();
}
