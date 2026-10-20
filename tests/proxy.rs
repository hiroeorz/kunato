use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::{Buf, Bytes};
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Version};
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

async fn spawn_body_echo_upstream() -> SocketAddr {
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
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();
                    Ok::<_, Infallible>(Response::new(Full::new(body)))
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

async fn spawn_encoded_response_upstream(
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Vec<u8>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let headers = headers.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |_request: Request<Incoming>| {
                    let headers = headers.clone();
                    let body = body.clone();
                    async move {
                        let mut response = Response::new(Full::new(Bytes::from(body)));
                        *response.status_mut() = status;
                        for (name, value) in headers {
                            response.headers_mut().insert(name, value);
                        }
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

async fn spawn_stalling_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
                    .await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });

    addr
}

async fn spawn_identifying_upstream() -> SocketAddr {
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
                    let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
                    response
                        .headers_mut()
                        .insert("server", HeaderValue::from_static("upstream/1.0"));
                    response
                        .headers_mut()
                        .insert("x-powered-by", HeaderValue::from_static("php"));
                    Ok::<_, Infallible>(response)
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

async fn spawn_upgrade_upstream() -> SocketAddr {
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
                let service = service_fn(move |mut request: Request<Incoming>| async move {
                    if request.uri().path() != "/ws" {
                        return Ok::<_, Infallible>(upstream_error(StatusCode::NOT_FOUND));
                    }
                    let forwarded_for = request.headers().contains_key("x-forwarded-for");
                    let forwarded_host = request
                        .headers()
                        .get("x-forwarded-host")
                        .is_some_and(|value| value.as_bytes() == b"kunato.test");
                    if !forwarded_for || !forwarded_host {
                        return Ok(upstream_error(StatusCode::BAD_REQUEST));
                    }

                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    response
                        .headers_mut()
                        .insert("connection", HeaderValue::from_static("upgrade"));
                    response
                        .headers_mut()
                        .insert("upgrade", HeaderValue::from_static("websocket"));
                    let accept = request
                        .headers()
                        .get("sec-websocket-key")
                        .cloned()
                        .unwrap_or_else(|| HeaderValue::from_static("kunato"));
                    response
                        .headers_mut()
                        .insert("sec-websocket-accept", accept);

                    let on_upgrade = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        let Ok(upgraded) = on_upgrade.await else {
                            return;
                        };
                        let mut upgraded = TokioIo::new(upgraded);
                        let mut buf = [0u8; 1024];
                        loop {
                            match upgraded.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => {
                                    if upgraded.write_all(&buf[..read]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                    Ok(response)
                });
                let _ = http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    addr
}

fn upstream_error(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

async fn websocket_handshake(addr: SocketAddr, path: &str) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(addr).await.expect("connect kunato");
    let request = format!(
        "GET {path} HTTP/1.1\r\nhost: kunato.test\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write handshake");
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).await.expect("read handshake");
        if read == 0 || response.len() > 8192 {
            break;
        }
        response.push(byte[0]);
    }
    (String::from_utf8_lossy(&response).into_owned(), stream)
}

struct Running {
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    config: Arc<ArcSwap<config::CompiledConfig>>,
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
    let listen = compiled.listen;
    let config = Arc::new(ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(Metrics::new());
    let server = Server::bind(listen, config.clone(), metrics.clone(), None)
        .await
        .expect("bind kunato");
    let addr = server.local_addr().expect("local address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown_rx));
    Running {
        addr,
        metrics,
        config,
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

async fn send_h1_with_host(
    addr: SocketAddr,
    method: Method,
    uri: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr).await.expect("connect kunato");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("http1 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("build request");

    let response = sender.send_request(request).await.expect("request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn send_h2c_with_authority(
    addr: SocketAddr,
    authority: &str,
    path: &str,
) -> (StatusCode, String) {
    send_h2c_request(addr, authority, None, path).await
}

async fn send_h2c_request(
    addr: SocketAddr,
    authority: &str,
    host: Option<&str>,
    path: &str,
) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr).await.expect("connect kunato");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("http2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri(format!("http://{authority}{path}"));
    if let Some(host) = host {
        builder = builder.header("host", host);
    }
    let request = builder
        .body(Full::new(Bytes::new()))
        .expect("build request");

    let response = sender.send_request(request).await.expect("request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn read_status(stream: &mut TcpStream) -> StatusCode {
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("read timeout")
            .expect("read response");
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&response);
    let code: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .expect("status line");
    StatusCode::from_u16(code).expect("valid status")
}

async fn send_raw_request(addr: SocketAddr, request: &str) -> StatusCode {
    let mut stream = TcpStream::connect(addr).await.expect("connect kunato");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    read_status(&mut stream).await
}

fn config_with_allowed_hosts(upstream: SocketAddr, allowed: &str) -> String {
    format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nallowed_hosts: {allowed}\ncategories: []\n"
    )
}

async fn send_bytes(
    addr: SocketAddr,
    method: Method,
    path: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> (StatusCode, Vec<u8>) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", addr.to_string());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .expect("build request");

    let response = client.request(request).await.expect("request");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, bytes.to_vec())
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("zlib write");
    encoder.finish().expect("zlib finish")
}

fn nested_query(depth: usize) -> String {
    let mut query = String::new();
    for _ in 0..depth {
        query.push_str("{ a ");
    }
    query.push_str(&"}".repeat(depth));
    query
}

fn multipart_upload(filename: &str, content_type: &str, value: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"--X\r\n");
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(value);
    body.extend_from_slice(b"\r\n--X--\r\n");
    body
}

fn json_query_body(query: &str) -> Vec<u8> {
    format!(
        "{{\"query\":{}}}",
        serde_json::to_string(query).expect("encode query")
    )
    .into_bytes()
}

async fn send_with_headers(
    addr: SocketAddr,
    method: Method,
    path: &str,
    body: &str,
) -> (StatusCode, http::HeaderMap) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", addr.to_string())
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("build request");

    let response = client.request(request).await.expect("request");
    (response.status(), response.headers().clone())
}

async fn send_h2c(
    addr: SocketAddr,
    method: Method,
    path: &str,
    body: &str,
) -> (StatusCode, String) {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(method)
        .uri(format!("http://{addr}{path}"))
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

fn write_test_certificate(
    dir: &tempfile::TempDir,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    rustls::pki_types::CertificateDer<'static>,
) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).expect("write key");
    (cert_path, key_path, certified.cert.der().clone())
}

async fn start_http3_kunato(
    upstream: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    categories: &str,
) -> Running {
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
tls:
  cert_file: {}
  key_file: {}
http3: {{ enabled: true }}
{categories}
",
        cert_path.display(),
        key_path.display()
    );
    start_kunato(&yaml).await
}

async fn send_h3(
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    method: Method,
    path: &str,
    body: &str,
) -> (StatusCode, String, http::HeaderMap) {
    send_h3_with_authority(addr, certificate, "localhost", method, path, body).await
}

async fn send_h3_with_authority(
    addr: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    authority: &str,
    method: Method,
    path: &str,
    body: &str,
) -> (StatusCode, String, http::HeaderMap) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("trust test certificate");
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_config)
            .expect("QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
        .expect("create client endpoint");
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(addr, "localhost")
        .expect("start connection")
        .await
        .expect("QUIC handshake");
    let (mut h3_connection, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .expect("HTTP/3 handshake");
    let _connection_task = tokio::spawn(async move { h3_connection.wait_idle().await });

    let request = Request::builder()
        .method(method)
        .uri(format!("https://{authority}{path}"))
        .body(())
        .expect("build request");
    let mut stream = send_request
        .send_request(request)
        .await
        .expect("send request");
    if !body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(body.as_bytes()))
            .await
            .expect("send body");
    }
    stream.finish().await.expect("finish request");

    let response = stream.recv_response().await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let mut received = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("response body") {
        received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (
        status,
        String::from_utf8_lossy(&received).into_owned(),
        headers,
    )
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
async fn allowed_hosts_forwards_listed_and_rejects_unlisted_hosts() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let (status, body) =
        send_h1_with_host(running.addr, Method::GET, "/", "example.com", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, body) =
        send_h1_with_host(running.addr, Method::GET, "/", "evil.example", &[], "").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert!(
        !body.contains("example.com"),
        "the response must not disclose the allowlist"
    );

    assert!(
        running
            .metrics
            .render(0)
            .contains("kunato_host_rejected_total 1")
    );
    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_wildcards_and_ports() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(
        upstream,
        "['*.example.com', 127.0.0.1]",
    ))
    .await;

    for host in ["api.example.com", "a.b.example.com", "127.0.0.1:8080"] {
        let (status, _) = send_h1_with_host(running.addr, Method::GET, "/", host, &[], "").await;
        assert_eq!(status, StatusCode::OK, "host {host}");
    }
    for host in ["example.com", "evil.example"] {
        let (status, _) = send_h1_with_host(running.addr, Method::GET, "/", host, &[], "").await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "host {host}");
    }

    running.stop().await;
}

#[tokio::test]
async fn host_checking_is_disabled_without_allowed_hosts() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (status, body) =
        send_h1_with_host(running.addr, Method::GET, "/", "evil.example", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_checks_the_http2_authority() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[allowed.example]")).await;

    let (status, body) = send_h2c_with_authority(running.addr, "allowed.example", "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, _) = send_h2c_with_authority(running.addr, "evil.example", "/").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_checks_both_http2_host_sources() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(
        upstream,
        "[example.com, other.example]",
    ))
    .await;

    // Both sources are allowed even though they differ; the Host header is what
    // the upstream receives.
    let (status, body) =
        send_h2c_request(running.addr, "other.example", Some("example.com"), "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, _) =
        send_h2c_request(running.addr, "evil.example", Some("example.com"), "/").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    let (status, _) =
        send_h2c_request(running.addr, "example.com", Some("evil.example"), "/").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_checks_the_http3_authority() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(
        upstream,
        &cert_path,
        &key_path,
        "allowed_hosts: [allowed.example]\n",
    )
    .await;

    let (status, body, _) = send_h3_with_authority(
        running.addr,
        certificate.clone(),
        "allowed.example",
        Method::GET,
        "/",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, _, _) = send_h3_with_authority(
        running.addr,
        certificate,
        "evil.example",
        Method::GET,
        "/",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_checks_an_absolute_form_authority() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let (status, _) = send_h1_with_host(
        running.addr,
        Method::GET,
        "http://evil.example/",
        "example.com",
        &[],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    let (status, _) = send_h1_with_host(
        running.addr,
        Method::GET,
        "http://example.com/",
        "evil.example",
        &[],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    let (status, _) = send_h1_with_host(
        running.addr,
        Method::GET,
        "http://example.com/",
        "example.com",
        &[],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_rejects_duplicate_host_headers() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let status = send_raw_request(
        running.addr,
        "GET / HTTP/1.1\r\nHost: example.com\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_rejects_a_missing_host_with_400() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let status = send_raw_request(running.addr, "GET / HTTP/1.0\r\n\r\n").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        running
            .metrics
            .render(0)
            .contains("kunato_host_rejected_total 1")
    );

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_enforces_a_configured_port() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "['example.com:8443']")).await;

    let (status, _) =
        send_h1_with_host(running.addr, Method::GET, "/", "example.com:8443", &[], "").await;
    assert_eq!(status, StatusCode::OK);

    for host in ["example.com", "example.com:443"] {
        let (status, _) = send_h1_with_host(running.addr, Method::GET, "/", host, &[], "").await;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "host {host}");
    }

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_rejects_before_reading_the_body() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nallowed_hosts: [example.com]\ntimeouts: {{ body_read: 200ms }}\ncategories: []\n"
    ))
    .await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 10\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write request");
    assert_eq!(
        read_status(&mut stream).await,
        StatusCode::MISDIRECTED_REQUEST
    );

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_ignores_x_forwarded_host() {
    let upstream = spawn_header_echo_upstream("x-forwarded-host").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let (status, body) = send_h1_with_host(
        running.addr,
        Method::GET,
        "/",
        "example.com",
        &[("x-forwarded-host", "evil.example")],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "example.com");

    let (status, _) = send_h1_with_host(
        running.addr,
        Method::GET,
        "/",
        "evil.example",
        &[("x-forwarded-host", "example.com")],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_cannot_be_bypassed_by_an_allow_rule_or_disabled_protection() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
allowed_hosts: [example.com]
protection: {{ enabled: false }}
categories:
  - name: allow-all
    action: ALLOW
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) =
        send_h1_with_host(running.addr, Method::GET, "/", "evil.example", &[], "").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);

    let (status, body) =
        send_h1_with_host(running.addr, Method::GET, "/", "example.com", &[], "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_rejects_a_websocket_handshake_for_an_unlisted_host() {
    let upstream = spawn_upgrade_upstream().await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let (handshake, _stream) = websocket_handshake(running.addr, "/ws").await;
    assert!(
        handshake.starts_with("HTTP/1.1 421"),
        "unexpected handshake: {handshake}"
    );

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_forwards_a_listed_websocket_handshake() {
    let upstream = spawn_upgrade_upstream().await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[kunato.test]")).await;

    let (handshake, _stream) = websocket_handshake(running.addr, "/ws").await;
    assert!(
        handshake.starts_with("HTTP/1.1 101"),
        "unexpected handshake: {handshake}"
    );

    running.stop().await;
}

#[tokio::test]
async fn allowed_hosts_hot_reload_swaps_the_policy() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let running = start_kunato(&config_with_allowed_hosts(upstream, "[example.com]")).await;

    let (status, _) =
        send_h1_with_host(running.addr, Method::GET, "/", "example.com", &[], "").await;
    assert_eq!(status, StatusCode::OK);

    running.config.store(Arc::new(
        config::parse(&config_with_allowed_hosts(upstream, "[other.example]"))
            .expect("valid config"),
    ));

    let (status, _) =
        send_h1_with_host(running.addr, Method::GET, "/", "example.com", &[], "").await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    let (status, _) =
        send_h1_with_host(running.addr, Method::GET, "/", "other.example", &[], "").await;
    assert_eq!(status, StatusCode::OK);

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
async fn allow_marker_cannot_be_shadowed_by_duplicate_header_values() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: trusted-marker
    action: ALLOW
    rules:
      - name: marker
        match: {{ headers: {{ x-marker: '^tokenfree$' }} }}
  - name: protected
    action: BLOCK
    rules:
      - name: no-secret
        match: {{ path: ^/secret }}
"
    );
    let running = start_kunato(&yaml).await;

    // Without the marker the BLOCK stands.
    let (status, _) = send(running.addr, Method::GET, "/secret", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A trusted request with the marker is allowed.
    let (status, body) = send_bytes(
        running.addr,
        Method::GET,
        "/secret",
        Vec::new(),
        &[("x-marker", "tokenfree")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello");

    // A second copy of the same header must agree too, so the marker cannot
    // shadow the BLOCK by appending a forged value.
    for extra in ["bogus", "tokenfreebogus"] {
        let (status, _) = send_bytes(
            running.addr,
            Method::GET,
            "/secret",
            Vec::new(),
            &[("x-marker", "tokenfree"), ("x-marker", extra)],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "extra value {extra}");
    }

    running.stop().await;
}

#[tokio::test]
async fn allow_query_marker_cannot_be_appended_to_blocked_path() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: trusted-marker
    action: ALLOW
    rules:
      - name: marker
        match: {{ regex: '^q=tokenfree$', in: [query] }}
  - name: protected
    action: BLOCK
    rules:
      - name: no-secret
        match: {{ path: ^/secret }}
"
    );
    let running = start_kunato(&yaml).await;

    // The exact marker query is trusted.
    let (status, body) = send(running.addr, Method::GET, "/secret?q=tokenfree", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    // Appending the marker anywhere else keeps the BLOCK.
    for appended in ["/secret?q=tokenfree&z=1", "/secret?a=zz&q=tokenfree"] {
        let (status, _) = send(running.addr, Method::GET, appended, "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{appended}");
    }

    // Encoded forms of the marker do not pass either: the raw query must agree.
    let (status, _) = send(running.addr, Method::GET, "/secret?q=token%66ree", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn response_header_policy_rewrites_upstream_headers() {
    let upstream = spawn_identifying_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
response_headers:
  remove: [server, x-powered-by]
  set: {{ x-served-by: kunato }}
categories: []
"
    );
    let running = start_kunato(&yaml).await;

    let (status, headers) = send_with_headers(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("server"));
    assert!(!headers.contains_key("x-powered-by"));
    assert_eq!(
        headers
            .get("x-served-by")
            .and_then(|value| value.to_str().ok()),
        Some("kunato")
    );

    running.stop().await;
}

#[tokio::test]
async fn response_header_policy_applies_to_block_responses() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
response_headers:
  set: {{ server: hidden }}
categories:
  - name: catch-all
    action: BLOCK
    rules:
      - name: everything
        match: {{ path: ^/ }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, headers) = send_with_headers(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        headers.get("server").and_then(|value| value.to_str().ok()),
        Some("hidden")
    );

    running.stop().await;
}

#[tokio::test]
async fn response_header_policy_applies_to_http3() {
    let upstream = spawn_identifying_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(
        upstream,
        &cert_path,
        &key_path,
        "response_headers:\n  remove: [server, x-powered-by]\n",
    )
    .await;

    let (status, _, headers) = send_h3(running.addr, certificate, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!headers.contains_key("server"));
    assert!(!headers.contains_key("x-powered-by"));

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
async fn oversized_body_without_body_rules_is_streamed() {
    let upstream = spawn_body_echo_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let body: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    let (status, echoed) =
        send_bytes(running.addr, Method::POST, "/upload", body.clone(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, body);

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_applies_after_rule_evaluation() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\ncategories:\n  - name: sig\n    action: BLOCK\n    rules:\n      - name: prefix-signature\n        match: {{ regex: 'BLOCKME', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    // A matching BLOCK rule still decides, with its configured response.
    let mut body = b"BLOCKME".to_vec();
    body.extend_from_slice(&vec![b'x'; 64 * 1024]);
    let (status, _) = send_bytes(running.addr, Method::POST, "/upload", body, &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Padding the body past the limit used to hide the signature from the
    // body rules; with no rule deciding, strict inspection rejects instead.
    let mut body = b"AAAAAAAA".to_vec();
    body.extend_from_slice(b"BLOCKME");
    let (status, _) = send_bytes(running.addr, Method::POST, "/upload", body, &[]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_body_rejected_total 1"),
        "{rendered}"
    );
    assert!(
        rendered.contains("kunato_request_truncated_total 2"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_allows_a_matching_allow_rule() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\ncategories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: local\n        match: {{ source_ip: 127.0.0.1/32 }}\n  - name: sig\n    action: BLOCK\n    rules:\n      - name: body-signature\n        match: {{ regex: 'BLOCKME', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        b"123456789".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_body_rejected_total 0"),
        "{rendered}"
    );
    assert!(
        rendered.contains("kunato_request_truncated_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn stalled_encoded_bodies_do_not_exhaust_the_inspection_budget() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8388608 }}\ntimeouts: {{ body_read: 5s }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let mut held = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(running.addr)
            .await
            .expect("connect kunato");
        let request = "POST /hold HTTP/1.1\r\nhost: kunato.test\r\ncontent-encoding: gzip\r\ntransfer-encoding: chunked\r\n\r\n1\r\nA\r\n";
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write held request");
        held.push(stream);
    }
    for _ in 0..50 {
        if running
            .metrics
            .render(0)
            .contains("kunato_requests_total 4")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    drop(held);
    running.stop().await;
}

#[tokio::test]
async fn stream_body_inspection_only_inspects_the_prefix() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8, body_inspection: stream }}\ncategories:\n  - name: sig\n    action: BLOCK\n    rules:\n      - name: prefix-signature\n        match: {{ regex: 'BLOCKME', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let mut body = b"BLOCKME".to_vec();
    body.extend_from_slice(&vec![b'x'; 64 * 1024]);
    let (status, _) = send_bytes(running.addr, Method::POST, "/upload", body, &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut body = b"AAAAAAAA".to_vec();
    body.extend_from_slice(b"BLOCKME");
    let (status, _) = send_bytes(running.addr, Method::POST, "/upload", body, &[]).await;
    assert_eq!(status, StatusCode::OK);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_body_rejected_total 0"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_rejects_spoofed_content() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ upload_inspection: mismatch }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let body = multipart_upload(
        "photo.jpg",
        "image/jpeg",
        b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
    );
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body,
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_upload_rejected_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_accepts_benign_and_explicit_uploads() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ upload_inspection: mismatch }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    for (filename, content_type, value) in [
        (
            "photo.jpg",
            "image/jpeg",
            b"\xff\xd8\xff\xe0JFIF".as_slice(),
        ),
        ("report.pdf", "application/pdf", b"%PDF-1.7\n"),
        ("tool", "application/octet-stream", b"\x7fELF\x02\x01\x01"),
        (
            "page.html",
            "text/html",
            b"<!doctype html><script>alert(1)</script>",
        ),
    ] {
        let body = multipart_upload(filename, content_type, value);
        let (status, _) = send_bytes(
            running.addr,
            Method::POST,
            "/upload",
            body,
            &[("content-type", "multipart/form-data; boundary=X")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{filename} ({content_type})");
    }

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_upload_rejected_total 0"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_strict_blocks_generic_executables() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ upload_inspection: strict }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let body = multipart_upload("tool", "application/octet-stream", b"\x7fELF\x02\x01\x01");
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body,
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let body = multipart_upload(
        "page.html",
        "text/html",
        b"<!doctype html><script>alert(1)</script>",
    );
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body,
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_is_not_bypassed_by_allow_rules() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ upload_inspection: mismatch }}\ncategories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: local\n        match: {{ source_ip: 127.0.0.1/32 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let body = multipart_upload("photo.jpg", "image/jpeg", b"<?php echo 1;");
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body,
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_decodes_compressed_bodies() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ upload_inspection: mismatch }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let body = multipart_upload("photo.jpg", "image/jpeg", b"<?php echo 1;");
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        gzip(&body),
        &[
            ("content-type", "multipart/form-data; boundary=X"),
            ("content-encoding", "gzip"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn upload_inspection_rejects_truncated_uploads_in_strict_mode() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 64 }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let body = multipart_upload("photo.jpg", "image/jpeg", &[b'A'; 256]);
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body,
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn graphql_depth_and_field_limits_reject_complex_queries() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let (status, body) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body("{ viewer { name } }"),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello");

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&nested_query(21)),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut fragments = String::from("query { ...F0 }");
    for level in 0..21 {
        fragments.push_str(&format!(
            " fragment F{level} on Query {{ a {{ ...F{} }} }}",
            level + 1
        ));
    }
    fragments.push_str(" fragment F21 on Query { a }");
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&fragments),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut aliases = String::from("query {");
    for index in 0..1001 {
        aliases.push_str(&format!(" a{index}: field"));
    }
    aliases.push('}');
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&aliases),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let multipart = "--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n\r\nPNG\r\n--X--\r\n";
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        multipart.as_bytes().to_vec(),
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(
        running
            .metrics
            .render(0)
            .contains("kunato_graphql_rejected_total 4")
    );

    running.stop().await;
}

#[tokio::test]
async fn graphql_parser_handles_the_maximum_configured_depth() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\nlimits: {{ graphql: {{ max_depth: 1000, max_fields: 10000 }} }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&nested_query(1000)),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello");

    running.stop().await;
}

#[tokio::test]
async fn graphql_inline_fragment_recursion_is_bounded() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let mut query = String::from("{");
    for _ in 0..15_000 {
        query.push_str("...{");
    }
    query.push_str(&"}".repeat(15_001));

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&query),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limits_are_path_scoped_and_configurable() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\nlimits: {{ graphql: {{ paths: [/query] }} }}\n"
    );
    let running = start_kunato(&yaml).await;

    let deep = json_query_body(&nested_query(21));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/query",
        deep.clone(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = send_bytes(
        running.addr,
        Method::POST,
        "/ordinary",
        deep.clone(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello");

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/api/gql",
        deep.clone(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql;jsessionid=abc",
        deep,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_applies_to_h2c_and_upgrade_handshakes() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let (status, _) = send_h2c(
        running.addr,
        Method::POST,
        "/graphql",
        &String::from_utf8(json_query_body(&nested_query(21))).expect("json"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let query = nested_query(21)
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace(' ', "%20");
    let (response, _stream) =
        websocket_handshake(running.addr, &format!("/graphql?query={query}")).await;
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected handshake response: {response}"
    );

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_is_independent_of_protection() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\nprotection: {{ enabled: false }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        json_query_body(&nested_query(21)),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_accepts_a_disabled_guard() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\nlimits: {{ graphql: {{ enabled: false }} }}\n"
    );
    let running = start_kunato(&yaml).await;

    let deep = json_query_body(&nested_query(21));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        deep,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_decodes_compressed_bodies() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let body = gzip(&json_query_body(&nested_query(21)));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        body,
        &[
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_rejects_a_truncated_uninspectable_body() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\nlimits: {{ max_body_bytes: 32, body_inspection: stream }}\n"
    );
    let running = start_kunato(&yaml).await;

    let deep = json_query_body(&nested_query(21));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        deep,
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_detects_get_queries() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let query = nested_query(21)
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace(' ', "%20");
    let (status, _) = send(
        running.addr,
        Method::GET,
        &format!("/graphql?query={query}"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    running.stop().await;
}

#[tokio::test]
async fn graphql_limit_ignores_non_graphql_bodies() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n");
    let running = start_kunato(&yaml).await;

    let (status, body) = send_bytes(
        running.addr,
        Method::POST,
        "/graphql",
        br#"{"query":"select * from users"}"#.to_vec(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello");

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
async fn behavior_enumeration_flags_and_logs() {
    let upstream = spawn_upstream(StatusCode::NOT_FOUND, "missing").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    enabled: true
    window: 60s
    min_requests: 1
    enumeration: {{ enabled: true, action: LOG, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/missing-one", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(running.metrics.behavior_blocked.load(Ordering::Relaxed), 0);

    running.stop().await;
}

#[tokio::test]
async fn behavior_enumeration_block_bans_the_source() {
    let upstream = spawn_upstream(StatusCode::NOT_FOUND, "missing").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    min_requests: 1
    enumeration: {{ enabled: true, action: BLOCK, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/missing-one", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(running.metrics.behavior_blocked.load(Ordering::Relaxed), 1);

    let (status, _) = send(running.addr, Method::GET, "/missing-two", "").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(running.metrics.banned.load(Ordering::Relaxed), 1);

    running.stop().await;
}

#[tokio::test]
async fn behavior_auth_failures_only_count_auth_paths() {
    let upstream = spawn_upstream(StatusCode::UNAUTHORIZED, "denied").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    enumeration: {{ enabled: false }}
    auth: {{ enabled: true, action: LOG, min_failures: 2 }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::POST, "/login", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(running.addr, Method::POST, "/login", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        running
            .metrics
            .behavior_auth_failures
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        running.metrics.behavior_auth_flags.load(Ordering::Relaxed),
        1
    );

    let (status, _) = send(running.addr, Method::POST, "/api/users", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        running
            .metrics
            .behavior_auth_failures
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        running.metrics.behavior_auth_flags.load(Ordering::Relaxed),
        1
    );

    running.stop().await;
}

#[tokio::test]
async fn behavior_ignores_locally_blocked_requests() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: block-admin
    action: BLOCK
    rules:
      - name: admin
        match: {{ path: '^/admin' }}
protection:
  behavior:
    min_requests: 1
    enumeration: {{ enabled: true, action: LOG, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/admin", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        0
    );

    running.stop().await;
}

#[tokio::test]
async fn behavior_is_disabled_with_protection() {
    let upstream = spawn_upstream(StatusCode::NOT_FOUND, "missing").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  enabled: false
  behavior:
    min_requests: 1
    enumeration: {{ enabled: true, action: LOG, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/missing", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        0
    );

    running.stop().await;
}

#[tokio::test]
async fn behavior_observes_http2_responses() {
    let upstream = spawn_upstream(StatusCode::NOT_FOUND, "missing").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    min_requests: 1
    enumeration: {{ enabled: true, action: LOG, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_h2c(running.addr, Method::GET, "/missing-h2", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        1
    );

    running.stop().await;
}

#[tokio::test]
async fn behavior_settings_hot_reload() {
    let upstream = spawn_upstream(StatusCode::NOT_FOUND, "missing").await;
    let enabled = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    min_requests: 1
    enumeration: {{ enabled: true, action: LOG, not_found_ratio: 0.0, distinct_paths: 1 }}
    auth: {{ enabled: false }}
    global_auth: {{ enabled: false }}
"
    );
    let running = start_kunato(&enabled).await;

    let (status, _) = send(running.addr, Method::GET, "/missing-one", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        1
    );

    let disabled = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection:
  behavior:
    enabled: false
"
    );
    running
        .config
        .store(Arc::new(config::parse(&disabled).expect("valid config")));

    let (status, _) = send(running.addr, Method::GET, "/missing-two", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        running
            .metrics
            .behavior_enumeration_flags
            .load(Ordering::Relaxed),
        1
    );

    running.stop().await;
}

#[tokio::test]
async fn ipv6_listener_enforces_rate_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: \"[::1]:0\"\nupstream: http://{upstream}\nprotection: {{ requests_per_second: 1, burst: 1 }}\n"
    );
    let running = start_kunato(&yaml).await;
    assert!(running.addr.is_ipv6());

    let (first, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(first, StatusCode::OK);

    let (second, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);

    running.stop().await;
}

#[tokio::test]
async fn gzip_request_body_is_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        gzip(b"q=1 union select password"),
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn multi_member_gzip_request_body_is_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let mut body = gzip(b"benign first member");
    body.extend_from_slice(&gzip(b" union select password"));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        body,
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn stacked_content_encodings_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let body = zlib(&gzip(b"q=1 union select password"));
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        body,
        &[("content-encoding", "gzip, deflate")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn compressed_request_body_is_forwarded_unchanged() {
    let upstream = spawn_body_echo_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: never-matches\n        match: {{ regex: 'never-matches-xyz', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let body = gzip(b"payload for the upstream");
    let (status, echoed) = send_bytes(
        running.addr,
        Method::POST,
        "/echo",
        body.clone(),
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, body);

    running.stop().await;
}

#[tokio::test]
async fn truncated_body_cannot_satisfy_an_allow_rule() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_body_bytes: 8, body_inspection: stream }}
categories:
  - name: trusted
    action: ALLOW
    rules:
      - name: trusted-body
        match: {{ regex: '^trusted!.*$', in: [body] }}
  - name: deny
    action: BLOCK
    rules:
      - name: deny-path
        match: {{ path: ^/truncated-allow$ }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/truncated-allow",
        b"trusted!this suffix was not inspected".to_vec(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn urlencoded_request_body_is_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-slash\n        match: {{ regex: '(?i)union/select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        b"q=%27+union%2Fselect+1".to_vec(),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn json_request_body_is_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        br#"{"q":"\u0075nion select"}"#.to_vec(),
        &[("content-type", "application/json")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn double_encoded_query_payloads_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [query] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/?q=union%2520select", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = send(running.addr, Method::GET, "/safe", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn plus_separated_query_payloads_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [query] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/?q=union+select+password", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(running.addr, Method::GET, "/?q=unionxxselect", "").await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn double_encoded_body_payloads_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: sqli\n    action: BLOCK\n    rules:\n      - name: union-select\n        match: {{ regex: '(?i)union\\s+select', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        b"q=1%2520union%2520select%2520password".to_vec(),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn multipart_filename_traversal_is_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: traversal\n    action: BLOCK\n    rules:\n      - name: dot-dot-slash\n        match: {{ regex: '\\.\\./', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let body = b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../etc/passwd\"\r\nContent-Type: text/plain\r\n\r\nblob\r\n--X--\r\n";
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        body.to_vec(),
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let safe = b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\nblob\r\n--X--\r\n";
    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/upload",
        safe.to_vec(),
        &[("content-type", "multipart/form-data; boundary=X")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn rule_limit_blocks_after_burst_but_not_other_paths() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: brute-force\n    action: BLOCK\n    rules:\n      - name: login\n        limit: {{ requests: 2, window: 60s }}\n        match: {{ path: ^/login$ }}\n"
    );
    let running = start_kunato(&yaml).await;

    for _ in 0..2 {
        let (status, _) = send(running.addr, Method::POST, "/login", "user=a").await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = send(running.addr, Method::POST, "/login", "user=a").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(running.addr, Method::POST, "/other", "user=a").await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn threshold_category_blocks_on_enough_signals() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: anomaly\n    action: BLOCK\n    threshold: 2\n    rules:\n      - name: login-path\n        match: {{ path: ^/login$ }}\n      - name: admin-param\n        match: {{ regex: '(?i)admin', in: [query] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/login", "").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(running.addr, Method::GET, "/login?u=admin", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn gzip_response_body_is_rule_evaluated() {
    let upstream = spawn_encoded_response_upstream(
        StatusCode::OK,
        vec![(
            HeaderName::from_static("content-encoding"),
            HeaderValue::from_static("gzip"),
        )],
        gzip(b"warning: stack trace leak"),
    )
    .await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories:\n  - name: leaks\n    phase: response\n    action: BLOCK\n    rules:\n      - name: stack-trace\n        match: {{ regex: '(?i)stack trace', in: [response_body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn body_at_limit_is_accepted_without_body_rules() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::POST, "/exact", "12345678").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(running.addr, Method::POST, "/over", "123456789").await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_accepts_a_body_at_the_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\ncategories:\n  - name: sig\n    action: BLOCK\n    rules:\n      - name: prefix-signature\n        match: {{ regex: 'BLOCKME', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::POST, "/exact", "12345678").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(running.addr, Method::POST, "/over", "123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_body_rejected_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

async fn send_chunked_request(addr: SocketAddr, path: &str, body: &[u8]) -> (StatusCode, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect kunato");
    let mut wire =
        format!("POST {path} HTTP/1.1\r\nhost: kunato.test\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n")
            .into_bytes();
    wire.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    wire.extend_from_slice(body);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    stream
        .write_all(&wire)
        .await
        .expect("write chunked request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&response).into_owned();
    let status = response
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.split(' ').next())
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let status = StatusCode::from_u16(status).expect("status code");
    let (_, body) = response.split_once("\r\n\r\n").expect("response head");
    (status, body.to_owned())
}

/// A chunked body whose total size equals `max_body_bytes` is inspected in
/// full: no truncation counter, and the replay body must stay byte-exact.
#[tokio::test]
async fn chunked_request_body_at_the_limit_is_not_truncated() {
    let upstream = spawn_body_echo_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send_chunked_request(running.addr, "/exact", b"12345678").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "12345678");

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_truncated_total 0"),
        "{rendered}"
    );

    let (status, body) = send_chunked_request(running.addr, "/over", b"123456789").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "123456789");

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_truncated_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_rejects_a_chunked_body_over_the_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_body_bytes: 8 }}\ncategories:\n  - name: sig\n    action: BLOCK\n    rules:\n      - name: prefix-signature\n        match: {{ regex: 'BLOCKME', in: [body] }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_chunked_request(running.addr, "/exact", b"12345678").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_chunked_request(running.addr, "/over", b"123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_body_rejected_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

async fn spawn_chunked_response_upstream(raw: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n{raw}").as_bytes(),
                    )
                    .await
                    .expect("write chunked response");
            });
        }
    });

    addr
}

#[tokio::test]
async fn chunked_response_body_at_the_limit_is_not_truncated() {
    let exact = spawn_chunked_response_upstream("8\r\n12345678\r\n0\r\n\r\n").await;
    let over = spawn_chunked_response_upstream("8\r\n12345678\r\n1\r\n9\r\n0\r\n\r\n").await;
    let yaml = |response_addr| {
        format!(
            "listen: 127.0.0.1:0\nupstream: http://{response_addr}\nlimits: {{ max_response_body_bytes: 8 }}\ncategories:\n  - name: inspect\n    phase: response\n    action: LOG\n    rules:\n      - name: never\n        match: {{ regex: 'never-matches-xyz', in: [response_body] }}\n"
        )
    };

    let running = start_kunato(&yaml(exact)).await;
    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "12345678");
    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_response_truncated_total 0"),
        "{rendered}"
    );
    running.stop().await;

    let running = start_kunato(&yaml(over)).await;
    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    // The body streamed past the limit keeps every byte the lookahead consumed.
    assert_eq!(body, "123456789");
    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_response_truncated_total 1"),
        "{rendered}"
    );
    running.stop().await;
}

#[tokio::test]
async fn malformed_chunked_body_is_bad_request() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\n");
    let running = start_kunato(&yaml).await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    let request = "POST /upload HTTP/1.1\r\nhost: kunato.test\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\nnot-a-chunk\r\n";
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
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );

    // The 400 is a handled request, so the total must include it.
    let rendered = running.metrics.render(0);
    assert!(rendered.contains("kunato_requests_total 1"), "{rendered}");

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
async fn oversized_request_target_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\nlimits: {{ max_path_bytes: 16 }}\n"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/?q=0123456789abcdef", "").await;
    assert_eq!(status, StatusCode::URI_TOO_LONG);

    let (status, _) = send(running.addr, Method::GET, "/?q=short", "").await;
    assert_eq!(status, StatusCode::OK);

    running.stop().await;
}

#[tokio::test]
async fn non_canonical_method_case_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!("listen: 127.0.0.1:0\nupstream: http://{upstream}\n");
    let running = start_kunato(&yaml).await;

    for method in ["get", "Get", "pOsT"] {
        let mut stream = TcpStream::connect(running.addr)
            .await
            .expect("connect kunato");
        let request =
            format!("{method} / HTTP/1.1\r\nhost: kunato.test\r\nconnection: close\r\n\r\n");
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
            response.starts_with("HTTP/1.1 400"),
            "method `{method}` should be rejected: {response}"
        );
    }

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);

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
async fn http2_cleartext_prior_knowledge_is_proxied() {
    let upstream = spawn_header_echo_upstream("x-forwarded-proto").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (status, body) = send_h2c(running.addr, Method::POST, "/echo", "payload").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "http");

    running.stop().await;
}

#[tokio::test]
async fn http2_requests_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: sql-injection
    action: BLOCK
    rules:
      - name: union-select
        match: {{ regex: '(?i)union\\s+select', in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send_h2c(running.addr, Method::POST, "/", "hello").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, _) = send_h2c(running.addr, Method::POST, "/", "union select 1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_rejects_an_http2_body_over_the_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_body_bytes: 8 }}
categories:
  - name: sig
    action: BLOCK
    rules:
      - name: prefix-signature
        match: {{ regex: 'BLOCKME', in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_h2c(running.addr, Method::POST, "/", "12345678").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_h2c(running.addr, Method::POST, "/", "123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn tls_alpn_negotiates_http2() {
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
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(running.addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "server must negotiate h2 over ALPN"
    );

    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 handshake");
    let connection_task = tokio::spawn(connection);

    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri("https://localhost/")
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let response = sender.send_request(request).await.expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(String::from_utf8_lossy(&bytes), "https");

    running.stop().await;
    let _ = connection_task.await;
}

#[tokio::test]
async fn tls_h2_connection_without_a_preface_is_closed_by_the_idle_watchdog() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
timeouts: {{ header_read: 2s, connection_idle: 100ms }}
tls:
  cert_file: {}
  key_file: {}
",
        cert_path.display(),
        key_path.display()
    );
    let running = start_kunato(&yaml).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("trust test certificate");
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(running.addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let mut bytes = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut bytes)).await;
    assert!(
        closed.is_ok(),
        "a TLS/ALPN h2 connection that never sends a preface must not hold a slot"
    );

    running.stop().await;
}

#[tokio::test]
async fn http3_requests_are_proxied_and_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(
        upstream,
        &cert_path,
        &key_path,
        "categories:
  - name: sql-injection
    action: BLOCK
    rules:
      - name: union-select
        match: { regex: '(?i)union\\s+select', in: [body] }
",
    )
    .await;

    let (status, body, _) = send_h3(
        running.addr,
        certificate.clone(),
        Method::POST,
        "/",
        "hello",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    let (status, _, _) = send_h3(
        running.addr,
        certificate,
        Method::POST,
        "/",
        "union select 1",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_rejects_an_http3_body_over_the_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(
        upstream,
        &cert_path,
        &key_path,
        "limits: { max_body_bytes: 8 }
categories:
  - name: sig
    action: BLOCK
    rules:
      - name: prefix-signature
        match: { regex: 'BLOCKME', in: [body] }
",
    )
    .await;

    let (status, _, _) = send_h3(
        running.addr,
        certificate.clone(),
        Method::POST,
        "/",
        "12345678",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = send_h3(running.addr, certificate, Method::POST, "/", "123456789").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    running.stop().await;
}

#[tokio::test]
async fn http3_graphql_limit_rejects_deep_queries() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(upstream, &cert_path, &key_path, "categories: []").await;

    let deep = String::from_utf8(json_query_body(&nested_query(21))).expect("json");
    let (status, _, _) = send_h3(
        running.addr,
        certificate.clone(),
        Method::POST,
        "/graphql",
        &deep,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let shallow = String::from_utf8(json_query_body("{ a }")).expect("json");
    let (status, body, _) = send_h3(
        running.addr,
        certificate,
        Method::POST,
        "/graphql",
        &shallow,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");

    running.stop().await;
}

#[tokio::test]
async fn http3_sets_forwarded_host_and_advertises_alt_svc() {
    let upstream = spawn_header_echo_upstream("x-forwarded-host").await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(upstream, &cert_path, &key_path, "categories: []").await;

    let (status, body, _) = send_h3(running.addr, certificate.clone(), Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "localhost");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("trust test certificate");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(running.addr).await.expect("connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("HTTP/1.1 handshake");
    let connection_task = tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://localhost:{}/", running.addr.port()))
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let response = sender.send_request(request).await.expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let alt_svc = response
        .headers()
        .get("alt-svc")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        alt_svc.contains(&format!("h3=\":{}\"", running.addr.port())),
        "unexpected alt-svc: {alt_svc}"
    );

    drop(sender);
    let _ = connection_task.await;
    running.stop().await;
}

#[tokio::test]
async fn http3_oversized_body_without_body_rules_is_streamed() {
    let upstream = spawn_body_echo_upstream().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let running = start_http3_kunato(
        upstream,
        &cert_path,
        &key_path,
        "limits: { max_body_bytes: 8 }\ncategories: []",
    )
    .await;

    let body: String = (0..4096)
        .map(|index| char::from(b'a' + (index % 26) as u8))
        .collect();
    let (status, echoed, _) =
        send_h3(running.addr, certificate, Method::POST, "/upload", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, body);

    running.stop().await;
}

#[tokio::test]
async fn websocket_upgrade_is_tunneled() {
    let upstream = spawn_upgrade_upstream().await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (handshake, mut stream) = websocket_handshake(running.addr, "/ws").await;
    assert!(
        handshake.starts_with("HTTP/1.1 101"),
        "unexpected handshake: {handshake}"
    );

    stream.write_all(b"ping").await.expect("write frame");
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).await.expect("read echo");
    assert_eq!(&echo, b"ping");

    drop(stream);
    running.stop().await;
}

#[tokio::test]
async fn websocket_handshake_is_rule_evaluated() {
    let upstream = spawn_upgrade_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: websockets
    action: BLOCK
    rules:
      - name: deny-admin-socket
        match: {{ path: ^/ws }}
"
    );
    let running = start_kunato(&yaml).await;

    let (handshake, _stream) = websocket_handshake(running.addr, "/ws").await;
    assert!(
        handshake.starts_with("HTTP/1.1 403"),
        "unexpected handshake: {handshake}"
    );

    running.stop().await;
}

#[tokio::test]
async fn websocket_rejected_upstream_passes_through() {
    let upstream = spawn_upgrade_upstream().await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (handshake, _stream) = websocket_handshake(running.addr, "/nope").await;
    assert!(
        handshake.starts_with("HTTP/1.1 404"),
        "unexpected handshake: {handshake}"
    );

    running.stop().await;
}

#[tokio::test]
async fn websocket_idle_timeout_closes_tunnel() {
    let upstream = spawn_upgrade_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ntimeouts: {{ websocket_idle: 200ms }}\ncategories: []\n"
    );
    let running = start_kunato(&yaml).await;

    let (handshake, mut stream) = websocket_handshake(running.addr, "/ws").await;
    assert!(
        handshake.starts_with("HTTP/1.1 101"),
        "unexpected handshake: {handshake}"
    );

    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("tunnel did not close");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "unexpected read: {closed:?}"
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
        None,
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

#[tokio::test]
async fn response_rule_blocks_matching_upstream_body() {
    let upstream = spawn_upstream(StatusCode::OK, "prefix <script>alert(1)</script>").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: response-xss
    phase: response
    action: BLOCK
    rules:
      - name: reflected-script
        match: {{ path: ^/admin, regex: '(?i)<script', in: [response_body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send(running.addr, Method::GET, "/admin", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Forbidden");

    let (status, body) = send(running.addr, Method::GET, "/public", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "prefix <script>alert(1)</script>");

    running.stop().await;
}

#[tokio::test]
async fn response_log_rule_passes_through() {
    let upstream = spawn_upstream(StatusCode::OK, "the secret is out").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: response-leak
    phase: response
    action: LOG
    rules:
      - name: leaked-secret
        match: {{ regex: secret }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "the secret is out");

    running.stop().await;
}

#[tokio::test]
async fn response_rule_matches_status_and_headers() {
    let upstream = spawn_identifying_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: identifying-responses
    phase: response
    action: BLOCK
    rules:
      - name: versioned-server
        match:
          status: 2xx
          response_headers: {{ server: '(?i)upstream/' }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn payload_after_prefix_limit_is_forwarded() {
    let upstream = spawn_upstream(StatusCode::OK, "safe <script>alert(1)</script>").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_response_body_bytes: 4 }}
categories:
  - name: response-xss
    phase: response
    action: BLOCK
    rules:
      - name: reflected-script
        match: {{ regex: '(?i)<script' }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, body) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "safe <script>alert(1)</script>");

    running.stop().await;
}

#[tokio::test]
async fn prefix_hit_blocks_response_larger_than_limit() {
    let upstream = spawn_upstream(StatusCode::OK, "evil script follows here").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_response_body_bytes: 8 }}
categories:
  - name: response-xss
    phase: response
    action: BLOCK
    rules:
      - name: reflected-script
        match: {{ regex: evil }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn response_rule_blocks_over_h2c() {
    let upstream = spawn_upstream(StatusCode::OK, "the secret is out").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: response-leak
    phase: response
    action: BLOCK
    rules:
      - name: leaked-secret
        match: {{ regex: secret }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_h2c(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn non_utf8_header_does_not_bypass_header_rules() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: scanners
    action: BLOCK
    rules:
      - name: sqlmap
        match: {{ headers: {{ user-agent: '(?i)sqlmap' }} }}
"
    );
    let running = start_kunato(&yaml).await;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/", running.addr))
        .header("host", running.addr.to_string())
        .header(
            "user-agent",
            HeaderValue::from_bytes(b"sqlmap/1.0\xff").expect("valid header bytes"),
        )
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let response = client.request(request).await.expect("request");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn normalized_paths_are_rule_evaluated() {
    let upstream = spawn_upstream(StatusCode::OK, "ADMIN-PANEL").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: admin
    action: BLOCK
    rules:
      - name: admin-area
        match: {{ path: '^/admin$' }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/admin", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for path in [
        "//admin",
        "/./admin",
        "/x/../admin",
        "/a/b/../../admin",
        "/%2fadmin",
    ] {
        let (status, _) = send(running.addr, Method::GET, path, "").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "path {path} bypassed the rule"
        );
    }

    running.stop().await;
}

#[tokio::test]
async fn dual_stack_listener_normalizes_ipv4_mapped_clients() {
    let probe = TcpListener::bind("[::]:0").await;
    let Ok(probe) = probe else {
        return;
    };
    let probe_port = probe.local_addr().expect("probe address").port();
    if TcpStream::connect(("127.0.0.1", probe_port)).await.is_err() {
        return;
    }
    drop(probe);

    let upstream = spawn_header_echo_upstream("x-forwarded-for").await;
    let yaml = format!(
        "listen: \"[::]:0\"
upstream: http://{upstream}
categories:
  - name: local-only
    action: BLOCK
    rules:
      - name: block-loopback
        match: {{ source_ip: 127.0.0.1 }}
"
    );
    let running = start_kunato(&yaml).await;
    assert!(running.addr.is_ipv6());
    let addr = SocketAddr::from(([127, 0, 0, 1], running.addr.port()));

    let (status, _) = send(addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;

    let upstream = spawn_header_echo_upstream("x-forwarded-for").await;
    let running = start_kunato(&format!(
        "listen: \"[::]:0\"\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;
    let addr = SocketAddr::from(([127, 0, 0, 1], running.addr.port()));

    let (status, body) = send(addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "127.0.0.1");

    running.stop().await;
}

#[tokio::test]
async fn decompressed_request_truncation_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_body_bytes: 64 }}
categories:
  - name: signatures
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: never-matches-xyz, in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        gzip(&vec![b'a'; 4096]),
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_decode_truncated_total 1"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("kunato_request_truncated_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn unsupported_request_encoding_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: signatures
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: never-matches-xyz, in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        b"compressed payload".to_vec(),
        &[("content-encoding", "compress")],
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_decode_skipped_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn malformed_request_encoding_is_rejected() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: signatures
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: never-matches-xyz, in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send_bytes(
        running.addr,
        Method::POST,
        "/",
        b"not a gzip stream".to_vec(),
        &[("content-encoding", "gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_request_decode_skipped_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn decompressed_response_truncation_is_reported() {
    let upstream = spawn_encoded_response_upstream(
        StatusCode::OK,
        vec![(
            HeaderName::from_static("content-encoding"),
            HeaderValue::from_static("gzip"),
        )],
        gzip(&vec![b'a'; 4096]),
    )
    .await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_response_body_bytes: 64 }}
categories:
  - name: response-signatures
    phase: response
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: never-matches-xyz, in: [response_body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::OK);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_response_decode_truncated_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn stalled_upstream_response_returns_gateway_timeout() {
    let upstream = spawn_stalling_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
timeouts: {{ upstream_response: 300ms }}
categories:
  - name: response-signatures
    phase: response
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: never-matches-xyz }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);

    let rendered = running.metrics.render(0);
    assert!(
        rendered.contains("kunato_upstream_timeouts_total 1"),
        "{rendered}"
    );

    running.stop().await;
}

#[tokio::test]
async fn failed_websocket_upgrade_keeps_connection_budget() {
    let upstream = spawn_upgrade_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
protection: {{ max_connections_per_ip: 1, max_connections: 8 }}
categories: []
"
    );
    let running = start_kunato(&yaml).await;

    let (handshake, _held) = websocket_handshake(running.addr, "/nope").await;
    assert!(
        handshake.starts_with("HTTP/1.1 404"),
        "unexpected handshake: {handshake}"
    );

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    running.stop().await;
}

async fn spawn_prefix_stalling_upstream(body: &'static [u8], content_length: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream address");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let headers =
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {content_length}\r\n\r\n");
                let _ = stream.write_all(headers.as_bytes()).await;
                let _ = stream.write_all(body).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn partial_http2_preface_is_closed_within_the_header_timeout() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ntimeouts: {{ header_read: 100ms }}\n"
    );
    let running = start_kunato(&yaml).await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    stream.write_all(b"P").await.expect("write partial preface");
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    assert!(
        read.is_ok(),
        "a partial preface must not keep the connection spinning past the deadline"
    );

    running.stop().await;
}

#[tokio::test]
async fn websocket_upstream_error_respects_response_rules() {
    let upstream = spawn_upgrade_upstream().await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
categories:
  - name: upstream-errors
    phase: response
    action: BLOCK
    response: {{ status: 451 }}
    rules:
      - name: not-found
        match: {{ status: 404 }}
"
    );
    let running = start_kunato(&yaml).await;

    let (handshake, _stream) = websocket_handshake(running.addr, "/nope").await;
    assert!(
        handshake.starts_with("HTTP/1.1 451"),
        "non-101 upgrade responses must pass through response rules: {handshake}"
    );

    running.stop().await;
}

#[tokio::test]
async fn request_prefix_at_limit_is_inspected_without_waiting_for_eof() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_body_bytes: 8, body_inspection: stream }}
timeouts: {{ body_read: 300ms }}
categories:
  - name: signatures
    action: BLOCK
    rules:
      - name: prefix-signature
        match: {{ regex: '^ABCDEFGH$', in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    let request =
        "POST /upload HTTP/1.1\r\nhost: kunato.test\r\ncontent-length: 100\r\n\r\nABCDEFGH";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write partial body");
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    assert!(read.is_ok(), "request evaluation must not wait for EOF");
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "the exact-limit prefix must be evaluated: {response}"
    );

    running.stop().await;
}

#[tokio::test]
async fn strict_body_inspection_rejects_without_waiting_for_eof() {
    let upstream = spawn_upstream(StatusCode::OK, "hello").await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_body_bytes: 8 }}
timeouts: {{ body_read: 300ms }}
categories:
  - name: signatures
    action: BLOCK
    rules:
      - name: never-matches
        match: {{ regex: 'NEVERMATCH', in: [body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let mut stream = TcpStream::connect(running.addr)
        .await
        .expect("connect kunato");
    let request =
        "POST /upload HTTP/1.1\r\nhost: kunato.test\r\ncontent-length: 100\r\n\r\nABCDEFGH";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write partial body");
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response)).await;
    assert!(read.is_ok(), "strict rejection must not wait for EOF");
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 413"),
        "the oversized body must be rejected before the rest arrives: {response}"
    );

    running.stop().await;
}

#[tokio::test]
async fn response_prefix_at_limit_is_inspected_without_waiting_for_eof() {
    let upstream = spawn_prefix_stalling_upstream(b"ABCDEFGH", 100).await;
    let yaml = format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
limits: {{ max_response_body_bytes: 8 }}
timeouts: {{ upstream_response: 300ms }}
categories:
  - name: response-signatures
    phase: response
    action: BLOCK
    rules:
      - name: prefix-signature
        match: {{ regex: '^ABCDEFGH$', in: [response_body] }}
"
    );
    let running = start_kunato(&yaml).await;

    let (status, _) = send(running.addr, Method::GET, "/", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    running.stop().await;
}

#[tokio::test]
async fn http2_authority_is_forwarded_as_host() {
    let upstream = spawn_header_echo_upstream("host").await;
    let running = start_kunato(&format!(
        "listen: 127.0.0.1:0\nupstream: http://{upstream}\ncategories: []\n"
    ))
    .await;

    let (status, body) = send_h2c(running.addr, Method::GET, "/echo", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, running.addr.to_string());

    running.stop().await;
}
