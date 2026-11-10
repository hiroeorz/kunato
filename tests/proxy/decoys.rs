use super::*;
use std::sync::atomic::AtomicUsize;

const HOST: &str = "blog.example.test";
const SINK: &str = "/_decoy/api/v1/storage/list";

fn decoy_config(upstream: SocketAddr) -> String {
    format!(
        "listen: 127.0.0.1:0
upstream: http://{upstream}
allowed_hosts: [blog.example.test, other.example.test]
client_ip: {{ trusted_proxies: [127.0.0.1] }}
protection:
  requests_per_second: 2000
  burst: 1000
  global_requests_per_second: 10000
  behavior:
    sequence: {{ action: BLOCK, threshold: 1, min_dimensions: 1, min_windows: 1 }}
decoys:
  enabled: true
  on_reuse: BLOCK
  issuance: {{ per_minute: 6000, burst: 100, per_source_per_minute: 600, per_source_burst: 100 }}
  sites:
    - name: blog
      origin: https://blog.example.test
      sink: {SINK}
      presets: [dotenv, git-config, wordpress-backup, spring-env]
"
    )
}

async fn receipts() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.fetch_add(1, Ordering::Relaxed);
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        Ok::<_, Infallible>(Response::new(Full::new(bytes)))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, count)
}

async fn request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (StatusCode, String, http::HeaderMap) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", HOST);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-for"))
    {
        builder = builder.header("x-forwarded-for", "203.0.113.7");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = sender
        .send_request(
            builder
                .body(Full::new(Bytes::copy_from_slice(body)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    )
}

fn extract_token(body: &str) -> String {
    let start = body.find("kdt1.").expect("response token");
    body[start..start + 169].to_owned()
}

#[tokio::test]
async fn decoy_cross_source_credentials_block_only_the_owned_sink() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let (status, body, _) = request(running.addr, Method::GET, "/.env", &[], &[]).await;
    assert_eq!(status, StatusCode::OK);
    let token = extract_token(&body);
    let auth = format!("Bearer {token}");
    let headers = [
        ("authorization", auth.as_str()),
        ("x-forwarded-for", "198.51.100.9"),
    ];
    assert_eq!(
        request(running.addr, Method::GET, SINK, &headers, &[])
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
    for path in [format!("/public?token={token}"), format!("/public/{token}")] {
        assert_eq!(
            request(running.addr, Method::GET, &path, &headers, &[])
                .await
                .0,
            StatusCode::OK
        );
    }
    let (_, echo, _) = request(
        running.addr,
        Method::POST,
        "/public",
        &[("content-type", "application/json")],
        format!("{{\"quoted\":\"{token}\"}}").as_bytes(),
    )
    .await;
    assert!(echo.contains(&token));
    assert_eq!(
        request(running.addr, Method::GET, "/healthy", &headers, &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(running.metrics.decoys.blocked.load(Ordering::Relaxed), 1);
    assert_eq!(running.metrics.decoys.reuse[0].load(Ordering::Relaxed), 1);
    assert!(running.metrics.decoys.reuse[1].load(Ordering::Relaxed) >= 3);
    assert_eq!(
        running
            .metrics
            .behavior_sequence_events
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        running
            .metrics
            .behavior_auth_failures
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        running.metrics.behavior_not_found.load(Ordering::Relaxed),
        0
    );
    assert_eq!(count.load(Ordering::Relaxed), 4);
    running.stop().await;
}

#[tokio::test]
async fn decoy_all_owned_methods_and_aliases_stay_local_and_headers_are_final() {
    let (upstream, count) = receipts().await;
    let config = format!(
        "{}\nresponse_headers:\n  remove: [cache-control, x-robots-tag]\n  set:\n    cache-control: public\n    content-type: text/html\n    access-control-allow-origin: '*'\n    set-cookie: injected=yes\n    location: https://external.example.invalid/\n    content-encoding: gzip\n    etag: injected\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&config).await;
    let mut previous = String::new();
    for path in [
        "/.env",
        "/%252eenv",
        "/x/../.env",
        "/.git/config",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/actuator/env",
    ] {
        let (status, body, headers) = request(
            running.addr,
            Method::GET,
            path,
            &[("range", "bytes=0-1"), ("if-none-match", "injected")],
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-robots-tag"], "noindex, nofollow");
        assert_ne!(headers["content-type"], "text/html");
        for name in [
            "access-control-allow-origin",
            "set-cookie",
            "location",
            "content-encoding",
            "etag",
        ] {
            assert!(!headers.contains_key(name));
        }
        assert_ne!(previous, extract_token(&body));
        previous = extract_token(&body);
        let issued = running.metrics.decoys.issued.load(Ordering::Relaxed);
        let (status, empty, headers) = request(running.addr, Method::HEAD, path, &[], &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(empty.is_empty());
        assert_eq!(
            headers["content-length"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            body.len()
        );
        assert_eq!(
            running.metrics.decoys.issued.load(Ordering::Relaxed),
            issued
        );
        for method in [Method::POST, Method::OPTIONS, Method::DELETE] {
            assert_eq!(
                request(running.addr, method, path, &[], b"untrusted")
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
        }
    }
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_log_mode_and_ambiguous_credentials_do_not_score_or_ban() {
    let (upstream, count) = receipts().await;
    let running =
        start_kunato(&decoy_config(upstream).replace("on_reuse: BLOCK", "on_reuse: LOG")).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let auth = format!("Bearer {token}");
    for headers in [
        vec![("authorization", auth.as_str())],
        vec![("x-api-key", token.as_str())],
        vec![
            ("authorization", auth.as_str()),
            ("authorization", auth.as_str()),
        ],
        vec![
            ("authorization", auth.as_str()),
            ("x-api-key", token.as_str()),
        ],
    ] {
        assert_eq!(
            request(running.addr, Method::GET, SINK, &headers, &[])
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(running.addr, Method::GET, "/normal", &[], &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert_eq!(running.metrics.decoys.blocked.load(Ordering::Relaxed), 0);
    assert_eq!(
        running
            .metrics
            .behavior_sequence_events
            .load(Ordering::Relaxed),
        0
    );
    running.stop().await;
}

#[tokio::test]
async fn decoy_head_checks_prioritize_credentials_over_fake_candidates_and_scope() {
    let (upstream, count) = receipts().await;
    let config = format!(
        "{}    - name: other\n      origin: https://other.example.test\n      sink: {SINK}\n      presets: [dotenv]\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&config).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let fake = "kdt1.0000000000000000.000000000000003c.00000000000000000000000000000000.00000000000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000";
    let path = format!(
        "{SINK}?noise={}",
        std::iter::repeat_n(fake, 20).collect::<Vec<_>>().join("-")
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            &path,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, _) = send_h2c_with_headers(
        running.addr,
        "other.example.test",
        None,
        SINK,
        &[("x-api-key", &token), ("x-forwarded-for", "203.0.113.8")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_quotas_are_per_resolved_source_and_global_and_never_forward() {
    let (upstream, count) = receipts().await;
    let config = decoy_config(upstream).replace(
        "per_minute: 6000, burst: 100, per_source_per_minute: 600, per_source_burst: 100",
        "per_minute: 60, burst: 3, per_source_per_minute: 6, per_source_burst: 1",
    );
    let running = start_kunato(&config).await;
    assert_eq!(
        request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            "/.env",
            &[("x-forwarded-for", "203.0.113.8")],
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            "/.env",
            &[("x-forwarded-for", "203.0.113.9")],
            &[]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(running.metrics.decoys.issued.load(Ordering::Relaxed), 2);
    assert_eq!(running.metrics.decoys.limited[0].load(Ordering::Relaxed), 1);
    assert_eq!(running.metrics.decoys.limited[1].load(Ordering::Relaxed), 1);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_http2_and_http3_share_tokens_and_head_semantics() {
    let (upstream, count) = receipts().await;
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, certificate) = write_test_certificate(&dir);
    let yaml = format!(
        "{}tls:\n  cert_file: {}\n  key_file: {}\nhttp3: {{ enabled: true }}\n",
        decoy_config(upstream),
        cert_path.display(),
        key_path.display()
    );
    let running = start_kunato(&yaml).await;
    let (status, body, headers) = send_h3_request(
        running.addr,
        certificate.clone(),
        Request::builder()
            .uri(format!("https://{HOST}/.env"))
            .header("x-forwarded-for", "203.0.113.7")
            .body(())
            .unwrap(),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let token = extract_token(&body);
    let (status, _, _) = send_h3_request(
        running.addr,
        certificate.clone(),
        Request::builder()
            .uri(format!("https://{HOST}{SINK}"))
            .header("x-forwarded-for", "198.51.100.9")
            .header("x-api-key", &token)
            .body(())
            .unwrap(),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, empty, headers) = send_h3_request(
        running.addr,
        certificate,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("https://{HOST}/.env"))
            .header("x-forwarded-for", "203.0.113.7")
            .body(())
            .unwrap(),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty.is_empty());
    assert_eq!(
        headers["content-length"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        body.len()
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;

    let running = start_kunato(&decoy_config(upstream)).await;
    let (status, body, _) = send_h2c_with_headers(
        running.addr,
        HOST,
        None,
        "/.env",
        &[("x-forwarded-for", "203.0.113.7")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = extract_token(&body);
    let (status, _, _) = send_h2c_with_headers(
        running.addr,
        HOST,
        None,
        SINK,
        &[("x-forwarded-for", "198.51.100.9"), ("x-api-key", &token)],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_unread_http1_body_is_closed_and_never_replayed_upstream() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let mut stream = TcpStream::connect(running.addr).await.unwrap();
    stream.write_all(format!("GET /.env HTTP/1.1\r\nHost: {HOST}\r\nX-Forwarded-For: 203.0.113.7\r\nContent-Length: 100000\r\n\r\nGET /public HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("connection: close"));
    assert_eq!(response.matches("HTTP/1.1").count(), 1);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_reload_keeps_credentials_and_quota_and_invalid_reload_keeps_policy() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let runtime = Arc::clone(&running.config.load().decoys.runtime);
    let next =
        config::parse(&decoy_config(upstream).replace("on_reuse: BLOCK", "on_reuse: LOG")).unwrap();
    config::watcher::apply(
        std::path::Path::new("decoy-test.yaml"),
        next,
        &running.config,
        &running.metrics,
        false,
    )
    .unwrap();
    assert!(Arc::ptr_eq(&runtime, &running.config.load().decoys.runtime));
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kunato.yaml");
    std::fs::write(
        &path,
        decoy_config(upstream).replace("on_reuse: BLOCK", "on_reuse: BAN"),
    )
    .unwrap();
    assert!(config::watcher::reload(&path, &running.config, &running.metrics, false).is_none());
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_precedence_exemptions_and_disable_preserve_existing_policies() {
    let (upstream, count) = receipts().await;
    let config = format!(
        "{}admin_access: {{enabled: true, default: close}}\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&config).await;
    assert_eq!(
        request(running.addr, Method::GET, "/actuator/env", &[], &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(running.metrics.decoys.issued.load(Ordering::Relaxed), 0);
    assert_eq!(
        running.metrics.admin_access_denied.load(Ordering::Relaxed),
        1
    );
    // A separate resolved source avoids the existing Sequence ban from that admin denial.
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            "/.env",
            &[("x-forwarded-for", "203.0.113.8")],
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, _, headers) = send_h2c_with_headers(
        running.addr,
        "unlisted.example.test",
        None,
        "/.env",
        &[("x-forwarded-for", "203.0.113.9")],
    )
    .await;
    assert!(!headers.contains_key("x-robots-tag"));
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;

    let config = decoy_config(upstream).replace(
        "  requests_per_second: 2000",
        "  allowlist: [203.0.113.7]\n  requests_per_second: 2000",
    );
    let running = start_kunato(&config).await;
    assert_eq!(
        request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(running.metrics.decoys.issued.load(Ordering::Relaxed), 0);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;

    let config = decoy_config(upstream).replace(
        "  requests_per_second: 2000",
        "  enabled: false\n  requests_per_second: 2000",
    );
    let running = start_kunato(&config).await;
    assert_eq!(
        request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(running.metrics.decoys.issued.load(Ordering::Relaxed), 0);
    assert_eq!(count.load(Ordering::Relaxed), 1);
    running.stop().await;
}

#[tokio::test]
async fn decoy_verification_exhaustion_never_blocks_ordinary_requests() {
    let (upstream, count) = receipts().await;
    let config = decoy_config(upstream).replace(
        "  on_reuse: BLOCK",
        "  on_reuse: BLOCK\n  verification: {per_second: 1, burst: 1}",
    );
    let running = start_kunato(&config).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            "/public",
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert!(running.metrics.decoys.incomplete[4].load(Ordering::Relaxed) >= 2);
    assert_eq!(
        running
            .metrics
            .behavior_sequence_events
            .load(Ordering::Relaxed),
        0
    );
    running.stop().await;
}

#[tokio::test]
async fn decoy_http2_unread_body_does_not_stall_or_reset_other_streams() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let stream = TcpStream::connect(running.addr).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let pending: kunato::proxy::ProxyBody = PendingBody
        .map_err(|error| -> kunato::proxy::BoxError { match error {} })
        .boxed();
    let first = Request::builder()
        .uri(format!("http://{HOST}/.env"))
        .header("x-forwarded-for", "203.0.113.7")
        .body(pending)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), sender.send_request(first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("kdt1."));
    let complete: kunato::proxy::ProxyBody = Full::new(Bytes::new()).boxed();
    let second = Request::builder()
        .uri(format!("http://{HOST}/healthy"))
        .header("x-forwarded-for", "203.0.113.7")
        .body(complete)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), sender.send_request(second))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await.unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
    running.stop().await;
}

#[tokio::test]
async fn decoy_http3_returns_without_waiting_for_request_end() {
    let (upstream, count) = receipts().await;
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert) = write_test_certificate(&dir);
    let yaml = format!(
        "{}tls:\n  cert_file: {}\n  key_file: {}\nhttp3: {{enabled: true}}\n",
        decoy_config(upstream),
        cert_path.display(),
        key_path.display()
    );
    let running = start_kunato(&yaml).await;
    let request = Request::builder()
        .uri(format!("https://{HOST}/.env"))
        .header("x-forwarded-for", "203.0.113.7")
        .body(())
        .unwrap();
    let (status, body, _) = tokio::time::timeout(
        Duration::from_secs(2),
        send_h3_request_inner(running.addr, cert, request, "", false),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("kdt1."));
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_body_observation_reuses_decoding_and_keeps_content_routes_passive() {
    let (upstream, count) = receipts().await;
    let yaml = format!(
        "{}content_routes: [{{path: '^/editor$'}}]\ncategories:\n  - name: body-rule\n    action: BLOCK\n    rules:\n      - name: keep-decoding\n        match: {{regex: NEVER_MATCH, in: body}}\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&yaml).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let encoded = token.replace("kdt1.", "%6b%64%74%31%2e");
    let auth = format!("Basic {}", basic64(format!("deploy:{token}").as_bytes()));
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            "/public",
            &[("authorization", &auth)],
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    for path in ["/public", "/editor"] {
        let bytes = gzip(format!("{{\"quoted\":\"{encoded}\"}}").as_bytes());
        let (status, echo, _) = request(
            running.addr,
            Method::POST,
            path,
            &[
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
            &bytes,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!echo.is_empty());
    }
    assert!(running.metrics.decoys.reuse[1].load(Ordering::Relaxed) >= 2);
    assert_eq!(running.metrics.decoys.blocked.load(Ordering::Relaxed), 0);
    assert_eq!(count.load(Ordering::Relaxed), 3);
    running.stop().await;
}

fn basic64(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for bytes in bytes.chunks(3) {
        let word = (u32::from(bytes[0]) << 16)
            | (u32::from(*bytes.get(1).unwrap_or(&0)) << 8)
            | u32::from(*bytes.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0] {
            out.push(DIGITS[((word >> shift) & 63) as usize] as char);
        }
        if bytes.len() < 3 {
            out.pop();
            out.push('=');
        }
        if bytes.len() < 2 {
            out.pop();
            out.pop();
            out.push('=');
            out.push('=');
        }
    }
    out
}

#[tokio::test]
async fn decoy_multipart_observes_fields_and_excludes_every_file_payload() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let file = multipart_upload("notes.txt", "text/plain", token.as_bytes());
    assert_eq!(
        request(
            running.addr,
            Method::POST,
            "/upload",
            &[("content-type", "multipart/form-data; boundary=X")],
            &file
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(running.metrics.decoys.reuse[1].load(Ordering::Relaxed), 0);
    let form = format!(
        "--X\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{token}\r\n--X--\r\n"
    );
    assert_eq!(
        request(
            running.addr,
            Method::POST,
            "/upload",
            &[("content-type", "multipart/form-data; boundary=X")],
            form.as_bytes()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(running.metrics.decoys.reuse[1].load(Ordering::Relaxed), 1);
    assert_eq!(count.load(Ordering::Relaxed), 2);
    running.stop().await;
}

#[tokio::test]
async fn decoy_concurrent_sources_and_ipv6_prefixes_obey_bounded_issuance() {
    let (upstream, count) = receipts().await;
    let config = decoy_config(upstream).replace(
        "per_minute: 6000, burst: 100, per_source_per_minute: 600, per_source_burst: 100",
        "per_minute: 60, burst: 10, per_source_per_minute: 6, per_source_burst: 2",
    );
    let running = start_kunato(&config).await;
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let addr = running.addr;
        requests.spawn(async move { request(addr, Method::GET, "/.env", &[], &[]).await.0 });
    }
    let mut issued = 0;
    while let Some(result) = requests.join_next().await {
        if result.unwrap() == StatusCode::OK {
            issued += 1;
        }
    }
    assert_eq!(issued, 2);
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
    let running = start_kunato(&config).await;
    for (ip, status) in [
        ("2001:db8:1::1", StatusCode::OK),
        ("2001:db8:1::2", StatusCode::OK),
        ("2001:db8:1::3", StatusCode::NOT_FOUND),
        ("2001:db8:2::1", StatusCode::OK),
    ] {
        assert_eq!(
            request(
                running.addr,
                Method::GET,
                "/.env",
                &[("x-forwarded-for", ip)],
                &[]
            )
            .await
            .0,
            status
        );
    }
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_disabled_reenabled_renamed_and_restarted_sites_have_explicit_scope() {
    let (upstream, count) = receipts().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    for (yaml, status) in [
        (
            decoy_config(upstream).replace("decoys:\n  enabled: true", "decoys:\n  enabled: false"),
            StatusCode::OK,
        ),
        (decoy_config(upstream), StatusCode::FORBIDDEN),
        (
            decoy_config(upstream).replace("name: blog", "name: renamed"),
            StatusCode::UNAUTHORIZED,
        ),
        (decoy_config(upstream), StatusCode::FORBIDDEN),
    ] {
        config::watcher::apply(
            std::path::Path::new("decoy-scope.yaml"),
            config::parse(&yaml).unwrap(),
            &running.config,
            &running.metrics,
            false,
        )
        .unwrap();
        assert_eq!(
            request(
                running.addr,
                Method::GET,
                SINK,
                &[("x-api-key", &token)],
                &[]
            )
            .await
            .0,
            status
        );
    }
    assert_eq!(count.load(Ordering::Relaxed), 1);
    running.stop().await;
    let running = start_kunato(&decoy_config(upstream)).await;
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("x-api-key", &token)],
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(count.load(Ordering::Relaxed), 1);
    running.stop().await;
}

#[tokio::test]
async fn decoy_block_requires_a_single_explicit_sink_credential() {
    let (upstream, count) = receipts().await;
    let config = format!(
        "{}response_headers: {{set: {{www-authenticate: Basic}}}}\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&config).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    let auth = format!("Bearer {token}");
    let basic = format!("Basic {}", basic64(format!("deploy:{token}").as_bytes()));
    for headers in [
        vec![
            ("authorization", auth.as_str()),
            ("authorization", auth.as_str()),
        ],
        vec![
            ("authorization", auth.as_str()),
            ("x-api-key", token.as_str()),
        ],
        vec![("authorization", basic.as_str())],
        vec![("cookie", token.as_str())],
    ] {
        let (status, _, headers) = request(running.addr, Method::GET, SINK, &headers, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers["www-authenticate"], "Bearer realm=\"internal-api\"");
    }
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            &format!("{SINK}?token={token}"),
            &[],
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            running.addr,
            Method::GET,
            SINK,
            &[("authorization", &format!("bEaReR {token}\t"))],
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(running.metrics.decoys.blocked.load(Ordering::Relaxed), 1);
    assert_eq!(
        running
            .metrics
            .behavior_sequence_events
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
    running.stop().await;
}

#[tokio::test]
async fn decoy_authored_and_urlencoded_content_are_observed_without_enforcement() {
    let (upstream, count) = receipts().await;
    let config = format!(
        "{}content_routes: [{{path: '^/editor$'}}]\n",
        decoy_config(upstream)
    );
    let running = start_kunato(&config).await;
    let token = extract_token(
        &request(running.addr, Method::GET, "/.env", &[], &[])
            .await
            .1,
    );
    for (content_type, body) in [
        ("application/json", format!("{{\"article\":\"{token}\"}}")),
        (
            "application/x-www-form-urlencoded",
            format!("quoted={}", token.replace("kdt1.", "%6b%64%74%31%2e")),
        ),
    ] {
        let (status, echo, _) = request(
            running.addr,
            Method::POST,
            "/editor",
            &[("content-type", content_type)],
            body.as_bytes(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(echo, body);
    }
    assert_eq!(running.metrics.decoys.reuse[1].load(Ordering::Relaxed), 2);
    assert_eq!(running.metrics.decoys.blocked.load(Ordering::Relaxed), 0);
    assert_eq!(
        running
            .metrics
            .behavior_sequence_events
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(count.load(Ordering::Relaxed), 2);
    running.stop().await;
}
