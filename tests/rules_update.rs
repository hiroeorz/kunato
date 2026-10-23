use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ETAG, HeaderName, HeaderValue, IF_NONE_MATCH, LOCATION};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use kunato::config::{self, RulesUpdate};
use kunato::rules_update::{self, UpdateOutcome};

const RULES: &str = "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: catch-all
        match: { path: ^/ }
";

#[derive(Clone)]
struct Route {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Vec<u8>,
    etag: Option<String>,
}

impl Route {
    fn body(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: StatusCode::OK,
            headers: Vec::new(),
            body: body.into(),
            etag: None,
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: StatusCode::FOUND,
            headers: vec![(
                LOCATION,
                HeaderValue::from_str(&location).expect("valid location"),
            )],
            body: Vec::new(),
            etag: None,
        }
    }
}

async fn spawn_server(routes: HashMap<String, Route>) -> SocketAddr {
    spawn_server_on("127.0.0.1", routes).await
}

/// Distinct 127/8 spellings are distinct hosts for the redirect policy, so
/// tests can bounce a download between loopback addresses without DNS.
async fn spawn_server_on(host: &str, routes: HashMap<String, Route>) -> SocketAddr {
    let listener = TcpListener::bind(format!("{host}:0"))
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("mock address");
    let routes = Arc::new(routes);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |request: Request<Incoming>| {
                    let routes = routes.clone();
                    async move {
                        let path = request.uri().path().to_owned();
                        let Some(route) = routes.get(&path) else {
                            let mut response = Response::new(Full::new(Bytes::new()));
                            *response.status_mut() = StatusCode::NOT_FOUND;
                            return Ok::<_, Infallible>(response);
                        };
                        let not_modified = route.etag.as_deref().is_some_and(|etag| {
                            request
                                .headers()
                                .get(IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok())
                                == Some(etag)
                        });
                        if not_modified {
                            let mut response = Response::new(Full::new(Bytes::new()));
                            *response.status_mut() = StatusCode::NOT_MODIFIED;
                            return Ok(response);
                        }
                        let mut response =
                            Response::new(Full::new(Bytes::from(route.body.clone())));
                        *response.status_mut() = route.status;
                        for (name, value) in &route.headers {
                            response.headers_mut().insert(name.clone(), value.clone());
                        }
                        if let Some(etag) = &route.etag {
                            response
                                .headers_mut()
                                .insert(ETAG, HeaderValue::from_str(etag).expect("valid etag"));
                        }
                        Ok(response)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    addr
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn rules_routes(rules: &[u8]) -> HashMap<String, Route> {
    let mut routes = HashMap::new();
    routes.insert("/rules.yaml".to_owned(), Route::body(rules.to_vec()));
    routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(rules).into_bytes()),
    );
    routes
}

fn update_settings(dir: &Path, port: u16, max_bytes: usize) -> (RulesUpdate, PathBuf, PathBuf) {
    let rules_file = dir.join("rules.yaml");
    let main = dir.join("kunato.yaml");
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
  interval: 24h
  jitter_percent: 0
  max_bytes: {max_bytes}
",
        rules_file = rules_file.display()
    );
    std::fs::write(&main, &text).expect("write main config");
    let parsed = config::parse(&text).expect("valid update config");
    (
        parsed.rules_update.clone(),
        parsed.rules_file.clone().expect("rules file"),
        main,
    )
}

#[tokio::test]
async fn downloads_and_replaces_the_rules_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let outcome = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect("update succeeds");

    assert_eq!(outcome, UpdateOutcome::Updated);
    let written = std::fs::read_to_string(&rules_file).expect("rules written");
    assert_eq!(written, RULES);
    config::parse_rules(&written).expect("written rules are valid");

    let state = std::fs::read_to_string(&state_file).expect("state written");
    assert!(state.contains("last_success="));
}

#[tokio::test]
async fn rejects_a_checksum_mismatch_without_touching_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut routes = rules_routes(RULES.as_bytes());
    routes.insert("/rules.yaml.sha256".to_owned(), Route::body(vec![b'a'; 64]));
    let addr = spawn_server(routes).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("checksum mismatch must fail");

    assert!(error.to_string().contains("checksum mismatch"));
    assert!(!rules_file.exists());
}

#[tokio::test]
async fn handles_not_modified_responses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut routes = rules_routes(RULES.as_bytes());
    routes.get_mut("/rules.yaml").expect("route").etag = Some("\"v1\"".to_owned());
    let addr = spawn_server(routes).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);
    std::fs::write(&rules_file, RULES).expect("installed rules");
    std::fs::write(&state_file, "last_success=1\netag=\"v1\"\n").expect("state");

    let outcome = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect("update succeeds");

    assert_eq!(outcome, UpdateOutcome::NotModified);
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("installed rules unchanged"),
        RULES
    );
    let state = std::fs::read_to_string(&state_file).expect("state written");
    assert!(!state.contains("last_success=1\n"));
    assert!(state.contains("etag=\"v1\""));
}

/// A 304 must not bless a crash-truncated or deleted rules file: the
/// validators are cleared and the outcome is a failure so the next attempt
/// refetches the whole file.
#[tokio::test]
async fn not_modified_with_a_missing_rules_file_forces_a_refetch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut routes = rules_routes(RULES.as_bytes());
    routes.get_mut("/rules.yaml").expect("route").etag = Some("\"v1\"".to_owned());
    let addr = spawn_server(routes).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);
    std::fs::write(&state_file, "last_success=1\netag=\"v1\"\n").expect("state");

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("a missing rules file must fail despite the 304");

    assert!(error.to_string().contains("missing or empty"), "{error}");
    // The state kept its schedule but lost the validators, so the next
    // attempt performs a fresh fetch and repairs the installation.
    let state = std::fs::read_to_string(&state_file).expect("state kept");
    assert!(state.contains("last_success=1\n"));
    assert!(!state.contains("etag="));

    let outcome = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect("refetch succeeds");
    assert_eq!(outcome, UpdateOutcome::Updated);
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("rules recovered"),
        RULES
    );
}

#[tokio::test]
async fn rejects_bodies_over_the_configured_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 32);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("oversized body must fail");

    assert!(error.to_string().contains("exceeds"));
    assert!(!rules_file.exists());
}

#[tokio::test]
async fn rejects_invalid_rule_documents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let invalid = b"categories:\n  - name: broken\n    action: BLOCK\n    rules:\n      - name: rule\n        match: { path: '(' }\n";
    let addr = spawn_server(rules_routes(invalid)).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("invalid rules must fail");

    assert!(error.to_string().contains("invalid"));
    assert!(!rules_file.exists());
}

#[tokio::test]
async fn rejects_downloaded_files_that_disable_local_rules() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules = b"disabled_rules: [important]\ncategories: []\n";
    let addr = spawn_server(rules_routes(rules)).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("disabled_rules in the managed file must fail");

    assert!(error.to_string().contains("disabled_rules"));
    assert!(!rules_file.exists());
}

#[tokio::test]
async fn follows_absolute_redirects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut target_routes = HashMap::new();
    target_routes.insert(
        "/real.yaml".to_owned(),
        Route::body(RULES.as_bytes().to_vec()),
    );
    target_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let target = spawn_server(target_routes).await;

    let mut redirect_routes = HashMap::new();
    redirect_routes.insert(
        "/rules.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.1:{}/real.yaml", target.port())),
    );
    redirect_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let redirect = spawn_server(redirect_routes).await;

    let (settings, rules_file, main) = update_settings(dir.path(), redirect.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let outcome = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect("redirected update succeeds");

    assert_eq!(outcome, UpdateOutcome::Updated);
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("rules written"),
        RULES
    );
}

#[tokio::test]
async fn update_creates_a_rules_file_that_config_load_accepts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let rules_file = dir.path().join("rules.yaml");
    let main = dir.path().join("kunato.yaml");
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
",
        rules_file = rules_file.display(),
        port = addr.port()
    );
    std::fs::write(&main, &text).expect("write config");

    assert!(config::load(&main).is_err(), "missing rules file must fail");

    let parsed = config::parse(&text).expect("parse config");
    let state_file = rules_update::state_path(&rules_file);
    rules_update::update_once(&main, &parsed.rules_update, &rules_file, &state_file)
        .await
        .expect("update succeeds");

    let loaded = config::load(&main).expect("config loads after update");
    assert_eq!(loaded.categories.len(), 1);
    assert_eq!(loaded.categories[0].name, "auto");
}

#[tokio::test]
async fn rejects_redirects_to_remote_http_and_keeps_the_file_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut routes = HashMap::new();
    routes.insert(
        "/rules.yaml".to_owned(),
        Route::redirect("http://rules.invalid.example/rules.yaml".to_owned()),
    );
    routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let addr = spawn_server(routes).await;
    let (settings, rules_file, main) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("remote http redirect must be rejected");

    assert!(error.to_string().contains("transport policy"), "{error}");
    assert!(!rules_file.exists());
}

/// A cross-host hop is the normal CDN bounce-through, so the download still
/// succeeds when it leaves the origin within the cap (two hops here).
#[tokio::test]
async fn allows_cross_host_redirects_up_to_the_cap() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut final_routes = HashMap::new();
    final_routes.insert(
        "/real.yaml".to_owned(),
        Route::body(RULES.as_bytes().to_vec()),
    );
    final_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let final_addr = spawn_server_on("127.0.0.3", final_routes).await;

    let mut second_routes = HashMap::new();
    second_routes.insert(
        "/hop.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.3:{}/real.yaml", final_addr.port())),
    );
    let second_addr = spawn_server_on("127.0.0.2", second_routes).await;

    let mut first_routes = HashMap::new();
    first_routes.insert(
        "/rules.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.2:{}/hop.yaml", second_addr.port())),
    );
    first_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let first_addr = spawn_server(first_routes).await;

    let (settings, rules_file, main) = update_settings(dir.path(), first_addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let outcome = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect("update within the cross-host cap succeeds");

    assert_eq!(outcome, UpdateOutcome::Updated);
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("rules written"),
        RULES
    );
}

/// A chain that keeps moving the download away from the configured origin is
/// refused; the installed rules file stays untouched.
#[tokio::test]
async fn caps_cross_host_redirect_hops() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut final_routes = HashMap::new();
    final_routes.insert(
        "/real.yaml".to_owned(),
        Route::body(RULES.as_bytes().to_vec()),
    );
    final_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let final_addr = spawn_server_on("127.0.0.4", final_routes).await;

    let mut third_routes = HashMap::new();
    third_routes.insert(
        "/hop2.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.4:{}/real.yaml", final_addr.port())),
    );
    let third_addr = spawn_server_on("127.0.0.3", third_routes).await;

    let mut second_routes = HashMap::new();
    second_routes.insert(
        "/hop.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.3:{}/hop2.yaml", third_addr.port())),
    );
    let second_addr = spawn_server_on("127.0.0.2", second_routes).await;

    let mut first_routes = HashMap::new();
    first_routes.insert(
        "/rules.yaml".to_owned(),
        Route::redirect(format!("http://127.0.0.2:{}/hop.yaml", second_addr.port())),
    );
    first_routes.insert(
        "/rules.yaml.sha256".to_owned(),
        Route::body(sha256_hex(RULES.as_bytes()).into_bytes()),
    );
    let first_addr = spawn_server(first_routes).await;

    let (settings, rules_file, main) = update_settings(dir.path(), first_addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &settings, &rules_file, &state_file)
        .await
        .expect_err("a redirected redirect chain must be capped");

    assert!(
        error
            .to_string()
            .contains("away from the configured origin"),
        "{error}"
    );
    assert!(!rules_file.exists());
}

#[tokio::test]
async fn rejects_candidates_that_conflict_with_inline_categories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_file = dir.path().join("rules.yaml");
    let main = dir.path().join("kunato.yaml");
    let existing = "categories:
  - name: previous
    action: LOG
    rules:
      - name: old
        match: { path: ^/old }
";
    std::fs::write(&rules_file, existing).expect("write previous rules");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
categories:
  - name: auto
    action: BLOCK
    rules:
      - name: inline
        match: {{ path: ^/inline }}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
  jitter_percent: 0
",
        rules_file = rules_file.display(),
        port = addr.port()
    );
    std::fs::write(&main, &text).expect("write config");
    let parsed = config::parse(&text).expect("parse config");
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &parsed.rules_update, &rules_file, &state_file)
        .await
        .expect_err("duplicate category across sources must fail validation");

    assert!(error.to_string().contains("duplicate category"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("previous rules intact"),
        existing
    );
    assert!(!state_file.exists());
}

#[tokio::test]
async fn rejects_rule_sets_that_need_a_newer_build() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_file = dir.path().join("rules.yaml");
    let main = dir.path().join("kunato.yaml");
    let existing = "categories:
  - name: previous
    action: LOG
    rules:
      - name: old
        match: { path: ^/old }
";
    std::fs::write(&rules_file, existing).expect("write previous rules");
    let future = "categories:
  - name: future
    action: BLOCK
    rules:
      - name: future-rule
        match: { regex: a, json_body: true }
";
    let addr = spawn_server(rules_routes(future.as_bytes())).await;
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
  jitter_percent: 0
",
        rules_file = rules_file.display(),
        port = addr.port()
    );
    std::fs::write(&main, &text).expect("write config");
    let parsed = config::parse(&text).expect("parse config");
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&main, &parsed.rules_update, &rules_file, &state_file)
        .await
        .expect_err("a rule set with an unknown field must be rejected");

    assert!(
        matches!(error, kunato::error::Error::RulesNeedNewerBuild(_)),
        "{error}"
    );
    assert!(error.to_string().contains("json_body"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("previous rules intact"),
        existing
    );
    assert!(!state_file.exists());
}

#[tokio::test]
async fn run_counts_rule_sets_that_need_a_newer_build() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rules_file = dir.path().join("rules.yaml");
    write_placeholder_rules(&rules_file);
    let future = "categories:
  - name: future
    action: BLOCK
    rules:
      - name: future-rule
        match: { regex: a, in: [json_body] }
";
    let addr = spawn_server(rules_routes(future.as_bytes())).await;
    let main = dir.path().join("kunato.yaml");
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
  interval: 1s
  jitter_percent: 0
",
        rules_file = rules_file.display(),
        port = addr.port()
    );
    std::fs::write(&main, &text).expect("write config");
    let compiled = config::load(&main).expect("load config");
    let config = Arc::new(arc_swap::ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(kunato::metrics::Metrics::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(rules_update::run(
        config,
        main,
        metrics.clone(),
        false,
        shutdown_rx,
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while metrics.rules_update_failure.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the updater never attempted a download"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    shutdown_tx.send(true).expect("send shutdown");
    let result = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(result.is_ok(), "rules update task must stop on shutdown");

    assert!(
        metrics.rules_update_incompatible.load(Ordering::Relaxed) >= 1,
        "the incompatible rule set must be counted separately"
    );
    assert_eq!(
        metrics.rules_update_incompatible.load(Ordering::Relaxed),
        metrics.rules_update_failure.load(Ordering::Relaxed),
        "every failure in this scenario is an incompatible rule set"
    );
    assert_eq!(metrics.rules_update_success.load(Ordering::Relaxed), 0);
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("rules intact"),
        PLACEHOLDER_RULES
    );
}

#[tokio::test]
async fn run_stops_promptly_when_shutdown_interrupts_a_stalled_download() {
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled server");
    let addr = listener.local_addr().expect("address");
    let (headers_sent, headers_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial")
            .await;
        let _ = headers_sent.send(());
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let rules_file = dir.path().join("rules.yaml");
    write_placeholder_rules(&rules_file);
    let main = dir.path().join("kunato.yaml");
    let text = format!(
        "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: {rules_file}
rules_update:
  enabled: true
  url: http://127.0.0.1:{port}/rules.yaml
  checksum_url: http://127.0.0.1:{port}/rules.yaml.sha256
  jitter_percent: 0
",
        rules_file = rules_file.display(),
        port = addr.port()
    );
    std::fs::write(&main, &text).expect("write config");
    let compiled = config::load(&main).expect("load config");
    let config = Arc::new(arc_swap::ArcSwap::from_pointee(compiled));
    let metrics = Arc::new(kunato::metrics::Metrics::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(rules_update::run(config, main, metrics, false, shutdown_rx));

    headers_rx.await.expect("stalled server contacted");
    shutdown_tx.send(true).expect("send shutdown");
    let result = tokio::time::timeout(Duration::from_secs(5), task).await;
    assert!(result.is_ok(), "rules update task must stop on shutdown");
    assert_eq!(
        std::fs::read_to_string(&rules_file).expect("rules intact"),
        PLACEHOLDER_RULES
    );
}

const PLACEHOLDER_RULES: &str = "categories: []\n";

fn write_placeholder_rules(path: &Path) {
    std::fs::write(path, PLACEHOLDER_RULES).expect("write placeholder rules");
}
