use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{ETAG, HeaderName, HeaderValue, IF_NONE_MATCH, LOCATION};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sha2::Digest;
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
    let listener = TcpListener::bind("127.0.0.1:0")
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
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn update_settings(dir: &Path, port: u16, max_bytes: usize) -> (RulesUpdate, PathBuf) {
    let rules_file = dir.join("rules.yaml");
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
    let parsed = config::parse(&text).expect("valid update config");
    (
        parsed.rules_update.clone(),
        parsed.rules_file.clone().expect("rules file"),
    )
}

#[tokio::test]
async fn downloads_and_replaces_the_rules_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let outcome = rules_update::update_once(&settings, &rules_file, &state_file)
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
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&settings, &rules_file, &state_file)
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
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);
    std::fs::write(&state_file, "last_success=1\netag=\"v1\"\n").expect("state");

    let outcome = rules_update::update_once(&settings, &rules_file, &state_file)
        .await
        .expect("update succeeds");

    assert_eq!(outcome, UpdateOutcome::NotModified);
    assert!(!rules_file.exists());
    let state = std::fs::read_to_string(&state_file).expect("state written");
    assert!(!state.contains("last_success=1\n"));
}

#[tokio::test]
async fn rejects_bodies_over_the_configured_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let addr = spawn_server(rules_routes(RULES.as_bytes())).await;
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 32);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&settings, &rules_file, &state_file)
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
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&settings, &rules_file, &state_file)
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
    let (settings, rules_file) = update_settings(dir.path(), addr.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let error = rules_update::update_once(&settings, &rules_file, &state_file)
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

    let (settings, rules_file) = update_settings(dir.path(), redirect.port(), 1024 * 1024);
    let state_file = rules_update::state_path(&rules_file);

    let outcome = rules_update::update_once(&settings, &rules_file, &state_file)
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
    rules_update::update_once(&parsed.rules_update, &rules_file, &state_file)
        .await
        .expect("update succeeds");

    let loaded = config::load(&main).expect("config loads after update");
    assert_eq!(loaded.categories.len(), 1);
    assert_eq!(loaded.categories[0].name, "auto");
}
