use super::*;
use std::sync::atomic::Ordering;

const BASE: &str =
    "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:1\nallowed_hosts: [example.test]\n";
const DECOYS: &str = "decoys:\n  enabled: true\n  sites:\n    - name: blog\n      origin: https://example.test\n      sink: /_decoy/api\n      presets: [dotenv]\n";

fn compiled() -> CompiledConfig {
    crate::config::parse(&format!("{BASE}{DECOYS}")).unwrap()
}

fn parts(path: &str) -> http::request::Parts {
    http::Request::builder()
        .uri(path)
        .header("host", "example.test")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[test]
fn config_defaults_presets_overrides_and_diagnostics_are_bounded() {
    let config = compiled();
    assert_eq!(config.decoys.token_ttl.as_secs(), 1800);
    assert_eq!(config.decoys.on_reuse, Action::Log);
    assert!(config.decoys.observation.body);
    assert_eq!(config.decoy_routes().len(), 2);
    let text = format!(
        "{BASE}{DECOYS}      paths:\n        - {{path: /.env, template: spring-env}}\n        - {{path: /.env.local, template: dotenv}}\n"
    );
    let config = crate::config::parse(&text).unwrap();
    assert_eq!(config.decoys.sites[0].traps["/.env"], Template::SpringEnv);
    assert_eq!(config.decoys.sites[0].traps.len(), 2);
    let omitted = crate::config::parse(BASE).unwrap();
    assert!(!omitted.decoys.enabled);
    let disabled = crate::config::parse(&format!("{BASE}decoys: {{enabled: false}}\n")).unwrap();
    assert!(!disabled.decoys.enabled);
    assert!(disabled.decoys.runtime.key().is_none());
}

#[test]
fn config_rejects_unsupported_ambiguous_and_unbounded_inputs() {
    let text = format!("{BASE}{DECOYS}");
    for invalid in [
        text.replace("enabled: true","enabled: true\n  ban: 1h"),
        text.replace("enabled: true","enabled: true\n  on_reuse: BAN"),
        text.replace("enabled: true","enabled: true\n  token_ttl: 59s"),
        text.replace("enabled: true","enabled: true\n  token_ttl: 25h"),
        text.replace("enabled: true","enabled: true\n  token_ttl: 1500ms"),
        text.replace("enabled: true","enabled: true\n  issuance: {burst: 0}"),
        text.replace("enabled: true","enabled: true\n  issuance: {per_source_per_minute: 61}"),
        text.replace("enabled: true","enabled: true\n  verification: {burst: 4097}"),
        text.replace("origin: https://example.test","origin: http://example.test"),
        text.replace("origin: https://example.test","origin: https://example.test/#fragment"),
        text.replace("origin: https://example.test","origin: https://deploy:secret@example.test"),
        text.replace("origin: https://example.test","origin: https://unlisted.example.test"),
        text.replace("sink: /_decoy/api","sink: /.env"),
        text.replace("sink: /_decoy/api","sink: /a/../api"),
        text.replace("sink: /_decoy/api","sink: /%61pi"),
        text.replace("sink: /_decoy/api","sink: /api?x=1"),
        text.replace("presets: [dotenv]","presets: [dotenv, dotenv]"),
        text.replace("presets: [dotenv]","presets: [unknown]"),
        text.replace("presets: [dotenv]","presets: [dotenv]\n      disabled_paths: [/.unknown]"),
        text.replace("presets: [dotenv]","presets: [dotenv]\n      disabled_paths: [/.env]"),
        text.replace("presets: [dotenv]","presets: [dotenv]\n      paths: [{path: /.x, template: dotenv}, {path: /.x, template: dotenv}]"),
        text.replace("presets: [dotenv]","presets: [dotenv]\n      paths: [{path: /.x, template: dotenv, extra: true}]"),
        format!("{BASE}decoys: {{enabled: true}}\n"),
    ] {assert!(crate::config::parse(&invalid).is_err(),"accepted: {invalid}");}
    let many=(0..17).map(|i|format!("    - name: s{i}\n      origin: https://example.test:{port}\n      sink: /sink\n      presets: [dotenv]\n",port=8000+i)).collect::<String>();
    assert!(
        crate::config::parse(&format!("{BASE}decoys:\n  enabled: true\n  sites:\n{many}")).is_err()
    );
}

#[test]
fn host_allowlisting_is_optional_and_checked_only_when_configured() {
    let base = BASE.replace("allowed_hosts: [example.test]\n", "");
    let config = crate::config::parse(&format!("{base}{DECOYS}")).unwrap();
    assert!(config.allowed_hosts.is_none());
    assert!(config.decoys.enabled);
    assert!(config.decoys.site(&parts("/.env").headers).is_some());
    for allowed in ["example.test", "example.test:443", "*.test"] {
        let text = format!("{base}allowed_hosts: ['{allowed}']\n{DECOYS}");
        assert!(crate::config::parse(&text).is_ok(), "rejected: {allowed}");
    }
    for allowed in ["other.test", "example.test:8443", "*.example.test"] {
        let text = format!("{base}allowed_hosts: ['{allowed}']\n{DECOYS}");
        assert!(crate::config::parse(&text).is_err(), "accepted: {allowed}");
    }
}

#[test]
fn origin_canonicalization_and_site_scope_match_only_valid_authorities() {
    let text = format!(
        "{BASE}{}",
        DECOYS.replace("https://example.test", "https://EXAMPLE.TEST.:443/")
    );
    let config = crate::config::parse(&text).unwrap();
    assert_eq!(config.decoys.sites[0].origin, "https://example.test");
    for host in ["example.test", "EXAMPLE.TEST.", "example.test:443"] {
        let parts = http::Request::builder()
            .uri("/")
            .header("host", host)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(config.decoys.site(&parts.headers).is_some());
    }
    for host in ["example.test:8443", "sub.example.test", "example.test.evil"] {
        let parts = http::Request::builder()
            .uri("/")
            .header("host", host)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(config.decoys.site(&parts.headers).is_none());
    }
}

#[tokio::test]
async fn entropy_or_tracking_failure_returns_local_fallback_without_minting() {
    let config = compiled();
    let metrics = Arc::new(Metrics::new());
    let protection = Arc::new(ProtectionState::new());
    let source = ClientSource::direct("127.0.0.1:12345".parse().unwrap());
    let budget = Arc::new(crate::proxy::server::InspectionBudget::new());
    let mut head = parts("/.env");
    let response = dispatch(
        &mut head,
        &config,
        source,
        metrics.clone(),
        protection.clone(),
        budget.reserve(65536),
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    drop(head);
    protection.check_request(source.client_ip, &config.protection);
    config.decoys.runtime.fail_entropy(false);
    let mut head = parts("/.env");
    let response = dispatch(
        &mut head,
        &config,
        source,
        metrics.clone(),
        protection,
        budget.reserve(65536),
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(metrics.decoys.issued.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.decoys.errors.load(Ordering::Relaxed), 1);
}

#[test]
fn first_enable_entropy_failure_retains_the_previous_snapshot() {
    let current = crate::config::parse(BASE).unwrap();
    current.decoys.runtime.fail_entropy(true);
    let snapshot = crate::snapshot::Snapshot::new(current);
    let metrics = Metrics::new();
    assert!(
        crate::config::watcher::apply(
            std::path::Path::new("decoy.yaml"),
            compiled(),
            &snapshot,
            &metrics,
            false
        )
        .is_none()
    );
    assert!(!snapshot.load().decoys.enabled);
    assert_eq!(metrics.reload_failure.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn scanner_honors_encoding_candidate_byte_and_expiry_limits() {
    let config = compiled();
    let metrics = Arc::new(Metrics::new());
    let protection = Arc::new(ProtectionState::new());
    let site = &config.decoys.sites[0];
    let source = ClientSource::direct("127.0.0.1:12345".parse().unwrap());
    let token = config.decoys.runtime.mint(site.id, 60).unwrap();
    let new = || {
        Observation::new(
            &config.decoys,
            site,
            source,
            source.client_ip,
            metrics.clone(),
            protection.clone(),
            None,
        )
    };
    let encoded = token.replace("kdt1.", "%6b%64%74%31%2e");
    let observation = new();
    observation.head(&parts(&format!("/public?token={encoded}")));
    drop(observation);
    assert_eq!(metrics.decoys.reuse[1].load(Ordering::Relaxed), 1);
    let mut head = parts("/public");
    head.headers.insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    let observation = new();
    observation.body(
        format!("{{\"value\":\"{}\"}}", token.replace("kdt1", "\\u006bdt1")).as_bytes(),
        &head.headers,
        true,
        false,
    );
    drop(observation);
    assert_eq!(metrics.decoys.reuse[1].load(Ordering::Relaxed), 2);
    let observation = new();
    observation.body(token.as_bytes(), &head.headers, false, false);
    drop(observation);
    assert_eq!(metrics.decoys.incomplete[3].load(Ordering::Relaxed), 1);
    let observation = new();
    observation.body(
        format!("{}{token}", " ".repeat(8192)).as_bytes(),
        &head.headers,
        true,
        false,
    );
    drop(observation);
    assert_eq!(metrics.decoys.reuse[1].load(Ordering::Relaxed), 2);
    assert_eq!(metrics.decoys.incomplete[2].load(Ordering::Relaxed), 1);
    let observation = new();
    observation.head(&parts(&format!("/{}", "x".repeat(40000))));
    drop(observation);
    assert!(metrics.decoys.incomplete[0].load(Ordering::Relaxed) > 0);
    let tokens = (0..17)
        .map(|_| config.decoys.runtime.mint(site.id, 60).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    let observation = new();
    observation.head(&parts(&format!("/?{tokens}")));
    drop(observation);
    assert_eq!(metrics.decoys.incomplete[1].load(Ordering::Relaxed), 1);
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    let observation = new();
    observation.head(&parts(&format!("/?{token}")));
    drop(observation);
    assert_eq!(metrics.decoys.reuse[1].load(Ordering::Relaxed), 3);
    assert!(metrics.decoys.invalid[2].load(Ordering::Relaxed) > 0);
}

#[test]
fn redactor_covers_raw_once_twice_encoded_and_partial_token_markers() {
    for path in [
        "/kdt1.value",
        "/%6bdt1%2evalue",
        "/%256bdt1%252evalue",
        "/kdt1",
    ] {
        assert_eq!(log_path(path), "[redacted]");
    }
    assert_eq!(log_path("/public"), "/public");
    assert_eq!(log_path(&format!("/{}", "x".repeat(32769))), "[redacted]");
}

#[test]
fn config_enforces_global_route_and_duplicate_site_bounds() {
    let sites=(0..5).map(|index|{
        let paths=(0..if index==4 {1}else{32}).map(|path|format!("        - {{path: /p{path}, template: dotenv}}\n")).collect::<String>();
        format!("    - name: s{index}\n      origin: https://example.test:{port}\n      sink: /sink\n      paths:\n{paths}",port=8000+index)
    }).collect::<String>();
    let error = crate::config::parse(&format!(
        "{BASE}decoys:\n  enabled: true\n  sites:\n{sites}"
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("128 traps"), "{error}");
    let duplicate = format!(
        "{BASE}{DECOYS}    - name: second\n      origin: https://EXAMPLE.TEST:443\n      sink: /other\n      presets: [dotenv]\n"
    );
    assert!(
        crate::config::parse(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate site origin")
    );
}

#[tokio::test(start_paused = true)]
async fn shorter_ttl_does_not_revoke_existing_signed_expiries() {
    let mut prior = compiled();
    let site = prior.decoys.sites[0].id;
    let old = prior.decoys.runtime.mint(site, 1800).unwrap();
    let mut next = compiled();
    next.decoys.token_ttl = std::time::Duration::from_secs(60);
    next.decoys.adopt_runtime(&prior.decoys, true).unwrap();
    let short = next.decoys.runtime.mint(site, 60).unwrap();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    let key = next.decoys.runtime.key().unwrap();
    assert_eq!(
        key.verify(
            &token::Parsed::parse(old.as_bytes()).unwrap(),
            site,
            next.decoys.runtime.elapsed()
        ),
        Ok(61)
    );
    assert_eq!(
        key.verify(
            &token::Parsed::parse(short.as_bytes()).unwrap(),
            site,
            next.decoys.runtime.elapsed()
        ),
        Err(token::Invalid::Expired)
    );
    prior.decoys.enabled = false;
    prior.decoys.adopt_runtime(&next.decoys, true).unwrap();
    next.decoys.adopt_runtime(&prior.decoys, true).unwrap();
    assert!(Arc::ptr_eq(&next.decoys.runtime, &prior.decoys.runtime));
}

#[test]
fn scratch_exhaustion_is_visible_without_owning_ordinary_routes() {
    let config = compiled();
    let metrics = Arc::new(Metrics::new());
    let protection = Arc::new(ProtectionState::new());
    let source = ClientSource::direct("127.0.0.1:12345".parse().unwrap());
    assert!(
        dispatch(
            &mut parts("/public"),
            &config,
            source,
            metrics.clone(),
            protection.clone(),
            None
        )
        .is_none()
    );
    assert_eq!(
        dispatch(
            &mut parts("/.env"),
            &config,
            source,
            metrics.clone(),
            protection,
            None
        )
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(metrics.decoys.incomplete[6].load(Ordering::Relaxed), 2);
    assert_eq!(metrics.decoys.limited[4].load(Ordering::Relaxed), 1);
    let rendered = metrics.render(0);
    assert!(rendered.contains("kunato_decoy_limited_total{reason=\"inspection\"} 1"));
    assert!(!rendered.contains("example.test"));
}

#[test]
fn mandatory_body_budget_can_reclaim_optional_decoy_scratch() {
    let config = compiled();
    let metrics = Arc::new(Metrics::new());
    let protection = Arc::new(ProtectionState::new());
    let source = ClientSource::direct("127.0.0.1:12345".parse().unwrap());
    let budget = Arc::new(crate::proxy::server::InspectionBudget::new());
    let scratch = budget.reserve(65536).unwrap();
    let observation = Observation::new(
        &config.decoys,
        &config.decoys.sites[0],
        source,
        source.client_ip,
        metrics.clone(),
        protection,
        Some(scratch),
    );
    let mut body = budget.reserve(65536).unwrap();
    body.attach_decoy(observation.reclaimer());
    let occupied = budget
        .reserve(256 * 1024 * 1024 - 2 * 65536 - 32768)
        .unwrap();
    assert!(body.grow(65536));
    drop(observation);
    assert_eq!(metrics.decoys.incomplete[6].load(Ordering::Relaxed), 1);
    drop(occupied);
    drop(body);
    assert!(budget.reserve(256 * 1024 * 1024).is_some());
}
