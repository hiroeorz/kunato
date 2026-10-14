use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::watcher;
use crate::config::{self, CompiledConfig, RulesUpdate};
use crate::error::Error;
use crate::metrics::Metrics;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const FAILURE_RETRY: Duration = Duration::from_secs(600);
const DISABLED_POLL: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 5;
const MAX_CHECKSUM_BYTES: usize = 4096;
const MAX_STATE_BYTES: u64 = 16 * 1024;

type RulesClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated,
    NotModified,
}

/// Background task that refreshes the managed rules file on the configured
/// interval. Errors never terminate the loop: the previous rules stay active.
pub async fn run(
    config: Arc<ArcSwap<CompiledConfig>>,
    main_config: PathBuf,
    metrics: Arc<Metrics>,
    disable_protection: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let (settings, rules_file) = {
            let current = config.load();
            (current.rules_update.clone(), current.rules_file.clone())
        };
        let Some(rules_file) = rules_file.filter(|_| settings.enabled) else {
            if wait_for_shutdown(&mut shutdown, DISABLED_POLL).await {
                break;
            }
            continue;
        };

        let state_file = state_path(&rules_file);
        let state = UpdateState::read(&state_file);
        if let Some(delay) = delay_until_due(&state, &settings) {
            if wait_for_shutdown(&mut shutdown, delay).await {
                break;
            }
            continue;
        }

        let succeeded = match update_once(&settings, &rules_file, &state_file).await {
            Ok(UpdateOutcome::Updated) => {
                metrics.rules_update_success.fetch_add(1, Ordering::Relaxed);
                metrics
                    .rules_last_success
                    .store(unix_now(), Ordering::Relaxed);
                info!(path = %rules_file.display(), "rules file updated");
                watcher::reload(&main_config, &config, &metrics, disable_protection);
                true
            }
            Ok(UpdateOutcome::NotModified) => {
                metrics
                    .rules_update_not_modified
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .rules_last_success
                    .store(unix_now(), Ordering::Relaxed);
                info!("rules are up to date");
                true
            }
            Err(err) => {
                metrics.rules_update_failure.fetch_add(1, Ordering::Relaxed);
                error!(error = %err, "rules update failed; keeping the current rules");
                false
            }
        };

        let delay = if succeeded {
            jittered(settings.interval, settings.jitter_percent)
        } else {
            settings.interval.min(FAILURE_RETRY)
        };
        if wait_for_shutdown(&mut shutdown, delay).await {
            break;
        }
    }
}

/// Download, verify, validate, and atomically replace the rules file.
pub async fn update_once(
    settings: &RulesUpdate,
    rules_file: &Path,
    state_file: &Path,
) -> Result<UpdateOutcome, Error> {
    let Some(url) = &settings.url else {
        return Err(Error::Message(
            "rules update URL is not configured".to_owned(),
        ));
    };
    let Some(checksum_url) = &settings.checksum_url else {
        return Err(Error::Message(
            "rules update checksum URL is not configured".to_owned(),
        ));
    };

    let state = UpdateState::read(state_file);
    let client = build_client()?;
    let fetched = fetch(&client, url, settings.max_bytes, &state).await?;
    let Fetched::Body {
        bytes,
        etag,
        last_modified,
    } = fetched
    else {
        let next = UpdateState {
            last_success: Some(unix_now()),
            ..state
        };
        write_state(&next, state_file);
        return Ok(UpdateOutcome::NotModified);
    };

    let expected = fetch_checksum(&client, checksum_url).await?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(Error::Message(format!(
            "rules checksum mismatch: expected {expected}, got {actual}"
        )));
    }

    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Message("rules file is not valid UTF-8".to_owned()))?;
    let parsed = config::parse_rules(text)?;
    if !parsed.disabled_rules.is_empty() {
        return Err(Error::Message(
            "rules file must not contain `disabled_rules`; put them in overrides_file".to_owned(),
        ));
    }

    write_atomic(rules_file, &bytes)?;
    let next = UpdateState {
        last_success: Some(unix_now()),
        etag,
        last_modified,
    };
    write_state(&next, state_file);
    Ok(UpdateOutcome::Updated)
}

pub fn state_path(rules_file: &Path) -> PathBuf {
    let file_name = rules_file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules.yaml".to_owned());
    rules_file.with_file_name(format!("{file_name}.update-state"))
}

enum Fetched {
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
    NotModified,
}

async fn fetch(
    client: &RulesClient,
    url: &Uri,
    max_bytes: usize,
    state: &UpdateState,
) -> Result<Fetched, Error> {
    let mut current = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let mut builder = Request::builder().method(Method::GET).uri(current.clone());
        if let Some(etag) = &state.etag
            && let Ok(value) = HeaderValue::from_str(etag)
        {
            builder = builder.header(IF_NONE_MATCH, value);
        }
        if let Some(last_modified) = &state.last_modified
            && let Ok(value) = HeaderValue::from_str(last_modified)
        {
            builder = builder.header(IF_MODIFIED_SINCE, value);
        }
        let request = builder
            .body(Full::new(Bytes::new()))
            .map_err(|err| Error::Message(format!("invalid rules update request: {err}")))?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request))
            .await
            .map_err(|_| Error::Message("rules update request timed out".to_owned()))?
            .map_err(|err| Error::Message(format!("rules update request failed: {err}")))?;

        match response.status() {
            StatusCode::OK => {
                let etag = header_string(response.headers(), ETAG);
                let last_modified = header_string(response.headers(), LAST_MODIFIED);
                let bytes = read_body(response.into_body(), max_bytes).await?;
                return Ok(Fetched::Body {
                    bytes,
                    etag,
                    last_modified,
                });
            }
            StatusCode::NOT_MODIFIED => return Ok(Fetched::NotModified),
            status if status.is_redirection() => {
                let Some(location) = header_string(response.headers(), LOCATION) else {
                    return Err(Error::Message(format!(
                        "rules update redirect ({status}) without a Location header"
                    )));
                };
                current = Uri::from_str(&location).map_err(|err| {
                    Error::Message(format!("invalid redirect target `{location}`: {err}"))
                })?;
            }
            status => {
                return Err(Error::Message(format!(
                    "rules update request returned {status}"
                )));
            }
        }
    }
    Err(Error::Message(
        "too many redirects while fetching rules".to_owned(),
    ))
}

fn header_string(headers: &http::HeaderMap, name: http::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn fetch_checksum(client: &RulesClient, url: &Uri) -> Result<String, Error> {
    let fetched = fetch(client, url, MAX_CHECKSUM_BYTES, &UpdateState::default()).await?;
    let Fetched::Body { bytes, .. } = fetched else {
        return Err(Error::Message(
            "checksum request was unexpectedly not modified".to_owned(),
        ));
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Message("checksum file is not valid UTF-8".to_owned()))?;
    parse_checksum(text)
}

fn parse_checksum(text: &str) -> Result<String, Error> {
    let token = text
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Message(
            "checksum file does not contain a sha256 digest".to_owned(),
        ));
    }
    Ok(token)
}

fn build_client() -> Result<RulesClient, Error> {
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|err| Error::Message(format!("failed to load system TLS roots: {err}")))?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

async fn read_body(mut body: Incoming, max_bytes: usize) -> Result<Vec<u8>, Error> {
    use http_body_util::BodyExt;

    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|err| Error::Message(format!("failed to read rules body: {err}")))?;
        if let Some(chunk) = frame.data_ref() {
            if bytes.len() + chunk.len() > max_bytes {
                return Err(Error::Message(format!(
                    "rules body exceeds the {max_bytes} byte limit"
                )));
            }
            bytes.extend_from_slice(chunk);
        }
    }
    Ok(bytes)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules.yaml".to_owned());
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(|err| {
        Error::Message(format!("failed to write `{}`: {err}", temporary.display()))
    })?;
    std::fs::rename(&temporary, path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        Error::Message(format!("failed to replace `{}`: {err}", path.display()))
    })
}

fn write_state(state: &UpdateState, path: &Path) {
    if let Err(err) = state.write(path) {
        warn!(error = %err, "failed to persist rules update state");
    }
}

#[derive(Debug, Clone, Default)]
struct UpdateState {
    last_success: Option<u64>,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl UpdateState {
    fn read(path: &Path) -> Self {
        let Ok(metadata) = std::fs::metadata(path) else {
            return Self::default();
        };
        if metadata.len() > MAX_STATE_BYTES {
            warn!(path = %path.display(), "rules update state file is too large; ignoring it");
            return Self::default();
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let mut state = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "last_success" => state.last_success = value.trim().parse().ok(),
                "etag" if !value.trim().is_empty() => state.etag = Some(value.trim().to_owned()),
                "last_modified" if !value.trim().is_empty() => {
                    state.last_modified = Some(value.trim().to_owned());
                }
                _ => {}
            }
        }
        state
    }

    fn write(&self, path: &Path) -> Result<(), Error> {
        let mut text = String::with_capacity(256);
        if let Some(last_success) = self.last_success {
            let _ = writeln!(text, "last_success={last_success}");
        }
        if let Some(etag) = &self.etag {
            let _ = writeln!(text, "etag={etag}");
        }
        if let Some(last_modified) = &self.last_modified {
            let _ = writeln!(text, "last_modified={last_modified}");
        }
        write_atomic(path, text.as_bytes())
    }
}

fn delay_until_due(state: &UpdateState, settings: &RulesUpdate) -> Option<Duration> {
    let last_success = state.last_success?;
    let due = Duration::from_secs(last_success).saturating_add(settings.interval);
    let now = Duration::from_secs(unix_now());
    due.checked_sub(now)
}

fn jittered(interval: Duration, percent: u8) -> Duration {
    if percent == 0 {
        return interval;
    }
    let spread = interval.as_millis() * u128::from(percent) / 100;
    if spread == 0 {
        return interval;
    }
    let half = spread / 2;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u128::from(duration.subsec_nanos()))
        .unwrap_or(0);
    let offset = nanos % spread;
    let base = interval.as_millis();
    Duration::from_millis((base.saturating_sub(half).saturating_add(offset)) as u64)
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow_and_update(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_path_appends_suffix() {
        assert_eq!(
            state_path(Path::new("/var/lib/kunato/rules.yaml")),
            PathBuf::from("/var/lib/kunato/rules.yaml.update-state")
        );
    }

    #[test]
    fn parses_sha256sum_style_checksum() {
        let digest = "a".repeat(64);
        let text = format!("{digest}  rules.yaml\n");
        assert_eq!(parse_checksum(&text).expect("valid"), digest);
    }

    #[test]
    fn rejects_short_checksums() {
        assert!(parse_checksum("abc rules.yaml").is_err());
        assert!(parse_checksum("").is_err());
        assert!(parse_checksum(&format!("{}z", "a".repeat(63))).is_err());
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let interval = Duration::from_secs(3600);
        for _ in 0..64 {
            let jittered = jittered(interval, 10);
            assert!(jittered >= Duration::from_secs(3420));
            assert!(jittered < Duration::from_secs(3780));
        }
        assert_eq!(jittered(interval, 0), interval);
    }

    #[test]
    fn delay_is_none_without_a_successful_check() {
        let settings = RulesUpdate::default();
        assert!(delay_until_due(&UpdateState::default(), &settings).is_none());
    }

    #[test]
    fn delay_counts_down_from_last_success() {
        let settings = RulesUpdate {
            interval: Duration::from_secs(60),
            ..RulesUpdate::default()
        };
        let state = UpdateState {
            last_success: Some(unix_now().saturating_sub(30)),
            ..UpdateState::default()
        };
        let delay = delay_until_due(&state, &settings).expect("due in the future");
        assert!(delay <= Duration::from_secs(30));
        assert!(delay >= Duration::from_secs(25));
    }

    #[test]
    fn state_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state");
        let state = UpdateState {
            last_success: Some(42),
            etag: Some("\"abc\"".to_owned()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_owned()),
        };
        state.write(&path).expect("write state");
        let read = UpdateState::read(&path);
        assert_eq!(read.last_success, Some(42));
        assert_eq!(read.etag.as_deref(), Some("\"abc\""));
        assert_eq!(
            read.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    }
}
