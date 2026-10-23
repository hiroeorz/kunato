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
/// Redirects may leave the configured origin at most this many times. CDNs
/// legitimately bounce release assets to object storage, so one hop keeps the
/// release channel working, but a chain that keeps moving the download between
/// hosts is refused: the configured origin is the only host the operator chose.
const MAX_CROSS_HOST_REDIRECTS: usize = 2;
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

        let outcome = tokio::select! {
            result = update_once(&main_config, &settings, &rules_file, &state_file) => result,
            _ = shutdown.changed() => {
                info!("rules update cancelled for shutdown");
                break;
            }
        };

        let succeeded = match outcome {
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
                if matches!(err, Error::RulesNeedNewerBuild(_)) {
                    metrics
                        .rules_update_incompatible
                        .fetch_add(1, Ordering::Relaxed);
                    error!(
                        error = %err,
                        "the published rule set needs a newer Kunato build; keeping the current rules"
                    );
                } else {
                    error!(error = %err, "rules update failed; keeping the current rules");
                }
                false
            }
        };

        if succeeded {
            continue;
        }
        let delay = settings.interval.min(FAILURE_RETRY);
        if wait_for_shutdown(&mut shutdown, delay).await {
            break;
        }
    }
}

/// Download, verify, validate against the whole configuration, and atomically
/// replace the rules file. `main_config` is the entry configuration whose
/// `rules_file` must resolve to `rules_file`; the candidate is compiled together
/// with the inline and overrides sources before anything is written.
pub async fn update_once(
    main_config: &Path,
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
    let fetched = fetch(&client, url, settings.max_bytes, &state, "rules update").await?;
    let Fetched::Body {
        bytes,
        etag,
        last_modified,
    } = fetched
    else {
        // A 304 answer is only meaningful while the installed file still
        // holds what the validators describe. Accepting the shortcut for a
        // missing or empty file would leave a crash-truncated install with
        // no rules forever on channels that never change, so the validators
        // are cleared to force a fresh fetch on the next attempt.
        let installed = std::fs::metadata(rules_file).is_ok_and(|meta| meta.len() > 0);
        let next = if installed {
            UpdateState {
                last_success: Some(unix_now()),
                next_due: Some(next_due(settings)),
                ..state
            }
        } else {
            warn!(
                path = %rules_file.display(),
                "rules file is missing or empty despite an unmodified response; validators cleared"
            );
            UpdateState {
                etag: None,
                last_modified: None,
                ..state
            }
        };
        write_state(&next, state_file);
        if !installed {
            return Err(Error::Message(format!(
                "`{}` is missing or empty while the update server reports the rules as unmodified",
                rules_file.display()
            )));
        }
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
    // A construct this build does not implement means the published set is newer
    // than the running binary: that needs an upgrade, which is a different
    // remedy than a transient failure, so it gets its own error variant.
    let parsed = config::parse_rules(text).map_err(|err| match err.unsupported_construct() {
        Some(construct) => Error::RulesNeedNewerBuild(construct),
        None => err,
    })?;
    if !parsed.disabled_rules.is_empty() {
        return Err(Error::Message(
            "rules file must not contain `disabled_rules`; put them in overrides_file".to_owned(),
        ));
    }

    let candidate = config::load_with_rules_candidate(main_config, text)?;
    match &candidate.rules_file {
        Some(installed) if same_path(installed, rules_file) => {}
        _ => {
            return Err(Error::Message(format!(
                "`{}` does not point `rules_file` at `{}`",
                main_config.display(),
                rules_file.display()
            )));
        }
    }

    write_atomic(rules_file, &bytes)?;
    let now = unix_now();
    let next = UpdateState {
        last_success: Some(now),
        next_due: Some(
            now.saturating_add(jittered(settings.interval, settings.jitter_percent).as_secs()),
        ),
        etag,
        last_modified,
    };
    write_state(&next, state_file);
    Ok(UpdateOutcome::Updated)
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (std::path::absolute(a), std::path::absolute(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn next_due(settings: &RulesUpdate) -> u64 {
    unix_now().saturating_add(jittered(settings.interval, settings.jitter_percent).as_secs())
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
    what: &str,
) -> Result<Fetched, Error> {
    let mut current = url.clone();
    let mut cross_host_redirects = 0usize;
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
            .map_err(|err| Error::Message(format!("{what} request is invalid: {err}")))?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, client.request(request))
            .await
            .map_err(|_| Error::Message(format!("{what} request timed out")))?
            .map_err(|err| Error::Message(format!("{what} request failed: {err}")))?;

        match response.status() {
            StatusCode::OK => {
                let etag = header_string(response.headers(), ETAG);
                let last_modified = header_string(response.headers(), LAST_MODIFIED);
                let body = tokio::time::timeout(
                    REQUEST_TIMEOUT,
                    read_body(response.into_body(), max_bytes, what),
                )
                .await
                .map_err(|_| Error::Message(format!("{what} body read timed out")))??;
                return Ok(Fetched::Body {
                    bytes: body,
                    etag,
                    last_modified,
                });
            }
            StatusCode::NOT_MODIFIED => return Ok(Fetched::NotModified),
            status if status.is_redirection() => {
                let Some(location) = header_string(response.headers(), LOCATION) else {
                    return Err(Error::Message(format!(
                        "{what} redirect ({status}) without a Location header"
                    )));
                };
                let target = resolve_location(&current, &location)?;
                if !redirect_allowed(url, &target) {
                    return Err(Error::Message(format!(
                        "{what} redirect to `{target}` violates the transport policy"
                    )));
                }
                if !same_host(url, &target) {
                    cross_host_redirects += 1;
                    if cross_host_redirects > MAX_CROSS_HOST_REDIRECTS {
                        return Err(Error::Message(format!(
                            "{what} redirected away from the configured origin across more than {MAX_CROSS_HOST_REDIRECTS} hosts"
                        )));
                    }
                    info!(
                        what,
                        from = %current,
                        to = %target,
                        hops = cross_host_redirects,
                        "redirect moved the download to another host"
                    );
                }
                current = target;
            }
            status => {
                return Err(Error::Message(format!("{what} request returned {status}")));
            }
        }
    }
    Err(Error::Message(format!(
        "{what} exceeded the redirect limit"
    )))
}

/// Resolve a `Location` header against the URL that produced it, supporting
/// absolute, scheme-relative, and path-relative targets.
fn resolve_location(current: &Uri, location: &str) -> Result<Uri, Error> {
    let next = Uri::from_str(location)
        .map_err(|err| Error::Message(format!("invalid redirect target `{location}`: {err}")))?;
    if next.scheme().is_some() && next.authority().is_some() {
        return Ok(next);
    }
    let mut parts = current.clone().into_parts();
    if next.authority().is_some() {
        parts.authority = next.authority().cloned();
    }
    parts.path_and_query = next.path_and_query().cloned();
    Uri::from_parts(parts)
        .map_err(|err| Error::Message(format!("invalid redirect target `{location}`: {err}")))
}

/// Redirects must never weaken transport security: an HTTPS acquisition may
/// only follow HTTPS redirects, and a loopback-HTTP acquisition may only follow
/// HTTPS or loopback HTTP. How far the download may travel away from the
/// configured origin is capped separately by [`MAX_CROSS_HOST_REDIRECTS`].
fn redirect_allowed(start: &Uri, next: &Uri) -> bool {
    match next.scheme_str() {
        Some("https") => next.authority().is_some(),
        Some("http") => {
            start.scheme_str() != Some("https")
                && next
                    .authority()
                    .is_some_and(|authority| host_is_loopback(authority.host()))
        }
        _ => false,
    }
}

/// Bracket-stripped host, so IPv6 literals compare like their textual form.
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

/// The rules download stays on the configured origin apart from CDN hops:
/// hostnames compare case-insensitively and ports and IPv6 brackets do not
/// make a different host.
fn same_host(a: &Uri, b: &Uri) -> bool {
    match (a.authority(), b.authority()) {
        (Some(a), Some(b)) => bare_host(a.host()).eq_ignore_ascii_case(bare_host(b.host())),
        _ => false,
    }
}

fn host_is_loopback(host: &str) -> bool {
    let host = bare_host(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn header_string(headers: &http::HeaderMap, name: http::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn fetch_checksum(client: &RulesClient, url: &Uri) -> Result<String, Error> {
    let fetched = fetch(
        client,
        url,
        MAX_CHECKSUM_BYTES,
        &UpdateState::default(),
        "checksum",
    )
    .await?;
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

async fn read_body(mut body: Incoming, max_bytes: usize, what: &str) -> Result<Vec<u8>, Error> {
    use http_body_util::BodyExt;

    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame =
            frame.map_err(|err| Error::Message(format!("failed to read {what} body: {err}")))?;
        if let Some(chunk) = frame.data_ref() {
            if bytes.len() + chunk.len() > max_bytes {
                return Err(Error::Message(format!(
                    "{what} body exceeds the {max_bytes} byte limit"
                )));
            }
            bytes.extend_from_slice(chunk);
        }
    }
    Ok(bytes)
}

/// Download a small release asset (for example the installer script) with the
/// same transport policy the rules updater uses: HTTPS with system roots,
/// bounded redirects, and bounded size. Used by `kunato upgrade`.
pub async fn fetch_release_asset(url: &str, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let uri: Uri = url
        .parse()
        .map_err(|err| Error::Message(format!("invalid URL `{url}`: {err}")))?;
    let client = build_client()?;
    match fetch(
        &client,
        &uri,
        max_bytes,
        &UpdateState::default(),
        "release download",
    )
    .await?
    {
        Fetched::Body { bytes, .. } => Ok(bytes),
        Fetched::NotModified => Err(Error::Message(
            "release download was unexpectedly not modified".to_owned(),
        )),
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules.yaml".to_owned());
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    // Flush to stable storage before the rename commit and sync the directory
    // afterwards: a crash in between must not leave an empty or truncated
    // rules file behind on the next restart.
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            // Best effort; some filesystems do not support directory fsync.
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = std::fs::remove_file(&temporary);
            Err(Error::Message(format!(
                "failed to replace `{}`: {err}",
                path.display()
            )))
        }
    }
}

fn write_state(state: &UpdateState, path: &Path) {
    if let Err(err) = state.write(path) {
        warn!(error = %err, "failed to persist rules update state");
    }
}

#[derive(Debug, Clone, Default)]
struct UpdateState {
    last_success: Option<u64>,
    next_due: Option<u64>,
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
                "next_due" => state.next_due = value.trim().parse().ok(),
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
        if let Some(next_due) = self.next_due {
            let _ = writeln!(text, "next_due={next_due}");
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
    if let Some(next_due) = state.next_due {
        let now = Duration::from_secs(unix_now());
        return Duration::from_secs(next_due).checked_sub(now);
    }
    let last_success = state.last_success?;
    let due = Duration::from_secs(last_success).saturating_add(settings.interval);
    let now = Duration::from_secs(unix_now());
    due.checked_sub(now)
}

/// Randomize the next check by the configured percentage in both directions:
/// the result falls in `[interval * (1 - percent/100), interval * (1 + percent/100)]`.
fn jittered(interval: Duration, percent: u8) -> Duration {
    if percent == 0 {
        return interval;
    }
    let base = interval.as_millis();
    let spread = base.saturating_mul(u128::from(percent)) / 100;
    if spread == 0 {
        return interval;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u128::from(duration.subsec_nanos()))
        .unwrap_or(0);
    let offset = nanos % spread.saturating_mul(2).saturating_add(1);
    let millis = base.saturating_sub(spread).saturating_add(offset);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
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
    fn sha256_hex_matches_known_vectors() {
        let padding_boundary = [b'a'; 55];
        let full_block = [b'a'; 64];
        let cases: &[(&[u8], &str)] = &[
            // Empty input.
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            // "abc" from the NIST test suite.
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            // 56 bytes: the padding no longer fits in the final block.
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            // 55 bytes: the largest message whose padding fits in one block.
            (
                &padding_boundary,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            // 64 bytes: one full block plus a padding block.
            (
                &full_block,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
        ];
        for &(input, expected) in cases {
            assert_eq!(sha256_hex(input), expected);
        }
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let interval = Duration::from_secs(3600);
        for _ in 0..256 {
            let jittered = jittered(interval, 10);
            assert!(jittered >= Duration::from_secs(3240));
            assert!(jittered <= Duration::from_secs(3960));
        }
        assert_eq!(jittered(interval, 0), interval);
        for _ in 0..256 {
            let jittered = jittered(interval, 50);
            assert!(jittered >= Duration::from_secs(1800));
            assert!(jittered <= Duration::from_secs(5400));
        }
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
    fn delay_prefers_the_jittered_next_due() {
        let settings = RulesUpdate {
            interval: Duration::from_secs(3600),
            jitter_percent: 10,
            ..RulesUpdate::default()
        };
        let now = unix_now();
        let state = UpdateState {
            last_success: Some(now),
            next_due: Some(now.saturating_add(3240)),
            ..UpdateState::default()
        };
        let delay = delay_until_due(&state, &settings).expect("due in the future");
        assert!(delay <= Duration::from_secs(3240));
        assert!(delay >= Duration::from_secs(3235));
    }

    #[test]
    fn redirect_policy_rejects_downgrades_and_remote_http() {
        let https_start: Uri = "https://rules.example/path".parse().expect("valid URI");
        let http_loopback: Uri = "http://127.0.0.1:8080/path".parse().expect("valid URI");

        assert!(redirect_allowed(
            &https_start,
            &"https://mirror.example/rules".parse().expect("valid URI")
        ));
        assert!(!redirect_allowed(
            &https_start,
            &"http://127.0.0.1:8080/rules".parse().expect("valid URI")
        ));
        assert!(!redirect_allowed(
            &https_start,
            &"http://rules.example/rules".parse().expect("valid URI")
        ));
        assert!(redirect_allowed(
            &http_loopback,
            &"https://rules.example/rules".parse().expect("valid URI")
        ));
        assert!(redirect_allowed(
            &http_loopback,
            &"http://localhost:9090/rules".parse().expect("valid URI")
        ));
        assert!(!redirect_allowed(
            &http_loopback,
            &"http://rules.example/rules".parse().expect("valid URI")
        ));
        assert!(!redirect_allowed(
            &http_loopback,
            &"ftp://rules.example/rules".parse().expect("valid URI")
        ));
    }

    #[test]
    fn same_host_lookup_ignores_case_ports_and_ipv6_brackets() {
        let origin: Uri = "https://Mirror.Example/rules.yaml"
            .parse()
            .expect("valid URI");

        assert!(same_host(
            &origin,
            &"https://mirror.example/rules".parse().expect("valid URI")
        ));
        assert!(same_host(
            &origin,
            &"https://MIRROR.EXAMPLE:8443/rules"
                .parse()
                .expect("valid URI")
        ));
        assert!(!same_host(
            &origin,
            &"https://mirror.other.example/rules"
                .parse()
                .expect("valid URI")
        ));

        let ipv6: Uri = "https://[::1]:8080/rules.yaml".parse().expect("valid URI");
        assert!(same_host(
            &ipv6,
            &"https://[::1]:9090/rules".parse().expect("valid URI")
        ));
        assert!(!same_host(
            &ipv6,
            &"https://[::2]:8080/rules".parse().expect("valid URI")
        ));
    }

    #[test]
    fn relative_redirects_resolve_against_the_current_url() {
        let current: Uri = "https://rules.example/v1/rules.yaml"
            .parse()
            .expect("valid URI");
        assert_eq!(
            resolve_location(&current, "/v2/rules.yaml").expect("resolved"),
            "https://rules.example/v2/rules.yaml"
                .parse::<Uri>()
                .expect("valid URI")
        );
        assert_eq!(
            resolve_location(&current, "https://other.example/rules.yaml").expect("resolved"),
            "https://other.example/rules.yaml"
                .parse::<Uri>()
                .expect("valid URI")
        );
    }

    #[test]
    fn state_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state");
        let state = UpdateState {
            last_success: Some(42),
            next_due: Some(3600),
            etag: Some("\"abc\"".to_owned()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_owned()),
        };
        state.write(&path).expect("write state");
        let read = UpdateState::read(&path);
        assert_eq!(read.last_success, Some(42));
        assert_eq!(read.next_due, Some(3600));
        assert_eq!(read.etag.as_deref(), Some("\"abc\""));
        assert_eq!(
            read.last_modified.as_deref(),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
    }
}
