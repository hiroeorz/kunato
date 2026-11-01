use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION};
use http::{Method, Request, StatusCode, Uri};
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
use crate::proxy::{BodyExt, Full};
use crate::snapshot::Snapshot;

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
/// Detached minisign signatures are a few hundred bytes.
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
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
    config: Arc<Snapshot<CompiledConfig>>,
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
            result = update_candidate(
                &main_config,
                &settings,
                &rules_file,
                &state_file,
                Some(LiveTarget {
                    config: Arc::clone(&config),
                    metrics: Arc::clone(&metrics),
                    disable_protection,
                }),
            ) => result,
            _ = shutdown.changed() => {
                info!("rules update cancelled for shutdown");
                break;
            }
        };

        let succeeded = match outcome {
            Ok(true) => {
                metrics.rules_update_success.fetch_add(1, Ordering::Relaxed);
                metrics
                    .rules_last_success
                    .store(unix_now(), Ordering::Relaxed);
                info!(path = %rules_file.display(), "rules file updated");
                true
            }
            Ok(false) => {
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
                if matches!(err, Error::Signature(_)) {
                    metrics
                        .rules_signature_failure
                        .fetch_add(1, Ordering::Relaxed);
                }
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
            // The state file may be unwritable (read-only directory): never
            // fall through into an immediate re-check loop. Reading the state
            // again covers the normal case; otherwise wait one interval.
            let delay = delay_until_due(&UpdateState::read(&state_file), &settings)
                .filter(|delay| *delay <= settings.interval)
                .unwrap_or(settings.interval);
            if wait_for_shutdown(&mut shutdown, delay).await {
                break;
            }
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
    match update_candidate(main_config, settings, rules_file, state_file, None).await? {
        true => Ok(UpdateOutcome::Updated),
        false => Ok(UpdateOutcome::NotModified),
    }
}

struct LiveTarget {
    config: Arc<Snapshot<CompiledConfig>>,
    metrics: Arc<Metrics>,
    disable_protection: bool,
}

/// The update path that keeps the compiled configuration: validating the
/// candidate already compiled it, so the caller can install that snapshot
/// instead of re-reading and recompiling the same files.
async fn update_candidate(
    main_config: &Path,
    settings: &RulesUpdate,
    rules_file: &Path,
    state_file: &Path,
    live: Option<LiveTarget>,
) -> Result<bool, Error> {
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
        return Ok(false);
    };

    let expected = fetch_checksum(&client, checksum_url).await?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(Error::Message(format!(
            "rules checksum mismatch: expected {expected}, got {actual}"
        )));
    }
    verify_rules_signature(&client, url, &bytes).await?;

    let main_config = main_config.to_path_buf();
    let rules_file = rules_file.to_path_buf();
    let state_file = state_file.to_path_buf();
    let settings = settings.clone();

    tokio::task::spawn_blocking(move || -> Result<(), Error> {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Message("rules file is not valid UTF-8".to_owned()))?;
        // A construct this build does not implement means the published set is newer
        // than the running binary: that needs an upgrade, which is a different
        // remedy than a transient failure, so it gets its own error variant.
        let parsed =
            config::parse_rules(text).map_err(|err| match err.unsupported_construct() {
                Some(construct) => Error::RulesNeedNewerBuild(construct),
                None => err,
            })?;
        if !parsed.disabled_rules.is_empty() {
            return Err(Error::Message(
                "rules file must not contain `disabled_rules`; put them in overrides_file"
                    .to_owned(),
            ));
        }

        let _serialized = watcher::lock_reload();
        let main_abs = std::path::absolute(&main_config).unwrap_or_else(|_| main_config.clone());
        let main_stamp = watcher::file_stamp(&main_abs);
        let candidate = config::load_with_rules_candidate(&main_config, text)?;
        match &candidate.rules_file {
            Some(installed) if same_path(installed, &rules_file) => {}
            _ => {
                return Err(Error::Message(format!(
                    "`{}` does not point `rules_file` at `{}`",
                    main_config.display(),
                    rules_file.display()
                )));
            }
        }
        let overrides_stamp = candidate
            .overrides_file
            .as_ref()
            .map(|path| std::path::absolute(path).unwrap_or_else(|_| path.clone()))
            .map(|path| (path.clone(), watcher::file_stamp(&path)));

        write_atomic(&rules_file, &bytes)?;
        let now = unix_now();
        let next = UpdateState {
            last_success: Some(now),
            next_due: Some(
                now.saturating_add(jittered(settings.interval, settings.jitter_percent).as_secs()),
            ),
            etag,
            last_modified,
        };
        write_state(&next, &state_file);

        if let Some(live) = live {
            let mut stamps = std::collections::BTreeMap::new();
            stamps.insert(main_abs, main_stamp);
            let rules_abs = std::path::absolute(&rules_file).unwrap_or_else(|_| rules_file.clone());
            stamps.insert(rules_abs, watcher::file_stamp(&rules_file));
            if let Some((overrides_path, stamp)) = overrides_stamp {
                stamps.insert(overrides_path, stamp);
            }
            watcher::apply_with_stamps(
                &main_config,
                candidate,
                &live.config,
                &live.metrics,
                live.disable_protection,
                stamps,
            );
        }
        Ok(())
    })
    .await
    .map_err(|err| Error::Message(format!("rules update worker failed: {err}")))??;
    Ok(true)
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

/// Verify the detached minisign signature published next to the rule set.
/// With no trusted key configured this is skipped with a warning so existing
/// installs keep updating until keys are embedded.
async fn verify_rules_signature(
    client: &RulesClient,
    rules_url: &Uri,
    bytes: &[u8],
) -> Result<(), Error> {
    if crate::trust::RULES_KEYS.is_empty() {
        warn_once_no_rules_key();
        return Ok(());
    }
    // Loopback HTTP is the documented development/local-mirror path (plain
    // HTTP is rejected for any other host). Requiring a signature there would
    // make the local test setup impossible, so it is skipped with a warning.
    if rules_url.scheme_str() == Some("http") {
        warn_once_http_rules_url();
        return Ok(());
    }
    let signature_url = signature_url(rules_url)?;
    let fetched = fetch(
        client,
        &signature_url,
        MAX_SIGNATURE_BYTES,
        &UpdateState::default(),
        "rules signature",
    )
    .await?;
    let Fetched::Body {
        bytes: signature, ..
    } = fetched
    else {
        return Err(Error::Message(
            "rules signature request was unexpectedly not modified".to_owned(),
        ));
    };
    check_rules_signature(crate::trust::RULES_KEYS, bytes, &signature)
}

/// Verify the downloaded signature against the embedded rules keys.
fn check_rules_signature(keys: &[&str], bytes: &[u8], signature: &[u8]) -> Result<(), Error> {
    let signature = std::str::from_utf8(signature)
        .map_err(|_| Error::Message("rules signature is not valid UTF-8".to_owned()))?;
    match crate::trust::verify(keys, bytes, signature)
        .map_err(|err| Error::Signature(err.to_string()))?
    {
        crate::trust::Verification::Verified | crate::trust::Verification::NoTrustedKeys => Ok(()),
    }
}

fn warn_once_http_rules_url() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        warn!(
            "rules update URL uses plain HTTP; detached signature verification is skipped for this development path"
        );
    });
}

fn warn_once_no_rules_key() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        warn!(
            "no rules signing key is embedded in this build; rules are verified by checksum only"
        );
    });
}

/// The detached signature is published next to the rule set as
/// `<rules url>.minisig`.
fn signature_url(rules_url: &Uri) -> Result<Uri, Error> {
    let text = rules_url.to_string();
    if text.contains('?') || text.contains('#') {
        return Err(Error::Message(
            "rules update URL must not carry a query or fragment to locate its signature"
                .to_owned(),
        ));
    }
    format!("{text}.minisig")
        .parse()
        .map_err(|_| Error::Message("invalid rules signature URL".to_owned()))
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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules.yaml".to_owned());
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        random_suffix()
    ));
    let (owner, mode) = target_attributes(path, parent);
    // Flush to stable storage before the rename commit and sync the directory
    // afterwards: a crash in between must not leave an empty or truncated
    // rules file behind on the next restart.
    let result = (|| -> std::io::Result<()> {
        // A rename replaces the inode, so the new file inherits the owner and
        // mode of the file it replaces (or a readable default). Otherwise a
        // root `update-rules` run would leave a root-owned 0600 file that the
        // service user can no longer read.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        if let Some((uid, gid)) = owner
            && let Err(err) = set_owner(&temporary, uid, gid)
        {
            warn!(error = %err, path = %temporary.display(), "failed to keep the rule file owner");
        }
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

/// Owner and mode the replaced file should keep: the existing file's, or the
/// state directory's with a readable default for a fresh install.
fn target_attributes(path: &Path, parent: &Path) -> (Option<(u32, u32)>, u32) {
    use std::os::unix::fs::MetadataExt;

    let parent_owner = std::fs::metadata(parent)
        .ok()
        .map(|metadata| (metadata.uid(), metadata.gid()));
    if let Ok(metadata) = std::fs::metadata(path) {
        let file_owner = (metadata.uid(), metadata.gid());
        // If `kunato init` wrote a root-owned stub inside a state directory
        // owned by the service user, hand the replaced file to the directory's
        // owner so the service can read and update it.
        let owner = match parent_owner {
            Some(dir_owner) if file_owner.0 == 0 && dir_owner.0 != 0 => Some(dir_owner),
            _ => Some(file_owner),
        };
        return (owner, metadata.mode() & 0o777);
    }
    (parent_owner, 0o640)
}

fn set_owner(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains a NUL byte"))?;
    // SAFETY: `path` is a valid NUL-terminated string and the ids are plain
    // integers; the call does not retain the pointer.
    let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// An unpredictable suffix so a temporary file cannot be pre-created or
/// guessed by another local user.
fn random_suffix() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 4];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return std::process::id().to_string();
    }
    let mut suffix = String::with_capacity(8);
    for byte in bytes {
        let _ = write!(suffix, "{byte:02x}");
    }
    suffix
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
    let delay = if let Some(next_due) = state.next_due {
        Duration::from_secs(next_due).checked_sub(Duration::from_secs(unix_now()))
    } else {
        let last_success = state.last_success?;
        Duration::from_secs(last_success)
            .saturating_add(settings.interval)
            .checked_sub(Duration::from_secs(unix_now()))
    };
    // `next_due` has second granularity, so it equals `now` for up to a second
    // after it is written; sleeping at least a second avoids a busy loop
    // without re-checking the remote immediately.
    delay.map(|delay| delay.max(Duration::from_secs(1)))
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

    #[test]
    fn the_signature_url_is_the_rules_url_plus_minisig() {
        let url: Uri = "https://example.com/dist/rules.yaml"
            .parse()
            .expect("valid url");
        assert_eq!(
            signature_url(&url).expect("signature url").to_string(),
            "https://example.com/dist/rules.yaml.minisig"
        );
        let url: Uri = "https://example.com/rules.yaml?token=1"
            .parse()
            .expect("valid url");
        assert!(signature_url(&url).is_err(), "query strings are ambiguous");
    }

    #[test]
    fn a_signature_is_checked_only_when_a_key_is_configured() {
        assert!(check_rules_signature(&[], b"rules", b"not a signature").is_ok());
        let error = check_rules_signature(&["not a key"], b"rules", b"not a signature")
            .expect_err("configured key must enforce the check");
        assert!(matches!(error, Error::Signature(_)), "{error:?}");
    }

    #[test]
    fn a_due_timer_never_returns_a_zero_delay() {
        use crate::config::RulesUpdate;

        let settings = RulesUpdate::default();
        let now = unix_now();
        let state = UpdateState {
            next_due: Some(now + 1),
            ..UpdateState::default()
        };
        assert_eq!(
            delay_until_due(&state, &settings),
            Some(Duration::from_secs(1)),
            "a timer that just came due must not spin"
        );

        let state = UpdateState {
            next_due: Some(now + 60),
            ..UpdateState::default()
        };
        let delay = delay_until_due(&state, &settings).expect("future delay");
        assert!(
            (58..=60).contains(&delay.as_secs()),
            "unexpected delay: {delay:?}"
        );
    }

    #[test]
    fn write_atomic_keeps_the_replaced_files_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("set mode");

        write_atomic(&path, b"new").expect("atomic write");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the reader must keep access after the swap");
    }
}
