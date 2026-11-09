use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::{self, CompiledConfig};
use crate::metrics::Metrics;
use crate::snapshot::Snapshot;

#[cfg(not(test))]
const POLL_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// All files that make up the active configuration: the main file, the managed
/// rules file, and the optional overrides file.
pub fn source_paths(main: &Path, config: &CompiledConfig) -> Vec<PathBuf> {
    let mut paths = vec![absolute(main)];
    if let Some(path) = &config.rules_file {
        paths.push(absolute(path));
    }
    if let Some(path) = &config.overrides_file {
        paths.push(absolute(path));
    }
    paths
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

type Stamp = Option<(SystemTime, u64)>;
type Stamps = BTreeMap<PathBuf, Stamp>;

/// Stamps of the sources that produced the active snapshot. Shared so a reload
/// triggered by the rules updater (or SIGHUP) also tells the file watcher that
/// it already applied the change; otherwise the watcher would compile the very
/// same files again on its next tick.
static APPLIED_STAMPS: std::sync::Mutex<Option<Stamps>> = std::sync::Mutex::new(None);

fn record_stamps_map(stamps: Stamps) {
    let mut applied = APPLIED_STAMPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *applied = Some(stamps);
}

fn record_stamps(sources: &[PathBuf]) {
    record_stamps_map(source_stamps(sources));
}

pub(crate) fn lock_reload() -> std::sync::MutexGuard<'static, ()> {
    RELOAD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn file_stamp(path: &Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| Some((metadata.modified().ok()?, metadata.len())))
}

fn applied_stamps() -> Option<Stamps> {
    APPLIED_STAMPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(test)]
fn reset_applied_stamps() {
    *APPLIED_STAMPS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

pub async fn watch(
    path: PathBuf,
    config: Arc<Snapshot<CompiledConfig>>,
    metrics: Arc<Metrics>,
    disable_protection: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    let main = absolute(&path);
    let initial = source_paths(&main, &config.load());
    // Seed the shared stamps with what the active snapshot was built from so
    // the first tick does not look like a change.
    if applied_stamps().is_none() {
        record_stamps(&initial);
    }
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(
        paths = ?initial,
        "watching configuration for changes"
    );

    loop {
        if *shutdown.borrow() {
            break;
        }
        let changed = tokio::select! {
            _ = shutdown.changed() => break,
            _ = poll.tick() => {
                let sources = source_paths(&main, &config.load());
                let current = source_stamps(&sources);
                match applied_stamps() {
                    Some(applied) => current != applied,
                    None => true,
                }
            }
        };
        if changed {
            let path = main.clone();
            let reload_config = Arc::clone(&config);
            let metrics = Arc::clone(&metrics);
            if let Err(err) = tokio::task::spawn_blocking(move || {
                reload(&path, &reload_config, &metrics, disable_protection)
            })
            .await
            {
                error!(error = %err, "configuration reload task failed");
            }
            // The reload records the applied stamps itself; a failed reload
            // leaves them unchanged so the next tick retries.
        }
    }
}

fn source_stamps(paths: &[PathBuf]) -> BTreeMap<PathBuf, Option<(SystemTime, u64)>> {
    paths
        .iter()
        .map(|path| {
            let stamp = std::fs::metadata(path)
                .ok()
                .and_then(|metadata| Some((metadata.modified().ok()?, metadata.len())));
            (path.clone(), stamp)
        })
        .collect()
}

/// Serializes reloads. The file watcher, SIGHUP handling, and the rules
/// updater can all reload at once; without this, a snapshot built before the
/// winner's write could be stored last and leave stale rules active.
static RELOAD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn reload(
    path: &Path,
    config: &Snapshot<CompiledConfig>,
    metrics: &Metrics,
    disable_protection: bool,
) -> Option<Vec<PathBuf>> {
    let _serialized = lock_reload();
    let main_abs = absolute(path);
    let main_stamp = file_stamp(&main_abs);
    let prior_overrides = config
        .load()
        .overrides_file
        .as_ref()
        .map(|file| absolute(file));
    let prior_overrides_stamp = prior_overrides.as_deref().map(file_stamp);
    let prior_rules = config.load().rules_file.as_ref().map(|file| absolute(file));
    let prior_rules_stamp = prior_rules.as_deref().map(file_stamp);
    match config::load(path) {
        Ok(new_config) => {
            metrics.reload_success.fetch_add(1, Ordering::Relaxed);
            let sources = source_paths(path, &new_config);
            let mut stamps = source_stamps(&sources);
            stamps.insert(main_abs, main_stamp);
            if let (Some(overrides), Some(stamp)) = (prior_overrides, prior_overrides_stamp)
                && stamps.contains_key(&overrides)
            {
                stamps.insert(overrides, stamp);
            }
            if let (Some(rules), Some(stamp)) = (prior_rules, prior_rules_stamp)
                && stamps.contains_key(&rules)
            {
                stamps.insert(rules, stamp);
            }
            Some(install_with_stamps(
                path,
                new_config,
                config,
                disable_protection,
                Some(stamps),
            ))
        }
        Err(err) => {
            metrics.reload_failure.fetch_add(1, Ordering::Relaxed);
            error!(error = %err, "configuration reload failed; keeping previous configuration");
            None
        }
    }
}

/// Install a configuration that was already parsed and compiled — the rules
/// updater validates the candidate before writing it, so re-reading and
/// recompiling the same files here would repeat that work.
pub fn apply(
    path: &Path,
    new_config: CompiledConfig,
    config: &Snapshot<CompiledConfig>,
    metrics: &Metrics,
    disable_protection: bool,
) -> Option<Vec<PathBuf>> {
    let _serialized = lock_reload();
    metrics.reload_success.fetch_add(1, Ordering::Relaxed);
    Some(install_with_stamps(
        path,
        new_config,
        config,
        disable_protection,
        None,
    ))
}

pub(crate) fn apply_with_stamps(
    path: &Path,
    new_config: CompiledConfig,
    config: &Snapshot<CompiledConfig>,
    metrics: &Metrics,
    disable_protection: bool,
    stamps: Stamps,
) -> Option<Vec<PathBuf>> {
    metrics.reload_success.fetch_add(1, Ordering::Relaxed);
    Some(install_with_stamps(
        path,
        new_config,
        config,
        disable_protection,
        Some(stamps),
    ))
}

fn install_with_stamps(
    path: &Path,
    mut new_config: CompiledConfig,
    config: &Snapshot<CompiledConfig>,
    disable_protection: bool,
    stamps: Option<Stamps>,
) -> Vec<PathBuf> {
    if disable_protection {
        new_config.protection.enabled = false;
    }
    let (active_listen, active_tls, active_http3, active_admin) = {
        let current = config.load();
        (
            current.listen,
            current.tls.clone(),
            current.http3,
            current.admin.clone(),
        )
    };
    if new_config.listen != active_listen {
        warn!(
            configured = %new_config.listen,
            active = %active_listen,
            "listen address changes require a restart; keeping the active listener"
        );
        new_config.listen = active_listen;
    }
    if new_config.tls != active_tls {
        warn!("TLS settings changes require a restart; keeping the active TLS configuration");
        new_config.tls = active_tls;
    }
    if new_config.http3 != active_http3 {
        warn!("HTTP/3 settings changes require a restart; keeping the active HTTP/3 configuration");
        new_config.http3 = active_http3;
    }
    if new_config.admin != active_admin {
        warn!("admin settings changes require a restart; keeping the active admin listener");
        new_config.admin = active_admin;
    }

    let sources = source_paths(path, &new_config);
    let categories = new_config.categories.len();
    let rules: usize = new_config
        .categories
        .iter()
        .map(|category| category.rules.len())
        .sum();
    let body_inspection_warning = new_config.body_inspection_warning();
    let allowed_hosts_warning = new_config.allowed_hosts_warning();
    let admin_access_warning = new_config.admin_access_warning();
    config.store(Arc::new(new_config));
    // The snapshot is live: remember the stamps of the sources that were read
    // to build it so the watcher does not compile the same files again, while
    // any concurrent edit made during compilation still triggers a reload.
    match stamps {
        Some(stamps) => record_stamps_map(stamps),
        None => record_stamps(&sources),
    }
    if let Some(warning) = body_inspection_warning {
        warn!("{warning}");
    }
    if let Some(warning) = allowed_hosts_warning {
        warn!("{warning}");
    }
    if let Some(warning) = admin_access_warning {
        warn!("{warning}");
    }
    info!(categories, rules, "configuration reloaded");
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).expect("write config");
    }

    #[test]
    fn a_reload_records_the_stamps_it_applied() {
        reset_applied_stamps();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kunato.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));
        let sources = reload(&path, &config, &Metrics::new(), false).expect("reload");
        assert_eq!(
            applied_stamps(),
            Some(source_stamps(&sources)),
            "the watcher must see the applied files as current"
        );
        reset_applied_stamps();
    }

    #[test]
    fn applying_a_compiled_configuration_records_its_stamps() {
        reset_applied_stamps();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kunato.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));
        let compiled = config::parse("listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n")
            .expect("compiled config");
        apply(&path, compiled, &config, &Metrics::new(), false).expect("apply");
        assert_eq!(
            applied_stamps(),
            Some(source_stamps(&source_paths(&path, &config.load()))),
            "an updater-driven apply must not be reloaded again by the watcher"
        );
        reset_applied_stamps();
    }

    #[test]
    fn reload_swaps_to_new_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:9090\nupstream: http://127.0.0.1:4000\nlimits: { max_body_bytes: 42 }\n",
        );
        reload(&path, &config, &Metrics::new(), false);

        let current = config.load();
        assert_eq!(current.limits.max_body_bytes, 42);
        assert_eq!(current.listen.port(), 8080);
    }

    #[tokio::test]
    async fn watch_reloads_after_a_polled_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Arc::new(Snapshot::new(config::load(&path).expect("initial config")));
        let (shutdown, shutdown_rx) = watch::channel(false);
        let watcher = tokio::spawn(watch(
            path.clone(),
            Arc::clone(&config),
            Arc::new(Metrics::new()),
            false,
            shutdown_rx,
        ));

        tokio::time::sleep(POLL_INTERVAL * 5).await;
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nlimits: { max_body_bytes: 42 }\n",
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            while config.load().limits.max_body_bytes != 42 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("polled reload");

        let _ = shutdown.send(true);
        watcher.await.expect("watcher task");
    }

    #[test]
    fn reload_updates_graphql_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nlimits: { graphql: { max_depth: 7, max_fields: 80 } }\n",
        );
        reload(&path, &config, &Metrics::new(), false);

        let current = config.load();
        assert_eq!(current.limits.graphql.max_depth, 7);
        assert_eq!(current.limits.graphql.max_fields, 80);
    }

    #[test]
    fn reload_keeps_the_previous_allowed_hosts_on_an_invalid_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nallowed_hosts: [example.com]\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));
        assert!(
            config
                .load()
                .allowed_hosts
                .as_ref()
                .expect("allowed hosts")
                .matches("example.com")
        );

        for invalid in ["allowed_hosts: []\n", "allowed_hosts:\n"] {
            write(
                &path,
                &format!("listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n{invalid}"),
            );
            assert!(reload(&path, &config, &Metrics::new(), false).is_none());
            assert!(
                config
                    .load()
                    .allowed_hosts
                    .as_ref()
                    .expect("previous allowed hosts")
                    .matches("example.com")
            );
        }

        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        assert!(reload(&path, &config, &Metrics::new(), false).is_some());
        assert!(config.load().allowed_hosts.is_none());
    }

    #[test]
    fn client_ip_reload_applies_valid_changes_and_keeps_previous_trust_on_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        let base = "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n";
        write(&path, base);
        let config = Snapshot::new(config::load(&path).expect("config"));
        let peer = "127.0.0.1:443".parse().expect("peer");
        let headers = http::HeaderMap::new();
        assert!(config.load().client_ip.resolve(peer, &headers).is_ok());
        write(
            &path,
            &format!("{base}client_ip: {{ trusted_proxies: [127.0.0.1] }}\n"),
        );
        assert!(reload(&path, &config, &Metrics::new(), false).is_some());
        assert!(config.load().client_ip.resolve(peer, &headers).is_err());
        write(
            &path,
            &format!("{base}client_ip: {{ trusted_proxies: [] }}\n"),
        );
        assert!(reload(&path, &config, &Metrics::new(), false).is_none());
        assert!(config.load().client_ip.resolve(peer, &headers).is_err());
        write(&path, base);
        assert!(reload(&path, &config, &Metrics::new(), false).is_some());
        assert!(config.load().client_ip.resolve(peer, &headers).is_ok());
    }

    #[test]
    fn reload_keeps_previous_configuration_on_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nlimits: { max_body_bytes: 42 }\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(&path, "this is not: [valid\n");
        reload(&path, &config, &Metrics::new(), false);

        assert_eq!(config.load().limits.max_body_bytes, 42);
    }

    #[test]
    fn reload_recovers_after_a_rejected_duration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nlimits: { max_body_bytes: 42 }\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\ntimeouts: { header_read: 18446744073709551615h }\n",
        );
        assert!(reload(&path, &config, &Metrics::new(), false).is_none());
        assert_eq!(config.load().limits.max_body_bytes, 42);

        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nlimits: { max_body_bytes: 7 }\n",
        );
        assert!(reload(&path, &config, &Metrics::new(), false).is_some());
        assert_eq!(config.load().limits.max_body_bytes, 7);
    }

    #[test]
    fn reload_applies_disable_protection_override() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));
        assert!(config.load().protection.enabled);

        reload(&path, &config, &Metrics::new(), true);

        assert!(!config.load().protection.enabled);
    }

    #[test]
    fn reload_keeps_active_tls_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
tls: { cert_file: old-cert.pem, key_file: old-key.pem }
",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
tls: { cert_file: new-cert.pem, key_file: new-key.pem }
",
        );
        reload(&path, &config, &Metrics::new(), false);

        let tls = config.load().tls.clone().expect("tls block");
        assert_eq!(tls.cert_file.as_deref(), Some(Path::new("old-cert.pem")));
    }

    #[test]
    fn reload_keeps_active_http3_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
tls: { cert_file: cert.pem, key_file: key.pem }
http3: { enabled: true, listen: 127.0.0.1:443 }
",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
tls: { cert_file: cert.pem, key_file: key.pem }
http3: { enabled: false }
",
        );
        reload(&path, &config, &Metrics::new(), false);

        let http3 = config.load().http3;
        assert!(http3.enabled);
        assert_eq!(http3.listen.map(|addr| addr.port()), Some(443));
    }

    #[test]
    fn reload_keeps_active_admin_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: { enabled: true, listen: 127.0.0.1:9090 }
",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: { enabled: true, listen: 127.0.0.1:9999 }
",
        );
        reload(&path, &config, &Metrics::new(), false);

        assert_eq!(config.load().admin.listen.port(), 9090);
    }

    #[test]
    fn reload_keeps_active_listen_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = Snapshot::new(config::load(&path).expect("initial config"));

        write(
            &path,
            "listen: 127.0.0.1:9999\nupstream: http://127.0.0.1:3000\n",
        );
        reload(&path, &config, &Metrics::new(), false);

        assert_eq!(config.load().listen.port(), 8080);
    }

    #[test]
    fn reload_picks_up_rules_file_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rules = dir.path().join("rules.yaml");
        write(
            &rules,
            "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: catch-all
        match: { path: ^/ }
",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: rules.yaml
",
        );
        let config = Snapshot::new(config::load(&main).expect("initial config"));
        assert_eq!(config.load().categories.len(), 1);

        write(&rules, "categories: []\n");
        let sources = reload(&main, &config, &Metrics::new(), false).expect("reload");

        assert!(config.load().categories.is_empty());
        assert!(sources.iter().any(|path| path.ends_with("rules.yaml")));
    }

    #[test]
    fn reload_keeps_previous_configuration_when_rules_file_disappears() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rules = dir.path().join("rules.yaml");
        write(
            &rules,
            "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: catch-all
        match: { path: ^/ }
",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: rules.yaml
",
        );
        let config = Snapshot::new(config::load(&main).expect("initial config"));

        std::fs::remove_file(&rules).expect("remove rules file");
        assert!(reload(&main, &config, &Metrics::new(), false).is_none());

        assert_eq!(config.load().categories.len(), 1);
    }
}
