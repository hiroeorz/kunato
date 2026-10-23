use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::{self, CompiledConfig};
use crate::metrics::Metrics;

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

pub async fn watch(
    path: PathBuf,
    config: Arc<ArcSwap<CompiledConfig>>,
    metrics: Arc<Metrics>,
    disable_protection: bool,
    mut shutdown: watch::Receiver<bool>,
) {
    let main = absolute(&path);
    let initial = source_paths(&main, &config.load());
    let mut stamps = source_stamps(&initial);
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
                if current.keys().ne(stamps.keys()) {
                    stamps = current;
                    false
                } else {
                    current != stamps
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
            stamps = source_stamps(&source_paths(&main, &config.load()));
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

pub fn reload(
    path: &Path,
    config: &ArcSwap<CompiledConfig>,
    metrics: &Metrics,
    disable_protection: bool,
) -> Option<Vec<PathBuf>> {
    match config::load(path) {
        Ok(mut new_config) => {
            metrics.reload_success.fetch_add(1, Ordering::Relaxed);
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
                warn!(
                    "TLS settings changes require a restart; keeping the active TLS configuration"
                );
                new_config.tls = active_tls;
            }
            if new_config.http3 != active_http3 {
                warn!(
                    "HTTP/3 settings changes require a restart; keeping the active HTTP/3 configuration"
                );
                new_config.http3 = active_http3;
            }
            if new_config.admin != active_admin {
                warn!(
                    "admin settings changes require a restart; keeping the active admin listener"
                );
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
            config.store(Arc::new(new_config));
            if let Some(warning) = body_inspection_warning {
                warn!("{warning}");
            }
            if let Some(warning) = allowed_hosts_warning {
                warn!("{warning}");
            }
            info!(categories, rules, "configuration reloaded");
            Some(sources)
        }
        Err(err) => {
            metrics.reload_failure.fetch_add(1, Ordering::Relaxed);
            error!(error = %err, "configuration reload failed; keeping previous configuration");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).expect("write config");
    }

    #[test]
    fn reload_swaps_to_new_configuration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write(
            &path,
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n",
        );
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = Arc::new(ArcSwap::from_pointee(
            config::load(&path).expect("initial config"),
        ));
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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));
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
        let config = ArcSwap::from_pointee(config::load(&path).expect("config"));
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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));
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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&path).expect("initial config"));

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
        let config = ArcSwap::from_pointee(config::load(&main).expect("initial config"));
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
        let config = ArcSwap::from_pointee(config::load(&main).expect("initial config"));

        std::fs::remove_file(&rules).expect("remove rules file");
        assert!(reload(&main, &config, &Metrics::new(), false).is_none());

        assert_eq!(config.load().categories.len(), 1);
    }
}
