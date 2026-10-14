use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, trace, warn};

use crate::config::{self, CompiledConfig};
use crate::metrics::Metrics;

const DEBOUNCE: Duration = Duration::from_millis(250);

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
    let watched: Arc<Mutex<BTreeSet<PathBuf>>> =
        Arc::new(Mutex::new(initial.iter().cloned().collect()));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let filter = watched.clone();

    let mut watcher =
        match notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) if is_relevant(&event, &filter) => {
                let _ = event_tx.send(event);
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "filesystem watch error"),
        }) {
            Ok(watcher) => watcher,
            Err(err) => {
                error!(error = %err, "failed to create file watcher; hot reload disabled");
                return;
            }
        };

    let mut state = WatchState::default();
    for source in &initial {
        state.add(&mut watcher, source);
    }

    info!(
        paths = ?initial,
        "watching configuration for changes"
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            event = event_rx.recv() => {
                match event {
                    None => break,
                    Some(event) => {
                        trace!(kind = ?event.kind, paths = ?event.paths, "configuration source changed");
                        debounce(&mut event_rx).await;
                        if let Some(sources) = reload(&main, &config, &metrics, disable_protection) {
                            state.sync(&mut watcher, &watched, &sources);
                        }
                    }
                }
            }
        }
    }
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
            let (active_listen, active_tls, active_http3) = {
                let current = config.load();
                (current.listen, current.tls.clone(), current.http3)
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

            let sources = source_paths(path, &new_config);
            let categories = new_config.categories.len();
            let rules: usize = new_config
                .categories
                .iter()
                .map(|category| category.rules.len())
                .sum();
            config.store(Arc::new(new_config));
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

#[derive(Debug, Default)]
struct WatchState {
    files: BTreeSet<PathBuf>,
    parents: BTreeMap<PathBuf, usize>,
}

impl WatchState {
    fn add(&mut self, watcher: &mut impl Watcher, path: &Path) {
        if !self.files.insert(path.to_path_buf()) {
            return;
        }
        if let Err(err) = watcher.watch(path, RecursiveMode::NonRecursive) {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to watch configuration file"
            );
        }
        if let Some(parent) = path.parent() {
            let count = self.parents.entry(parent.to_path_buf()).or_insert(0);
            if *count == 0
                && let Err(err) = watcher.watch(parent, RecursiveMode::NonRecursive)
            {
                warn!(
                    path = %parent.display(),
                    error = %err,
                    "failed to watch configuration directory; rename-based updates may be missed"
                );
            }
            *count += 1;
        }
    }

    fn remove(&mut self, watcher: &mut impl Watcher, path: &Path) {
        if !self.files.remove(path) {
            return;
        }
        let _ = watcher.unwatch(path);
        if let Some(parent) = path.parent()
            && let Some(count) = self.parents.get_mut(parent)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.parents.remove(parent);
                let _ = watcher.unwatch(parent);
            }
        }
    }

    fn sync(
        &mut self,
        watcher: &mut impl Watcher,
        watched: &Mutex<BTreeSet<PathBuf>>,
        sources: &[PathBuf],
    ) {
        let desired: BTreeSet<PathBuf> = sources.iter().cloned().collect();
        let stale: Vec<PathBuf> = self
            .files
            .iter()
            .filter(|path| !desired.contains(*path))
            .cloned()
            .collect();
        for path in stale {
            self.remove(watcher, &path);
        }
        for path in &desired {
            self.add(watcher, path);
        }
        *lock(watched) = desired;
    }
}

fn lock(set: &Mutex<BTreeSet<PathBuf>>) -> std::sync::MutexGuard<'_, BTreeSet<PathBuf>> {
    set.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_relevant(event: &Event, watched: &Mutex<BTreeSet<PathBuf>>) -> bool {
    let relevant_kind = matches!(
        event.kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    relevant_kind && event.paths.iter().any(|path| lock(watched).contains(path))
}

async fn debounce(rx: &mut mpsc::UnboundedReceiver<Event>) {
    let deadline = tokio::time::Instant::now() + DEBOUNCE;
    while let Ok(Some(_)) = tokio::time::timeout_at(deadline, rx.recv()).await {}
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
        assert_eq!(tls.cert_file, PathBuf::from("old-cert.pem"));
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
