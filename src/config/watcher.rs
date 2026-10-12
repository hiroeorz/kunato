use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, trace, warn};

use crate::config::{self, CompiledConfig};
use crate::metrics::Metrics;

const DEBOUNCE: Duration = Duration::from_millis(250);

pub async fn watch(
    path: PathBuf,
    config: Arc<ArcSwap<CompiledConfig>>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let absolute = std::path::absolute(&path).unwrap_or_else(|_| path.clone());
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let filter_path = absolute.clone();

    let mut watcher =
        match notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) if is_relevant(&event, &filter_path) => {
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

    if let Err(err) = watcher.watch(&absolute, RecursiveMode::NonRecursive) {
        error!(
            path = %absolute.display(),
            error = %err,
            "failed to watch configuration file; hot reload disabled"
        );
        return;
    }

    if let Some(parent) = absolute.parent()
        && let Err(err) = watcher.watch(parent, RecursiveMode::NonRecursive)
    {
        warn!(
            path = %parent.display(),
            error = %err,
            "failed to watch configuration directory; rename-based updates may be missed"
        );
    }

    info!(path = %absolute.display(), "watching configuration for changes");

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            event = event_rx.recv() => {
                match event {
                    None => break,
                    Some(event) => {
                        trace!(kind = ?event.kind, paths = ?event.paths, "configuration file changed");
                        debounce(&mut event_rx).await;
                        reload(&absolute, &config, &metrics);
                    }
                }
            }
        }
    }
}

pub fn reload(path: &Path, config: &ArcSwap<CompiledConfig>, metrics: &Metrics) {
    match config::load(path) {
        Ok(mut new_config) => {
            metrics.reload_success.fetch_add(1, Ordering::Relaxed);
            let active_listen = config.load().listen;
            if new_config.listen != active_listen {
                warn!(
                    configured = %new_config.listen,
                    active = %active_listen,
                    "listen address changes require a restart; keeping the active listener"
                );
                new_config.listen = active_listen;
            }

            let categories = new_config.categories.len();
            let rules: usize = new_config
                .categories
                .iter()
                .map(|category| category.rules.len())
                .sum();
            config.store(Arc::new(new_config));
            info!(categories, rules, "configuration reloaded");
        }
        Err(err) => {
            metrics.reload_failure.fetch_add(1, Ordering::Relaxed);
            error!(error = %err, "configuration reload failed; keeping previous configuration");
        }
    }
}

fn is_relevant(event: &Event, path: &Path) -> bool {
    let relevant_kind = matches!(
        event.kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    relevant_kind && event.paths.iter().any(|event_path| event_path == path)
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
        reload(&path, &config, &Metrics::new());

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
        reload(&path, &config, &Metrics::new());

        assert_eq!(config.load().limits.max_body_bytes, 42);
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
        reload(&path, &config, &Metrics::new());

        assert_eq!(config.load().listen.port(), 8080);
    }
}
