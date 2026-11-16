//! Console process runtime: collection, health publication, and shutdown.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config;
use crate::config::Console;
use crate::console::collector::{Collector, CollectorConfig, CollectorHealth, HttpSource};
use crate::console::server::ConsoleServer;
use crate::console::{StorageConfig, WriterConfig};
use crate::error::Error;
use crate::observations::StatisticsSnapshot;

/// The latest state published to browsers.
#[derive(Clone, Debug)]
pub struct LiveState {
    pub snapshot: Option<StatisticsSnapshot>,
    pub health: CollectorHealth,
}

/// A running console service.
pub struct ConsoleRuntime {
    pub address: SocketAddr,
    shutdown: watch::Sender<bool>,
    server: Option<tokio::task::JoinHandle<()>>,
    collector: Option<tokio::task::JoinHandle<()>>,
}

impl ConsoleRuntime {
    pub async fn start(console: Console) -> Result<Self, Error> {
        if !console.enabled {
            return Err(Error::Message(
                "console.enabled is false; nothing to start".to_owned(),
            ));
        }
        let mut storage = StorageConfig::new(console.storage_dir.clone());
        storage.max_bytes = console.max_bytes;
        storage.event_retention = console.event_retention;
        let collector_config = CollectorConfig {
            instance: console.instance.clone(),
            ..CollectorConfig::default()
        };
        let sample_interval = collector_config.sample_interval;
        let collector =
            Collector::start(storage, WriterConfig::default(), collector_config).await?;
        let reader = collector.history_reader();
        let source = HttpSource::new(console.source)?;

        let (live_tx, live_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = match ConsoleServer::bind(&console, live_rx, reader, shutdown_rx.clone()).await
        {
            Ok(server) => server,
            Err(error) => {
                let _ = collector.shutdown(Duration::from_secs(2)).await;
                return Err(error);
            }
        };
        let address = server.local_addr()?;
        let server_task = tokio::spawn(server.run(shutdown_rx.clone()));
        let collector_task = tokio::spawn(run_collection(
            collector,
            source,
            live_tx,
            shutdown_rx,
            sample_interval,
        ));
        Ok(Self {
            address,
            shutdown: shutdown_tx,
            server: Some(server_task),
            collector: Some(collector_task),
        })
    }

    pub async fn shutdown(mut self) -> Result<(), Error> {
        if !*self.shutdown.borrow() {
            let _ = self.shutdown.send(true);
        }
        if let Some(server) = self.server.take()
            && let Err(error) = server.await
        {
            warn!(error = %error, "console server task failed");
        }
        if let Some(collector) = self.collector.take()
            && let Err(error) = collector.await
        {
            warn!(error = %error, "console collector task failed");
        }
        Ok(())
    }
}

impl Drop for ConsoleRuntime {
    fn drop(&mut self) {
        if !*self.shutdown.borrow() {
            let _ = self.shutdown.send(true);
        }
    }
}

async fn run_collection(
    mut collector: Collector,
    source: HttpSource,
    live: watch::Sender<Option<Arc<LiveState>>>,
    mut shutdown: watch::Receiver<bool>,
    sample_interval: Duration,
) {
    let mut interval = tokio::time::interval(sample_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut snapshot: Option<StatisticsSnapshot> = None;
    publish(&live, &collector, snapshot.as_ref());

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            _ = interval.tick() => {
                let fetched = tokio::select! {
                    _ = shutdown.changed() => break,
                    result = source.fetch() => result,
                };
                match fetched {
                    Ok(packet) => {
                        snapshot = Some(packet.clone());
                        if let Err(error) = collector.receive(packet).await {
                            collector.source_failed(error);
                        }
                    }
                    Err(error) => collector.source_failed(error),
                }
                collector.tick(false);
                publish(&live, &collector, snapshot.as_ref());
            }
        }
    }

    match collector.shutdown(Duration::from_secs(5)).await {
        Ok(report) if report.timed_out => {
            warn!("console final flush timed out; some pending observations may be lost");
        }
        Ok(_) => info!("console collection stopped"),
        Err(error) => warn!(error = %error, "console final flush failed"),
    }
}

fn publish(
    live: &watch::Sender<Option<Arc<LiveState>>>,
    collector: &Collector,
    snapshot: Option<&StatisticsSnapshot>,
) {
    live.send_replace(Some(Arc::new(LiveState {
        snapshot: snapshot.cloned(),
        health: collector.health(),
    })));
}

/// Run the console until SIGINT or SIGTERM.
pub async fn run(config_path: &Path) -> Result<(), Error> {
    let loaded = config::load_settings(config_path)?;
    let console = loaded.console.clone();
    if !console.enabled {
        return Err(Error::Message(format!(
            "`{}` does not set `console.enabled: true`",
            config_path.display()
        )));
    }
    let runtime = ConsoleRuntime::start(console).await?;
    info!(
        addr = %runtime.address,
        config = %config_path.display(),
        "console started"
    );
    wait_for_signal().await?;
    info!("console shutdown signal received");
    runtime.shutdown().await
}

async fn wait_for_signal() -> Result<(), Error> {
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }
    Ok(())
}
