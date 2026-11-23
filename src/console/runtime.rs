//! Console process runtime: collection, health publication, and shutdown.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config;
use crate::config::{Console, ConsoleEdr};
use crate::console::collector::{Collector, CollectorConfig, CollectorHealth, HttpSource};
use crate::console::edr::{self, EdrView, TaskState};
use crate::console::history::HOUR_MS;
use crate::console::model::MINUTE_MS;
use crate::console::server::ConsoleServer;
use crate::console::{StorageConfig, WriterConfig};
use crate::edr::live::{LiveConfig, LiveEdr};
use crate::edr::{Evidence, Report, Thresholds};
use crate::error::Error;
use crate::geoip::GeoIp;
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
    edr: Option<tokio::task::JoinHandle<()>>,
}

impl ConsoleRuntime {
    pub async fn start(console: Console, geoip: Arc<GeoIp>) -> Result<Self, Error> {
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
        let edr_snapshots = collector.subscribe();
        let edr_state_path = console.storage_dir.join("edr-state.json");
        let edr_config = console.edr;
        let source = HttpSource::new(console.source)?;

        let (live_tx, live_rx) = watch::channel(None);
        let (edr_tx, edr_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server =
            match ConsoleServer::bind(&console, live_rx, edr_rx, reader, shutdown_rx.clone()).await
            {
                Ok(server) => server,
                Err(error) => {
                    let _ = collector.shutdown(Duration::from_secs(2)).await;
                    return Err(error);
                }
            };
        let address = server.local_addr()?;
        let server_task = tokio::spawn(server.run(shutdown_rx.clone()));
        let edr_task = if edr_config.enabled {
            Some(tokio::spawn(run_edr(
                edr_snapshots,
                edr_config,
                edr_state_path,
                edr_tx,
                geoip,
                shutdown_rx.clone(),
            )))
        } else {
            None
        };
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
            edr: edr_task,
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
        if let Some(edr) = self.edr.take() {
            match tokio::time::timeout(Duration::from_secs(2), edr).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(error = %error, "console EDR task failed"),
                Err(_) => warn!("console EDR task did not stop before the shutdown deadline"),
            }
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

const EDR_SAVE_INTERVAL_MS: u64 = 5 * MINUTE_MS;
const EDR_RING: Duration = Duration::from_secs(12 * 60);
const MAX_LOGGED_FINDINGS: usize = 20;

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn next_hour_end(now: u64) -> u64 {
    (now / HOUR_MS + 1).saturating_mul(HOUR_MS)
}

async fn run_edr(
    mut snapshots: watch::Receiver<Option<Arc<StatisticsSnapshot>>>,
    config: ConsoleEdr,
    state_path: PathBuf,
    views: watch::Sender<Option<Arc<EdrView>>>,
    geoip: Arc<GeoIp>,
    mut shutdown: watch::Receiver<bool>,
) {
    let live_config = LiveConfig {
        window: config.window,
        baseline: config.baseline,
        poll_interval: Duration::from_secs(1),
        ring: EDR_RING,
        thresholds: Thresholds::default(),
    };
    let mut live = match LiveEdr::load(&state_path, live_config) {
        Ok(Some(state)) => {
            info!(
                state = %state_path.display(),
                minutes = state.retained_minutes(),
                hours = state.retained_hours(),
                "console EDR restored its state"
            );
            state
        }
        Ok(None) => match LiveEdr::new(live_config) {
            Ok(state) => state,
            Err(error) => {
                warn!(error = %error, "console EDR configuration is invalid");
                let _ = views.send(Some(Arc::new(edr::failed(config, &error.to_string()))));
                return;
            }
        },
        Err(error) => {
            warn!(
                error = %error,
                state = %state_path.display(),
                "console EDR state could not be restored; starting empty"
            );
            match LiveEdr::new(live_config) {
                Ok(state) => state,
                Err(error) => {
                    warn!(error = %error, "console EDR configuration is invalid");
                    let _ = views.send(Some(Arc::new(edr::failed(config, &error.to_string()))));
                    return;
                }
            }
        }
    };

    if let Some(packet) = snapshots.borrow_and_update().clone()
        && let Err(error) = live.ingest(&packet)
    {
        warn!(error = %error, "console EDR rejected the initial snapshot");
    }

    let now = wall_clock_ms();
    let mut next_end = next_hour_end(now);
    let mut next_report_at = next_end.saturating_add(edr::REPORT_DELAY_MS);
    let mut next_save_at = now.saturating_add(EDR_SAVE_INTERVAL_MS);
    let initial_state = if live.last_report().is_some() {
        TaskState::Running
    } else {
        TaskState::Starting
    };
    publish_edr(
        &views,
        &live,
        &config,
        &geoip,
        initial_state,
        None,
        Some(next_report_at),
    );
    let mut minute = tokio::time::interval(Duration::from_secs(60));
    minute.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!(
        window_secs = config.window.as_secs(),
        baseline_secs = config.baseline.as_secs(),
        state = %state_path.display(),
        "console EDR started"
    );

    loop {
        tokio::select! {
            changed = snapshots.changed() => {
                if changed.is_err() {
                    break;
                }
                let packet = snapshots.borrow_and_update().clone();
                if let Some(packet) = packet
                    && let Err(error) = live.ingest(&packet)
                {
                    warn!(error = %error, observed_at = packet.observed_at_ms, "console EDR rejected a snapshot");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            _ = minute.tick() => {
                let now = wall_clock_ms();
                // A delayed task must not replay already-trimmed windows.
                while now >= next_report_at.saturating_add(HOUR_MS) {
                    warn!(
                        missed_end = next_end,
                        "console EDR skipped a missed report window"
                    );
                    next_end = next_end.saturating_add(HOUR_MS);
                    next_report_at = next_report_at.saturating_add(HOUR_MS);
                }
                if now >= next_report_at {
                    let mut error_message = match live.report(next_end) {
                        Ok(report) => {
                            log_edr_report(&report);
                            live.record_report(report, wall_clock_ms());
                            None
                        }
                        Err(error) => {
                            warn!(error = %error, until = next_end, "console EDR report failed");
                            Some(error.to_string())
                        }
                    };
                    if let Err(error) = live.save(&state_path) {
                        warn!(error = %error, state = %state_path.display(), "console EDR state save failed");
                        error_message.get_or_insert_with(|| error.to_string());
                    }
                    next_end = next_end.saturating_add(HOUR_MS);
                    next_report_at = next_report_at.saturating_add(HOUR_MS);
                    publish_edr(
                        &views,
                        &live,
                        &config,
                        &geoip,
                        TaskState::Running,
                        error_message.as_deref(),
                        Some(next_report_at),
                    );
                }
                if now >= next_save_at {
                    if let Err(error) = live.save(&state_path) {
                        warn!(error = %error, state = %state_path.display(), "console EDR state save failed");
                    }
                    next_save_at = now.saturating_add(EDR_SAVE_INTERVAL_MS);
                }
            }
        }
    }

    if let Err(error) = live.save(&state_path) {
        warn!(error = %error, state = %state_path.display(), "console EDR final state save failed");
    }
    publish_edr(
        &views,
        &live,
        &config,
        &geoip,
        TaskState::Stopped,
        None,
        None,
    );
    info!("console EDR stopped");
}

fn publish_edr(
    views: &watch::Sender<Option<Arc<EdrView>>>,
    live: &LiveEdr,
    config: &ConsoleEdr,
    geoip: &GeoIp,
    state: TaskState,
    error: Option<&str>,
    next_evaluation_at_ms: Option<u64>,
) {
    let view = edr::build(edr::ViewInput {
        enabled: config.enabled,
        state,
        error,
        config: *config,
        live,
        geoip,
        next_evaluation_at_ms,
    });
    let _ = views.send(Some(Arc::new(view)));
}

fn log_edr_report(report: &Report) {
    info!(
        event = "edr.report",
        until = report.window.until_ms,
        findings = report.findings.len(),
        auth_failures = report.summary.auth_failures,
        telemetry = report.telemetry.as_str(),
        incomplete = report.summary.incomplete,
        baseline_hours = report.summary.baseline_hours,
        "EDR report"
    );
    for finding in report.findings.iter().take(MAX_LOGGED_FINDINGS) {
        log_edr_finding(finding);
    }
    if report.findings.len() > MAX_LOGGED_FINDINGS {
        warn!(
            findings = report.findings.len(),
            logged = MAX_LOGGED_FINDINGS,
            "console EDR finding log truncated"
        );
    }
    for note in &report.notes {
        debug!(event = "edr.note", note = %note);
    }
}

fn log_edr_finding(finding: &crate::edr::Finding) {
    let source = finding
        .source
        .map_or_else(|| "campaign".to_owned(), |source| source.to_string());
    match &finding.evidence {
        Evidence::SlowAuthentication(evidence) => warn!(
            event = "edr.finding",
            kind = finding.kind.as_str(),
            severity = finding.severity.as_str(),
            source = %source,
            client = %source,
            failures = evidence.failures,
            active_buckets = evidence.active_buckets,
            span_minutes = evidence.span_minutes,
            max_per_minute = evidence.max_failures_per_minute,
            gap_cv = ?evidence.gap_cv,
            baseline_z = ?evidence.baseline_z,
            "EDR slow authentication finding"
        ),
        Evidence::ReverseBruteForce(evidence) => warn!(
            event = "edr.finding",
            kind = finding.kind.as_str(),
            severity = finding.severity.as_str(),
            source = %source,
            client = %source,
            failures = evidence.failures,
            distinct_sources = evidence.distinct_sources,
            mean_per_source = evidence.mean_failures_per_source,
            top_path = evidence.top_path.as_deref().unwrap_or("n/a"),
            top_path_share = evidence.top_path_share,
            baseline_z = ?evidence.baseline_z,
            "EDR distributed authentication finding"
        ),
        Evidence::AuthSuccessAfterFailures(evidence) => warn!(
            event = "edr.finding",
            kind = finding.kind.as_str(),
            severity = finding.severity.as_str(),
            source = %source,
            client = %source,
            failures = evidence.failures,
            active_buckets = evidence.active_buckets,
            successes = evidence.successes,
            total_failures = evidence.total_failures,
            success_at = %crate::edr::format_utc(evidence.success_ms),
            "EDR authentication success after failures finding"
        ),
        Evidence::CampaignSuccess(evidence) => warn!(
            event = "edr.finding",
            kind = finding.kind.as_str(),
            severity = finding.severity.as_str(),
            source = %source,
            client = evidence
                .success_source
                .map_or_else(|| "unknown".to_owned(), |source| source.to_string()),
            failures = evidence.failures,
            distinct_sources = evidence.distinct_sources,
            mean_per_source = evidence.mean_failures_per_source,
            source_failures = evidence.source_failures,
            success_at = %crate::edr::format_utc(evidence.success_ms),
            "EDR campaign success finding"
        ),
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
        info!(
            config = %config_path.display(),
            "console is disabled by configuration; nothing to do"
        );
        return Ok(());
    }
    if !loaded.admin.enabled {
        warn!(
            config = %config_path.display(),
            "console needs the loopback admin listener but admin.enabled is false; nothing to do"
        );
        return Ok(());
    }
    let runtime = ConsoleRuntime::start(console, loaded.geoip.clone()).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
        let path = dir.join("kunato.yaml");
        std::fs::write(&path, text).expect("write config");
        path
    }

    #[tokio::test]
    async fn a_disabled_console_exits_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(
            dir.path(),
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
",
        );
        run(&path)
            .await
            .expect("a disabled console is not an error");
    }

    #[tokio::test]
    async fn a_console_without_an_admin_listener_exits_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(
            dir.path(),
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: { enabled: false }
console: { enabled: true }
",
        );
        run(&path).await.expect("an inert console is not an error");
    }
}
