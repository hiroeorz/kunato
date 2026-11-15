//! Development runner for the counter-based collection layer, without a web UI.

use kunato::console::collector::{Collector, CollectorConfig, HttpSource, run};
use kunato::console::{StorageConfig, WriterConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let directory = args
        .next()
        .ok_or("usage: console_collect DATA_DIRECTORY LOOPBACK_ADMIN_ADDRESS [INSTANCE]")?;
    let address = args
        .next()
        .ok_or("missing loopback admin address")?
        .parse()?;
    let config = CollectorConfig {
        instance: args.next().unwrap_or_else(|| "local-waf".into()),
        ..CollectorConfig::default()
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let source = HttpSource::new(address)?;
    let mut collector = Collector::start(
        StorageConfig::new(directory),
        WriterConfig::default(),
        config,
    )
    .await?;
    let (stop, changed) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    });
    run(source, &mut collector, changed).await;
    signal.abort();
    let report = collector.shutdown(Duration::from_secs(5)).await?;
    println!(
        "shutdown timed_out={} committed_batches={}",
        report.timed_out, report.health.committed_batches
    );
    Ok(())
}
