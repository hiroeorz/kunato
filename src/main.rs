use std::process::ExitCode;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser;
use tokio::sync::watch;
use tracing::{error, info};

use kunato::cli::Cli;
use kunato::config;
use kunato::config::CompiledConfig;
use kunato::config::watcher;
use kunato::error::Error;
use kunato::proxy::server::Server;
use kunato::telemetry;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(err) = telemetry::init(cli.log_level.as_deref(), cli.log_format) {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("{err}");
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Error> {
    let initial = config::load(&cli.config)?;

    if cli.validate {
        println!("configuration OK: {}", cli.config.display());
        return Ok(());
    }

    let listen = initial.listen;
    let config = Arc::new(ArcSwap::from_pointee(initial));

    let server = Server::bind(listen, config.clone()).await?;
    info!(addr = %server.local_addr()?, config = %cli.config.display(), "kunato started");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(shutdown_rx.clone()));
    let watcher_task = tokio::spawn(watcher::watch(
        cli.config.clone(),
        config.clone(),
        shutdown_rx.clone(),
    ));

    #[cfg(unix)]
    spawn_sighup_reload(cli.config.clone(), config.clone());

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");

    let _ = shutdown_tx.send(true);

    match server_task.await {
        Ok(()) => info!("shutdown complete"),
        Err(err) => error!(error = %err, "server task failed"),
    }
    let _ = watcher_task.await;

    Ok(())
}

#[cfg(unix)]
fn spawn_sighup_reload(path: std::path::PathBuf, config: Arc<ArcSwap<CompiledConfig>>) {
    tokio::spawn(async move {
        let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while sighup.recv().await.is_some() {
            info!("SIGHUP received, reloading configuration");
            watcher::reload(&path, &config);
        }
    });
}

async fn wait_for_shutdown_signal() -> Result<(), Error> {
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
