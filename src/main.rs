use std::process::ExitCode;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{error, info, warn};

use kunato::acme::AcmeService;
use kunato::admin::AdminServer;
use kunato::cli::{Cli, Command, InitArgs};
use kunato::config;
use kunato::config::CompiledConfig;
use kunato::config::watcher;
use kunato::error::Error;
use kunato::metrics::Metrics;
use kunato::proxy::server::Server;
use kunato::rules_update::{self, UpdateOutcome};
use kunato::snapshot::Snapshot;
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
    if let Some(command) = cli.command {
        return match command {
            Command::Init(args) => run_init(&args),
            Command::Validate => {
                let config = config::load(&cli.config)?;
                warn_configuration(&config);
                println!("configuration OK: {}", cli.config.display());
                Ok(())
            }
            Command::UpdateRules => run_update_rules(&cli.config).await,
            Command::Upgrade(args) => kunato::upgrade::run(args).await,
            Command::Log(args) => kunato::logs::run(*args).await,
            Command::Metrics(args) => kunato::admin_client::run(args).await,
        };
    }

    let mut initial = config::load(&cli.config)?;
    warn_configuration(&initial);

    if cli.validate {
        println!("configuration OK: {}", cli.config.display());
        return Ok(());
    }

    if cli.disable_protection {
        warn!("DoS/DDoS protection disabled by --disable-protection");
        initial.protection.enabled = false;
    }

    let listen = initial.listen;
    let admin_config = initial.admin.clone();
    let acme_spec = initial.tls.as_ref().and_then(|tls| tls.acme.clone());
    let config = Arc::new(Snapshot::new(initial));
    let metrics = Arc::new(Metrics::new());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let acme = match &acme_spec {
        Some(settings) => {
            Some(AcmeService::start(settings, metrics.clone(), shutdown_rx.clone()).await?)
        }
        None => None,
    };

    let server = Server::bind(listen, config.clone(), metrics.clone(), acme.as_ref()).await?;
    let protection = server.protection();
    info!(addr = %server.local_addr()?, config = %cli.config.display(), "kunato started");

    let server_task = tokio::spawn(server.run(shutdown_rx.clone()));
    let watcher_task = tokio::spawn(watcher::watch(
        cli.config.clone(),
        config.clone(),
        metrics.clone(),
        cli.disable_protection,
        shutdown_rx.clone(),
    ));
    let rules_update_task = tokio::spawn(rules_update::run(
        config.clone(),
        cli.config.clone(),
        metrics.clone(),
        cli.disable_protection,
        shutdown_rx.clone(),
    ));

    let admin_task = if admin_config.enabled {
        match AdminServer::bind(&admin_config, metrics.clone(), protection).await {
            Ok(admin) => {
                info!(addr = %admin.local_addr()?, "admin listening");
                Some(tokio::spawn(admin.run(shutdown_rx.clone())))
            }
            Err(err) => {
                warn!(error = %err, "failed to start admin listener; metrics unavailable");
                None
            }
        }
    } else {
        None
    };

    #[cfg(unix)]
    spawn_sighup_reload(
        cli.config.clone(),
        config.clone(),
        metrics.clone(),
        cli.disable_protection,
    );

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received");

    let _ = shutdown_tx.send(true);

    match server_task.await {
        Ok(()) => info!("shutdown complete"),
        Err(err) => error!(error = %err, "server task failed"),
    }
    let _ = watcher_task.await;
    let _ = rules_update_task.await;
    if let Some(admin_task) = admin_task {
        let _ = admin_task.await;
    }
    if let Some(acme) = acme {
        let _ = acme.into_driver().await;
    }

    Ok(())
}

fn warn_configuration(config: &CompiledConfig) {
    if let Some(warning) = config.body_inspection_warning() {
        warn!("{warning}");
    }
    if let Some(warning) = config.allowed_hosts_warning() {
        warn!("{warning}");
    }
}

fn run_init(args: &InitArgs) -> Result<(), Error> {
    if args.output.exists() && !args.force {
        return Err(Error::Message(format!(
            "`{}` already exists; pass --force to overwrite",
            args.output.display()
        )));
    }
    let text = args.render()?;
    config::parse(&text)
        .map_err(|err| Error::Message(format!("generated configuration is invalid: {err}")))?;
    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, text)?;
    println!("wrote {}", args.output.display());
    if args.allowed_hosts.is_empty() && args.acme_domains.is_empty() {
        println!(
            "note: allowed_hosts is not set; any Host header is accepted. Add the names \
             clients use to enable host checking."
        );
    }

    let rules_file = args.rules_file.as_path();
    if !rules_file.exists() {
        write_starter_rules(rules_file, "Managed rule set; replaced by rules_update.\n")?;
        println!("wrote {}", rules_file.display());
    }
    if let Some(overrides_file) = &args.overrides_file
        && !overrides_file.exists()
    {
        write_starter_rules(
            overrides_file,
            "Local overrides, evaluated before every other rule source.\n\
             # disabled_rules: [rule-name]\n",
        )?;
        println!("wrote {}", overrides_file.display());
    }
    Ok(())
}

fn write_starter_rules(path: &std::path::Path, header: &str) -> Result<(), Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("# {header}\ncategories: []\n"))?;
    Ok(())
}

async fn run_update_rules(config_path: &std::path::Path) -> Result<(), Error> {
    let loaded = config::load_settings(config_path)?;
    let Some(rules_file) = &loaded.rules_file else {
        return Err(Error::Message(format!(
            "`{}` does not configure `rules_file`",
            config_path.display()
        )));
    };
    if !loaded.rules_update.enabled {
        return Err(Error::Message(format!(
            "`{}` does not enable `rules_update`",
            config_path.display()
        )));
    }
    let state_file = rules_update::state_path(rules_file);
    match rules_update::update_once(config_path, &loaded.rules_update, rules_file, &state_file)
        .await?
    {
        UpdateOutcome::Updated => println!("rules updated: {}", rules_file.display()),
        UpdateOutcome::NotModified => println!("rules are up to date: {}", rules_file.display()),
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_sighup_reload(
    path: std::path::PathBuf,
    config: Arc<Snapshot<CompiledConfig>>,
    metrics: Arc<Metrics>,
    disable_protection: bool,
) {
    tokio::spawn(async move {
        let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while sighup.recv().await.is_some() {
            info!("SIGHUP received, reloading configuration");
            watcher::reload(&path, &config, &metrics, disable_protection);
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
