use std::net::{IpAddr, SocketAddr};
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
            Command::Maintenance(args) => kunato::admin_client::run_maintenance(args).await,
            Command::AdminAccess(args) => kunato::admin_client::run_admin_access(args).await,
            Command::Banner(args) => kunato::banner::run(args),
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
        for warning in initial.decoy_warnings() {
            warn!("{warning}");
        }
    }

    let listen = initial.listen;
    let admin_config = initial.admin.clone();
    let acme_spec = initial.tls.as_ref().and_then(|tls| tls.acme.clone());
    let config = Arc::new(Snapshot::new(initial));
    let metrics = Arc::new(Metrics::new());

    if admin_config.enabled {
        let compiled = config.load();
        if admin_overlaps_upstream(&compiled.upstream, compiled.admin.listen) {
            warn!(
                upstream = %compiled.upstream.authority(),
                admin = %compiled.admin.listen,
                "upstream targets the admin listener; remote requests could reach metrics and maintenance controls"
            );
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let acme = match &acme_spec {
        Some(settings) => {
            Some(AcmeService::start(settings, metrics.clone(), shutdown_rx.clone()).await?)
        }
        None => None,
    };

    let server = Server::bind(listen, config.clone(), metrics.clone(), acme.as_ref()).await?;
    let protection = server.protection();
    let maintenance = server.maintenance();
    let admin_access = server.admin_access();
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
        match AdminServer::bind(
            &admin_config,
            config.clone(),
            metrics.clone(),
            protection,
            maintenance,
            admin_access,
        )
        .await
        {
            Ok(admin) => {
                info!(addr = %admin.local_addr()?, "admin listening");
                Some(tokio::spawn(admin.run(shutdown_rx.clone())))
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to start admin listener; metrics, maintenance, and administrative \
                     access controls unavailable, and administrative functions stay closed"
                );
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
    for route in config.decoy_routes() {
        info!("{route}");
    }
    for warning in config.decoy_warnings() {
        warn!("{warning}");
    }
    if let Some(warning) = config.body_inspection_warning() {
        warn!("{warning}");
    }
    if let Some(warning) = config.allowed_hosts_warning() {
        warn!("{warning}");
    }
    if let Some(warning) = config.admin_access_warning() {
        warn!("{warning}");
    }
}

/// Whether the configured upstream authority is the admin listener itself.
/// Only literal IPs and `localhost` can be decided at startup; a hostname that
/// resolves to the admin socket is deployment-dependent.
fn admin_overlaps_upstream(upstream: &config::Upstream, admin: SocketAddr) -> bool {
    let Ok(uri) = format!("http://{}", upstream.authority()).parse::<http::Uri>() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    let port = uri.port_u16().unwrap_or(80);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return SocketAddr::new(ip, port) == admin;
    }
    host.eq_ignore_ascii_case("localhost") && admin.ip().is_loopback() && port == admin.port()
}

fn run_init(args: &InitArgs) -> Result<(), Error> {
    let text = args.render()?;
    config::parse(&text)
        .map_err(|err| Error::Message(format!("generated configuration is invalid: {err}")))?;
    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    write_config_atomic(&args.output, &text, args.force)?;
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

/// Write the generated configuration without following a planted symlink.
///
/// `kunato init` may run as root in a directory the service user can write, so
/// the output path is inspected with `symlink_metadata` (never `exists`+write,
/// which follows a dangling link) and the contents go to a `create_new` temp
/// file that is fsynced and renamed over the path.
fn write_config_atomic(path: &std::path::Path, text: &str, force: bool) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(Error::Message(format!(
                "refusing to replace non-regular file `{}`",
                path.display()
            )));
        }
        Ok(_) if !force => {
            return Err(Error::Message(format!(
                "`{}` already exists; pass --force to overwrite",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut created = None;
    for attempt in 0..8u32 {
        let candidate = parent.join(format!(".kunato-init-{}-{attempt}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
    }
    let Some((temp, mut file)) = created else {
        return Err(Error::Message(format!(
            "could not create a temporary file next to `{}`",
            path.display()
        )));
    };
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err.into());
    }
    if let Err(err) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(err.into());
    }
    if let Ok(directory) = std::fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn write_starter_rules(path: &std::path::Path, header: &str) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    // The state directory belongs to the service user. A planted symlink must
    // not make root create or truncate a file outside it; `create_new` also
    // refuses a path that appeared between the caller's existence check and
    // this open.
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && !metadata.is_file()
    {
        return Err(Error::Message(format!(
            "refusing to replace non-regular file `{}`",
            path.display()
        )));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)?;
    file.write_all(format!("# {header}\ncategories: []\n").as_bytes())?;
    file.sync_all()?;
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
            let reload_path = path.clone();
            let reload_config = Arc::clone(&config);
            let reload_metrics = Arc::clone(&metrics);
            if let Err(err) = tokio::task::spawn_blocking(move || {
                watcher::reload(
                    &reload_path,
                    &reload_config,
                    &reload_metrics,
                    disable_protection,
                );
            })
            .await
            {
                tracing::error!(error = %err, "configuration reload task failed");
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_rules_refuse_a_planted_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim").expect("seed victim");
        let path = dir.path().join("rules.yaml");
        std::os::unix::fs::symlink(&victim, &path).expect("symlink");

        assert!(write_starter_rules(&path, "header").is_err());
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"victim");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn init_refuses_to_follow_a_symlinked_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"victim").expect("seed victim");
        let path = dir.path().join("config.yaml");
        std::os::unix::fs::symlink(&victim, &path).expect("symlink");

        assert!(write_config_atomic(&path, "listen: 127.0.0.1:0\n", true).is_err());
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"victim");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn init_refuses_a_dangling_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        let missing = dir.path().join("missing");
        std::os::unix::fs::symlink(&missing, &path).expect("symlink");

        assert!(write_config_atomic(&path, "content", true).is_err());
        assert!(!missing.exists(), "the link target must not be created");
    }

    #[test]
    fn init_overwrites_a_regular_file_only_with_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, b"old").expect("seed");

        assert!(write_config_atomic(&path, "new", false).is_err());
        assert_eq!(std::fs::read(&path).expect("read"), b"old");

        write_config_atomic(&path, "new", true).expect("replace");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        assert_eq!(
            std::fs::read_dir(&dir)
                .expect("entries")
                .filter_map(Result::ok)
                .count(),
            1,
            "no temporary file is left behind"
        );
    }

    #[test]
    fn init_creates_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        write_config_atomic(&path, "content", false).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"content");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type()
                .is_file()
        );
    }

    #[test]
    fn starter_rules_create_a_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.yaml");
        write_starter_rules(&path, "header").expect("starter write");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("metadata")
                .file_type()
                .is_file()
        );
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"# header\ncategories: []\n"
        );
    }
}
