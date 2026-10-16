//! Automatic certificate management through the ACME protocol (RFC 8555).
//!
//! Challenges are answered with TLS-ALPN-01 on the same listener as regular
//! TLS traffic, and certificates are renewed automatically after roughly two
//! thirds of their validity have elapsed. Issued material is cached in a
//! directory with restrictive permissions so restarts reuse it without
//! contacting the certificate authority again.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::StreamExt;
use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY;
use tokio_rustls_acme::{AccountCache, AcmeAcceptor, AcmeConfig, CertCache, EventOk};
use tracing::{debug, info, warn};

use crate::config::Acme;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::proxy::tls;

const CERT_FILE_NAME: &str = "cert.pem";
const ACCOUNT_FILE_NAME: &str = "account.key";

/// How long startup waits for a cached certificate to be deployed before
/// serving traffic with a not-yet-available certificate.
const CACHE_LOAD_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Readiness {
    Pending,
    Deployed,
    Failed,
}

/// A running ACME certificate manager.
///
/// Owns the certificate resolver shared by the TCP and QUIC listeners, the
/// TLS-ALPN-01 challenge acceptor, and the background task that orders,
/// renews, and caches certificates. The task stops when the shutdown channel
/// fires.
pub struct AcmeService {
    acceptor: AcmeAcceptor,
    tls_config: Arc<ServerConfig>,
    quic_config: Arc<ServerConfig>,
    driver: JoinHandle<()>,
}

impl AcmeService {
    pub async fn start(
        settings: &Acme,
        metrics: Arc<Metrics>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self, Error> {
        info!(
            directory = %settings.directory,
            domains = ?settings.domains,
            cache = %settings.cache_dir.display(),
            "ACME certificate management enabled"
        );
        if settings.directory == LETS_ENCRYPT_STAGING_DIRECTORY {
            warn!("ACME staging directory in use; issued certificates are not trusted by browsers");
        }

        let mut config =
            AcmeConfig::new_with_client_tls_config(settings.domains.clone(), api_client_config()?)
                .directory(settings.directory.clone())
                .cache(FileCache::new(settings.cache_dir.clone()));
        if let Some(contact) = &settings.contact {
            config = config.contact_push(match contact.starts_with("mailto:") {
                true => contact.clone(),
                false => format!("mailto:{contact}"),
            });
        }

        let mut state = config.state();
        let resolver = state.resolver();
        let acceptor = state.acceptor();
        let tls_config = tls::server_config_with_resolver(resolver.clone(), &[b"h2", b"http/1.1"])?;
        let quic_config = tls::server_config_with_resolver(resolver, &[b"h3"])?;

        let (ready_tx, mut ready_rx) = watch::channel(Readiness::Pending);
        let driver_metrics = Arc::clone(&metrics);
        let driver = tokio::spawn(async move {
            let mut shutdown = shutdown;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    event = state.next() => {
                        let Some(event) = event else { break };
                        match event {
                            Ok(EventOk::DeployedNewCert) => {
                                driver_metrics.acme_issued.fetch_add(1, Ordering::Relaxed);
                                mark_deployed(&ready_tx, &driver_metrics);
                                info!("ACME certificate issued and deployed");
                            }
                            Ok(EventOk::DeployedCachedCert) => {
                                driver_metrics.acme_cached.fetch_add(1, Ordering::Relaxed);
                                mark_deployed(&ready_tx, &driver_metrics);
                                info!("ACME certificate loaded from the cache");
                            }
                            Ok(event) => debug!(?event, "ACME event"),
                            Err(err) => {
                                driver_metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                                warn!(error = %err, "ACME certificate error");
                                if *ready_tx.borrow() == Readiness::Pending {
                                    let _ = ready_tx.send(Readiness::Failed);
                                }
                            }
                        }
                    }
                }
            }
        });

        if settings.cache_dir.join(CERT_FILE_NAME).is_file() {
            wait_for_cache_load(&mut ready_rx).await;
        }

        Ok(Self {
            acceptor,
            tls_config,
            quic_config,
            driver,
        })
    }

    pub fn acceptor(&self) -> AcmeAcceptor {
        self.acceptor.clone()
    }

    pub fn tls_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.tls_config)
    }

    pub fn quic_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.quic_config)
    }

    /// Returns the background task; it stops after the shutdown channel fires.
    pub fn into_driver(self) -> JoinHandle<()> {
        self.driver
    }
}

fn mark_deployed(ready: &watch::Sender<Readiness>, metrics: &Metrics) {
    if *ready.borrow() == Readiness::Pending {
        let _ = ready.send(Readiness::Deployed);
    }
    metrics
        .acme_last_success
        .store(unix_timestamp(), Ordering::Relaxed);
}

async fn wait_for_cache_load(ready: &mut watch::Receiver<Readiness>) {
    let wait = async {
        loop {
            if *ready.borrow() != Readiness::Pending {
                break;
            }
            if ready.changed().await.is_err() {
                break;
            }
        }
    };
    match tokio::time::timeout(CACHE_LOAD_TIMEOUT, wait).await {
        Ok(()) if *ready.borrow() == Readiness::Deployed => {
            info!("ACME certificate cache restored")
        }
        Ok(()) => {
            warn!("ACME certificate cache could not be loaded; a new certificate will be ordered")
        }
        Err(_) => warn!("timed out loading the ACME certificate cache; continuing without it"),
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn api_client_config() -> Result<Arc<rustls::ClientConfig>, Error> {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        debug!(
            errors = native.errors.len(),
            "failed to load some native CA certificates"
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        warn!(
            "no native CA certificates found; ACME directory requests will fail until a trust store is available"
        );
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(format!("failed to initialize TLS client: {err}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Caches the certificate chain (private key first) and the ACME account key
/// as files written atomically with mode 0600 inside a 0700 directory.
struct FileCache {
    dir: PathBuf,
}

impl FileCache {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join(CERT_FILE_NAME)
    }

    fn account_path(&self) -> PathBuf {
        self.dir.join(ACCOUNT_FILE_NAME)
    }

    async fn load(path: &Path) -> Result<Option<Vec<u8>>, io::Error> {
        match tokio::fs::read(path).await {
            Ok(contents) => Ok(Some(contents)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    async fn store(&self, path: &Path, contents: &[u8]) -> Result<(), io::Error> {
        tokio::fs::create_dir_all(&self.dir).await?;
        set_dir_permissions(&self.dir).await?;
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, contents).await?;
        set_file_permissions(&tmp).await?;
        match tokio::fs::rename(&tmp, path).await {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(err)
            }
        }
    }
}

#[cfg(unix)]
async fn set_file_permissions(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn set_file_permissions(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(unix)]
async fn set_dir_permissions(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn set_dir_permissions(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}

#[async_trait]
impl CertCache for FileCache {
    type EC = io::Error;

    async fn load_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, io::Error> {
        Self::load(&self.cert_path()).await
    }

    async fn store_cert(
        &self,
        _domains: &[String],
        _directory_url: &str,
        cert: &[u8],
    ) -> Result<(), io::Error> {
        self.store(&self.cert_path(), cert).await
    }
}

#[async_trait]
impl AccountCache for FileCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, io::Error> {
        Self::load(&self.account_path()).await
    }

    async fn store_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
        account: &[u8],
    ) -> Result<(), io::Error> {
        self.store(&self.account_path(), account).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_cache_round_trips_and_tightens_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");
        let cache = FileCache::new(cache_dir.clone());

        assert_eq!(cache.load_cert(&[], "").await.expect("load"), None);

        cache
            .store_cert(&[], "", b"cert")
            .await
            .expect("store cert");
        cache
            .store_account(&[], "", b"account")
            .await
            .expect("store account");
        assert_eq!(
            cache.load_cert(&[], "").await.expect("load"),
            Some(b"cert".to_vec())
        );
        assert_eq!(
            cache.load_account(&[], "").await.expect("load"),
            Some(b"account".to_vec())
        );

        cache
            .store_cert(&[], "", b"renewed")
            .await
            .expect("replace cert");
        assert_eq!(
            cache.load_cert(&[], "").await.expect("load"),
            Some(b"renewed".to_vec())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&cache.cert_path()), 0o600);
            assert_eq!(mode(&cache.account_path()), 0o600);
            assert_eq!(mode(&cache_dir), 0o700);
        }
    }
}
