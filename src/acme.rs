//! Automatic certificate management through the ACME protocol (RFC 8555).
//!
//! Challenges are answered with TLS-ALPN-01 on the same listener as regular
//! TLS traffic, and certificates are renewed after roughly two thirds of their
//! validity have elapsed. Issued material is cached in a directory with
//! restrictive permissions so restarts reuse it without contacting the
//! certificate authority again.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::Acme;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::proxy::tls;

mod base64;
mod cache;
mod client;
mod der;
mod jose;
mod pem;
mod resolver;

use client::{AcmeClient, Auth, AuthStatus, Order, OrderStatus, bounded_text};
use der::Validity;
use jose::AccountKey;
use resolver::AcmeResolver;

pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
pub(crate) const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// How long a challenge certificate stays available for the CA's validation
/// connection.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(600);
/// Upper bound for one complete issuance attempt, including validation polls
/// and any `Retry-After` delays requested by the CA.
const ORDER_TIMEOUT: Duration = Duration::from_secs(180);
const ORDER_ATTEMPTS: usize = 20;
const CHALLENGE_ATTEMPTS: u32 = 6;
const MAX_CHAIN_BYTES: usize = 64 * 1024;
const MAX_CHAIN_CERTS: usize = 10;
const MAX_POLL_DELAY: Duration = Duration::from_secs(30);
const MAX_ORDER_TRANSIENT_RETRIES: u32 = 4;
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(3600);
/// Minimum delay before re-ordering when a freshly issued certificate is
/// already past its renewal point (for example, a CA that backdates validity).
const RENEWAL_RETRY_DELAY: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AcmeError {
    #[error("ACME HTTP error: {0}")]
    Http(String),
    #[error("ACME response JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ACME cryptography error: {0}")]
    Crypto(String),
    #[error("ACME protocol error: {0}")]
    Protocol(String),
    #[error("ACME response is missing the {0} header")]
    MissingHeader(&'static str),
    #[error("ACME API error ({status}): {detail}")]
    Api {
        status: u16,
        detail: String,
        retry_after: Option<Duration>,
    },
    #[error("ACME operation timed out")]
    Timeout,
}

struct CachedCertificate {
    certified: CertifiedKey,
    validity: Validity,
    domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheMetadata {
    directory: String,
    domains: Vec<String>,
}

impl AcmeError {
    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    fn is_transient(&self) -> bool {
        match self {
            Self::Http(_) | Self::Timeout => true,
            Self::Api { status, .. } => *status == 429 || (500..=599).contains(status),
            _ => false,
        }
    }
}

/// A running ACME certificate manager.
///
/// Owns the TLS configurations that read from the shared certificate resolver
/// and the background task that orders, renews, and caches certificates. The
/// task stops when the shutdown channel fires.
pub struct AcmeService {
    tls_config: Arc<ServerConfig>,
    quic_config: Arc<ServerConfig>,
    activate: watch::Sender<bool>,
    driver: JoinHandle<()>,
}

impl AcmeService {
    /// Create the ACME manager and its background driver.
    ///
    /// The driver waits for [`AcmeService::activate`] before ordering a
    /// certificate. `Server::bind` calls it after the TLS listener is bound;
    /// callers that drive [`AcmeService`] directly must call it themselves.
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

        let resolver = Arc::new(AcmeResolver::new());
        let renew_at = Arc::new(AtomicU64::new(0));
        let cache_allowed = match load_cache_metadata(&settings.cache_dir).await {
            Ok(Some(metadata)) => {
                let matches = metadata_matches(&metadata, settings);
                if !matches {
                    warn!(
                        directory = %metadata.directory,
                        domains = ?metadata.domains,
                        "cached ACME certificate metadata does not match the configuration"
                    );
                }
                matches
            }
            Ok(None) => true,
            Err(err) => {
                metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, "failed to read cached ACME certificate metadata");
                false
            }
        };

        if cache_allowed {
            match cache::load_cert(&settings.cache_dir).await {
                Ok(Some(blob)) => match parse_certificate_cache(&blob) {
                    Ok(cached) => {
                        let now = der::unix_now();
                        if !domains_cover(&cached.domains, &settings.domains) {
                            warn!(
                                cached = ?cached.domains,
                                configured = ?settings.domains,
                                "cached ACME certificate does not cover the configured domains"
                            );
                        } else if cached.validity.not_after <= now {
                            warn!("cached ACME certificate has expired");
                        } else {
                            resolver.set_current(Arc::new(cached.certified));
                            renew_at.store(renewal_time(cached.validity), Ordering::Relaxed);
                            metrics.acme_cached.fetch_add(1, Ordering::Relaxed);
                            mark_last_success(&metrics);
                            info!("ACME certificate loaded from cache");
                        }
                    }
                    Err(err) => {
                        metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(error = %err, "cached ACME certificate could not be used");
                    }
                },
                Ok(None) => {}
                Err(err) => {
                    metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(error = %err, "failed to read the ACME certificate cache");
                }
            }
        }

        let account_key = load_account_key(&settings.cache_dir, &metrics).await?;
        let tls_config = tls::server_config_with_resolver(
            resolver.clone(),
            &[ACME_TLS_ALPN, b"h2", b"http/1.1"],
        )?;
        let quic_config = tls::server_config_with_resolver(resolver.clone(), &[b"h3"])?;
        let (activate, activate_rx) = watch::channel(false);
        let driver = tokio::spawn(run_driver(
            settings.clone(),
            resolver,
            account_key,
            renew_at,
            metrics,
            activate_rx,
            shutdown,
        ));

        Ok(Self {
            tls_config,
            quic_config,
            activate,
            driver,
        })
    }

    pub fn tls_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.tls_config)
    }

    pub fn quic_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.quic_config)
    }

    /// Allow the driver to start ordering certificates.
    ///
    /// Call this after the TLS listener is bound so the certificate authority
    /// can reach the TLS-ALPN-01 endpoint. `Server::bind` calls it
    /// automatically; users who drive [`AcmeService`] directly must call it
    /// once their listener is ready.
    pub fn activate(&self) {
        let _ = self.activate.send(true);
    }

    /// Returns the background task; it stops after the shutdown channel fires.
    pub fn into_driver(self) -> JoinHandle<()> {
        self.driver
    }
}

async fn load_cache_metadata(cache_dir: &Path) -> Result<Option<CacheMetadata>, Error> {
    let Some(bytes) = cache::load_meta(cache_dir)
        .await
        .map_err(|err| Error::Message(format!("failed to read ACME cache metadata: {err}")))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| Error::Message(format!("invalid ACME cache metadata: {err}")))
}

fn metadata_matches(metadata: &CacheMetadata, settings: &Acme) -> bool {
    metadata.directory == settings.directory && domains_equal(&metadata.domains, &settings.domains)
}

fn domains_equal(left: &[String], right: &[String]) -> bool {
    fn normalized(domains: &[String]) -> BTreeSet<String> {
        domains
            .iter()
            .map(|domain| domain.to_ascii_lowercase())
            .collect()
    }

    normalized(left) == normalized(right)
}

fn domains_cover(certificate: &[String], configured: &[String]) -> bool {
    let certificate: BTreeSet<String> = certificate
        .iter()
        .map(|domain| domain.to_ascii_lowercase())
        .collect();
    configured
        .iter()
        .all(|domain| certificate.contains(&domain.to_ascii_lowercase()))
}

fn deployment_renewal(validity: Validity, now: u64) -> Result<u64, AcmeError> {
    if validity.not_after <= now {
        return Err(AcmeError::Protocol(
            "issued certificate is already expired".to_owned(),
        ));
    }

    let renew = renewal_time(validity);
    if renew > now {
        return Ok(renew);
    }

    let remaining = validity.not_after - now;
    Ok(now + (remaining / 2).max(RENEWAL_RETRY_DELAY).min(remaining))
}

async fn load_account_key(cache_dir: &Path, metrics: &Metrics) -> Result<Arc<AccountKey>, Error> {
    match cache::load_account(cache_dir).await {
        Ok(Some(bytes)) => match AccountKey::from_pkcs8(&bytes) {
            Ok(key) => return Ok(Arc::new(key)),
            Err(err) => {
                metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, "cached ACME account key is invalid; generating a new one");
            }
        },
        Ok(None) => {}
        Err(err) => {
            metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
            warn!(error = %err, "failed to read the ACME account key cache");
        }
    }

    let (key, pkcs8) = AccountKey::generate()
        .map_err(|err| Error::Message(format!("failed to generate an ACME account key: {err}")))?;
    if let Err(err) = cache::store_account(cache_dir, &pkcs8).await {
        metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
        warn!(error = %err, "failed to cache the ACME account key");
    }
    Ok(Arc::new(key))
}

async fn run_driver(
    settings: Acme,
    resolver: Arc<AcmeResolver>,
    account_key: Arc<AccountKey>,
    renew_at: Arc<AtomicU64>,
    metrics: Arc<Metrics>,
    mut activate: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        return;
    }
    if !*activate.borrow() {
        tokio::select! {
            _ = shutdown.changed() => return,
            changed = activate.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }

    let mut backoff = BACKOFF_INITIAL;

    loop {
        if *shutdown.borrow() {
            break;
        }

        let now = der::unix_now();
        let renew = renew_at.load(Ordering::Relaxed);
        if renew > now {
            let wait = Duration::from_secs(renew - now);
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(wait) => {}
            }
            continue;
        }

        resolver.clear_challenges();
        let result = tokio::select! {
            _ = shutdown.changed() => break,
            result = order_certificate(&settings, &resolver, &account_key) => result,
        };

        resolver.clear_challenges();
        let mut failed = false;
        match result {
            Ok(blob) => match parse_certificate_cache(&blob) {
                Ok(cached) => {
                    let issued_at = der::unix_now();
                    if !domains_cover(&cached.domains, &settings.domains) {
                        metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            issued = ?cached.domains,
                            configured = ?settings.domains,
                            "ACME certificate does not cover the configured domains"
                        );
                        failed = true;
                    } else {
                        match deployment_renewal(cached.validity, issued_at) {
                            Ok(renew) => {
                                resolver.set_current(Arc::new(cached.certified));
                                renew_at.store(renew, Ordering::Relaxed);
                                metrics.acme_issued.fetch_add(1, Ordering::Relaxed);
                                mark_last_success(&metrics);
                                info!("ACME certificate issued and deployed");
                                if let Err(err) =
                                    cache::store_cert(&settings.cache_dir, &blob).await
                                {
                                    metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                                    warn!(error = %err, "failed to cache the ACME certificate");
                                }
                                let metadata = CacheMetadata {
                                    directory: settings.directory.clone(),
                                    domains: settings.domains.clone(),
                                };
                                match serde_json::to_vec(&metadata) {
                                    Ok(bytes) => {
                                        if let Err(err) =
                                            cache::store_meta(&settings.cache_dir, &bytes).await
                                        {
                                            metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                                            warn!(error = %err, "failed to cache ACME certificate metadata");
                                        }
                                    }
                                    Err(err) => {
                                        metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                                        warn!(error = %err, "failed to encode ACME certificate metadata");
                                    }
                                }
                                backoff = BACKOFF_INITIAL;
                            }
                            Err(err) => {
                                metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                                warn!(error = %err, "ACME certificate is not deployable");
                                failed = true;
                            }
                        }
                    }
                }
                Err(err) => {
                    metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(error = %err, "ACME certificate response could not be parsed");
                    failed = true;
                }
            },
            Err(err) => {
                metrics.acme_errors.fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, "ACME certificate error");
                if let Some(delay) = err.retry_after() {
                    backoff = backoff.max(delay.min(BACKOFF_MAX));
                }
                failed = true;
            }
        }

        if failed {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }
}

async fn order_certificate(
    settings: &Acme,
    resolver: &AcmeResolver,
    account_key: &Arc<AccountKey>,
) -> Result<Vec<u8>, AcmeError> {
    tokio::time::timeout(
        ORDER_TIMEOUT,
        order_certificate_inner(settings, resolver, account_key),
    )
    .await
    .map_err(|_| AcmeError::Timeout)?
}

struct OrderState {
    url: String,
    order: Order,
    csr: Option<der::CsrMaterial>,
    finalized: bool,
    poll_attempt: u32,
}

async fn process_order(
    client: &mut AcmeClient,
    resolver: &AcmeResolver,
    settings: &Acme,
    state: &mut OrderState,
) -> Result<Option<Vec<u8>>, AcmeError> {
    match state.order.status {
        OrderStatus::Pending => {
            let mut pending = Vec::new();
            for url in &state.order.authorizations {
                if let Some(authorization) =
                    start_authorization(client, resolver, &settings.domains, url).await?
                {
                    pending.push(authorization);
                }
            }
            if !pending.is_empty() {
                poll_authorizations(client, &mut pending).await?;
            }
            state.order = client.order(&state.url).await?;
            if matches!(state.order.status, OrderStatus::Pending) {
                let delay = client
                    .retry_after()
                    .unwrap_or_else(|| Duration::from_secs(1))
                    .max(Duration::from_secs(1))
                    .min(MAX_POLL_DELAY);
                tokio::time::sleep(delay).await;
            }
            Ok(None)
        }
        OrderStatus::Ready => {
            if !state.finalized {
                if state.csr.is_none() {
                    state.csr = Some(der::generate_csr(&settings.domains)?);
                }
                let material = state.csr.as_ref().ok_or_else(|| {
                    AcmeError::Protocol("certificate signing request vanished".to_owned())
                })?;
                let finalize_url = state.order.finalize.clone();
                state.order = client.finalize(&finalize_url, &material.der).await?;
                state.finalized = true;
            } else {
                let delay = client
                    .retry_after()
                    .unwrap_or_else(|| Duration::from_secs(1))
                    .max(Duration::from_secs(1))
                    .min(MAX_POLL_DELAY);
                tokio::time::sleep(delay).await;
                state.order = client.order(&state.url).await?;
            }
            Ok(None)
        }
        OrderStatus::Processing => {
            let delay = client
                .retry_after()
                .unwrap_or_else(|| Duration::from_secs(1u64 << state.poll_attempt.min(4)))
                .max(Duration::from_secs(1))
                .min(MAX_POLL_DELAY);
            state.poll_attempt += 1;
            tokio::time::sleep(delay).await;
            state.order = client.order(&state.url).await?;
            Ok(None)
        }
        OrderStatus::Valid => {
            let certificate_url = state.order.certificate.clone().ok_or_else(|| {
                AcmeError::Protocol("valid ACME order has no certificate URL".to_owned())
            })?;
            let chain = client.certificate(&certificate_url).await?;
            let material = state.csr.take().ok_or_else(|| {
                AcmeError::Protocol("ACME order completed without a CSR".to_owned())
            })?;
            Ok(Some(combine_key_and_chain(&material.key_pkcs8, &chain)))
        }
        OrderStatus::Invalid => Err(order_error(&state.order)),
    }
}

async fn order_certificate_inner(
    settings: &Acme,
    resolver: &AcmeResolver,
    account_key: &Arc<AccountKey>,
) -> Result<Vec<u8>, AcmeError> {
    let mut client = AcmeClient::new(
        settings.directory.clone(),
        &settings.allowed_origins,
        Arc::clone(account_key),
    )?;
    client.register_account(settings.contact.as_deref()).await?;

    let (order_url, order) = client.new_order(&settings.domains).await?;
    let mut state = OrderState {
        url: order_url,
        order,
        csr: None,
        finalized: false,
        poll_attempt: 0,
    };
    let mut steps = 0usize;
    let mut transient_failures = 0u32;

    while steps < ORDER_ATTEMPTS {
        match process_order(&mut client, resolver, settings, &mut state).await {
            Ok(Some(blob)) => return Ok(blob),
            Ok(None) => steps += 1,
            Err(err) if err.is_transient() && transient_failures < MAX_ORDER_TRANSIENT_RETRIES => {
                transient_failures += 1;
                warn!(error = %err, "ACME order step failed; retrying the same order");
                let delay =
                    Duration::from_secs(1u64 << transient_failures.min(4)).min(MAX_POLL_DELAY);
                tokio::time::sleep(delay).await;
                match client.order(&state.url).await {
                    Ok(order) => state.order = order,
                    Err(err) if err.is_transient() => {
                        debug!(error = %err, "could not refresh the ACME order yet");
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) => return Err(err),
        }
    }

    Err(AcmeError::Protocol(
        "ACME order did not reach a final state".to_owned(),
    ))
}

struct PendingAuthorization {
    url: String,
    domain: String,
}

async fn start_authorization(
    client: &mut AcmeClient,
    resolver: &AcmeResolver,
    domains: &[String],
    url: &str,
) -> Result<Option<PendingAuthorization>, AcmeError> {
    let auth = client.authorization(url).await?;
    if auth.identifier.kind != "dns" {
        return Err(AcmeError::Protocol(
            "ACME authorization is not for a DNS identifier".to_owned(),
        ));
    }
    let domain = auth.identifier.value.clone();
    if !domains
        .iter()
        .any(|configured| configured.eq_ignore_ascii_case(&domain))
    {
        return Err(AcmeError::Protocol(format!(
            "ACME authorization for unconfigured domain {}",
            bounded_text(&domain)
        )));
    }
    match auth.status {
        AuthStatus::Valid => return Ok(None),
        AuthStatus::Pending => {}
        _ => return Err(auth_error(&auth)),
    }

    let challenge = auth
        .challenges
        .iter()
        .find(|challenge| challenge.kind == "tls-alpn-01")
        .ok_or_else(|| {
            AcmeError::Protocol(format!(
                "no TLS-ALPN-01 challenge offered for {}",
                bounded_text(&domain)
            ))
        })?;
    if challenge.token.is_empty() {
        return Err(AcmeError::Protocol(format!(
            "TLS-ALPN-01 challenge for {} has no token",
            bounded_text(&domain)
        )));
    }

    let digest = client
        .account_key()
        .key_authorization_digest(&challenge.token)?;
    let challenge_cert = der::generate_challenge_cert(&domain, &digest)?;
    let certified = certified_key(&challenge_cert.cert_der, &challenge_cert.key_pkcs8)?;
    resolver.insert_challenge(&domain, Arc::new(certified), CHALLENGE_LIFETIME);

    debug!(domain = %domain, "triggering TLS-ALPN-01 challenge");
    client.trigger_challenge(&challenge.url).await?;

    Ok(Some(PendingAuthorization {
        url: url.to_owned(),
        domain,
    }))
}

async fn poll_authorizations(
    client: &mut AcmeClient,
    pending: &mut Vec<PendingAuthorization>,
) -> Result<(), AcmeError> {
    let mut delay = Duration::from_secs(1);
    for attempt in 0..CHALLENGE_ATTEMPTS {
        tokio::time::sleep(delay).await;
        let mut still_pending = Vec::new();
        let mut next_delay: Option<Duration> = None;
        for authorization in pending.drain(..) {
            let auth = client.authorization(&authorization.url).await?;
            if let Some(requested) = client.retry_after() {
                next_delay =
                    Some(next_delay.map_or(requested, |current: Duration| current.max(requested)));
            }
            match auth.status {
                AuthStatus::Valid => {}
                AuthStatus::Pending => still_pending.push(authorization),
                _ => return Err(auth_error(&auth)),
            }
        }
        *pending = still_pending;
        if pending.is_empty() {
            return Ok(());
        }
        let default = Duration::from_secs(1u64 << attempt.min(4));
        delay = next_delay.unwrap_or(default).min(MAX_POLL_DELAY);
        if delay.is_zero() {
            delay = default;
        }
    }

    let domains: Vec<String> = pending
        .iter()
        .map(|authorization| bounded_text(&authorization.domain))
        .collect();
    Err(AcmeError::Protocol(format!(
        "TLS-ALPN-01 authorization did not complete for {}",
        domains.join(", ")
    )))
}

fn auth_error(auth: &Auth) -> AcmeError {
    let domain = bounded_text(&auth.identifier.value);
    let problem = auth.error.as_ref().or_else(|| {
        auth.challenges
            .iter()
            .find_map(|challenge| challenge.error.as_ref())
    });
    match problem {
        Some(error) => AcmeError::Protocol(format!("authorization for {domain} failed: {error}")),
        None => AcmeError::Protocol(format!(
            "authorization for {domain} has status {:?}",
            auth.status
        )),
    }
}

fn order_error(order: &Order) -> AcmeError {
    match &order.error {
        Some(error) => AcmeError::Protocol(format!("ACME order failed: {error}")),
        None => AcmeError::Protocol("ACME order is invalid".to_owned()),
    }
}

fn certified_key(cert_der: &[u8], key_pkcs8: &[u8]) -> Result<CertifiedKey, AcmeError> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8.to_vec()));
    // Do not use `CertifiedKey::from_der` here: the TLS-ALPN-01 certificate
    // carries the acmeIdentifier extension (1.3.6.1.5.5.7.1.31), whose last
    // OID arc collides with id-ce-cRLDistributionPoints in webpki's extension
    // dispatcher. The challenge certificate is only presented to the CA's
    // validator, so parse the key and keep the certificate opaque.
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key)
        .map_err(|err| AcmeError::Protocol(format!("invalid ACME key: {err}")))?;
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(cert_der.to_vec())],
        signing_key,
    ))
}

fn parse_certificate_cache(blob: &[u8]) -> Result<CachedCertificate, AcmeError> {
    let blocks = pem::decode_blocks(blob).ok_or_else(|| {
        AcmeError::Protocol("cached ACME certificate is not valid PEM".to_owned())
    })?;
    let mut blocks = blocks.into_iter();
    let first = blocks
        .next()
        .ok_or_else(|| AcmeError::Protocol("cached ACME certificate is empty".to_owned()))?;
    let key = match first.label.as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(first.der)),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(first.der)),
        label => {
            return Err(AcmeError::Protocol(format!(
                "cached ACME key has unsupported PEM label `{label}`"
            )));
        }
    };
    let certificates: Vec<CertificateDer<'static>> = blocks
        .filter(|block| block.label == "CERTIFICATE")
        .map(|block| CertificateDer::from(block.der))
        .collect();
    if certificates.is_empty() {
        return Err(AcmeError::Protocol(
            "cached ACME certificate has no certificate chain".to_owned(),
        ));
    }
    if certificates.len() > MAX_CHAIN_CERTS {
        return Err(AcmeError::Protocol(
            "cached ACME certificate chain is too long".to_owned(),
        ));
    }
    let chain_bytes: usize = certificates
        .iter()
        .map(|certificate| certificate.as_ref().len())
        .sum();
    if chain_bytes > MAX_CHAIN_BYTES {
        return Err(AcmeError::Protocol(
            "cached ACME certificate chain is too large".to_owned(),
        ));
    }

    let provider = rustls::crypto::ring::default_provider();
    let certified = match CertifiedKey::from_der(certificates.clone(), key.clone_key(), &provider) {
        Ok(certified) => certified,
        Err(err) => {
            debug!(
                error = %err,
                "webpki rejected the ACME certificate; verifying the key against its SPKI"
            );
            let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key)
                .map_err(|err| AcmeError::Protocol(format!("invalid ACME key: {err}")))?;
            let certificate_spki = der::certificate_spki(certificates[0].as_ref())?;
            let key_spki = signing_key.public_key().ok_or_else(|| {
                AcmeError::Protocol("ACME signing key has no public key".to_owned())
            })?;
            if key_spki.as_ref() != certificate_spki {
                return Err(AcmeError::Protocol(
                    "cached ACME certificate and private key do not match".to_owned(),
                ));
            }
            CertifiedKey::new(certificates, signing_key)
        }
    };
    let validity = der::certificate_validity(certified.cert[0].as_ref())?;
    let domains = der::certificate_sans(certified.cert[0].as_ref())?;
    Ok(CachedCertificate {
        certified,
        validity,
        domains,
    })
}

fn combine_key_and_chain(key_pkcs8: &[u8], chain: &str) -> Vec<u8> {
    let mut output = pem::encode("PRIVATE KEY", key_pkcs8).into_bytes();
    output.extend_from_slice(chain.trim_end().as_bytes());
    output.push(b'\n');
    output
}

fn renewal_time(validity: Validity) -> u64 {
    let lifetime = validity.not_after.saturating_sub(validity.not_before);
    validity.not_after.saturating_sub(lifetime / 3)
}

fn mark_last_success(metrics: &Metrics) {
    metrics
        .acme_last_success
        .store(der::unix_now(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_happens_at_two_thirds() {
        let validity = Validity {
            not_before: 1_000,
            not_after: 1_900,
        };
        assert_eq!(renewal_time(validity), 1_600);
    }

    #[test]
    fn cache_blob_round_trips_through_pem() {
        let challenge = der::generate_challenge_cert("localhost", &[3u8; 32]).expect("cert");
        let blob = combine_key_and_chain(
            &challenge.key_pkcs8,
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        );
        let blocks = pem::decode_blocks(&blob).expect("pem");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "PRIVATE KEY");
        assert_eq!(blocks[1].label, "CERTIFICATE");
    }

    #[test]
    fn parses_a_certificate_cache_blob() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let blob = format!(
            "{}{}",
            certified.signing_key.serialize_pem(),
            certified.cert.pem()
        );
        let cached = parse_certificate_cache(blob.as_bytes()).expect("parse");
        assert_eq!(cached.certified.cert.len(), 1);
        assert_eq!(cached.domains, vec!["localhost"]);
        assert!(cached.validity.not_after > cached.validity.not_before);
    }

    #[test]
    fn parses_a_certificate_with_an_unknown_critical_extension() {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        let mut extension = rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 99999, 1],
            b"custom".to_vec(),
        );
        extension.set_criticality(true);
        params.custom_extensions = vec![extension];
        let signing_key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&signing_key).expect("cert");
        let blob = format!("{}{}", signing_key.serialize_pem(), cert.pem());

        let cached = parse_certificate_cache(blob.as_bytes()).expect("fallback parse");
        assert_eq!(cached.certified.cert.len(), 1);
        assert_eq!(cached.domains, vec!["localhost"]);
    }

    #[test]
    fn cache_metadata_compares_case_insensitively() {
        let settings = Acme {
            directory: "https://ca.example/directory".to_owned(),
            domains: vec!["Example.com".to_owned(), "www.example.com".to_owned()],
            contact: None,
            cache_dir: std::path::PathBuf::from("/tmp/kunato-acme-test"),
            allowed_origins: Vec::new(),
        };
        let metadata = CacheMetadata {
            directory: settings.directory.clone(),
            domains: vec!["example.com".to_owned(), "WWW.example.com".to_owned()],
        };
        assert!(metadata_matches(&metadata, &settings));

        let mut changed = metadata;
        changed.directory = "https://staging.example/directory".to_owned();
        assert!(!metadata_matches(&changed, &settings));
    }

    #[test]
    fn certificate_domains_must_cover_configuration_but_may_be_a_superset() {
        let configured = vec!["example.com".to_owned(), "www.example.com".to_owned()];
        assert!(domains_cover(
            &["example.com".to_owned(), "www.example.com".to_owned()],
            &configured
        ));
        assert!(domains_cover(
            &[
                "example.com".to_owned(),
                "www.example.com".to_owned(),
                "extra.example.com".to_owned(),
            ],
            &configured
        ));
        assert!(!domains_cover(&["example.com".to_owned()], &configured));
    }

    #[test]
    fn transient_acme_errors_are_retryable() {
        assert!(AcmeError::Http("network".to_owned()).is_transient());
        assert!(AcmeError::Timeout.is_transient());
        assert!(
            AcmeError::Api {
                status: 503,
                detail: "unavailable".to_owned(),
                retry_after: None,
            }
            .is_transient()
        );
        assert!(
            AcmeError::Api {
                status: 429,
                detail: "slow down".to_owned(),
                retry_after: None,
            }
            .is_transient()
        );
        assert!(
            !AcmeError::Api {
                status: 400,
                detail: "bad request".to_owned(),
                retry_after: None,
            }
            .is_transient()
        );
        assert!(!AcmeError::Protocol("invalid order".to_owned()).is_transient());
    }

    #[test]
    fn deployment_renewal_backs_off_for_backdated_certificates() {
        let now = 1_000;
        let validity = Validity {
            not_before: 1_000,
            not_after: 1_900,
        };
        assert_eq!(deployment_renewal(validity, now).expect("future"), 1_600);

        let backdated = Validity {
            not_before: 0,
            not_after: 1_060,
        };
        let renew = deployment_renewal(backdated, now).expect("backdated");
        assert!(renew > now);
        assert!(renew <= backdated.not_after);

        let expired = Validity {
            not_before: 0,
            not_after: now,
        };
        assert!(deployment_renewal(expired, now).is_err());
    }

    #[test]
    fn builds_a_challenge_certified_key() {
        let challenge = der::generate_challenge_cert("localhost", &[3u8; 32]).expect("cert");
        let certified = certified_key(&challenge.cert_der, &challenge.key_pkcs8).expect("key");
        assert_eq!(certified.cert.len(), 1);
        assert!(certified.key.public_key().is_some());
    }
}
