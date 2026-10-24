//! Certificate resolver shared by the TCP and QUIC listeners.
//!
//! The resolver serves the currently deployed certificate for normal
//! handshakes and a short-lived challenge certificate when the client
//! negotiates the `acme-tls/1` ALPN protocol required by TLS-ALPN-01.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::ACME_TLS_ALPN;
use crate::snapshot::SnapshotOption;

pub(crate) struct AcmeResolver {
    current: SnapshotOption<CertifiedKey>,
    challenges: Mutex<HashMap<String, ChallengeEntry>>,
}

struct ChallengeEntry {
    key: Arc<CertifiedKey>,
    expires: Instant,
}

impl AcmeResolver {
    pub(crate) fn new() -> Self {
        Self {
            current: SnapshotOption::empty(),
            challenges: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn set_current(&self, key: Arc<CertifiedKey>) {
        self.current.store(Some(key));
    }

    pub(crate) fn insert_challenge(
        &self,
        domain: &str,
        key: Arc<CertifiedKey>,
        lifetime: Duration,
    ) {
        let Ok(mut challenges) = self.challenges.lock() else {
            return;
        };
        let now = Instant::now();
        challenges.retain(|_, entry| entry.expires > now);
        tracing::debug!(domain = %domain, "stored TLS-ALPN-01 challenge certificate");
        challenges.insert(
            domain.to_ascii_lowercase(),
            ChallengeEntry {
                key,
                expires: now + lifetime,
            },
        );
    }

    pub(crate) fn clear_challenges(&self) {
        if let Ok(mut challenges) = self.challenges.lock() {
            challenges.clear();
        }
    }
}

impl ResolvesServerCert for AcmeResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme = hello
            .alpn()
            .map(|mut protocols| protocols.any(|protocol| protocol == ACME_TLS_ALPN))
            .unwrap_or(false);
        if !wants_acme {
            return self.current.load();
        }

        let domain = hello.server_name()?.to_ascii_lowercase();
        tracing::debug!(domain = %domain, "acme-tls/1 handshake");
        let mut challenges = self.challenges.lock().ok()?;
        let now = Instant::now();
        let Some(entry) = challenges.get(&domain) else {
            tracing::debug!(domain = %domain, "no challenge certificate for acme-tls/1 handshake");
            return None;
        };
        if entry.expires <= now {
            challenges.remove(&domain);
            tracing::debug!(domain = %domain, "challenge certificate expired");
            return None;
        }
        tracing::debug!(domain = %domain, "serving TLS-ALPN-01 challenge certificate");
        Some(Arc::clone(&entry.key))
    }
}

impl fmt::Debug for AcmeResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcmeResolver")
    }
}
