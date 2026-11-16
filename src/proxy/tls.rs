use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;

use crate::error::Error;

pub fn load_server_config(cert_file: &Path, key_file: &Path) -> Result<Arc<ServerConfig>, Error> {
    warn_private_key_permissions(key_file);
    let (certificates, private_key) = load_material(cert_file, key_file)?;
    build_server_config(
        certificates,
        private_key,
        &[b"h2".as_slice(), b"http/1.1".as_slice()],
    )
}

pub(crate) fn certificate_expiry(cert_file: &Path) -> Option<u64> {
    let certificates = load_certificates(cert_file).ok()?;
    crate::acme::certificate_expiry(certificates.first()?.as_ref())
}

pub fn load_quic_server_config(
    cert_file: &Path,
    key_file: &Path,
) -> Result<Arc<ServerConfig>, Error> {
    let (certificates, private_key) = load_material(cert_file, key_file)?;
    build_server_config(certificates, private_key, &[b"h3".as_slice()])
}

fn load_material(
    cert_file: &Path,
    key_file: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
    let certificates = load_certificates(cert_file)?;
    let private_key = PrivateKeyDer::from_pem_file(key_file).map_err(|err| {
        Error::Tls(format!(
            "failed to read private key from `{}`: {err}",
            key_file.display()
        ))
    })?;
    Ok((certificates, private_key))
}

/// Warn when the TLS private key is accessible to users outside its owner and
/// group. The installer copies the key with `0640 root:kunato`; a manual copy
/// often leaves it world-readable.
#[cfg(unix)]
fn warn_private_key_permissions(key_file: &Path) {
    use std::os::unix::fs::PermissionsExt;
    use tracing::warn;

    let Ok(metadata) = std::fs::metadata(key_file) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if private_key_is_world_accessible(mode) {
        warn!(
            path = %key_file.display(),
            mode = %format!("{mode:04o}"),
            "TLS private key has permissions for users outside its owner and group; \
             install it with mode 0640 and the service user's group"
        );
    }
}

#[cfg(unix)]
fn private_key_is_world_accessible(mode: u32) -> bool {
    mode & 0o007 != 0
}

#[cfg(not(unix))]
fn warn_private_key_permissions(_key_file: &Path) {}

fn build_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(format!("failed to initialize TLS: {err}")))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|err| Error::Tls(format!("invalid certificate or private key: {err}")))?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    Ok(Arc::new(config))
}

/// Build a server config whose certificate comes from a resolver. Used for
/// ACME-managed certificates that rotate at runtime.
pub(crate) fn server_config_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(format!("failed to initialize TLS: {err}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();

    Ok(Arc::new(config))
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let iterator = CertificateDer::pem_file_iter(path).map_err(|err| {
        Error::Tls(format!(
            "failed to open certificate file `{}`: {err}",
            path.display()
        ))
    })?;

    let mut certificates = Vec::new();
    for certificate in iterator {
        certificates.push(certificate.map_err(|err| {
            Error::Tls(format!(
                "failed to read certificates from `{}`: {err}",
                path.display()
            ))
        })?);
    }

    if certificates.is_empty() {
        return Err(Error::Tls(format!(
            "no certificates found in `{}`",
            path.display()
        )));
    }

    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_files() {
        let error = load_server_config(
            Path::new("/nonexistent/kunato-cert.pem"),
            Path::new("/nonexistent/kunato-key.pem"),
        )
        .expect_err("must fail");
        assert!(matches!(error, Error::Tls(_)));
    }

    #[test]
    fn rejects_invalid_pem_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_file = dir.path().join("cert.pem");
        let key_file = dir.path().join("key.pem");
        std::fs::write(&cert_file, "not a certificate").expect("write cert");
        std::fs::write(&key_file, "not a key").expect("write key");

        let error = load_server_config(&cert_file, &key_file).expect_err("must fail");
        assert!(matches!(error, Error::Tls(_)));
    }

    #[test]
    fn quic_config_only_offers_h3_alpn() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_file = dir.path().join("cert.pem");
        let key_file = dir.path().join("key.pem");
        std::fs::write(&cert_file, certified.cert.pem()).expect("write cert");
        std::fs::write(&key_file, certified.signing_key.serialize_pem()).expect("write key");

        let config = load_quic_server_config(&cert_file, &key_file).expect("valid config");
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[cfg(unix)]
    #[test]
    fn flags_world_accessible_private_key_modes() {
        assert!(!private_key_is_world_accessible(0o600));
        assert!(!private_key_is_world_accessible(0o640));
        assert!(private_key_is_world_accessible(0o604));
        assert!(private_key_is_world_accessible(0o644));
    }
}
