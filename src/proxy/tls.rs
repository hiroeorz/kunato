use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::Error;

pub fn load_server_config(cert_file: &Path, key_file: &Path) -> Result<Arc<ServerConfig>, Error> {
    let certificates = load_certificates(cert_file)?;
    let private_key = PrivateKeyDer::from_pem_file(key_file).map_err(|err| {
        Error::Tls(format!(
            "failed to read private key from `{}`: {err}",
            key_file.display()
        ))
    })?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| Error::Tls(format!("failed to initialize TLS: {err}")))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|err| Error::Tls(format!("invalid certificate or private key: {err}")))?;

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
}
