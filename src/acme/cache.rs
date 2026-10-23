//! Certificate and account-key cache for the ACME service.
//!
//! Files are written atomically next to their destination and narrowed to
//! mode 0600 inside a 0700 directory, because `cert.pem` contains the
//! certificate private key and `account.key` is the ACME account credential.

use std::io;
use std::path::{Path, PathBuf};

pub(crate) const CERT_FILE_NAME: &str = "cert.pem";
pub(crate) const ACCOUNT_FILE_NAME: &str = "account.key";

pub(crate) async fn load_cert(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    load(&dir.join(CERT_FILE_NAME)).await
}

pub(crate) async fn store_cert(dir: &Path, contents: &[u8]) -> io::Result<()> {
    store(dir, &dir.join(CERT_FILE_NAME), contents).await
}

pub(crate) async fn load_account(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    load(&dir.join(ACCOUNT_FILE_NAME)).await
}

pub(crate) async fn store_account(dir: &Path, contents: &[u8]) -> io::Result<()> {
    store(dir, &dir.join(ACCOUNT_FILE_NAME), contents).await
}

async fn load(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match tokio::fs::read(path).await {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

async fn store(dir: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    set_dir_permissions(dir).await?;

    let tmp = temp_path(path);
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).await?;
    // `mode` only applies when the file is created; an older temp file may
    // have wider permissions, so narrow it before writing key material.
    set_file_permissions(&tmp).await?;
    use tokio::io::AsyncWriteExt as _;
    file.write_all(contents).await?;
    file.flush().await?;
    drop(file);

    match tokio::fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(err)
        }
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

#[cfg(unix)]
async fn set_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn set_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn set_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn set_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_and_tightens_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");

        assert_eq!(load_cert(&cache_dir).await.expect("load"), None);

        store_cert(&cache_dir, b"cert").await.expect("store cert");
        store_account(&cache_dir, b"account")
            .await
            .expect("store account");
        assert_eq!(
            load_cert(&cache_dir).await.expect("load"),
            Some(b"cert".to_vec())
        );
        assert_eq!(
            load_account(&cache_dir).await.expect("load"),
            Some(b"account".to_vec())
        );

        store_cert(&cache_dir, b"renewed")
            .await
            .expect("replace cert");
        assert_eq!(
            load_cert(&cache_dir).await.expect("load"),
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
            assert_eq!(mode(&cache_dir.join(CERT_FILE_NAME)), 0o600);
            assert_eq!(mode(&cache_dir.join(ACCOUNT_FILE_NAME)), 0o600);
            assert_eq!(mode(&cache_dir), 0o700);
        }
    }
}
