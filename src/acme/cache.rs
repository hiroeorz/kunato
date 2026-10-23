//! Certificate and account-key cache for the ACME service.
//!
//! Files are written atomically next to their destination and narrowed to
//! mode 0600 inside a 0700 directory, because `cert.pem` contains the
//! certificate private key and `account.key` is the ACME account credential.

use std::io;
use std::path::{Path, PathBuf};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub(crate) const CERT_FILE_NAME: &str = "cert.pem";
pub(crate) const ACCOUNT_FILE_NAME: &str = "account.key";
pub(crate) const META_FILE_NAME: &str = "cert.meta.json";

/// The certificate chain plus private key is small; anything larger than this
/// is not a cache entry we wrote and must not be read or rewritten.
const MAX_CACHE_BYTES: u64 = 2 * 1024 * 1024;

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

pub(crate) async fn load_meta(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    load(&dir.join(META_FILE_NAME)).await
}

pub(crate) async fn store_meta(dir: &Path, contents: &[u8]) -> io::Result<()> {
    store(dir, &dir.join(META_FILE_NAME), contents).await
}

async fn load(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is not a regular file",
        ));
    }
    if metadata.len() > MAX_CACHE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is too large",
        ));
    }
    restrict_existing_file(path, &metadata).await?;

    let file = tokio::fs::File::open(path).await?;
    let mut file = file.take(MAX_CACHE_BYTES + 1);
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await?;
    if contents.len() as u64 > MAX_CACHE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is too large",
        ));
    }
    Ok(Some(contents))
}

async fn store(dir: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    if contents.len() as u64 > MAX_CACHE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is too large",
        ));
    }

    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        builder.mode(0o700);
    }
    builder.create(dir).await?;
    set_dir_permissions(dir).await?;

    // A random suffix plus `create_new` prevents a pre-created file or symlink
    // from redirecting the private-key write.
    let tmp = temp_path(path)?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
        {
            drop(file);
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
    }

    let written = async {
        file.write_all(contents).await?;
        file.flush().await?;
        file.sync_all().await
    }
    .await;
    drop(file);
    if let Err(err) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(err);
    }

    match tokio::fs::rename(&tmp, path).await {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(err)
        }
    }
}

fn temp_path(path: &Path) -> io::Result<PathBuf> {
    let mut name = path.as_os_str().to_owned();
    let mut suffix = [0u8; 8];
    SystemRandom::new()
        .fill(&mut suffix)
        .map_err(|err| io::Error::other(format!("{err:?}")))?;
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    name.push(format!(".{suffix}.tmp"));
    Ok(PathBuf::from(name))
}

#[cfg(unix)]
async fn restrict_existing_file(path: &Path, metadata: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn restrict_existing_file(_path: &Path, _metadata: &std::fs::Metadata) -> io::Result<()> {
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
        store_meta(&cache_dir, b"meta").await.expect("store meta");
        assert_eq!(
            load_cert(&cache_dir).await.expect("load"),
            Some(b"cert".to_vec())
        );
        assert_eq!(
            load_account(&cache_dir).await.expect("load"),
            Some(b"account".to_vec())
        );
        assert_eq!(
            load_meta(&cache_dir).await.expect("load"),
            Some(b"meta".to_vec())
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
            assert_eq!(mode(&cache_dir.join(META_FILE_NAME)), 0o600);
            assert_eq!(mode(&cache_dir), 0o700);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_cache_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .expect("create dir");
        let target = dir.path().join("target");
        tokio::fs::write(&target, b"secret").await.expect("target");
        std::os::unix::fs::symlink(&target, cache_dir.join(CERT_FILE_NAME)).expect("symlink");
        let error = load_cert(&cache_dir).await.expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn does_not_follow_a_precreated_temp_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .expect("create dir");
        let target = dir.path().join("target");
        tokio::fs::write(&target, b"target").await.expect("target");
        std::os::unix::fs::symlink(&target, cache_dir.join("cert.pem.tmp")).expect("symlink");
        store_cert(&cache_dir, b"cert").await.expect("store");
        assert_eq!(
            tokio::fs::read(&target).await.expect("target"),
            b"target".to_vec()
        );
        assert_eq!(
            load_cert(&cache_dir).await.expect("load"),
            Some(b"cert".to_vec())
        );
    }

    #[tokio::test]
    async fn rejects_oversized_cache_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .expect("create dir");
        tokio::fs::write(
            cache_dir.join(CERT_FILE_NAME),
            vec![0u8; (MAX_CACHE_BYTES + 1) as usize],
        )
        .await
        .expect("write");
        let error = load_cert(&cache_dir).await.expect_err("must reject");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tightens_preexisting_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_dir = dir.path().join("acme");
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .expect("create dir");
        let path = cache_dir.join(CERT_FILE_NAME);
        tokio::fs::write(&path, b"cert").await.expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            load_cert(&cache_dir).await.expect("load"),
            Some(b"cert".to_vec())
        );
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
