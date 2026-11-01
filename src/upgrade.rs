//! `kunato upgrade`: rerun the official installer for a release.
//!
//! The installer remains the single source of truth for upgrading a server:
//! it replaces the binary and the systemd unit, keeps the configuration, and
//! restarts the service. This command downloads the installer published with
//! the target release (an immutable asset, the same file the documented
//! `curl ... | sudo sh` path runs) and pipes it to `sh`, exactly like that
//! manual command. The installer reads its prompts from `/dev/tty`, never
//! from stdin, and `--yes` keeps it noninteractive.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::cli::UpgradeArgs;
use crate::error::Error;
use crate::rules_update;

/// Release downloads live under this prefix; the installer asset is published
/// by the release workflow next to the binaries.
const RELEASE_BASE: &str = "https://github.com/hiroeorz/kunato/releases";
/// The installer script is a few kilobytes; the bound keeps a hostile or
/// broken response from being read into memory.
const MAX_INSTALLER_BYTES: usize = 256 * 1024;
/// Detached minisign signature published next to the installer.
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;

pub async fn run(args: UpgradeArgs) -> Result<(), Error> {
    let tag = args.version.as_deref().map(normalize_tag).transpose()?;
    let url = installer_url(tag.as_deref())?;

    if args.dry_run {
        println!("would download {url}");
        println!(
            "would run: sh -s --{} --yes",
            tag.as_deref()
                .map(|tag| format!(" --version {tag}"))
                .unwrap_or_default()
        );
        return Ok(());
    }

    if let Some(uid) = effective_uid()
        && uid != 0
    {
        return Err(Error::Message(
            "kunato upgrade must run as root (try: sudo kunato upgrade)".to_owned(),
        ));
    }

    let installer = rules_update::fetch_release_asset(&url, MAX_INSTALLER_BYTES).await?;
    verify_installer(&url, &installer).await?;
    if !installer.starts_with(b"#!/bin/sh") {
        return Err(Error::Message(
            "the downloaded installer does not look like a shell script".to_owned(),
        ));
    }
    let checksums_url = checksums_url(tag.as_deref())?;
    let checksums = rules_update::fetch_release_asset(&checksums_url, MAX_INSTALLER_BYTES).await?;
    verify_release_asset(&checksums_url, &checksums, "SHA256SUMS").await?;
    let verified_checksums = write_verified_checksums(&checksums)?;
    let _cleanup = TempFileGuard(&verified_checksums);
    println!("running the installer from {url}");

    let mut command = installer_command(tag.as_deref());
    command.env("KUNATO_VERIFIED_SHA256SUMS", &verified_checksums);
    command.stdin(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|err| Error::Message(format!("failed to run the installer: {err}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        // The installer can exit before it reads the whole script (a failed
        // precondition, for example); the exit status below is authoritative,
        // so a broken pipe here is ignored.
        let _ = stdin.write_all(&installer);
    }
    let status = child
        .wait()
        .map_err(|err| Error::Message(format!("failed to wait for the installer: {err}")))?;
    if !status.success() {
        return Err(Error::Message(format!(
            "the installer exited with {status}"
        )));
    }
    Ok(())
}

/// Verify the detached minisign signature of the installer before it runs as
/// root. With no trusted release key embedded the check is skipped with a
/// warning, so builds without keys can still upgrade.
async fn verify_installer(url: &str, installer: &[u8]) -> Result<(), Error> {
    verify_release_asset(url, installer, "installer").await
}

async fn verify_release_asset(url: &str, asset: &[u8], label: &str) -> Result<(), Error> {
    if crate::trust::RELEASE_KEYS.is_empty() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "no release signing key is embedded in this build; release assets are not verified"
            );
        });
        return Ok(());
    }
    let signature_url = format!("{url}.minisig");
    let signature = rules_update::fetch_release_asset(&signature_url, MAX_SIGNATURE_BYTES).await?;
    let signature = std::str::from_utf8(&signature)
        .map_err(|_| Error::Message(format!("{label} signature is not valid UTF-8")))?;
    match crate::trust::verify_release(asset, signature)? {
        crate::trust::Verification::Verified => Ok(()),
        crate::trust::Verification::NoTrustedKeys => Ok(()),
    }
}

struct TempFileGuard<'a>(&'a std::path::Path);

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

fn write_verified_checksums(bytes: &[u8]) -> Result<std::path::PathBuf, Error> {
    use ring::rand::{SecureRandom, SystemRandom};
    use std::os::unix::fs::OpenOptionsExt;

    let mut random = [0u8; 8];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| Error::Message("failed to generate temporary file name".to_owned()))?;
    let mut suffix = String::with_capacity(16);
    for byte in random {
        suffix.push_str(&format!("{byte:02x}"));
    }
    let path = std::env::temp_dir().join(format!(
        ".kunato-sha256sums.{}.{suffix}",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(path)
}

/// Build the shell invocation for the downloaded installer. The environment is
/// cleared: `kunato upgrade` runs as root, so a variable inherited from the
/// caller (`KUNATO_BASE_URL`, `PATH` with a planted `curl`) must not steer the
/// install. `PATH` is pinned to the standard system directories so the script
/// finds `curl`, `tar`, and `sha256sum` without trusting the caller's `PATH`.
fn installer_command(tag: Option<&str>) -> Command {
    const FALLBACK_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    let mut command = Command::new("/bin/sh");
    command.arg("-s").arg("--");
    if let Some(tag) = tag {
        command.arg("--version").arg(tag);
    }
    command.arg("--yes");
    command.env_clear();
    command.env("PATH", FALLBACK_PATH);
    command
}

/// Validate and normalize a release tag: `0.4.0` and `v0.4.0` name the same
/// tag. The result is passed to the installer as an argument and embedded in
/// a URL, so only a conservative character set is accepted and a leading `-`
/// is rejected.
pub fn normalize_tag(tag: &str) -> Result<String, Error> {
    let tag = tag.trim();
    let bare = tag.strip_prefix('v').unwrap_or(tag);
    let valid = !bare.is_empty()
        && bare.len() <= 64
        && !bare.starts_with('-')
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !valid {
        return Err(Error::Message(format!("invalid release tag `{tag}`")));
    }
    Ok(format!("v{bare}"))
}

/// URL of the installer asset for a pinned tag, or for the latest release.
pub fn installer_url(tag: Option<&str>) -> Result<String, Error> {
    release_asset_url(tag, "install.sh")
}

/// URL of the `SHA256SUMS` asset for a pinned tag, or for the latest release.
pub fn checksums_url(tag: Option<&str>) -> Result<String, Error> {
    release_asset_url(tag, "SHA256SUMS")
}

fn release_asset_url(tag: Option<&str>, asset: &str) -> Result<String, Error> {
    Ok(match tag {
        Some(tag) => {
            format!("{RELEASE_BASE}/download/{}/{asset}", normalize_tag(tag)?)
        }
        None => format!("{RELEASE_BASE}/latest/download/{asset}"),
    })
}

/// Effective user id from `/proc/self/status`. `None` when the file cannot be
/// read (not Linux); the installer repeats the check itself, so skipping it
/// is safe.
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_effective_uid(&status)
}

fn parse_effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .and_then(|euid| euid.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_and_prefixed_tags() {
        assert_eq!(normalize_tag("0.4.0").unwrap(), "v0.4.0");
        assert_eq!(normalize_tag("v0.4.0").unwrap(), "v0.4.0");
        assert_eq!(normalize_tag(" v0.4.0-rc.1 ").unwrap(), "v0.4.0-rc.1");
    }

    #[test]
    fn rejects_tags_that_could_confuse_the_installer_or_url() {
        for tag in [
            "",
            "v",
            "-e",
            "--evil",
            "v1.0.0 extra",
            "v1.0.0/x",
            "ü1.0.0",
        ] {
            assert!(normalize_tag(tag).is_err(), "expected `{tag}` to fail");
        }
        let long = format!("v{}", "1".repeat(80));
        assert!(normalize_tag(&long).is_err());
    }

    #[test]
    fn builds_installer_urls() {
        assert_eq!(
            installer_url(None).unwrap(),
            "https://github.com/hiroeorz/kunato/releases/latest/download/install.sh"
        );
        assert_eq!(
            installer_url(Some("0.4.0")).unwrap(),
            "https://github.com/hiroeorz/kunato/releases/download/v0.4.0/install.sh"
        );
        assert_eq!(
            installer_url(Some("v0.4.0")).unwrap(),
            "https://github.com/hiroeorz/kunato/releases/download/v0.4.0/install.sh"
        );
    }

    #[test]
    fn the_installer_runs_with_a_cleared_environment() {
        let command = installer_command(Some("v0.4.0"));
        let environment: Vec<_> = command.get_envs().collect();
        assert_eq!(
            environment.len(),
            1,
            "only PATH may be inherited: {environment:?}"
        );
        assert_eq!(environment[0].0, "PATH");
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(arguments, ["-s", "--", "--version", "v0.4.0", "--yes"]);
    }

    #[test]
    fn parses_the_effective_uid() {
        assert_eq!(
            parse_effective_uid("Name:\tkunato\nUid:\t1000\t0\t1000\t1000\n"),
            Some(0)
        );
        assert_eq!(
            parse_effective_uid("Uid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(parse_effective_uid("Name:\tkunato\n"), None);
    }
}
