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
    if !installer.starts_with(b"#!/bin/sh") {
        return Err(Error::Message(
            "the downloaded installer does not look like a shell script".to_owned(),
        ));
    }
    println!("running the installer from {url}");

    let mut command = Command::new("sh");
    command.arg("-s").arg("--");
    if let Some(tag) = &tag {
        command.arg("--version").arg(tag);
    }
    command.arg("--yes");
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
    Ok(match tag {
        Some(tag) => {
            format!("{RELEASE_BASE}/download/{}/install.sh", normalize_tag(tag)?)
        }
        None => format!("{RELEASE_BASE}/latest/download/install.sh"),
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
