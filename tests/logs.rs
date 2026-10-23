#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

const RULE_MATCH: &str = "2026-10-21T18:35:17+0900 host kunato[22992]: 2026-10-21T09:35:17.234772Z  INFO kunato::proxy::server: rule matched category=sql-injection rule=union-select action=\"BLOCK\" client=203.0.113.9 method=GET path=/search";
const OTHER_IP: &str = "2026-10-21T18:35:18+0900 host kunato[22992]: 2026-10-21T09:35:18.234772Z  INFO kunato::proxy::server: rule matched category=xss rule=script-tags action=\"BLOCK\" client=198.51.100.7 method=GET path=/comment";
const RATE_LIMIT: &str = "2026-10-21T18:35:19+0900 host kunato[22992]: 2026-10-21T09:35:19.234772Z  INFO kunato::proxy::server: rate limit exceeded event=\"protection.rate_limit\" client=203.0.113.9 peer=203.0.113.9:54321 status=429 retry_after_ms=250 suppressed=4 method=GET path=/search";

fn fake_journal(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("journalctl");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\ncat <<'EOF_JOURNAL'\n{RULE_MATCH}\n{OTHER_IP}\n{RATE_LIMIT}\nEOF_JOURNAL\n"
        ),
    )
    .expect("write fake journalctl");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod");
    path
}

fn run_log(args: &[&str]) -> std::process::Output {
    let dir = TempDir::new().expect("temporary directory");
    let journal = fake_journal(&dir);
    let output = Command::new(env!("CARGO_BIN_EXE_kunato"))
        .arg("log")
        .arg("--journalctl")
        .arg(journal)
        .args(args)
        .output()
        .expect("run kunato log");
    assert!(
        output.status.success(),
        "kunato log failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn filters_json_by_ip_and_attack() {
    let output = run_log(&[
        "--format",
        "json",
        "--ip",
        "203.0.113.9",
        "--attack",
        "sqli",
    ]);
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["client"], "203.0.113.9");
    assert_eq!(lines[0]["attack"], "sql-injection");
    assert_eq!(lines[0]["event"], "block");
}

#[test]
fn filters_rate_limits_by_ip_and_status() {
    let output = run_log(&["--format", "json", "--ip", "203.0.113.9", "--status", "429"]);
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "rate-limit");
    assert_eq!(lines[0]["status"], 429);
    assert_eq!(lines[0]["fields"]["suppressed"], "4");
}

#[test]
fn default_output_is_the_journal_line() {
    let output = run_log(&["--ip", "198.51.100.7"]);
    let text = String::from_utf8(output.stdout).expect("utf8");
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("2026-10-21T18:35:18+0900 host kunato[22992]:"));
    assert!(text.contains("client=198.51.100.7"));
}

#[test]
fn lists_attack_types_without_the_journal() {
    let dir = TempDir::new().expect("temporary directory");
    let missing = dir.path().join("does-not-exist");
    let output = Command::new(env!("CARGO_BIN_EXE_kunato"))
        .args(["log", "--list-attacks", "--journalctl"])
        .arg(missing)
        .output()
        .expect("run kunato log");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf8");
    assert!(text.contains("sql-injection"));
    assert!(text.contains("path-traversal"));
    assert!(text.contains("cve"));
}
