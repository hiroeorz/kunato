use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read configuration file `{path}`: {source}")]
    ConfigRead { path: PathBuf, source: io::Error },

    #[error("failed to parse configuration: {0}")]
    ConfigParse(#[from] serde_yaml_ng::Error),

    #[error("invalid configuration:\n{}", format_issues(.0))]
    ConfigInvalid(Vec<String>),

    #[error("failed to bind `{addr}`: {source}")]
    Bind { addr: String, source: io::Error },

    #[error("logging setup failed: {0}")]
    Telemetry(String),

    #[error(transparent)]
    Io(#[from] io::Error),
}

fn format_issues(issues: &[String]) -> String {
    issues
        .iter()
        .map(|issue| format!("  - {issue}"))
        .collect::<Vec<_>>()
        .join("\n")
}
