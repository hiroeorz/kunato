use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "kunato", version, about = "Personal-use WAF reverse proxy")]
pub struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "rules.yaml", value_name = "PATH")]
    pub config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    pub validate: bool,

    /// Log level filter (overrides RUST_LOG).
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Log output format.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}
