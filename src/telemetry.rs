//! Logging initialization and the in-tree `tracing` subscriber.
//!
//! The subscriber, its level/target filter, and the text and JSON formatters
//! live in this module. Records from the `log` crate (rustls and other
//! dependencies) are bridged directly so they use the same output format.

use std::io::{self, IsTerminal};
use std::sync::Arc;

use crate::cli::LogFormat;
use crate::error::Error;

mod filter;
mod format;
mod subscriber;

use subscriber::{LogBridge, Subscriber};

pub fn init(level: Option<&str>, format: LogFormat) -> Result<(), Error> {
    let filter = filter::Filter::from_arg(level).map_err(Error::Telemetry)?;
    let color = format == LogFormat::Text
        && io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none();
    let subscriber = Arc::new(Subscriber::new(
        filter,
        format,
        color,
        Box::new(io::stdout()),
    ));
    tracing::subscriber::set_global_default(Arc::clone(&subscriber))
        .map_err(|err| Error::Telemetry(err.to_string()))?;
    let logger: &'static dyn log::Log =
        Box::leak(Box::new(LogBridge::new(Arc::clone(&subscriber))));
    log::set_logger(logger).map_err(|err| Error::Telemetry(err.to_string()))?;
    log::set_max_level(subscriber.max_log_level());
    Ok(())
}
