use tracing_subscriber::EnvFilter;

use crate::cli::LogFormat;
use crate::error::Error;

pub fn init(level: Option<&str>, format: LogFormat) -> Result<(), Error> {
    let filter = match level {
        Some(level) => {
            EnvFilter::try_new(level).map_err(|err| Error::Telemetry(err.to_string()))?
        }
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    }
    .map_err(|err| Error::Telemetry(err.to_string()))
}
