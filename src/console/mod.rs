//! Console collection and persistence foundations, independent of WAF forwarding.

pub mod asn;
pub mod collector;
pub mod correlations;
pub mod edr;
pub mod history;
mod history_store;
pub mod measurements;
pub mod model;
pub mod runtime;
pub mod server;
pub mod storage;
pub mod writer;

use std::time::Duration;

pub use asn::{AsnDb, AsnLookup, AsnSource, AsnState};
pub use collector::HistoryReader;
pub use history::{HistoryBucket, HistoryPage, HistoryQuery, MaintenanceReport};
pub use storage::{ReadWindow, StorageConfig, Store, WriteReport};
pub use writer::{Health, Receipt, ShutdownReport, SubmitError, Writer, WriterConfig, WriterState};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid console storage input: {0}")]
    Invalid(&'static str),
    #[error("console storage I/O error: {0}")]
    Io(String),
    #[error("console database error: {0}")]
    Database(String),
    #[error("unsupported console database schema version {0}")]
    UnsupportedSchema(i64),
    #[error("the file is not an initialized Kunato console database")]
    ForeignDatabase,
    #[error("console storage capacity reached")]
    Capacity,
    #[error("console database is busy")]
    Busy,
    #[error("console storage operation cancelled")]
    Cancelled,
    #[error("console database operation timed out")]
    OperationTimeout,
    #[error("conflicting console source position or record identity")]
    Conflict,
    #[error("minute input was already compacted; its discarded provenance cannot be corrected")]
    CompactedInput,
    #[error("history changed; restart the paginated read")]
    HistoryChanged,
    #[error("console persistence worker stopped")]
    WorkerStopped,
    #[error("console persistence initialization timed out")]
    StartupTimeout,
    #[error("persistence receipt timed out; commit outcome is not yet known")]
    ReceiptTimeout,
}

impl From<Error> for crate::error::Error {
    fn from(error: Error) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DiskFull) => Self::Capacity,
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            Some(rusqlite::ErrorCode::ConstraintViolation) => Self::Conflict,
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::OperationTimeout,
            _ => Self::Database(error.to_string().chars().take(512).collect()),
        }
    }
}

pub(crate) fn validate_duration(value: Duration, max: Duration) -> Result<(), Error> {
    if value.is_zero() || value > max {
        return Err(Error::Invalid("duration outside supported bounds"));
    }
    Ok(())
}

/// Validate a configured console history instance name.
pub fn validate_instance(value: &str) -> Result<(), Error> {
    model::identifier(value, 120)
}
