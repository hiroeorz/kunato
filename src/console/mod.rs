//! Console persistence foundations. No collector, listener, or WAF integration.

pub mod model;
pub mod storage;
pub mod writer;

use std::time::Duration;

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
    #[error("console persistence worker stopped")]
    WorkerStopped,
    #[error("console persistence initialization timed out")]
    StartupTimeout,
    #[error("persistence receipt timed out; commit outcome is not yet known")]
    ReceiptTimeout,
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
