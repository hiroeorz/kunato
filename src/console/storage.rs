//! Synchronous, bounded SQLite operations for the console's dedicated worker.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};

use super::model::{
    Checkpoint, EventRecord, MAX_BATCH_BYTES, MAX_RECORD_BYTES, MetricBucket, SourceIdentity,
    WriteBatch,
};
use super::{Error, validate_duration};

const APPLICATION_ID: i64 = 0x4b55_4e43;
const SCHEMA_VERSION: i64 = 3;
const PAGE_BYTES: u64 = 4096;
const JOURNAL_RESERVE: u64 = 65_536;
const SCHEMA: &str = "
CREATE TABLE events (
 source TEXT NOT NULL, generation TEXT NOT NULL, sequence INTEGER NOT NULL,
 event_id TEXT NOT NULL, occurred_at INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source, generation, sequence), UNIQUE(source, generation, event_id)
) STRICT;
CREATE INDEX events_time ON events(source, generation, occurred_at, sequence);
CREATE TABLE metric_buckets (
 source TEXT NOT NULL, generation TEXT NOT NULL, site TEXT NOT NULL,
 start_ms INTEGER NOT NULL, revision INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source, generation, site, start_ms)
) STRICT;
CREATE INDEX metric_time ON metric_buckets(source, generation, start_ms, site);
CREATE TABLE checkpoints (
 source TEXT NOT NULL, generation TEXT NOT NULL, sequence INTEGER NOT NULL,
 payload TEXT NOT NULL, fingerprint BLOB NOT NULL,
 PRIMARY KEY(source, generation)
) STRICT;";

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub directory: PathBuf,
    /// Budget for the database and its rollback journal together.
    pub max_bytes: u64,
    pub busy_timeout: Duration,
    pub operation_timeout: Duration,
    /// Selected detail is independent of the fixed 30-day statistics horizon.
    pub event_retention: Duration,
    /// UTC clock injection for deterministic offline history tests.
    pub clock: fn() -> u64,
}

impl StorageConfig {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            max_bytes: 1024 * 1024 * 1024,
            busy_timeout: Duration::from_millis(25),
            operation_timeout: Duration::from_millis(250),
            event_retention: Duration::from_secs(7 * 24 * 60 * 60),
            clock: super::history_store::system_time_ms,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        super::model::timestamp((self.clock)())?;
        if self.event_retention < Duration::from_millis(1) {
            return Err(Error::Invalid("event retention is below clock resolution"));
        }
        if self.directory.as_os_str().is_empty()
            || !(256 * 1024..=1024_u64.pow(4)).contains(&self.max_bytes)
        {
            return Err(Error::Invalid("invalid storage directory or capacity"));
        }
        validate_duration(self.operation_timeout, Duration::from_secs(5))?;
        validate_duration(
            self.event_retention,
            Duration::from_millis(super::history::RETENTION_MS),
        )?;
        validate_duration(self.busy_timeout, self.operation_timeout)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadWindow {
    pub from_ms: u64,
    pub until_ms: u64,
    pub limit: usize,
}

impl ReadWindow {
    fn validate(self) -> Result<(), Error> {
        super::model::timestamp(self.from_ms)?;
        super::model::timestamp(self.until_ms)?;
        if self.from_ms >= self.until_ms || !(1..=256).contains(&self.limit) {
            return Err(Error::Invalid("invalid bounded read window"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub events_inserted: usize,
    pub metrics_written: usize,
    pub replayed: bool,
    pub stale: bool,
    pub expired_events: usize,
    pub expired_metrics: usize,
}

pub(crate) struct PreparedBatch {
    pub records: usize,
    pub has_events: bool,
    pub bytes: usize,
    payload: Vec<u8>,
    fingerprint: Vec<u8>,
}

impl PreparedBatch {
    pub fn new(batch: &WriteBatch) -> Result<Self, Error> {
        batch.validate()?;
        bounded_json(&batch.checkpoint)?;
        for event in &batch.events {
            bounded_json(event)?;
        }
        for metric in &batch.metrics {
            bounded_json(metric)?;
        }
        let payload = serde_json::to_vec(batch)
            .map_err(|_| Error::Invalid("observation serialization failed"))?;
        if payload.len() > MAX_BATCH_BYTES {
            return Err(Error::Invalid("batch exceeds encoded byte limit"));
        }
        let fingerprint = digest(&SHA256, &payload).as_ref().to_vec();
        let bytes = payload
            .capacity()
            .saturating_add(fingerprint.capacity())
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(256);
        Ok(Self {
            records: batch.record_count(),
            has_events: !batch.events.is_empty() || batch.metrics.is_empty(),
            bytes,
            payload,
            fingerprint,
        })
    }
}

pub struct Store {
    pub(super) connection: Connection,
    pub(super) config: StorageConfig,
    pub(super) cancel: Arc<AtomicBool>,
}

impl Store {
    pub fn open(config: StorageConfig) -> Result<Self, Error> {
        Self::open_cancellable(config, Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn open_cancellable(
        config: StorageConfig,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        config.validate()?;
        prepare_directory(&config.directory)?;
        let path = config.directory.join("history.sqlite3");
        prepare_database_file(&path)?;
        check_files(&config)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(config.busy_timeout)?;
        connection.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
            false,
        )?;
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_RECORD_BYTES * 4) as i32,
        )?;
        let mut store = Self {
            connection,
            config,
            cancel,
        };
        store.guarded(|store| store.initialize())?;
        Ok(store)
    }

    fn initialize(&mut self) -> Result<(), Error> {
        let application: i64 =
            self.connection
                .pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        let fresh = application == 0 && version == 0;
        if fresh {
            let objects: i64 = self.connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if objects != 0 {
                return Err(Error::ForeignDatabase);
            }
        } else {
            if application != APPLICATION_ID {
                return Err(Error::ForeignDatabase);
            }
            if !(1..=SCHEMA_VERSION).contains(&version) {
                return Err(Error::UnsupportedSchema(version));
            }
        }
        self.connection
            .pragma_update(None, "page_size", PAGE_BYTES as i64)?;
        let page_size: i64 = self
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        if page_size != PAGE_BYTES as i64 {
            return Err(Error::Invalid("unsupported database page size"));
        }
        let mode: String =
            self.connection
                .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
        if mode != "delete" {
            return Err(Error::Invalid("rollback journal mode is required"));
        }
        self.connection.execute_batch("PRAGMA synchronous = EXTRA; PRAGMA temp_store = MEMORY; PRAGMA cache_spill = OFF; PRAGMA cache_size = -2048;")?;
        self.connection.pragma_update(None, "foreign_keys", true)?;
        let pages = (self.config.max_bytes - JOURNAL_RESERVE) / (2 * PAGE_BYTES + 8);
        let current: i64 = self
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))?;
        if current > pages as i64 {
            return Err(Error::Capacity);
        }
        self.connection
            .pragma_update(None, "max_page_count", pages as i64)?;
        if fresh {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(SCHEMA)?;
            transaction.execute_batch(super::history_store::HISTORY_SCHEMA)?;
            transaction.execute_batch("CREATE INDEX metric_scope_time ON metric_buckets(source,site,start_ms,generation); CREATE INDEX metric_expiry ON metric_buckets(start_ms); CREATE INDEX events_expiry ON events(occurred_at); CREATE INDEX history_expiry ON history_buckets(start_ms);")?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }
        // Prepare real queries so a damaged or incomplete version-one schema fails at open.
        self.connection.prepare("SELECT sequence, payload, fingerprint FROM checkpoints WHERE source = ?1 AND generation = ?2")?;
        self.connection
            .prepare("SELECT event_id, payload FROM events WHERE occurred_at >= ?1")?;
        self.connection
            .prepare("SELECT revision, payload FROM metric_buckets WHERE start_ms >= ?1")?;
        if !fresh && version < SCHEMA_VERSION {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(super::history_store::HISTORY_SCHEMA)?;
            transaction.execute_batch("CREATE INDEX metric_scope_time ON metric_buckets(source,site,start_ms,generation); CREATE INDEX metric_expiry ON metric_buckets(start_ms); CREATE INDEX events_expiry ON events(occurred_at); CREATE INDEX history_expiry ON history_buckets(start_ms);")?;
            transaction.execute(
                "INSERT INTO history_sources SELECT source,generation,?1 FROM checkpoints",
                [(self.config.clock)() as i64],
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }
        self.connection.prepare(
            "SELECT expiry_ms,event_expiry_ms,revision FROM history_state WHERE singleton=1",
        )?;
        self.connection
            .prepare("SELECT reason,payload FROM rejection_buckets WHERE source=?1")?;
        Ok(())
    }

    pub fn write_batch(&mut self, batch: &WriteBatch) -> Result<WriteReport, Error> {
        let prepared = PreparedBatch::new(batch)?;
        self.write_many(&[prepared])?
            .pop()
            .ok_or(Error::Invalid("empty write result"))
    }

    pub(crate) fn write_many(
        &mut self,
        batches: &[PreparedBatch],
    ) -> Result<Vec<WriteReport>, Error> {
        self.guarded(|store| {
            check_files(&store.config)?;
            let cancel = store.cancel.clone();
            let deadline = Instant::now() + store.config.operation_timeout;
            let transaction = store.connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let now = (store.config.clock)();
            let (expiry,event_expiry) = super::history_store::advance_expiry(&transaction,now,store.config.event_retention)?;
            check_deadline(&cancel, deadline)?;
            let mut reports = Vec::with_capacity(batches.len());
            for prepared in batches {
                check_deadline(&cancel, deadline)?;
                let batch: WriteBatch = decode_batch(&prepared.payload)?;
                let source = &batch.checkpoint.source;
                let previous: Option<(i64, Vec<u8>)> = transaction.query_row(
                    "SELECT sequence, fingerprint FROM checkpoints WHERE source = ?1 AND generation = ?2",
                    params![source.instance, source.generation], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
                let mut report = WriteReport::default();
                if let Some((sequence, fingerprint)) = &previous {
                    if *sequence > batch.checkpoint.sequence as i64 { report.stale = true; reports.push(report); continue; }
                    if *sequence == batch.checkpoint.sequence as i64 {
                        if *fingerprint != prepared.fingerprint { return Err(Error::Conflict); }
                        report.replayed = true; reports.push(report); continue;
                    }
                }
                let old_sequence = previous.map_or(0, |(sequence, _)| sequence);
                for event in &batch.events {
                    if event.sequence as i64 <= old_sequence { continue; }
                    if event.occurred_at_ms < event_expiry { report.expired_events += 1; continue; }
                    transaction.execute("INSERT INTO events(source,generation,sequence,event_id,occurred_at,payload) VALUES (?1,?2,?3,?4,?5,?6)",
                        params![source.instance, source.generation, event.sequence as i64, event.id, event.occurred_at_ms as i64, bounded_json(event)?])?;
                    report.events_inserted += 1;
                }
                for metric in &batch.metrics {
                    if metric.revision as i64 <= old_sequence { continue; }
                    if metric.start_ms < expiry { report.expired_metrics += 1; continue; }
                    let site = metric.site.as_deref().unwrap_or("");
                    if super::history_store::compacted(&transaction,&source.instance,site,metric.start_ms)? { return Err(Error::CompactedInput); }
                    report.metrics_written += transaction.execute("INSERT INTO metric_buckets(source,generation,site,start_ms,revision,payload) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(source,generation,site,start_ms) DO UPDATE SET revision=excluded.revision,payload=excluded.payload WHERE excluded.revision > metric_buckets.revision",
                        params![source.instance, source.generation, metric.site.as_deref().unwrap_or(""), metric.start_ms as i64, metric.revision as i64, bounded_json(metric)?])?;
                    transaction.execute("INSERT INTO history_dirty(source,site,start_ms) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",params![source.instance,site,metric.start_ms as i64])?;
                }
                transaction.execute("INSERT INTO checkpoints(source,generation,sequence,payload,fingerprint) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(source,generation) DO UPDATE SET sequence=excluded.sequence,payload=excluded.payload,fingerprint=excluded.fingerprint",
                    params![source.instance, source.generation, batch.checkpoint.sequence as i64, bounded_json(&batch.checkpoint)?, prepared.fingerprint])?;
                transaction.execute("INSERT INTO history_sources(source,generation,seen_ms) VALUES(?1,?2,?3) ON CONFLICT(source,generation) DO UPDATE SET seen_ms=max(seen_ms,excluded.seen_ms)",params![source.instance,source.generation,now as i64])?;
                reports.push(report);
            }
            check_deadline(&cancel, deadline)?;
            transaction.commit()?;
            Ok(reports)
        })
    }

    pub fn checkpoint(&mut self, source: &SourceIdentity) -> Result<Option<Checkpoint>, Error> {
        source.validate()?;
        self.guarded(|store| {
            let payload: Option<String> = store
                .connection
                .query_row(
                    "SELECT payload FROM checkpoints WHERE source=?1 AND generation=?2",
                    params![source.instance, source.generation],
                    |row| row.get(0),
                )
                .optional()?;
            let checkpoint: Option<Checkpoint> =
                payload.as_deref().map(decode_record).transpose()?;
            if let Some(checkpoint) = &checkpoint {
                checkpoint.validate()?;
                if checkpoint.source != *source {
                    return Err(Error::Invalid("stored checkpoint source mismatch"));
                }
            }
            Ok(checkpoint)
        })
    }

    pub fn events(
        &mut self,
        source: &SourceIdentity,
        window: ReadWindow,
    ) -> Result<Vec<EventRecord>, Error> {
        let records: Vec<EventRecord> = self.read(source, window, "SELECT payload FROM events WHERE source=?1 AND generation=?2 AND occurred_at>=?3 AND occurred_at<?4 ORDER BY occurred_at,sequence LIMIT ?5",true)?;
        for record in &records {
            record.validate()?;
        }
        Ok(records)
    }

    pub fn metrics(
        &mut self,
        source: &SourceIdentity,
        window: ReadWindow,
    ) -> Result<Vec<MetricBucket>, Error> {
        let records: Vec<MetricBucket> = self.read(source, window, "SELECT payload FROM metric_buckets WHERE source=?1 AND generation=?2 AND start_ms>=?3 AND start_ms<?4 ORDER BY start_ms,site LIMIT ?5",false)?;
        for record in &records {
            record.validate()?;
        }
        Ok(records)
    }

    fn read<T: DeserializeOwned>(
        &mut self,
        source: &SourceIdentity,
        window: ReadWindow,
        sql: &str,
        detail: bool,
    ) -> Result<Vec<T>, Error> {
        source.validate()?;
        window.validate()?;
        self.guarded(|store| {
            check_files(&store.config)?;
            let cutoff = if detail {
                super::history_store::advance_expiry(
                    &store.connection,
                    (store.config.clock)(),
                    store.config.event_retention,
                )?
                .1
            } else {
                super::history_store::statistics_expiry(&store.connection, (store.config.clock)())?
            };
            let mut statement = store.connection.prepare(sql)?;
            let rows = statement.query_map(
                params![
                    source.instance,
                    source.generation,
                    window.from_ms.max(cutoff) as i64,
                    window.until_ms as i64,
                    window.limit as i64
                ],
                |row| row.get::<_, String>(0),
            )?;
            rows.map(|row| decode_record(&row?)).collect()
        })
    }

    pub(super) fn guarded<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        let deadline = Instant::now() + self.config.operation_timeout;
        let cancel = self.cancel.clone();
        self.connection.progress_handler(
            1000,
            Some(move || cancel.load(Ordering::Acquire) || Instant::now() >= deadline),
        )?;
        let result = operation(self);
        self.connection.progress_handler(0, None::<fn() -> bool>)?;
        if self.cancel.load(Ordering::Acquire) && matches!(result, Err(Error::OperationTimeout)) {
            return Err(Error::Cancelled);
        }
        result
    }
}

pub(super) fn check_deadline(cancel: &AtomicBool, deadline: Instant) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Error::OperationTimeout);
    }
    Ok(())
}

fn bounded_json<T: Serialize>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_string(value)
        .map_err(|_| Error::Invalid("observation serialization failed"))?;
    if json.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("record exceeds encoded byte limit"));
    }
    Ok(json)
}

pub(super) fn decode_record<T: DeserializeOwned>(json: &str) -> Result<T, Error> {
    if json.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid("stored record exceeds byte limit"));
    }
    serde_json::from_str(json).map_err(|_| Error::Invalid("invalid stored observation"))
}

fn decode_batch(json: &[u8]) -> Result<WriteBatch, Error> {
    serde_json::from_slice(json).map_err(|_| Error::Invalid("invalid prepared observation batch"))
}

fn prepare_directory(path: &Path) -> Result<(), Error> {
    if !path.try_exists()? {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    check_private(path, true)
}

fn prepare_database_file(path: &Path) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    check_private(path, false)
}

fn check_private(path: &Path, directory: bool) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(Error::Invalid(
            "storage paths must be regular private files and directories",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(Error::Invalid(
                "storage permissions must exclude group and other access",
            ));
        }
        if !directory && metadata.nlink() != 1 {
            return Err(Error::Invalid("database files must not have hard links"));
        }
    }
    Ok(())
}

pub(super) fn check_files(config: &StorageConfig) -> Result<(), Error> {
    let mut bytes = 0_u64;
    for name in [
        "history.sqlite3",
        "history.sqlite3-journal",
        "history.sqlite3-wal",
        "history.sqlite3-shm",
    ] {
        let path = config.directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                check_private(&path, false)?;
                bytes = bytes.saturating_add(metadata.len());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if bytes > config.max_bytes {
        return Err(Error::Capacity);
    }
    Ok(())
}
