//! Bounded materialization, atomic coarsening, and logical/physical history expiry.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};

use super::history::*;
use super::model::{MINUTE_MS, MetricBucket, RejectionReason};
use super::{Error, Store};

pub(super) const HISTORY_SCHEMA: &str = "
CREATE TABLE history_buckets (
 source TEXT NOT NULL, site TEXT NOT NULL, start_ms INTEGER NOT NULL,
 grain_ms INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source, site, start_ms)
) STRICT;
CREATE INDEX history_age ON history_buckets(grain_ms,start_ms,source,site);
CREATE TABLE rejection_buckets (
 source TEXT NOT NULL, site TEXT NOT NULL, start_ms INTEGER NOT NULL,
 reason TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source,site,start_ms,reason),
 FOREIGN KEY(source,site,start_ms) REFERENCES history_buckets(source,site,start_ms) ON DELETE CASCADE
) STRICT;
CREATE TABLE history_dirty (
 source TEXT NOT NULL, site TEXT NOT NULL, start_ms INTEGER NOT NULL,
 PRIMARY KEY(source,site,start_ms)
) STRICT;
CREATE INDEX history_dirty_time ON history_dirty(start_ms,source,site);
CREATE TABLE history_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 expiry_ms INTEGER NOT NULL, event_expiry_ms INTEGER NOT NULL,
 revision INTEGER NOT NULL
) STRICT;
INSERT INTO history_state VALUES(1,0,0,0);
CREATE TABLE history_sources (
 source TEXT NOT NULL, generation TEXT NOT NULL, seen_ms INTEGER NOT NULL,
 PRIMARY KEY(source,generation)
) STRICT;
CREATE INDEX history_sources_age ON history_sources(seen_ms,source,generation);
INSERT INTO history_dirty SELECT DISTINCT source,site,start_ms FROM metric_buckets;
";

pub fn system_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as u64
}

pub(super) fn advance_expiry(
    connection: &Connection,
    now_ms: u64,
    detail_retention: Duration,
) -> Result<(u64, u64), Error> {
    super::model::timestamp(now_ms)?;
    // Whole-hour expiry also discards the oldest straddling hour.
    let expiry = now_ms.saturating_sub(RETENTION_MS).div_ceil(HOUR_MS) * HOUR_MS;
    let detail = now_ms.saturating_sub(detail_retention.as_millis() as u64);
    connection.execute("UPDATE history_state SET expiry_ms=max(expiry_ms,?1),event_expiry_ms=max(event_expiry_ms,?2) WHERE singleton=1 AND (expiry_ms<?1 OR event_expiry_ms<?2)", params![expiry as i64, detail as i64])?;
    Ok(connection.query_row(
        "SELECT expiry_ms,event_expiry_ms FROM history_state WHERE singleton=1",
        [],
        |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
    )?)
}

pub(super) fn statistics_expiry(connection: &Connection, now_ms: u64) -> Result<u64, Error> {
    super::model::timestamp(now_ms)?;
    let wanted = now_ms.saturating_sub(RETENTION_MS).div_ceil(HOUR_MS) * HOUR_MS;
    let saved = connection.query_row(
        "SELECT expiry_ms FROM history_state WHERE singleton=1",
        [],
        |row| row.get::<_, i64>(0),
    )? as u64;
    if wanted > saved {
        connection.execute(
            "UPDATE history_state SET expiry_ms=max(expiry_ms,?1) WHERE singleton=1",
            [wanted as i64],
        )?;
        return Ok(connection.query_row(
            "SELECT expiry_ms FROM history_state WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )? as u64);
    }
    Ok(saved)
}

pub(super) fn compacted(
    connection: &Connection,
    source: &str,
    site: &str,
    at: u64,
) -> Result<bool, Error> {
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms<=?3 AND start_ms+grain_ms>?3 AND grain_ms>?4)",params![source,site,at as i64,MINUTE_MS as i64],|row| row.get(0))?)
}

impl Store {
    /// One finite maintenance transaction. Repeat while more_work is true, with a write budget.
    pub fn maintain(&mut self) -> Result<MaintenanceReport, Error> {
        self.maintain_at((self.config.clock)())
    }

    /// Explicit UTC time permits deterministic maintenance and recovery tests.
    pub fn maintain_at(&mut self, now_ms: u64) -> Result<MaintenanceReport, Error> {
        self.guarded(|store| {
            super::storage::check_files(&store.config)?;
            let deadline=Instant::now()+store.config.operation_timeout;
            let cancel=store.cancel.clone();
            let transaction = store.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changes_before = transaction.total_changes();
            let (expiry, event_expiry) = advance_expiry(&transaction, now_ms, store.config.event_retention)?;
            let mut report = MaintenanceReport { expiry_ms: expiry, ..MaintenanceReport::default() };
            // Including cascading reason rows, these deletes mutate fewer than 1,000 rows.
            for sql in [
                "DELETE FROM history_buckets WHERE rowid IN (SELECT rowid FROM history_buckets WHERE start_ms<?1 ORDER BY start_ms LIMIT 8)",
                "DELETE FROM metric_buckets WHERE rowid IN (SELECT rowid FROM metric_buckets WHERE start_ms<?1 ORDER BY start_ms LIMIT 64)",
                "DELETE FROM history_dirty WHERE rowid IN (SELECT rowid FROM history_dirty WHERE start_ms<?1 ORDER BY start_ms LIMIT 64)",
            ] { report.deleted_rows += transaction.execute(sql, [expiry as i64])? as u64; }
            report.deleted_rows += transaction.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE occurred_at<?1 ORDER BY occurred_at LIMIT 64)", [event_expiry as i64])? as u64;
            let old_sources: Vec<(String,String)> = {
                let mut statement = transaction.prepare("SELECT source,generation FROM history_sources WHERE seen_ms<?1 LIMIT 32")?;
                statement.query_map([expiry as i64], |row| Ok((row.get(0)?,row.get(1)?)))?.collect::<Result<_,_>>()?
            };
            for (source,generation) in old_sources {
                report.deleted_rows += transaction.execute("DELETE FROM checkpoints WHERE source=?1 AND generation=?2",params![source,generation])? as u64;
                transaction.execute("DELETE FROM history_sources WHERE source=?1 AND generation=?2",params![source,generation])?;
            }
            // Alternate materialization and coarsening so migration cannot expand a whole
            // month into minute/reason rows before reclaiming eligible input.
            if !coarsen(&transaction, now_ms, expiry)? {
                if materialize(&transaction, expiry)? { report.materialized_minutes = 1; }
            } else { report.compacted_intervals = 1; }
            if report.materialized_minutes + report.compacted_intervals + report.deleted_rows != 0 {
                transaction.execute("UPDATE history_state SET revision=revision+1 WHERE singleton=1", [])?;
            }
            report.pending_minutes = transaction.query_row("SELECT count(*) FROM history_dirty", [], |row| row.get::<_,i64>(0))? as u64;
            report.oldest_expired_ms = transaction.query_row("SELECT min(start_ms) FROM (SELECT min(start_ms) AS start_ms FROM history_buckets WHERE start_ms<?1 UNION ALL SELECT min(start_ms) FROM metric_buckets WHERE start_ms<?1)", [expiry as i64], |row| row.get::<_,Option<i64>>(0))?.map(|value| value as u64);
            report.more_work = report.pending_minutes != 0 || report.deleted_rows != 0 || report.compacted_intervals != 0 || eligible_parent(&transaction,now_ms,expiry)?.is_some();
            report.mutated_rows = transaction.total_changes()-changes_before;
            if report.mutated_rows>1_000 { return Err(Error::Invalid("history maintenance row budget exceeded")); }
            super::storage::check_deadline(&cancel,deadline)?;
            transaction.commit()?;
            Ok(report)
        })
    }

    /// Bounded mixed-grain history. Each returned bucket is wholly inside the requested range.
    pub fn history(&mut self, query: &HistoryQuery) -> Result<HistoryPage, Error> {
        query.validate()?;
        self.guarded(|store| {
            super::storage::check_files(&store.config)?;
            let deadline=Instant::now()+store.config.operation_timeout;
            let expiry = statistics_expiry(&store.connection,(store.config.clock)())?;
            let revision: i64 = store.connection.query_row("SELECT revision FROM history_state WHERE singleton=1", [], |row| row.get(0))?;
            if query.revision.is_some_and(|expected|expected!=revision as u64) { return Err(Error::HistoryChanged); }
            let site = query.site.as_deref().unwrap_or("");
            let raw: Vec<(u64,u64,String)> = {
                let mut statement = store.connection.prepare("SELECT start_ms,grain_ms,payload FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms+grain_ms<=?4 ORDER BY start_ms LIMIT ?5")?;
                statement.query_map(params![query.instance,site,query.from_ms.max(expiry) as i64,query.until_ms as i64,(query.limit+1) as i64], |row| Ok((row.get::<_,i64>(0)? as u64,row.get::<_,i64>(1)? as u64,row.get(2)?)))?.collect::<Result<_,_>>()?
            };
            let mut buckets = Vec::with_capacity(query.limit.min(raw.len()));
            let next_start_ms = raw.get(query.limit).map(|row|row.0);
            for (start,grain,payload) in raw.into_iter().take(query.limit) {
                super::storage::check_deadline(&store.cancel,deadline)?;
                buckets.push(load_bucket(&store.connection,&query.instance,site,start,grain,&payload)?);
            }
            let oldest_available_ms = store.connection.query_row("SELECT min(start_ms) FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3",params![query.instance,site,expiry as i64],|row|row.get::<_,Option<i64>>(0))?.map(|value|value as u64);
            let pending_minutes = store.connection.query_row("SELECT count(*) FROM history_dirty WHERE source=?1 AND site=?2 AND start_ms>=?3",params![query.instance,site,expiry as i64],|row|row.get::<_,i64>(0))? as u64;
            let after: i64 = store.connection.query_row("SELECT revision FROM history_state WHERE singleton=1",[],|row|row.get(0))?;
            if revision != after { return Err(Error::Busy); }
            super::storage::check_deadline(&store.cancel,deadline)?;
            Ok(HistoryPage { buckets,expiry_ms:expiry,oldest_available_ms,next_start_ms,pending_minutes,revision:revision as u64 })
        })
    }
}

fn materialize(connection: &Connection, expiry: u64) -> Result<bool, Error> {
    let dirty: Option<(String,String,u64)> = connection.query_row("SELECT source,site,start_ms FROM history_dirty WHERE start_ms>=?1 ORDER BY start_ms,source,site LIMIT 1",[expiry as i64],|row|Ok((row.get(0)?,row.get(1)?,row.get::<_,i64>(2)? as u64))).optional()?;
    let Some((source, site, start)) = dirty else {
        return Ok(false);
    };
    let values: Vec<MetricBucket> = {
        let mut statement = connection.prepare("SELECT payload FROM metric_buckets WHERE source=?1 AND site=?2 AND start_ms=?3 ORDER BY generation LIMIT 65")?;
        let payloads = statement
            .query_map(params![source, site, start as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if payloads.len() > 64 {
            return Err(Error::Invalid("too many generations in one history minute"));
        }
        payloads
            .iter()
            .map(|value| super::storage::decode_record(value))
            .collect::<Result<_, _>>()?
    };
    if !values.is_empty() {
        if compacted(connection, &source, &site, start)? {
            return Err(Error::CompactedInput);
        }
        save_bucket(connection, &source, &site, &HistoryBucket::minute(&values)?)?;
    }
    connection.execute(
        "DELETE FROM history_dirty WHERE source=?1 AND site=?2 AND start_ms=?3",
        params![source, site, start as i64],
    )?;
    Ok(true)
}

type Parent = (String, String, u64, Grain);

fn eligible_parent(
    connection: &Connection,
    now: u64,
    expiry: u64,
) -> Result<Option<Parent>, Error> {
    for grain in Grain::ALL {
        let Some((parent, age)) = grain.parent() else {
            continue;
        };
        let width = parent.milliseconds();
        if now < age + width {
            continue;
        }
        let candidates: Vec<(String, String, u64)> = {
            let mut statement = connection.prepare("SELECT source,site,start_ms FROM history_buckets WHERE grain_ms=?1 AND start_ms>=?2 AND (start_ms/?3)*?3+?3<=?4 ORDER BY start_ms,source,site LIMIT 8")?;
            statement
                .query_map(
                    params![
                        grain.milliseconds() as i64,
                        expiry as i64,
                        width as i64,
                        now.saturating_sub(age) as i64
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? as u64)),
                )?
                .collect::<Result<_, _>>()?
        };
        for (source, site, start) in candidates {
            let start = start / width * width;
            if start < expiry {
                continue;
            }
            let pending: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM history_dirty WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms<?4)",params![source,site,start as i64,(start+width) as i64],|row|row.get(0))?;
            let mixed: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms<?4 AND grain_ms!=?5)",params![source,site,start as i64,(start+width) as i64,grain.milliseconds() as i64],|row|row.get(0))?;
            if !pending && !mixed {
                return Ok(Some((source, site, start, parent)));
            }
        }
    }
    Ok(None)
}

fn coarsen(connection: &Connection, now: u64, expiry: u64) -> Result<bool, Error> {
    let Some((source, site, start, grain)) = eligible_parent(connection, now, expiry)? else {
        return Ok(false);
    };
    let width = grain.milliseconds();
    let raw: Vec<(u64, u64, String)> = {
        let mut statement = connection.prepare("SELECT start_ms,grain_ms,payload FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms<?4 ORDER BY start_ms LIMIT 61")?;
        statement
            .query_map(
                params![source, site, start as i64, (start + width) as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get(2)?,
                    ))
                },
            )?
            .collect::<Result<_, _>>()?
    };
    if raw.len() > 60 {
        return Err(Error::Invalid("too many history children"));
    }
    let children = raw
        .iter()
        .map(|(start, grain, payload)| {
            load_bucket(connection, &source, &site, *start, *grain, payload)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parent = HistoryBucket::merge(start, grain, &children)?;
    // The parent and all reason rows commit atomically with removal of its children.
    connection.execute(
        "DELETE FROM history_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms<?4",
        params![source, site, start as i64, (start + width) as i64],
    )?;
    save_bucket(connection, &source, &site, &parent)?;
    connection.execute(
        "DELETE FROM metric_buckets WHERE source=?1 AND site=?2 AND start_ms>=?3 AND start_ms<?4",
        params![source, site, start as i64, (start + width) as i64],
    )?;
    Ok(true)
}

fn save_bucket(
    connection: &Connection,
    source: &str,
    site: &str,
    bucket: &HistoryBucket,
) -> Result<(), Error> {
    bucket.validate()?;
    let mut stored = bucket.clone();
    stored.reasons.clear();
    connection.execute("INSERT INTO history_buckets(source,site,start_ms,grain_ms,payload) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(source,site,start_ms) DO UPDATE SET grain_ms=excluded.grain_ms,payload=excluded.payload",params![source,site,bucket.start_ms as i64,bucket.grain.milliseconds() as i64,encode(&stored)?])?;
    for reason in RejectionReason::ALL {
        let name =
            serde_json::to_string(&reason).map_err(|_| Error::Invalid("invalid history reason"))?;
        let statistics = bucket
            .reasons
            .get(&reason)
            .ok_or(Error::Invalid("missing history reason"))?;
        connection.execute("INSERT INTO rejection_buckets(source,site,start_ms,reason,payload) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(source,site,start_ms,reason) DO UPDATE SET payload=excluded.payload",params![source,site,bucket.start_ms as i64,name.trim_matches('"'),encode(statistics)?])?;
    }
    Ok(())
}

fn load_bucket(
    connection: &Connection,
    source: &str,
    site: &str,
    start: u64,
    grain: u64,
    payload: &str,
) -> Result<HistoryBucket, Error> {
    let mut bucket: HistoryBucket = decode(payload)?;
    if bucket.start_ms != start || bucket.grain != Grain::from_milliseconds(grain)? {
        return Err(Error::Invalid("history key mismatch"));
    }
    let mut statement = connection.prepare("SELECT reason,payload FROM rejection_buckets WHERE source=?1 AND site=?2 AND start_ms=?3 ORDER BY reason LIMIT 23")?;
    let raw = statement
        .query_map(params![source, site, start as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (reason, payload) in raw {
        let reason = serde_json::from_str(
            &serde_json::to_string(&reason)
                .map_err(|_| Error::Invalid("invalid history reason"))?,
        )
        .map_err(|_| Error::Invalid("unknown history reason"))?;
        bucket.reasons.insert(reason, decode(&payload)?);
    }
    if bucket.reasons.len() != RejectionReason::ALL.len() {
        return Err(Error::Busy);
    }
    bucket.validate()?;
    Ok(bucket)
}

fn encode(value: &impl Serialize) -> Result<String, Error> {
    let json =
        serde_json::to_string(value).map_err(|_| Error::Invalid("history serialization failed"))?;
    if json.len() > MAX_HISTORY_BYTES {
        return Err(Error::Invalid("history record exceeds byte limit"));
    }
    Ok(json)
}

fn decode<T: DeserializeOwned>(json: &str) -> Result<T, Error> {
    if json.len() > MAX_HISTORY_BYTES {
        return Err(Error::Invalid("history record exceeds byte limit"));
    }
    serde_json::from_str(json).map_err(|_| Error::Invalid("invalid stored history"))
}
