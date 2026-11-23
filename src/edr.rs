//! Offline authentication-abuse analysis over the console's SQLite history.
//!
//! The analyzer is deliberately read-only and independent of forwarding. It
//! looks for two patterns that per-minute rules miss:
//!
//! * a source that keeps failing authentication slowly enough to stay below
//!   the login throttle's burst limit, and
//! * many distinct sources that each fail a few times on the same
//!   authentication endpoint (a distributed reverse-brute-force campaign).

pub mod live;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;

use crate::console::history::{CountMetric, HOUR_MS, HistoryBucket};
use crate::console::measurements::{AdditionalMeasurements, DistinctSketch, Ranking};
use crate::console::model::{MINUTE_MS, MetricBucket};
use crate::error::Error;

const APPLICATION_ID: i64 = 0x4b55_4e43;
const MAX_SCHEMA_VERSION: i64 = 4;
const MAX_BUCKETS: usize = 100_000;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const DEFAULT_BASELINE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_REPORTED_PATHS: usize = 5;

/// One analysis window. Times are UTC milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Window {
    pub from_ms: u64,
    pub until_ms: u64,
}

impl Window {
    pub fn minutes(self) -> u64 {
        (self.until_ms - self.from_ms) / MINUTE_MS
    }
}

/// Tunable thresholds for the initial evaluation profiles.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Thresholds {
    pub slow_min_failures: u64,
    pub slow_min_active_buckets: u32,
    pub slow_min_span_minutes: u32,
    pub slow_max_per_minute: u64,
    pub slow_max_gap_cv: f64,
    pub slow_new_source_min_failures: u64,
    pub slow_baseline_excess: f64,
    pub slow_baseline_z: f64,
    pub reverse_min_failures: u64,
    pub reverse_min_sources: f64,
    pub reverse_max_mean_per_source: f64,
    pub reverse_min_top_path_share: f64,
    pub reverse_baseline_excess: f64,
    pub reverse_baseline_z: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            slow_min_failures: 6,
            slow_min_active_buckets: 4,
            slow_min_span_minutes: 30,
            slow_max_per_minute: 3,
            slow_max_gap_cv: 1.0,
            slow_new_source_min_failures: 8,
            slow_baseline_excess: 4.0,
            slow_baseline_z: 3.0,
            reverse_min_failures: 30,
            reverse_min_sources: 10.0,
            reverse_max_mean_per_source: 4.0,
            reverse_min_top_path_share: 0.5,
            reverse_baseline_excess: 15.0,
            reverse_baseline_z: 3.0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub database: PathBuf,
    pub window: Window,
    pub baseline: Duration,
    pub thresholds: Thresholds,
}

impl Options {
    pub fn new(database: impl Into<PathBuf>, window: Window) -> Self {
        Self {
            database: database.into(),
            window,
            baseline: DEFAULT_BASELINE,
            thresholds: Thresholds::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryState {
    /// The window contains records written with the authentication fields.
    Present,
    /// Every record predates the authentication fields.
    Missing,
    /// Only some records carry the fields, or the database has no records.
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    SlowAuthentication,
    ReverseBruteForce,
}

#[derive(Clone, Debug, Serialize)]
pub struct PathCount {
    pub path: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub buckets: usize,
    pub minutes_covered: u64,
    pub incomplete: bool,
    pub coarse: bool,
    pub requests: u64,
    pub auth_failures: u64,
    pub distinct_auth_sources: Option<u64>,
    pub status_401: u64,
    pub status_403: u64,
    pub auth_paths: Vec<PathCount>,
    pub baseline_hours: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct SlowEvidence {
    pub failures: u64,
    pub active_buckets: u32,
    pub span_minutes: u64,
    pub max_failures_per_minute: u64,
    pub gap_cv: Option<f64>,
    pub baseline_failures_per_hour: Option<f64>,
    pub baseline_z: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReverseEvidence {
    pub failures: u64,
    pub distinct_sources: f64,
    pub mean_failures_per_source: f64,
    pub top_path: Option<String>,
    pub top_path_share: f64,
    pub active_buckets: u32,
    pub baseline_failures_per_hour: Option<f64>,
    pub baseline_z: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    SlowAuthentication(SlowEvidence),
    ReverseBruteForce(ReverseEvidence),
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub source: Option<IpAddr>,
    pub title: String,
    pub evidence: Evidence,
    pub recommendation: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub generated_at_ms: u64,
    pub database: String,
    pub site: Option<String>,
    pub window: Window,
    pub telemetry: TelemetryState,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// Run one retrospective analysis. The database is opened read-only.
pub fn analyze(options: &Options) -> Result<Report, Error> {
    if options.window.from_ms >= options.window.until_ms
        || options.window.until_ms - options.window.from_ms < MINUTE_MS
        || options.window.until_ms - options.window.from_ms > 30 * 24 * HOUR_MS
        || options.window.from_ms == 0
        || options.window.until_ms > i64::MAX as u64
    {
        return Err(Error::Message(
            "EDR window must be a positive range of at most 30 days".to_owned(),
        ));
    }
    if options.baseline > Duration::from_millis(30 * 24 * HOUR_MS) {
        return Err(Error::Message(
            "EDR baseline must not exceed 30 days".to_owned(),
        ));
    }
    let connection = open_read_only(&options.database)?;
    let mut window = WindowData::new(options.window);
    for record in read_range(&connection, options.window, MAX_BUCKETS)? {
        window.add(record);
    }
    let baseline_window = Window {
        from_ms: options
            .window
            .from_ms
            .saturating_sub(options.baseline.as_millis().min(u128::from(u64::MAX)) as u64),
        until_ms: options.window.from_ms,
    };
    let baseline = if baseline_window.from_ms < baseline_window.until_ms {
        let mut records = Vec::new();
        for record in read_range(&connection, baseline_window, MAX_BUCKETS)? {
            records.push(record);
        }
        Baseline::from_records(&records)
    } else {
        Baseline::default()
    };

    let mut findings = Vec::new();
    findings.extend(window.slow_findings(&baseline, &options.thresholds));
    if let Some(finding) = window.reverse_finding(&baseline, &options.thresholds) {
        findings.push(finding);
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.source.cmp(&b.source))
    });

    let telemetry = window.telemetry_state();
    let mut notes = window.notes(&baseline, telemetry);
    if findings.is_empty() {
        notes.push(
            "No candidate exceeded the configured thresholds; this is not proof that no attack occurred."
                .to_owned(),
        );
    }
    Ok(Report {
        generated_at_ms: system_time_ms(),
        database: options.database.display().to_string(),
        site: None,
        window: options.window,
        telemetry,
        summary: window.summary(&baseline),
        findings,
        notes,
    })
}

fn open_read_only(path: &Path) -> Result<Connection, Error> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::Message(format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() {
        return Err(Error::Message(format!(
            "{} is not a regular console database",
            path.display()
        )));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| Error::Message(format!("{}: {error}", path.display())))?;
    connection
        .busy_timeout(Duration::from_millis(250))
        .map_err(|error| Error::Message(format!("{}: {error}", path.display())))?;
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|error| Error::Message(format!("{}: {error}", path.display())))?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| Error::Message(format!("{}: {error}", path.display())))?;
    if application != APPLICATION_ID || !(1..=MAX_SCHEMA_VERSION).contains(&version) {
        return Err(Error::Message(format!(
            "{} is not a Kunato console database (application_id={application}, user_version={version})",
            path.display()
        )));
    }
    Ok(connection)
}

fn read_range(
    connection: &Connection,
    window: Window,
    limit: usize,
) -> Result<Vec<BucketRecord>, Error> {
    let mut records = Vec::new();
    let mut metric_intervals = BTreeMap::<u64, u64>::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT start_ms, payload FROM metric_buckets \
                 WHERE start_ms >= ?1 AND start_ms < ?2 \
                 ORDER BY start_ms LIMIT ?3",
            )
            .map_err(|error| Error::Message(format!("metric_buckets: {error}")))?;
        let rows = statement
            .query_map(
                params![
                    window.from_ms as i64,
                    window.until_ms as i64,
                    (limit + 1) as i64
                ],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?)),
            )
            .map_err(|error| Error::Message(format!("metric_buckets: {error}")))?;
        for row in rows {
            let (start, payload) =
                row.map_err(|error| Error::Message(format!("metric_buckets: {error}")))?;
            let bucket: MetricBucket = decode(&payload)?;
            bucket
                .validate()
                .map_err(|error| Error::Message(format!("invalid metric bucket: {error}")))?;
            if bucket.start_ms != start || start < window.from_ms || start >= window.until_ms {
                return Err(Error::Message("metric bucket time mismatch".to_owned()));
            }
            metric_intervals
                .entry(start)
                .and_modify(|end| *end = (*end).max(start + MINUTE_MS))
                .or_insert(start + MINUTE_MS);
            records.push(BucketRecord::from_metric(bucket));
            if records.len() > limit {
                return Err(Error::Message(
                    "EDR window contains too many metric buckets".to_owned(),
                ));
            }
        }
    }
    {
        let mut statement = connection
            .prepare(
                "SELECT start_ms, grain_ms, payload FROM history_buckets \
                 WHERE start_ms >= ?1 AND start_ms + grain_ms <= ?2 \
                 ORDER BY start_ms LIMIT ?3",
            )
            .map_err(|error| Error::Message(format!("history_buckets: {error}")))?;
        let rows = statement
            .query_map(
                params![
                    window.from_ms as i64,
                    window.until_ms as i64,
                    (limit + 1) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| Error::Message(format!("history_buckets: {error}")))?;
        for row in rows {
            let (start, grain, payload) =
                row.map_err(|error| Error::Message(format!("history_buckets: {error}")))?;
            if grain == 0 || grain > 24 * HOUR_MS {
                return Err(Error::Message("invalid history grain".to_owned()));
            }
            if overlaps(&metric_intervals, start, start + grain) {
                // Metric rows are the more precise copy of the same interval.
                continue;
            }
            let bucket: HistoryBucket = decode(&payload)?;
            bucket
                .validate()
                .map_err(|error| Error::Message(format!("invalid history bucket: {error}")))?;
            if bucket.start_ms != start || bucket.grain.milliseconds() != grain {
                return Err(Error::Message("history bucket time mismatch".to_owned()));
            }
            records.push(BucketRecord::from_history(bucket));
            if records.len() > limit {
                return Err(Error::Message(
                    "EDR window contains too many history buckets".to_owned(),
                ));
            }
        }
    }
    records.sort_by_key(|record| record.start_ms);
    Ok(records)
}

fn overlaps(intervals: &BTreeMap<u64, u64>, start: u64, end: u64) -> bool {
    intervals
        .range(..end)
        .next_back()
        .is_some_and(|(_, metric_end)| *metric_end > start)
}

fn decode<T: serde::de::DeserializeOwned>(payload: &str) -> Result<T, Error> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(Error::Message(
            "stored EDR record exceeds the size limit".to_owned(),
        ));
    }
    serde_json::from_str(payload)
        .map_err(|error| Error::Message(format!("invalid stored console record: {error}")))
}

#[derive(Clone, Debug)]
struct BucketRecord {
    start_ms: u64,
    grain_ms: u64,
    requests: u64,
    auth_failures: u64,
    auth_sources: Vec<(String, u64, u64)>,
    auth_paths: Vec<(String, u64, u64)>,
    auth_sketch: Option<DistinctSketch>,
    status_401: u64,
    status_403: u64,
    observed_ms: u64,
    incomplete: bool,
    telemetry_version: Option<u32>,
}

impl BucketRecord {
    fn from_metric(bucket: MetricBucket) -> Self {
        let requests = bucket.counters.requests.unwrap_or(0);
        let fields = additional_fields(bucket.additional.as_deref());
        let (status_401, status_403) = status_counts(bucket.outcomes.as_ref());
        Self {
            start_ms: bucket.start_ms,
            grain_ms: MINUTE_MS,
            requests,
            auth_failures: fields.auth_failures,
            auth_sources: fields.auth_sources,
            auth_paths: fields.auth_paths,
            auth_sketch: fields.auth_sketch,
            status_401,
            status_403,
            observed_ms: u64::from(bucket.coverage.observed_ms),
            incomplete: bucket.coverage.incomplete || fields.incomplete,
            telemetry_version: fields.telemetry_version,
        }
    }

    fn from_history(bucket: HistoryBucket) -> Self {
        let requests = bucket
            .counters
            .get(&CountMetric::Requests)
            .map(|value| value.sum)
            .unwrap_or(0);
        let fields = additional_fields(bucket.additional.as_deref());
        let (status_401, status_403) = status_counts(bucket.outcomes.as_ref());
        Self {
            start_ms: bucket.start_ms,
            grain_ms: bucket.grain.milliseconds(),
            requests,
            auth_failures: fields.auth_failures,
            auth_sources: fields.auth_sources,
            auth_paths: fields.auth_paths,
            auth_sketch: fields.auth_sketch,
            status_401,
            status_403,
            observed_ms: bucket.coverage.observed_ms,
            incomplete: bucket.coverage.incomplete || fields.incomplete,
            telemetry_version: fields.telemetry_version,
        }
    }
}

struct AdditionalFields {
    auth_failures: u64,
    auth_sources: Vec<(String, u64, u64)>,
    auth_paths: Vec<(String, u64, u64)>,
    auth_sketch: Option<DistinctSketch>,
    telemetry_version: Option<u32>,
    incomplete: bool,
}

fn additional_fields(additional: Option<&AdditionalMeasurements>) -> AdditionalFields {
    let Some(additional) = additional else {
        return AdditionalFields {
            auth_failures: 0,
            auth_sources: Vec::new(),
            auth_paths: Vec::new(),
            auth_sketch: None,
            telemetry_version: None,
            incomplete: true,
        };
    };
    AdditionalFields {
        auth_failures: additional.auth_failures,
        auth_sources: ranking_entries(&additional.auth_sources),
        auth_paths: ranking_entries(&additional.auth_paths),
        auth_sketch: Some(additional.unique_auth_sources.clone()),
        telemetry_version: Some(additional.version),
        incomplete: additional.incomplete
            || additional.auth_sources.omitted_upper_bound != 0
            || additional.auth_paths.omitted_upper_bound != 0,
    }
}

fn ranking_entries(ranking: &Ranking) -> Vec<(String, u64, u64)> {
    ranking
        .entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.estimate, entry.error))
        .collect()
}

fn status_counts(outcomes: Option<&crate::console::model::Outcomes>) -> (u64, u64) {
    let Some(outcomes) = outcomes else {
        return (0, 0);
    };
    let get = |status: usize| {
        outcomes
            .statuses
            .get(status.saturating_sub(100))
            .copied()
            .unwrap_or(0)
    };
    (get(401), get(403))
}

#[derive(Clone, Debug, Default)]
struct BucketAggregate {
    requests: u64,
    auth_failures: u64,
    sources: BTreeMap<String, u64>,
    source_error: u64,
    paths: BTreeMap<String, u64>,
    path_error: u64,
    sketch: Option<DistinctSketch>,
    status_401: u64,
    status_403: u64,
}

#[derive(Clone, Debug, Default)]
struct SourceSeries {
    /// Bucket start to (failure count, grain milliseconds).
    buckets: BTreeMap<u64, (u64, u64)>,
    total: u64,
    error: u64,
}

struct WindowData {
    window: Window,
    buckets: BTreeMap<u64, BucketAggregate>,
    grain_by_start: BTreeMap<u64, u64>,
    sources: BTreeMap<String, SourceSeries>,
    incomplete: bool,
    coarse: bool,
    records: usize,
    telemetry_present: usize,
    status_401: u64,
    status_403: u64,
    paths: BTreeMap<String, u64>,
    path_omitted: u64,
    requests: u64,
}

impl WindowData {
    fn new(window: Window) -> Self {
        Self {
            window,
            buckets: BTreeMap::new(),
            grain_by_start: BTreeMap::new(),
            sources: BTreeMap::new(),
            incomplete: false,
            coarse: false,
            records: 0,
            telemetry_present: 0,
            status_401: 0,
            status_403: 0,
            paths: BTreeMap::new(),
            path_omitted: 0,
            requests: 0,
        }
    }

    fn add(&mut self, record: BucketRecord) {
        self.records += 1;
        self.incomplete |= record.incomplete || record.observed_ms < record.grain_ms;
        self.coarse |= record.grain_ms > MINUTE_MS;
        self.requests = self.requests.saturating_add(record.requests);
        self.status_401 = self.status_401.saturating_add(record.status_401);
        self.status_403 = self.status_403.saturating_add(record.status_403);
        self.grain_by_start
            .entry(record.start_ms)
            .and_modify(|grain| *grain = (*grain).max(record.grain_ms))
            .or_insert(record.grain_ms);
        let aggregate = self.buckets.entry(record.start_ms).or_default();
        aggregate.requests = aggregate.requests.saturating_add(record.requests);
        aggregate.auth_failures = aggregate.auth_failures.saturating_add(record.auth_failures);
        aggregate.status_401 = aggregate.status_401.saturating_add(record.status_401);
        aggregate.status_403 = aggregate.status_403.saturating_add(record.status_403);
        for (source, count, error) in record.auth_sources {
            aggregate
                .sources
                .entry(source.clone())
                .and_modify(|value| *value = value.saturating_add(count))
                .or_insert(count);
            aggregate.source_error = aggregate.source_error.saturating_add(error);
            let series = self.sources.entry(source).or_default();
            let entry = series
                .buckets
                .entry(record.start_ms)
                .or_insert((0, record.grain_ms));
            entry.0 = entry.0.saturating_add(count);
            entry.1 = entry.1.max(record.grain_ms);
            series.total = series.total.saturating_add(count);
            series.error = series.error.saturating_add(error);
        }
        if let Some(sketch) = record.auth_sketch {
            match &mut aggregate.sketch {
                Some(current) => {
                    if current.merge(&sketch).is_err() {
                        self.incomplete = true;
                    }
                }
                None => aggregate.sketch = Some(sketch),
            }
        }
        for (path, count, error) in record.auth_paths {
            aggregate
                .paths
                .entry(path.clone())
                .and_modify(|value| *value = value.saturating_add(count))
                .or_insert(count);
            aggregate.path_error = aggregate.path_error.saturating_add(error);
            self.paths
                .entry(path)
                .and_modify(|value| *value = value.saturating_add(count))
                .or_insert(count);
            self.path_omitted = self.path_omitted.saturating_add(error);
        }
        if record.telemetry_version.is_some_and(|version| version >= 2) {
            self.telemetry_present += 1;
        }
    }

    fn telemetry_state(&self) -> TelemetryState {
        if self.records == 0 || self.telemetry_present == 0 {
            return TelemetryState::Missing;
        }
        if self.telemetry_present == self.records && !self.incomplete {
            TelemetryState::Present
        } else {
            TelemetryState::Partial
        }
    }

    fn distinct_sources(&mut self) -> Option<f64> {
        let mut merged: Option<DistinctSketch> = None;
        for aggregate in self.buckets.values() {
            let Some(sketch) = &aggregate.sketch else {
                continue;
            };
            match &mut merged {
                Some(current) => current.merge(sketch).ok()?,
                None => merged = Some(sketch.clone()),
            }
        }
        if let Some(sketch) = merged {
            return sketch.estimate();
        }
        // Older records have no sketch. The per-bucket ranking is then a lower
        // bound on distinct sources, and every omitted occurrence sets error.
        let mut sources = BTreeMap::<String, ()>::new();
        let mut omitted = 0_u64;
        for aggregate in self.buckets.values() {
            for source in aggregate.sources.keys() {
                sources.insert(source.clone(), ());
            }
            omitted = omitted.saturating_add(aggregate.source_error);
        }
        (!sources.is_empty()).then_some(sources.len() as f64 + omitted as f64)
    }

    fn summary(&mut self, baseline: &Baseline) -> Summary {
        let distinct = self.distinct_sources().map(|value| value.round() as u64);
        let mut paths: Vec<PathCount> = self
            .paths
            .iter()
            .map(|(path, count)| PathCount {
                path: path.clone(),
                count: *count,
            })
            .collect();
        paths.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.path.cmp(&b.path)));
        paths.truncate(MAX_REPORTED_PATHS);
        let minutes_covered = self
            .buckets
            .keys()
            .map(|start| self.grain_by_start.get(start).copied().unwrap_or(MINUTE_MS) / MINUTE_MS)
            .sum::<u64>()
            .min(self.window.minutes());
        Summary {
            buckets: self.records,
            minutes_covered,
            incomplete: self.incomplete || self.path_omitted != 0,
            coarse: self.coarse,
            requests: self.requests,
            auth_failures: self.buckets.values().map(|value| value.auth_failures).sum(),
            distinct_auth_sources: distinct,
            status_401: self.status_401,
            status_403: self.status_403,
            auth_paths: paths,
            baseline_hours: baseline.hours(),
        }
    }

    fn notes(&self, baseline: &Baseline, telemetry: TelemetryState) -> Vec<String> {
        let mut notes = Vec::new();
        match telemetry {
            TelemetryState::Present => {}
            TelemetryState::Missing => notes.push(
                "No authentication-failure telemetry was found; records predate version 2 of the supplementary measurements or the window is empty. Run the updated WAF and console before relying on this analysis."
                    .to_owned(),
            ),
            TelemetryState::Partial => notes.push(
                "Authentication-failure telemetry is incomplete for this window; the findings are a lower bound. Check console coverage, collection gaps, and the record telemetry version."
                    .to_owned(),
            ),
        }
        if self.coarse {
            notes.push(
                "Some records are coarser than one minute; activity and gap estimates are conservative."
                    .to_owned(),
            );
        }
        if self.path_omitted != 0 {
            notes.push(format!(
                "{} authentication-path observations were outside the bounded ranking; path concentration may be understated.",
                self.path_omitted
            ));
        }
        if baseline.hours() < 24 {
            notes.push(format!(
                "Baseline covers only {} hours; anomaly scores are weaker until a full day is retained.",
                baseline.hours()
            ));
        }
        if self.records == 0 {
            notes.push("The selected window contains no console buckets.".to_owned());
        } else if telemetry == TelemetryState::Present
            && self
                .buckets
                .values()
                .all(|aggregate| aggregate.auth_failures == 0)
        {
            notes.push(
                "No authentication failures were recorded. This is also what disabled behavioral auth observation looks like; confirm protection.behavior.auth/global_auth and the authentication path list."
                    .to_owned(),
            );
        }
        notes
    }

    fn slow_findings(&self, baseline: &Baseline, thresholds: &Thresholds) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (source, series) in &self.sources {
            if series.total < thresholds.slow_min_failures {
                continue;
            }
            let (first, last, max_rate) = activity(series);
            let active = series.buckets.len() as u32;
            let span_minutes = last.saturating_sub(first) / MINUTE_MS;
            if active < thresholds.slow_min_active_buckets
                || span_minutes < u64::from(thresholds.slow_min_span_minutes)
                || max_rate > thresholds.slow_max_per_minute
            {
                continue;
            }
            let cv = gap_cv(series);
            let baseline_stats = baseline.source_stats(source);
            let z = baseline_stats
                .as_ref()
                .map(|stats| z_score(series.total as f64, stats));
            let elevated = baseline_stats.as_ref().is_some_and(|stats| {
                series.total as f64 >= stats.center + thresholds.slow_baseline_excess
                    && z.is_some_and(|z| z >= thresholds.slow_baseline_z)
            });
            let regular = cv.is_some_and(|value| value <= thresholds.slow_max_gap_cv);
            let new_source = baseline_stats.is_none();
            if new_source {
                if !regular || series.total < thresholds.slow_new_source_min_failures {
                    continue;
                }
            } else if !elevated || (!regular && active < 6) {
                continue;
            }
            let parsed = source.parse::<IpAddr>().ok();
            let severity = if series.total >= 12 && active >= 8 && !new_source {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(Finding {
                kind: FindingKind::SlowAuthentication,
                severity,
                source: parsed,
                title: "slow authentication failures".to_owned(),
                evidence: Evidence::SlowAuthentication(SlowEvidence {
                    failures: series.total,
                    active_buckets: active,
                    span_minutes,
                    max_failures_per_minute: max_rate,
                    gap_cv: cv,
                    baseline_failures_per_hour: baseline_stats.as_ref().map(|stats| stats.center),
                    baseline_z: z,
                }),
                recommendation: "Review the source's recent authentication outcomes. A source-scoped rate limit or temporary ban is appropriate only after confirming the address is not shared egress; keep the finding at LOG when the address is a NAT or scanner population."
                    .to_owned(),
            });
        }
        findings
    }

    fn reverse_finding(&mut self, baseline: &Baseline, thresholds: &Thresholds) -> Option<Finding> {
        let failures: u64 = self.buckets.values().map(|value| value.auth_failures).sum();
        let distinct = self.distinct_sources()?;
        if failures < thresholds.reverse_min_failures || distinct < thresholds.reverse_min_sources {
            return None;
        }
        let mean = failures as f64 / distinct.max(1.0);
        if mean > thresholds.reverse_max_mean_per_source {
            return None;
        }
        let (top_path, top_count) = self
            .paths
            .iter()
            .max_by_key(|(path, count)| (**count, *path))
            .map(|(path, count)| (path.clone(), *count))
            .unwrap_or_default();
        let share = if failures == 0 {
            0.0
        } else {
            top_count as f64 / failures as f64
        };
        if share < thresholds.reverse_min_top_path_share {
            return None;
        }
        let stats = baseline.global_stats();
        let z = stats.as_ref().map(|value| z_score(failures as f64, value));
        let elevated = stats.as_ref().is_none_or(|value| {
            failures as f64 >= value.center + thresholds.reverse_baseline_excess
                && z.is_some_and(|z| z >= thresholds.reverse_baseline_z)
        });
        if !elevated {
            return None;
        }
        let active = self.buckets.len() as u32;
        Some(Finding {
            kind: FindingKind::ReverseBruteForce,
            severity: if failures >= 100 && distinct >= 30.0 {
                Severity::High
            } else {
                Severity::Medium
            },
            source: None,
            title: "distributed authentication failure campaign".to_owned(),
            evidence: Evidence::ReverseBruteForce(ReverseEvidence {
                failures,
                distinct_sources: distinct,
                mean_failures_per_source: mean,
                top_path: Some(top_path),
                top_path_share: share,
                active_buckets: active,
                baseline_failures_per_hour: stats.as_ref().map(|value| value.center),
                baseline_z: z,
            }),
            recommendation: "Treat this as a campaign, not a single offender. Keep authentication outcomes at LOG, verify the application's failure semantics, and consider a bounded global throttle that still requires a recent source-local failure before rejecting a request."
                .to_owned(),
        })
    }
}

fn activity(series: &SourceSeries) -> (u64, u64, u64) {
    let first = series.buckets.keys().next().copied().unwrap_or(0);
    let last_entry = series
        .buckets
        .last_key_value()
        .map(|(start, (_, grain))| (*start, *grain))
        .unwrap_or((0, MINUTE_MS));
    let last = last_entry.0.saturating_add(last_entry.1);
    let max_rate = series
        .buckets
        .values()
        .map(|(count, grain)| {
            if *grain == 0 {
                0
            } else {
                count.saturating_mul(60_000) / (*grain).max(MINUTE_MS)
            }
        })
        .max()
        .unwrap_or(0);
    (first, last, max_rate)
}

fn gap_cv(series: &SourceSeries) -> Option<f64> {
    if series.buckets.len() < 3 {
        return None;
    }
    let starts: Vec<u64> = series.buckets.keys().copied().collect();
    let gaps: Vec<f64> = starts
        .windows(2)
        .map(|window| (window[1] - window[0]) as f64 / MINUTE_MS as f64)
        .collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance = gaps
        .iter()
        .map(|gap| (gap - mean) * (gap - mean))
        .sum::<f64>()
        / gaps.len() as f64;
    Some((variance.sqrt() / mean).min(100.0))
}

#[derive(Clone, Debug, Default)]
struct HourAggregate {
    failures: u64,
    sources: BTreeMap<String, u64>,
    /// False when any record in the hour predates the authentication fields.
    complete: bool,
}

#[derive(Clone, Debug, Default)]
struct Baseline {
    hours: BTreeMap<u64, HourAggregate>,
}

impl Baseline {
    fn from_records(records: &[BucketRecord]) -> Self {
        let mut hours: BTreeMap<u64, HourAggregate> = BTreeMap::new();
        for record in records {
            let hour = record.start_ms / HOUR_MS * HOUR_MS;
            let aggregate = hours.entry(hour).or_insert_with(|| HourAggregate {
                complete: true,
                ..HourAggregate::default()
            });
            if record.telemetry_version.unwrap_or(0) < 2 {
                // A version-1 record has no authentication fields; treating
                // it as zero would invent a quiet baseline.
                aggregate.complete = false;
                continue;
            }
            aggregate.failures = aggregate.failures.saturating_add(record.auth_failures);
            for (source, count, _) in &record.auth_sources {
                aggregate
                    .sources
                    .entry(source.clone())
                    .and_modify(|value| *value = value.saturating_add(*count))
                    .or_insert(*count);
            }
        }
        Self { hours }
    }

    fn hours(&self) -> u32 {
        self.hours
            .values()
            .filter(|aggregate| aggregate.complete)
            .count()
            .min(u32::MAX as usize) as u32
    }

    fn global_stats(&self) -> Option<Stats> {
        let values: Vec<f64> = self
            .hours
            .values()
            .filter(|aggregate| aggregate.complete)
            .map(|aggregate| aggregate.failures as f64)
            .collect();
        (!values.is_empty()).then(|| Stats::from_values(&values))
    }

    fn source_stats(&self, source: &str) -> Option<Stats> {
        let mut values = Vec::with_capacity(self.hours.len());
        let mut seen = false;
        for aggregate in self.hours.values().filter(|aggregate| aggregate.complete) {
            let count = aggregate.sources.get(source).copied().unwrap_or(0);
            seen |= count != 0;
            values.push(count as f64);
        }
        seen.then(|| Stats::from_values(&values))
    }
}

#[derive(Clone, Copy, Debug)]
struct Stats {
    /// Median of the hourly baseline. A sustained attack becomes part of the
    /// mean but not of the median while most hours remain quiet.
    center: f64,
    /// Normal-consistent MAD scale with a floor of one failure.
    scale: f64,
}

impl Stats {
    fn from_values(values: &[f64]) -> Self {
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        let center = median(&sorted);
        let mut deviations: Vec<f64> = sorted.iter().map(|value| (value - center).abs()).collect();
        deviations.sort_by(f64::total_cmp);
        let mad = median(&deviations);
        Self {
            center,
            scale: (1.4826 * mad).max(1.0),
        }
    }
}

fn median(sorted: &[f64]) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn z_score(current: f64, stats: &Stats) -> f64 {
    (current - stats.center) / stats.scale
}

fn system_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SlowAuthentication => "slow_authentication",
            Self::ReverseBruteForce => "reverse_brute_force",
        }
    }
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

impl TelemetryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Partial => "partial",
        }
    }
}

/// Parse a UTC RFC 3339 timestamp such as `2026-11-23T15:00:00Z`.
/// Fractional seconds are accepted up to milliseconds and `+00:00` is treated
/// as UTC.
pub fn parse_utc(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let body = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))
        .ok_or_else(|| "timestamp must end in Z or +00:00".to_owned())?;
    let (date, time) = body
        .split_once('T')
        .ok_or_else(|| "timestamp must use YYYY-MM-DDTHH:MM:SSZ".to_owned())?;
    let mut date_parts = date.split('-');
    let year = parse_part(date_parts.next(), "year")?;
    let month = parse_part(date_parts.next(), "month")?;
    let day = parse_part(date_parts.next(), "day")?;
    if date_parts.next().is_some() || !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return Err("timestamp has an invalid date".to_owned());
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        return Err("timestamp has an invalid day".to_owned());
    }
    let (clock, fraction) = time.split_once('.').map_or((time, ""), |(a, b)| (a, b));
    let mut clock_parts = clock.split(':');
    let hour = parse_part(clock_parts.next(), "hour")?;
    let minute = parse_part(clock_parts.next(), "minute")?;
    let second = parse_part(clock_parts.next(), "second")?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return Err("timestamp has an invalid time".to_owned());
    }
    let millis = if fraction.is_empty() {
        0
    } else {
        if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("timestamp fractions must be 1-3 digits".to_owned());
        }
        let mut value = fraction
            .parse::<u64>()
            .map_err(|_| "invalid fraction".to_owned())?;
        for _ in fraction.len()..3 {
            value *= 10;
        }
        value
    };
    let days = days_from_civil(i64::from(year), month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour * 3600 + minute * 60 + second)))
        .ok_or_else(|| "timestamp overflows".to_owned())?;
    if seconds < 0 {
        return Err("timestamp predates the Unix epoch".to_owned());
    }
    Ok(seconds as u64 * 1000 + millis)
}

fn parse_part(value: Option<&str>, name: &str) -> Result<u32, String> {
    value
        .ok_or_else(|| format!("timestamp is missing {name}"))?
        .parse::<u32>()
        .map_err(|_| format!("timestamp has an invalid {name}"))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month_prime = u64::from((month + 9) % 12);
    let day_of_year = (153 * month_prime + 2) / 5 + u64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = (days - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (
        if month <= 2 { year + 1 } else { year },
        month as u32,
        day as u32,
    )
}

/// Format UTC milliseconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc(ms: u64) -> String {
    let seconds = ms / 1000;
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3600;
    let minute = remainder % 3600 / 60;
    let second = remainder % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn last_complete_hour_ms() -> u64 {
    let now = system_time_ms();
    now / HOUR_MS * HOUR_MS
}

/// Render the operator-facing table representation.
pub fn render_table(report: &Report) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "Kunato EDR analysis");
    let _ = writeln!(output, "database: {}", report.database);
    let _ = writeln!(
        output,
        "window: {} .. {} ({} minutes)",
        format_utc(report.window.from_ms),
        format_utc(report.window.until_ms),
        report.window.minutes()
    );
    let _ = writeln!(
        output,
        "telemetry: {}{}",
        report.telemetry.as_str(),
        if report.summary.incomplete {
            " (incomplete)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        output,
        "requests: {}  auth_failures: {}  distinct_sources: {}  baseline_hours: {}",
        report.summary.requests,
        report.summary.auth_failures,
        report
            .summary
            .distinct_auth_sources
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        report.summary.baseline_hours
    );
    let _ = writeln!(
        output,
        "statuses: 401={} 403={}",
        report.summary.status_401, report.summary.status_403
    );
    if !report.summary.auth_paths.is_empty() {
        let paths = report
            .summary
            .auth_paths
            .iter()
            .map(|value| format!("{} ({})", value.path, value.count))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(output, "auth paths: {paths}");
    }
    if report.findings.is_empty() {
        let _ = writeln!(output, "findings: none");
    } else {
        let _ = writeln!(output, "findings: {}", report.findings.len());
        for finding in &report.findings {
            let _ = writeln!(
                output,
                "[{}] {} {}",
                finding.severity.as_str(),
                finding.kind.as_str(),
                finding.source.map_or_else(
                    || "[campaign]".to_owned(),
                    |source| format!("source={source}")
                )
            );
            match &finding.evidence {
                Evidence::SlowAuthentication(evidence) => {
                    let _ = writeln!(
                        output,
                        "  failures={} active={} span={}m max/min={} gap_cv={} baseline/h={} z={}",
                        evidence.failures,
                        evidence.active_buckets,
                        evidence.span_minutes,
                        evidence.max_failures_per_minute,
                        evidence
                            .gap_cv
                            .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}")),
                        evidence
                            .baseline_failures_per_hour
                            .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.1}")),
                        evidence
                            .baseline_z
                            .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.1}"))
                    );
                }
                Evidence::ReverseBruteForce(evidence) => {
                    let _ = writeln!(
                        output,
                        "  failures={} distinct_sources={} mean/source={} top_path={} share={:.2} baseline/h={} z={}",
                        evidence.failures,
                        evidence.distinct_sources.round(),
                        evidence.mean_failures_per_source,
                        evidence.top_path.as_deref().unwrap_or("n/a"),
                        evidence.top_path_share,
                        evidence
                            .baseline_failures_per_hour
                            .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.1}")),
                        evidence
                            .baseline_z
                            .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.1}"))
                    );
                }
            }
            let _ = writeln!(output, "  recommendation: {}", finding.recommendation);
        }
    }
    if !report.notes.is_empty() {
        let _ = writeln!(output, "notes:");
        for note in &report.notes {
            let _ = writeln!(output, "  - {note}");
        }
    }
    output
}

/// Run the `kunato edr` command and print the selected representation.
pub fn run(args: crate::cli::EdrArgs) -> Result<(), Error> {
    use crate::cli::EdrOutputFormat;

    let until = args.until_ms.unwrap_or_else(last_complete_hour_ms);
    if !until.is_multiple_of(MINUTE_MS) {
        return Err(Error::Message(
            "--until must align to a whole minute".to_owned(),
        ));
    }
    let window_ms = u64::try_from(args.window.as_millis())
        .map_err(|_| Error::Message("EDR window is too large".to_owned()))?;
    let from_ms = until
        .checked_sub(window_ms)
        .ok_or_else(|| Error::Message("EDR window starts before the Unix epoch".to_owned()))?;
    let baseline = if args.baseline.is_zero() {
        Duration::ZERO
    } else {
        args.baseline
    };
    let report = analyze(&Options {
        database: args.database,
        window: Window {
            from_ms,
            until_ms: until,
        },
        baseline,
        thresholds: Thresholds::default(),
    })?;
    match args.format {
        EdrOutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|error| Error::Message(format!("EDR report encoding failed: {error}")))?;
            println!("{json}");
        }
        EdrOutputFormat::Table => print!("{}", render_table(&report)),
    }
    if args.fail_on_findings && report.has_findings() {
        return Err(Error::Message(format!(
            "{} EDR finding(s) exceeded the configured thresholds",
            report.findings.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_timestamps_round_trip_and_validate_dates() {
        let value = parse_utc("2026-11-23T15:00:00Z").unwrap();
        assert_eq!(format_utc(value), "2026-11-23T15:00:00Z");
        assert_eq!(parse_utc("2026-11-23T15:00:00.250Z").unwrap(), value + 250);
        assert_eq!(parse_utc("2026-11-23T15:00:00+00:00").unwrap(), value);
        assert!(parse_utc("2026-02-29T00:00:00Z").is_err());
        assert!(parse_utc("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_utc("2026-11-23 15:00:00Z").is_err());
    }

    fn record(start: u64, failures: u64, source: &str, path: &str) -> BucketRecord {
        BucketRecord {
            start_ms: start,
            grain_ms: MINUTE_MS,
            requests: failures,
            auth_failures: failures,
            auth_sources: vec![(source.to_owned(), failures, 0)],
            auth_paths: vec![(path.to_owned(), failures, 0)],
            auth_sketch: None,
            status_401: failures,
            status_403: 0,
            observed_ms: MINUTE_MS,
            incomplete: false,
            telemetry_version: Some(2),
        }
    }

    #[test]
    fn table_output_includes_both_finding_shapes() {
        let report = Report {
            generated_at_ms: 0,
            database: "history.sqlite3".into(),
            site: None,
            window: Window {
                from_ms: 0,
                until_ms: HOUR_MS,
            },
            telemetry: TelemetryState::Present,
            summary: Summary {
                buckets: 60,
                minutes_covered: 60,
                incomplete: false,
                coarse: false,
                requests: 120,
                auth_failures: 10,
                distinct_auth_sources: Some(1),
                status_401: 10,
                status_403: 0,
                auth_paths: vec![PathCount {
                    path: "/login".into(),
                    count: 10,
                }],
                baseline_hours: 24,
            },
            findings: vec![
                Finding {
                    kind: FindingKind::SlowAuthentication,
                    severity: Severity::Medium,
                    source: Some("203.0.113.7".parse().unwrap()),
                    title: "slow authentication failures".into(),
                    evidence: Evidence::SlowAuthentication(SlowEvidence {
                        failures: 10,
                        active_buckets: 10,
                        span_minutes: 55,
                        max_failures_per_minute: 1,
                        gap_cv: Some(0.0),
                        baseline_failures_per_hour: None,
                        baseline_z: None,
                    }),
                    recommendation: "review".into(),
                },
                Finding {
                    kind: FindingKind::ReverseBruteForce,
                    severity: Severity::High,
                    source: None,
                    title: "distributed authentication failure campaign".into(),
                    evidence: Evidence::ReverseBruteForce(ReverseEvidence {
                        failures: 60,
                        distinct_sources: 48.0,
                        mean_failures_per_source: 1.25,
                        top_path: Some("/login".into()),
                        top_path_share: 1.0,
                        active_buckets: 60,
                        baseline_failures_per_hour: Some(1.0),
                        baseline_z: Some(7.4),
                    }),
                    recommendation: "campaign response".into(),
                },
            ],
            notes: vec!["note".into()],
        };
        let text = render_table(&report);
        assert!(
            text.contains("slow_authentication source=203.0.113.7"),
            "{text}"
        );
        assert!(text.contains("[campaign]"), "{text}");
        assert!(text.contains("top_path=/login"), "{text}");
        assert!(text.contains("/login (10)"), "{text}");
    }
    #[test]
    fn a_baseline_hour_with_missing_telemetry_is_not_used_as_zero() {
        let mut old = record(0, 0, "203.0.113.7", "/login");
        old.telemetry_version = Some(1);
        let mut current = record(MINUTE_MS, 5, "203.0.113.7", "/login");
        current.telemetry_version = Some(2);
        let baseline = Baseline::from_records(&[old, current]);
        assert_eq!(baseline.hours(), 0);
        assert!(baseline.global_stats().is_none());
        assert!(baseline.source_stats("203.0.113.7").is_none());
    }
    #[test]
    fn a_regular_slow_source_is_flagged_and_a_burst_is_not() {
        let window = Window {
            from_ms: 1_700_000_000_000,
            until_ms: 1_700_000_000_000 + HOUR_MS,
        };
        let mut data = WindowData::new(window);
        for index in 0..12 {
            data.add(record(
                window.from_ms + index * 5 * MINUTE_MS,
                1,
                "203.0.113.7",
                "/login",
            ));
        }
        let findings = data.slow_findings(&Baseline::default(), &Thresholds::default());
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence,
            Evidence::SlowAuthentication(SlowEvidence {
                failures: 12,
                max_failures_per_minute: 1,
                ..
            })
        ));

        let mut burst = WindowData::new(window);
        for index in 0..12 {
            burst.add(record(
                window.from_ms + index * MINUTE_MS,
                10,
                "203.0.113.8",
                "/login",
            ));
        }
        assert!(
            burst
                .slow_findings(&Baseline::default(), &Thresholds::default())
                .is_empty()
        );
    }

    #[test]
    fn a_distributed_single_failure_per_source_campaign_is_reverse_brute_force() {
        let window = Window {
            from_ms: 1_700_000_000_000,
            until_ms: 1_700_000_000_000 + HOUR_MS,
        };
        let mut data = WindowData::new(window);
        for index in 0..40_u64 {
            let source = format!("198.51.100.{}", index + 1);
            data.add(record(
                window.from_ms + (index % 60) * MINUTE_MS,
                1,
                &source,
                "/login",
            ));
        }
        let finding = data
            .reverse_finding(&Baseline::default(), &Thresholds::default())
            .expect("campaign finding");
        assert!(matches!(
            finding.evidence,
            Evidence::ReverseBruteForce(ReverseEvidence {
                failures: 40,
                distinct_sources,
                ..
            }) if distinct_sources >= 39.0
        ));
    }

    #[test]
    fn one_source_with_many_failures_is_not_reverse_brute_force() {
        let window = Window {
            from_ms: 1_700_000_000_000,
            until_ms: 1_700_000_000_000 + HOUR_MS,
        };
        let mut data = WindowData::new(window);
        for index in 0..60 {
            data.add(record(
                window.from_ms + index * MINUTE_MS,
                2,
                "203.0.113.9",
                "/login",
            ));
        }
        assert!(
            data.reverse_finding(&Baseline::default(), &Thresholds::default())
                .is_none()
        );
    }

    #[test]
    fn old_records_report_missing_telemetry_without_a_finding() {
        let window = Window {
            from_ms: 1_700_000_000_000,
            until_ms: 1_700_000_000_000 + HOUR_MS,
        };
        let mut data = WindowData::new(window);
        let mut old = record(window.from_ms, 20, "203.0.113.9", "/login");
        old.telemetry_version = Some(1);
        old.auth_failures = 0;
        old.auth_sources.clear();
        old.auth_paths.clear();
        data.add(old);
        assert_eq!(data.telemetry_state(), TelemetryState::Missing);
        assert!(
            data.reverse_finding(&Baseline::default(), &Thresholds::default())
                .is_none()
        );
    }
}
