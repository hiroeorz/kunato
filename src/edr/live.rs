//! Resident in-memory EDR state fed by bounded WAF snapshots.
//!
//! A daemon would call `ingest` with every `/console/snapshot` response and
//! `report` at hourly boundaries. The state keeps only the bounded
//! authentication-failure measurements; it does not retain raw requests.
//!
//! Status: used by the opt-in `console.edr` task. The standalone daemon and
//! its HTTP polling loop are not implemented; the console task feeds this state
//! from the collector's accepted one-second snapshot stream.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::console::history::HOUR_MS;
use crate::console::measurements::{DistinctSketch, Ranking};
use crate::console::model::{MINUTE_MS, MetricBucket};
use crate::error::Error;
use crate::observations::StatisticsSnapshot;

use super::{Baseline, BucketRecord, Report, Thresholds, Window, WindowData, format_utc};

const MAX_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MIN_RING: Duration = Duration::from_secs(10 * 60);
const MAX_POLL: Duration = Duration::from_secs(60 * 60);
const STATE_VERSION: u32 = 1;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATE_MINUTES: usize = 100_000;
const MAX_STATE_HOURS: usize = 1_000;
const MAX_STATE_GAPS: usize = 1_024;
const MAX_RANKS: usize = 16;

/// Configuration for the resident state machine.
#[derive(Clone, Copy, Debug)]
pub struct LiveConfig {
    /// Detection window, for example one hour or six hours.
    pub window: Duration,
    /// How much hourly evidence to keep for the baseline.
    pub baseline: Duration,
    /// Expected snapshot cadence. Used only for validation and documentation;
    /// gaps are detected from the snapshot timestamps themselves.
    pub poll_interval: Duration,
    /// Minutes older than this are considered outside the WAF snapshot ring.
    /// Must be at least the WAF's ten-minute ring; the default keeps a margin.
    pub ring: Duration,
    pub thresholds: Thresholds,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60 * 60),
            baseline: Duration::from_secs(7 * 24 * 60 * 60),
            poll_interval: Duration::from_secs(5 * 60),
            ring: Duration::from_secs(12 * 60),
            thresholds: Thresholds::default(),
        }
    }
}

impl LiveConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.window < Duration::from_millis(MINUTE_MS) || self.window > MAX_RETENTION {
            return Err(Error::Message(
                "live EDR window must be between one minute and 30 days".to_owned(),
            ));
        }
        if self.baseline > MAX_RETENTION {
            return Err(Error::Message(
                "live EDR baseline must not exceed 30 days".to_owned(),
            ));
        }
        if self.poll_interval.is_zero() || self.poll_interval > MAX_POLL {
            return Err(Error::Message(
                "live EDR poll interval must be between one second and one hour".to_owned(),
            ));
        }
        if self.ring < MIN_RING || self.ring > MAX_POLL {
            return Err(Error::Message(
                "live EDR ring must be at least the ten-minute WAF ring".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One hour of authentication evidence. Keeping this instead of the full
/// `AdditionalMeasurements` avoids retaining dimensions, countries, and
/// latency histograms that the EDR never uses.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HourAuth {
    failures: u64,
    sources: Ranking,
    paths: Ranking,
    distinct: DistinctSketch,
    incomplete: bool,
}

impl HourAuth {
    fn merge(&mut self, bucket: &MetricBucket) {
        if bucket.coverage.incomplete {
            self.incomplete = true;
        }
        let Some(additional) = &bucket.additional else {
            self.incomplete = true;
            return;
        };
        if additional.version < 2 {
            self.incomplete = true;
        }
        self.failures = self.failures.saturating_add(additional.auth_failures);
        for entry in &additional.auth_sources.entries {
            self.sources.add(&entry.key, entry.estimate);
        }
        for entry in &additional.auth_paths.entries {
            self.paths.add(&entry.key, entry.estimate);
        }
        if self
            .distinct
            .merge(&additional.unique_auth_sources)
            .is_err()
        {
            self.incomplete = true;
        }
        if additional.auth_sources.omitted_upper_bound != 0
            || additional.auth_paths.omitted_upper_bound != 0
        {
            self.incomplete = true;
        }
    }

    fn validate(&self) -> Result<(), Error> {
        validate_ranking(&self.sources)?;
        validate_ranking(&self.paths)?;
        if self.distinct.estimate().is_none() {
            return Err(Error::Message("invalid EDR distinct sketch".to_owned()));
        }
        Ok(())
    }
}

fn validate_ranking(ranking: &Ranking) -> Result<(), Error> {
    if ranking.entries.len() > MAX_RANKS {
        return Err(Error::Message("EDR ranking exceeds its bound".to_owned()));
    }
    let mut keys = BTreeSet::new();
    for entry in &ranking.entries {
        if entry.key.is_empty()
            || entry.key.len() > 160
            || entry.key.chars().any(char::is_control)
            || entry.error > entry.estimate
            || !keys.insert(&entry.key)
        {
            return Err(Error::Message("invalid EDR ranking entry".to_owned()));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedMinute {
    generation: String,
    start_ms: u64,
    bucket: MetricBucket,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedHour {
    start_ms: u64,
    hour: HourAuth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    minutes: Vec<PersistedMinute>,
    hours: Vec<PersistedHour>,
    rolled: Vec<(String, u64)>,
    gaps: Vec<(u64, u64)>,
    last_observed_ms: u64,
    first_observed_ms: u64,
    last_generation: Option<String>,
    last_missed_updates: u64,
    missed_updates_at: u64,
    clock_discontinuity_at: u64,
    late_revisions: u64,
    snapshots: u64,
}

/// Rolling authentication state. The state is bounded and can be saved to a
/// compact file so a console restart does not discard the baseline and the
/// current window.
pub struct LiveEdr {
    config: LiveConfig,
    /// Keyed by WAF generation and minute start. Keeping the generation
    /// separates buckets from before and after a WAF restart.
    minutes: BTreeMap<(String, u64), MetricBucket>,
    hours: BTreeMap<u64, HourAuth>,
    /// Minutes already merged into `hours`. They remain in `minutes` for the
    /// detection window but must not be added twice.
    rolled: BTreeSet<(String, u64)>,
    gaps: Vec<(u64, u64)>,
    last_observed_ms: u64,
    first_observed_ms: u64,
    last_generation: Option<String>,
    last_missed_updates: u64,
    missed_updates_at: u64,
    clock_discontinuity_at: u64,
    late_revisions: u64,
    snapshots: u64,
}

impl LiveEdr {
    pub fn new(config: LiveConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config,
            minutes: BTreeMap::new(),
            hours: BTreeMap::new(),
            rolled: BTreeSet::new(),
            gaps: Vec::new(),
            last_observed_ms: 0,
            first_observed_ms: 0,
            last_generation: None,
            last_missed_updates: 0,
            missed_updates_at: 0,
            clock_discontinuity_at: 0,
            late_revisions: 0,
            snapshots: 0,
        })
    }

    /// Ingest one bounded snapshot. Repeated buckets are replaced by a higher
    /// revision; older revisions are ignored.
    pub fn ingest(&mut self, snapshot: &StatisticsSnapshot) -> Result<(), Error> {
        snapshot
            .validate()
            .map_err(|error| Error::Message(format!("invalid live snapshot: {error}")))?;
        let observed = snapshot.observed_at_ms;
        let generation = snapshot.source.generation.clone();

        if self.last_observed_ms != 0 && observed < self.last_observed_ms {
            // A backwards wall-clock step can duplicate minutes. Keep the
            // evidence, but mark the window incomplete instead of inventing a
            // clean interval.
            self.clock_discontinuity_at = observed;
        } else if self.last_observed_ms != 0
            && let Some(earliest) = snapshot.buckets.iter().map(|bucket| bucket.start_ms).min()
            && earliest > self.last_observed_ms
        {
            // The last snapshot ended at `last_observed_ms`; if the new
            // snapshot starts later, the boundary minute was never completed.
            self.record_gap(self.last_observed_ms, earliest);
        }

        if self.last_generation.as_deref() == Some(generation.as_str()) {
            if snapshot.missed_updates > self.last_missed_updates {
                self.missed_updates_at = observed;
            }
        } else {
            self.last_missed_updates = snapshot.missed_updates;
        }
        self.last_missed_updates = snapshot.missed_updates;
        self.last_generation = Some(generation.clone());
        if snapshot.clock_discontinuity {
            self.clock_discontinuity_at = observed;
        }

        let ring_ms = millis(self.config.ring);
        for bucket in &snapshot.buckets {
            let key = (generation.clone(), bucket.start_ms);
            if bucket.start_ms.saturating_add(ring_ms) < observed {
                continue;
            }
            if self.rolled.contains(&key) {
                // A revision after the rolling cutoff is outside the WAF's
                // snapshot ring in a healthy stream. Ignore it rather than
                // double-counting the hour, and make the window incomplete.
                if self
                    .minutes
                    .get(&key)
                    .is_none_or(|old| old.revision < bucket.revision)
                {
                    self.late_revisions = self.late_revisions.saturating_add(1);
                    self.clock_discontinuity_at = observed;
                }
                continue;
            }
            match self.minutes.get(&key) {
                Some(old) if old.revision >= bucket.revision => {}
                _ => {
                    self.minutes.insert(key, bucket.clone());
                }
            }
        }

        self.roll(observed);
        self.trim(observed);
        self.last_observed_ms = self.last_observed_ms.max(observed);
        if self.first_observed_ms == 0 {
            self.first_observed_ms = observed;
        }
        self.snapshots = self.snapshots.saturating_add(1);
        Ok(())
    }

    fn record_gap(&mut self, from: u64, until: u64) {
        if until <= from {
            return;
        }
        self.gaps.push((from, until));
    }

    fn roll(&mut self, observed: u64) {
        let cutoff = observed.saturating_sub(millis(self.config.ring));
        let keys: Vec<(String, u64)> = self
            .minutes
            .iter()
            .filter(|((_, start), _)| *start < cutoff)
            .map(|(key, _)| key.clone())
            .filter(|key| !self.rolled.contains(key))
            .collect();
        for key in keys {
            let Some(bucket) = self.minutes.get(&key) else {
                continue;
            };
            let hour_start = bucket.start_ms / HOUR_MS * HOUR_MS;
            let hour = self.hours.entry(hour_start).or_default();
            hour.merge(bucket);
            self.rolled.insert(key);
        }
    }

    fn trim(&mut self, observed: u64) {
        let keep_from = observed
            .saturating_sub(millis(self.config.window).saturating_add(millis(self.config.ring)));
        self.minutes.retain(|(_, start), _| *start >= keep_from);
        self.rolled.retain(|(_, start)| *start >= keep_from);
        if self.config.baseline.is_zero() {
            self.hours.clear();
        } else {
            let baseline_from =
                observed.saturating_sub(millis(self.config.baseline).saturating_add(HOUR_MS));
            self.hours.retain(|hour, _| *hour >= baseline_from);
        }
        let keep_gap_from = observed.saturating_sub(
            millis(self.config.window)
                .max(millis(self.config.baseline))
                .saturating_add(HOUR_MS),
        );
        self.gaps.retain(|(_, until)| *until >= keep_gap_from);
        let anomaly_horizon = millis(self.config.baseline)
            .max(millis(self.config.window))
            .saturating_add(HOUR_MS);
        if self.clock_discontinuity_at != 0
            && self.clock_discontinuity_at.saturating_add(anomaly_horizon) < observed
        {
            self.clock_discontinuity_at = 0;
        }
        if self.missed_updates_at != 0
            && self.missed_updates_at.saturating_add(anomaly_horizon) < observed
        {
            self.missed_updates_at = 0;
        }
    }

    /// Build the record view for one hourly report. The baseline deliberately
    /// excludes hours that overlap the detection window.
    fn baseline_records(&self, until: u64) -> Vec<BucketRecord> {
        let window_start = until.saturating_sub(millis(self.config.window));
        self.hours
            .iter()
            .filter(|(hour, value)| **hour + HOUR_MS <= window_start && !value.incomplete)
            .map(|(hour, value)| BucketRecord {
                start_ms: *hour,
                grain_ms: HOUR_MS,
                requests: value.failures,
                auth_failures: value.failures,
                auth_sources: ranking_entries(&value.sources),
                auth_paths: ranking_entries(&value.paths),
                auth_sketch: Some(value.distinct.clone()),
                status_401: 0,
                status_403: 0,
                observed_ms: HOUR_MS,
                incomplete: false,
                telemetry_version: Some(2),
            })
            .collect()
    }

    fn window_data(&self, until: u64) -> WindowData {
        let from = until.saturating_sub(millis(self.config.window));
        let window = Window {
            from_ms: from,
            until_ms: until,
        };
        let mut data = WindowData::new(window);
        for bucket in self.minutes.values() {
            if bucket.start_ms >= from && bucket.start_ms < until {
                data.add(BucketRecord::from_metric(bucket.clone()));
            }
        }
        let observed_minutes = data.buckets.keys().count() as u64;
        if observed_minutes < window.minutes()
            || self.clock_discontinuity_at >= window.from_ms
            || self.missed_updates_at >= window.from_ms
            || self
                .gaps
                .iter()
                .any(|(from, until)| *from < window.until_ms && *until > window.from_ms)
        {
            data.incomplete = true;
        }
        data
    }

    /// Run the same detection rules as the SQLite-backed analyzer against the
    /// retained live state. `until_ms` must be a whole minute; callers normally
    /// pass the end of the last complete hour.
    pub fn report(&self, until_ms: u64) -> Result<Report, Error> {
        if until_ms == 0 || !until_ms.is_multiple_of(MINUTE_MS) {
            return Err(Error::Message(
                "live EDR report boundary must be a whole UTC minute".to_owned(),
            ));
        }
        let window = Window {
            from_ms: until_ms.saturating_sub(millis(self.config.window)),
            until_ms,
        };
        let mut data = self.window_data(until_ms);
        let baseline = Baseline::from_records(&self.baseline_records(until_ms));
        let mut findings = data.slow_findings(&baseline, &self.config.thresholds);
        if let Some(finding) = data.reverse_finding(&baseline, &self.config.thresholds) {
            findings.push(finding);
        }
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.source.cmp(&b.source))
        });
        let telemetry = data.telemetry_state();
        let mut notes = data.notes(&baseline, telemetry);
        notes.push(
            "Live in-memory source: the baseline is restored from the saved state when present; otherwise it begins at process start."
                .to_owned(),
        );
        if self.snapshots < 12 {
            notes.push(format!(
                "Only {} snapshot(s) have been ingested; the window is still warming up.",
                self.snapshots
            ));
        }
        if self.clock_discontinuity_at >= window.from_ms {
            notes.push(
                "A clock discontinuity was observed in this window; findings are a lower bound."
                    .to_owned(),
            );
        }
        if self.missed_updates_at >= window.from_ms {
            notes.push(
                "The WAF reported missed measurement updates in this window; findings are a lower bound."
                    .to_owned(),
            );
        }
        if self.late_revisions != 0 {
            notes.push(format!(
                "{} late bucket revision(s) arrived after rolling; their hourly contribution is not counted twice.",
                self.late_revisions
            ));
        }
        for (from, until) in self
            .gaps
            .iter()
            .filter(|(from, until)| *from < window.until_ms && *until > window.from_ms)
        {
            notes.push(format!(
                "Collection gap {} .. {}; minutes in the gap are missing.",
                format_utc(*from),
                format_utc(*until)
            ));
        }
        let summary = data.summary(&baseline);
        Ok(Report {
            generated_at_ms: until_ms,
            database: "live-memory".to_owned(),
            site: None,
            window,
            telemetry,
            summary,
            findings,
            notes,
        })
    }

    /// Load a previously saved state. Returns `Ok(None)` when the file does
    /// not exist. A malformed or oversized file is an error; the console
    /// runtime logs it and starts with an empty state.
    pub fn load(path: &Path, config: LiveConfig) -> Result<Option<Self>, Error> {
        config.validate()?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::Message(format!("{}: {error}", path.display())));
            }
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Message(format!(
                "{} is not a regular EDR state file",
                path.display()
            )));
        }
        if metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(Error::Message(
                "EDR state file exceeds the size limit".to_owned(),
            ));
        }
        let bytes = fs::read(path).map_err(|error| {
            Error::Message(format!("failed to read {}: {error}", path.display()))
        })?;
        let state: PersistedState = serde_json::from_slice(&bytes)
            .map_err(|error| Error::Message(format!("invalid EDR state: {error}")))?;
        if state.version != STATE_VERSION {
            return Err(Error::Message(format!(
                "unsupported EDR state version {}",
                state.version
            )));
        }
        if state.minutes.len() > MAX_STATE_MINUTES
            || state.hours.len() > MAX_STATE_HOURS
            || state.gaps.len() > MAX_STATE_GAPS
        {
            return Err(Error::Message("EDR state exceeds its bounds".to_owned()));
        }
        if state.last_observed_ms != 0 && state.first_observed_ms > state.last_observed_ms {
            return Err(Error::Message("invalid EDR state time range".to_owned()));
        }
        let mut minutes = BTreeMap::new();
        for minute in state.minutes {
            minute.bucket.validate()?;
            if minute.bucket.start_ms != minute.start_ms {
                return Err(Error::Message("EDR state minute key mismatch".to_owned()));
            }
            if minutes
                .insert((minute.generation, minute.start_ms), minute.bucket)
                .is_some()
            {
                return Err(Error::Message("duplicate EDR state minute".to_owned()));
            }
        }
        let mut hours = BTreeMap::new();
        for hour in state.hours {
            hour.hour.validate()?;
            if hours.insert(hour.start_ms, hour.hour).is_some() {
                return Err(Error::Message("duplicate EDR state hour".to_owned()));
            }
        }
        let rolled = state.rolled.into_iter().collect::<BTreeSet<_>>();
        let mut gaps = Vec::with_capacity(state.gaps.len());
        for (from, until) in state.gaps {
            if from >= until {
                return Err(Error::Message("invalid EDR state gap".to_owned()));
            }
            gaps.push((from, until));
        }
        let mut live = Self {
            config,
            minutes,
            hours,
            rolled,
            gaps,
            last_observed_ms: state.last_observed_ms,
            first_observed_ms: state.first_observed_ms,
            last_generation: state.last_generation,
            last_missed_updates: state.last_missed_updates,
            missed_updates_at: state.missed_updates_at,
            clock_discontinuity_at: state.clock_discontinuity_at,
            late_revisions: state.late_revisions,
            snapshots: state.snapshots,
        };
        live.trim(live.last_observed_ms);
        Ok(Some(live))
    }

    /// Persist the bounded state atomically. The caller supplies the file
    /// path; the console runtime uses `<storage_dir>/edr-state.json`.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let state = PersistedState {
            version: STATE_VERSION,
            minutes: self
                .minutes
                .iter()
                .map(|((generation, start_ms), bucket)| PersistedMinute {
                    generation: generation.clone(),
                    start_ms: *start_ms,
                    bucket: bucket.clone(),
                })
                .collect(),
            hours: self
                .hours
                .iter()
                .map(|(start_ms, hour)| PersistedHour {
                    start_ms: *start_ms,
                    hour: hour.clone(),
                })
                .collect(),
            rolled: self.rolled.iter().cloned().collect(),
            gaps: self.gaps.clone(),
            last_observed_ms: self.last_observed_ms,
            first_observed_ms: self.first_observed_ms,
            last_generation: self.last_generation.clone(),
            last_missed_updates: self.last_missed_updates,
            missed_updates_at: self.missed_updates_at,
            clock_discontinuity_at: self.clock_discontinuity_at,
            late_revisions: self.late_revisions,
            snapshots: self.snapshots,
        };
        let bytes = serde_json::to_vec(&state)
            .map_err(|error| Error::Message(format!("EDR state encoding failed: {error}")))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(Error::Message(
                "EDR state exceeds the encoded size limit".to_owned(),
            ));
        }
        let temporary = path.with_extension("json.tmp");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::Message(format!(
                    "failed to clear {}: {error}",
                    temporary.display()
                )));
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            Error::Message(format!("failed to create {}: {error}", temporary.display()))
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| Error::Message(format!("failed to write EDR state: {error}")))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| {
            Error::Message(format!("failed to replace {}: {error}", path.display()))
        })?;
        Ok(())
    }

    pub fn config(&self) -> LiveConfig {
        self.config
    }

    pub fn snapshots(&self) -> u64 {
        self.snapshots
    }

    pub fn retained_minutes(&self) -> usize {
        self.minutes.len()
    }

    pub fn retained_hours(&self) -> usize {
        self.hours.len()
    }

    pub fn gaps(&self) -> &[(u64, u64)] {
        &self.gaps
    }

    pub fn late_revisions(&self) -> u64 {
        self.late_revisions
    }

    pub fn last_observed_ms(&self) -> u64 {
        self.last_observed_ms
    }

    pub fn first_observed_ms(&self) -> u64 {
        self.first_observed_ms
    }

    /// Approximate retained payload size. This is a payload measurement, not
    /// an allocator measurement; the maps and allocator overhead are separate.
    pub fn retained_bytes(&self) -> usize {
        let minutes: usize = self
            .minutes
            .values()
            .map(|bucket| serde_json::to_vec(bucket).map_or(0, |value| value.len()))
            .sum();
        let hours: usize = self
            .hours
            .values()
            .map(|hour| 64 + hour.sources.entries.len() * 64 + hour.paths.entries.len() * 64 + 64)
            .sum();
        minutes.saturating_add(hours)
    }

    /// True when the retained state has no usable baseline yet.
    pub fn baseline_warming_up(&self) -> bool {
        self.hours.len() < 2
    }
}

fn ranking_entries(ranking: &Ranking) -> Vec<(String, u64, u64)> {
    ranking
        .entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.estimate, entry.error))
        .collect()
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::measurements::AdditionalMeasurements;
    use crate::console::model::{Counters, Coverage, SourceIdentity};
    use crate::observations::StatisticsSnapshot;

    const BASE: u64 = 1_700_000_040_000;

    fn partial_bucket(start: u64, revision: u64) -> MetricBucket {
        let additional = AdditionalMeasurements::measured();
        additional.validate().unwrap();
        MetricBucket {
            start_ms: start,
            site: None,
            revision,
            counters: Counters {
                requests: Some(0),
                ..Counters::default()
            },
            connections: None,
            coverage: Coverage {
                observed_ms: 0,
                incomplete: true,
                omitted_events: None,
            },
            outcomes: None,
            additional: Some(Box::new(additional)),
        }
    }

    #[test]
    fn a_missing_poll_is_visible_as_a_gap() {
        let mut live = LiveEdr::new(LiveConfig {
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(3600),
            poll_interval: Duration::from_secs(300),
            ring: Duration::from_secs(720),
            thresholds: Thresholds::default(),
        })
        .unwrap();
        let source = SourceIdentity {
            instance: "live-test".into(),
            generation: "g1".into(),
        };
        let first = StatisticsSnapshot {
            version: 3,
            source: source.clone(),
            sequence: 1,
            observed_at_ms: BASE,
            started_at_ms: BASE,
            clock_discontinuity: false,
            counters: Counters::default(),
            active_connections: 0,
            missed_updates: 0,
            buckets: vec![partial_bucket(BASE, 1)],
            events: Vec::new(),
            events_omitted: 0,
            event_sequence: 0,
            additional_missed_updates: Some(0),
        };
        live.ingest(&first).unwrap();
        let second = StatisticsSnapshot {
            version: 3,
            source,
            sequence: 2,
            observed_at_ms: BASE + 10 * MINUTE_MS,
            started_at_ms: BASE,
            clock_discontinuity: false,
            counters: Counters::default(),
            active_connections: 0,
            missed_updates: 0,
            buckets: vec![partial_bucket(BASE + 10 * MINUTE_MS, 2)],
            events: Vec::new(),
            events_omitted: 0,
            event_sequence: 0,
            additional_missed_updates: Some(0),
        };
        live.ingest(&second).unwrap();
        assert!(!live.gaps().is_empty());
    }
}
