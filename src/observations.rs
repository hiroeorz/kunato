//! Fixed-memory source measurements. Request updates never wait for export or storage.

use std::array;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::console::Error;
use crate::console::model::{
    ConnectionGauge, Counters, Coverage, Disposition, EventRecord, LATENCY_BOUNDS_US, MINUTE_MS,
    MetricBucket, Outcomes, Phase, RejectionReason, SourceIdentity,
};
mod additional;

pub const MINUTE_SLOTS: usize = 10;
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
const EXCLUSIVE: u64 = 1 << 63;
const EMPTY: u64 = u64::MAX;
const REASONS: usize = 16;
const ATTACK_CLASSES: usize = REASONS + RejectionReason::ALL.len();
const STATUS: usize = ATTACK_CLASSES + crate::logs::ATTACK_CLASS_COUNT;
const LATENCY: usize = STATUS + 500;
const LATENCY_COUNT: usize = LATENCY + 15;
const LATENCY_SUM: usize = LATENCY_COUNT + 1;
const IN_FLIGHT: usize = LATENCY_SUM + 1;
const CONNECTION_MS: usize = IN_FLIGHT + 1;
const CONNECTION_COVERAGE: usize = CONNECTION_MS + 1;
const CONNECTION_MAX: usize = CONNECTION_COVERAGE + 1;
const CONNECTION_SAMPLES: usize = CONNECTION_MAX + 1;
const LATENCY_MIN: usize = CONNECTION_SAMPLES + 1;
const LATENCY_MAX: usize = LATENCY_MIN + 1;
const CONNECTION_MIN: usize = LATENCY_MAX + 1;
const FIELDS: usize = CONNECTION_MIN + 1;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Count {
    Requests,
    Rejected,
    Logged,
    Matches,
    ResponseBlocks,
    RateLimited,
    Banned,
    Overloaded,
    UpstreamFailures,
    UpstreamTimeouts,
    DecoyCredential,
    DecoyOccurrence,
    DecoyBlocked,
    DecoyIssued,
    ResponseLogged,
    Aborted,
}

pub(crate) struct DecoyDetail<'a> {
    pub site: &'a str,
    pub credential_id: &'a str,
    pub context: crate::console::model::DecoyContext,
    pub age_seconds: Option<u64>,
    pub lure: Option<&'a str>,
    pub template: Option<&'a str>,
    pub source: crate::client_ip::ClientSource,
    pub blocked: bool,
    pub incomplete: bool,
}

struct Slot {
    gate: AtomicU64,
    version: AtomicU64,
    generation: AtomicU64,
    minute: AtomicU64,
    values: [AtomicU64; FIELDS],
}
struct Pinned<'a>(&'a Slot);
impl Drop for Pinned<'_> {
    fn drop(&mut self) {
        self.0.version.fetch_add(1, Ordering::Release);
        self.0.gate.fetch_sub(1, Ordering::Release);
    }
}

impl Slot {
    fn new() -> Self {
        Self {
            gate: AtomicU64::new(0),
            version: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            minute: AtomicU64::new(EMPTY),
            values: array::from_fn(|index| {
                AtomicU64::new(if index == LATENCY_MIN || index == CONNECTION_MIN {
                    u64::MAX
                } else {
                    0
                })
            }),
        }
    }
    fn pin(&self, generation: u64, minute: u64, initialize: bool) -> Option<Pinned<'_>> {
        let previous = self.gate.fetch_add(1, Ordering::Acquire);
        if previous & EXCLUSIVE == 0 {
            let pinned = Pinned(self);
            if self.generation.load(Ordering::Acquire) == generation
                && self.minute.load(Ordering::Acquire) == minute
            {
                return Some(pinned);
            }
            drop(pinned);
        } else {
            self.gate.fetch_sub(1, Ordering::Release);
        }
        if !initialize
            || self
                .gate
                .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        let old_generation = self.generation.load(Ordering::Relaxed);
        if old_generation > generation {
            self.gate.fetch_sub(EXCLUSIVE, Ordering::Release);
            return None;
        }
        let old = self.minute.load(Ordering::Relaxed);
        if old_generation != generation || old == EMPTY || old < minute {
            for (index, value) in self.values.iter().enumerate() {
                value.store(
                    if index == LATENCY_MIN || index == CONNECTION_MIN {
                        u64::MAX
                    } else {
                        0
                    },
                    Ordering::Relaxed,
                );
            }
            self.minute.store(minute, Ordering::Release);
            self.generation.store(generation, Ordering::Release);
        }
        self.gate.fetch_sub(EXCLUSIVE, Ordering::Release);
        let previous = self.gate.fetch_add(1, Ordering::Acquire);
        if previous & EXCLUSIVE == 0 {
            let pinned = Pinned(self);
            if self.generation.load(Ordering::Acquire) == generation
                && self.minute.load(Ordering::Acquire) == minute
            {
                return Some(pinned);
            }
            drop(pinned);
        } else {
            self.gate.fetch_sub(1, Ordering::Release);
        }
        None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatisticsSnapshot {
    pub version: u32,
    pub source: SourceIdentity,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub started_at_ms: u64,
    pub clock_discontinuity: bool,
    pub counters: Counters,
    pub active_connections: u64,
    pub missed_updates: u64,
    pub buckets: Vec<MetricBucket>,
    pub events: Vec<EventRecord>,
    pub events_omitted: u64,
    pub event_sequence: u64,
    #[serde(default)]
    pub additional_missed_updates: Option<u64>,
}

impl StatisticsSnapshot {
    pub fn validate(&self) -> Result<(), Error> {
        self.source.validate()?;
        if !matches!(self.version, 2 | 3)
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.started_at_ms > self.observed_at_ms
            || self.buckets.is_empty()
            || self.buckets.len() > MINUTE_SLOTS
            || self.events.len() > 64
        {
            return Err(Error::Invalid("invalid statistics snapshot envelope"));
        }
        crate::console::model::timestamp(self.observed_at_ms)?;
        let mut starts = std::collections::HashSet::new();
        let current = minute(self.observed_at_ms);
        for bucket in &self.buckets {
            bucket.validate()?;
            if bucket.site.is_some()
                || bucket.start_ms > current
                || current - bucket.start_ms >= MINUTE_SLOTS as u64 * MINUTE_MS
                || bucket.revision > self.sequence
                || !starts.insert(bucket.start_ms)
            {
                return Err(Error::Invalid("invalid source-minute range or revision"));
            }
        }
        for event in &self.events {
            event.validate()?;
        }
        if self.event_sequence > i64::MAX as u64
            || self
                .events
                .windows(2)
                .any(|events| events[0].sequence >= events[1].sequence)
            || self
                .events
                .last()
                .is_some_and(|event| event.sequence > self.event_sequence)
        {
            return Err(Error::Invalid("invalid event sequence window"));
        }
        Ok(())
    }
}

struct Export {
    sequence: u64,
    previous: Vec<MetricBucket>,
    gauge: Option<(u64, u64)>,
    events: Vec<EventRecord>,
    event_sequence: u64,
}
struct Detail {
    events: VecDeque<EventRecord>,
    bytes: usize,
    second: u64,
    emitted: usize,
    ordinary_emitted: usize,
}

pub struct Observations {
    additional: additional::Recorder,
    enabled: bool,
    source: SourceIdentity,
    started: Instant,
    epoch_ms: u64,
    clock_offset_ms: AtomicI64,
    ring_generation: AtomicU64,
    ring_floor_ms: AtomicU64,
    clock_transition: AtomicBool,
    slots: Box<[Slot; MINUTE_SLOTS]>,
    cumulative: [AtomicU64; STATUS],
    newest: AtomicU64,
    missed: AtomicU64,
    first_missed: AtomicU64,
    last_missed: AtomicU64,
    export: Mutex<Export>,
    detail: Mutex<Detail>,
    detail_omitted: AtomicU64,
    event_sequence: AtomicU64,
}

impl std::fmt::Debug for Observations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observations")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Observations {
    pub fn new() -> Self {
        let mut nonce = [0_u8; 16];
        let random = SystemRandom::new().fill(&mut nonce).is_ok();
        let generation = if random {
            nonce.iter().map(|byte| format!("{byte:02x}")).collect()
        } else {
            String::new()
        };
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as u64;
        Self {
            additional: additional::Recorder::new(&generation),
            enabled: true,
            source: SourceIdentity {
                instance: "waf".into(),
                generation,
            },
            started: Instant::now(),
            epoch_ms,
            clock_offset_ms: AtomicI64::new(0),
            ring_generation: AtomicU64::new(0),
            ring_floor_ms: AtomicU64::new(minute(epoch_ms)),
            clock_transition: AtomicBool::new(false),
            slots: Box::new(array::from_fn(|_| Slot::new())),
            cumulative: array::from_fn(|_| AtomicU64::new(0)),
            newest: AtomicU64::new(minute(epoch_ms)),
            missed: AtomicU64::new(0),
            first_missed: AtomicU64::new(EMPTY),
            last_missed: AtomicU64::new(0),
            export: Mutex::new(Export {
                sequence: 0,
                previous: Vec::new(),
                gauge: None,
                events: Vec::new(),
                event_sequence: 0,
            }),
            detail: Mutex::new(Detail {
                events: VecDeque::new(),
                bytes: 0,
                second: 0,
                emitted: 0,
                ordinary_emitted: 0,
            }),
            detail_omitted: AtomicU64::new(0),
            event_sequence: AtomicU64::new(0),
        }
    }

    pub fn now_ms(&self) -> u64 {
        let elapsed = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let base = self.epoch_ms.saturating_add(elapsed);
        let offset = self.clock_offset_ms.load(Ordering::Acquire);
        if offset >= 0 {
            base.saturating_add(offset as u64)
        } else {
            base.saturating_sub(offset.unsigned_abs())
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::new()
        }
    }

    fn lost(&self, start: u64) {
        self.missed.fetch_add(1, Ordering::Relaxed);
        self.first_missed.fetch_min(start, Ordering::Relaxed);
        self.last_missed.fetch_max(start, Ordering::Relaxed);
    }

    fn update_for(&self, generation: u64, start: u64, field: usize, value: u64) {
        self.update_many(generation, start, &[(field, value)]);
    }

    fn update_many(&self, generation: u64, start: u64, updates: &[(usize, u64)]) {
        for &(field, value) in updates {
            if field < STATUS {
                self.cumulative[field].fetch_add(value, Ordering::Relaxed);
            }
        }
        self.update_slot(generation, start, |slot| {
            for &(field, value) in updates {
                slot.values[field].fetch_add(value, Ordering::Relaxed);
            }
        });
    }

    fn update_slot(&self, generation: u64, start: u64, update: impl FnOnce(&Slot)) {
        if generation != self.ring_generation.load(Ordering::Acquire) {
            return;
        }
        let latest = self.newest.fetch_max(start, Ordering::Relaxed).max(start);
        if latest.saturating_sub(start) >= MINUTE_SLOTS as u64 * MINUTE_MS {
            self.lost(start);
            return;
        }
        let slot = &self.slots[(start / MINUTE_MS) as usize % MINUTE_SLOTS];
        if let Some(pinned) = slot.pin(generation, start, true) {
            update(pinned.0);
        } else {
            self.lost(start);
        }
    }

    pub fn count(&self, start: u64, count: Count) {
        self.count_for(self.ring_generation.load(Ordering::Acquire), start, count);
    }

    fn count_for(&self, generation: u64, start: u64, count: Count) {
        self.update_for(generation, start, count as usize, 1);
    }

    pub fn configure(&self, config: &crate::config::CompiledConfig) {
        self.additional.configure(self.now_ms(), config);
    }
    pub fn operation(&self, kind: crate::console::measurements::Operation) {
        self.additional.operation(self.now_ms(), kind);
    }
    pub fn certificate(&self, expires: u64) {
        self.additional.certificate(self.now_ms(), expires);
    }
    pub fn rules_success(&self) {
        self.additional.rules_success(self.now_ms());
    }
    pub fn credential_id(&self, at: Option<u64>, id: &str) {
        if self.enabled {
            let partition = CURRENT
                .try_with(|cell| cell.try_borrow().ok().map(|value| value.partition))
                .ok()
                .flatten()
                .unwrap_or(0);
            self.additional
                .credential(at.unwrap_or_else(|| minute(self.now_ms())), partition, id);
        }
    }

    pub fn record_event(&self, event: EventRecord) {
        self.event_with(|_, _| event);
    }

    pub(crate) fn decoy_detail(&self, detail: DecoyDetail<'_>) {
        use crate::console::model::{DecoyEvidence, Disposition, EventKind};
        let (method, path) = CURRENT
            .try_with(|cell| {
                cell.try_borrow()
                    .ok()
                    .map(|value| (value.method.clone(), event_path(&value.path)))
            })
            .ok()
            .flatten()
            .unwrap_or((None, None));
        self.event_with_priority(true, |sequence, time| EventRecord {
            id: format!("decoy-{sequence}"),
            sequence,
            occurred_at_ms: time,
            kind: EventKind::Decoy,
            disposition: if detail.blocked {
                Disposition::Block
            } else if detail.context == crate::console::model::DecoyContext::Issued {
                Disposition::Observe
            } else {
                Disposition::Log
            },
            phase: Phase::Request,
            site: event_site(detail.site),
            client: Some(detail.source.client_ip),
            peer: Some(detail.source.peer.ip()),
            country: current_country(),
            method,
            path,
            status: None,
            category: None,
            rule: None,
            attack_class: None,
            reason: None,
            decoy: Some(DecoyEvidence {
                credential_id: detail.credential_id.into(),
                context: detail.context,
                issued_at_ms: None,
                age_seconds: detail.age_seconds,
                lure: detail
                    .lure
                    .filter(|value| value.len() <= 2048)
                    .map(str::to_owned),
                template: detail
                    .template
                    .filter(|value| value.len() <= 64)
                    .map(str::to_owned),
            }),
            gap: None,
            incomplete: detail.incomplete,
        });
    }

    pub fn event_with(&self, make: impl FnOnce(u64, u64) -> EventRecord) {
        self.event_with_priority(false, make);
    }

    fn event_with_priority(&self, priority: bool, make: impl FnOnce(u64, u64) -> EventRecord) {
        if !self.enabled {
            return;
        }
        let Ok(mut detail) = self.detail.try_lock() else {
            self.detail_omitted.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let sequence = self
            .event_sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let second = self.now_ms() / 1000;
        if detail.second != second {
            detail.second = second;
            detail.emitted = 0;
            detail.ordinary_emitted = 0;
        }
        if detail.emitted >= 16 || !priority && detail.ordinary_emitted >= 12 {
            self.detail_omitted.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Invalid metadata still consumes its admission slot before validation.
        detail.emitted += 1;
        if !priority {
            detail.ordinary_emitted += 1;
        }
        let mut event = make(sequence, self.now_ms());
        event.sequence = sequence;
        if event.validate().is_err() {
            self.detail_omitted.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let bytes = serde_json::to_vec(&event).map_or(usize::MAX, |json| json.len());
        if bytes > 16 * 1024 {
            self.detail_omitted.fetch_add(1, Ordering::Relaxed);
            return;
        }
        while detail.events.len() >= 64 || detail.bytes.saturating_add(bytes) > 64 * 1024 {
            let replacement = detail
                .events
                .iter()
                .position(|old| old.decoy.is_none())
                .or_else(|| priority.then_some(0));
            let Some(index) = replacement else {
                self.detail_omitted.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let Some(old) = detail.events.remove(index) else {
                break;
            };
            detail.bytes = detail
                .bytes
                .saturating_sub(serde_json::to_vec(&old).map_or(0, |json| json.len()));
            self.detail_omitted.fetch_add(1, Ordering::Relaxed);
        }
        detail.bytes += bytes;
        detail.events.push_back(event);
    }

    pub fn snapshot(&self, active_connections: u64) -> Result<StatisticsSnapshot, Error> {
        if !self.enabled {
            return Err(Error::Invalid("statistics capture is disabled"));
        }
        let actual = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.reconcile_clock(actual);
        self.snapshot_at(self.now_ms(), actual, active_connections)
    }

    fn reconcile_clock(&self, actual: u64) {
        let Ok(mut export) = self.export.try_lock() else {
            return;
        };
        let now = self.now_ms();
        let diff = i128::from(actual) - i128::from(now);
        if diff.abs() <= 2000 || actual < self.epoch_ms {
            return;
        }
        let Ok(offset) = i64::try_from(diff) else {
            return;
        };
        self.clock_offset_ms.fetch_add(offset, Ordering::AcqRel);
        self.ring_generation.fetch_add(1, Ordering::AcqRel);
        let floor = minute(actual);
        self.additional.reset(floor);
        self.ring_floor_ms.store(floor, Ordering::Release);
        self.newest.store(floor, Ordering::Release);
        self.first_missed.store(EMPTY, Ordering::Release);
        self.last_missed.store(0, Ordering::Release);
        self.clock_transition.store(true, Ordering::Release);
        export.previous.clear();
        export.gauge = None;
    }

    fn snapshot_at(
        &self,
        now: u64,
        actual: u64,
        active_connections: u64,
    ) -> Result<StatisticsSnapshot, Error> {
        self.source.validate()?;
        let mut export = self.export.try_lock().map_err(|_| Error::Busy)?;
        let sequence = export
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= i64::MAX as u64)
            .ok_or(Error::Invalid("source sequence exhausted"))?;
        let generation = self.ring_generation.load(Ordering::Acquire);
        let floor = self.ring_floor_ms.load(Ordering::Acquire);
        let current = minute(now);
        self.newest.fetch_max(current, Ordering::Relaxed);
        let start = floor.max(current.saturating_sub((MINUTE_SLOTS as u64 - 1) * MINUTE_MS));
        if let Some((previous, value)) = export.gauge
            && now > previous
            && now - previous <= 2000
        {
            let mut at = previous;
            while at < now {
                let bucket = minute(at);
                let end = now.min(bucket.saturating_add(MINUTE_MS));
                self.update_for(
                    generation,
                    bucket,
                    CONNECTION_MS,
                    value.saturating_mul(end - at),
                );
                self.update_for(generation, bucket, CONNECTION_COVERAGE, end - at);
                let slot = &self.slots[(bucket / MINUTE_MS) as usize % MINUTE_SLOTS];
                if let Some(pinned) = slot.pin(generation, bucket, true) {
                    pinned.0.values[CONNECTION_MAX].fetch_max(value, Ordering::Relaxed);
                    pinned.0.values[CONNECTION_MIN].fetch_min(value, Ordering::Relaxed);
                }
                at = end;
            }
        }
        export.gauge = Some((now, active_connections));
        if let Some(pinned) =
            self.slots[(current / MINUTE_MS) as usize % MINUTE_SLOTS].pin(generation, current, true)
        {
            pinned.0.values[CONNECTION_MAX].fetch_max(active_connections, Ordering::Relaxed);
            pinned.0.values[CONNECTION_MIN].fetch_min(active_connections, Ordering::Relaxed);
            pinned.0.values[CONNECTION_SAMPLES].fetch_add(1, Ordering::Relaxed);
        } else {
            self.lost(current);
        }
        let clock_discontinuity =
            self.clock_transition.swap(false, Ordering::AcqRel) || now.abs_diff(actual) > 2000;
        let mut buckets = Vec::with_capacity(MINUTE_SLOTS);
        for i in 0..MINUTE_SLOTS {
            let at = start + i as u64 * MINUTE_MS;
            if at > current {
                break;
            }
            let slot = &self.slots[(at / MINUTE_MS) as usize % MINUTE_SLOTS];
            let mut captured = None;
            for _ in 0..3 {
                let Some(pinned) = slot.pin(generation, at, true) else {
                    continue;
                };
                let version = pinned.0.version.load(Ordering::Acquire);
                let values: [u64; FIELDS] =
                    array::from_fn(|index| pinned.0.values[index].load(Ordering::Acquire));
                if pinned.0.gate.load(Ordering::Acquire) == 1
                    && pinned.0.version.load(Ordering::Acquire) == version
                {
                    captured = Some(values);
                    break;
                }
            }
            let Some(values) = captured else {
                let mut bucket = export
                    .previous
                    .iter()
                    .find(|previous| previous.start_ms == at)
                    .cloned()
                    .unwrap_or(MetricBucket {
                        start_ms: at,
                        site: None,
                        revision: sequence,
                        counters: Counters::default(),
                        connections: None,
                        coverage: Coverage::default(),
                        outcomes: None,
                        additional: None,
                    });
                if !bucket.coverage.incomplete {
                    bucket.coverage.incomplete = true;
                    bucket.revision = sequence;
                }
                if let Some(additional) = &mut bucket.additional {
                    additional.incomplete = true;
                }
                buckets.push(bucket);
                continue;
            };
            let observed = now.min(at + MINUTE_MS).saturating_sub(at.max(floor)) as u32;
            let omitted = at >= self.first_missed.load(Ordering::Relaxed)
                && at <= self.last_missed.load(Ordering::Relaxed);
            let mut bucket = MetricBucket {
                start_ms: at,
                site: None,
                revision: sequence,
                counters: counters(|index| values[index]),
                connections: connection_gauge(&values),
                coverage: Coverage {
                    observed_ms: observed,
                    incomplete: observed != MINUTE_MS as u32
                        || values[IN_FLIGHT] != 0
                        || omitted
                        || clock_discontinuity,
                    omitted_events: None,
                },
                outcomes: Some(Outcomes {
                    statuses: values[STATUS..LATENCY].to_vec(),
                    latency_count: values[LATENCY_COUNT],
                    latency_sum_us: values[LATENCY_SUM],
                    latency_bins: array::from_fn(|index| values[LATENCY + index]),
                    in_flight: values[IN_FLIGHT],
                    latency_min_us: (values[LATENCY_COUNT] > 0).then_some(values[LATENCY_MIN]),
                    latency_max_us: (values[LATENCY_COUNT] > 0).then_some(values[LATENCY_MAX]),
                }),
                additional: self.additional.capture(at),
            };
            if let Some(additional) = &mut bucket.additional {
                additional.incomplete |= bucket.coverage.incomplete
                    || additional.completed_requests != values[Count::Requests as usize];
            }
            while serde_json::to_vec(&bucket).map_or(usize::MAX, |value| value.len())
                > crate::console::model::MAX_RECORD_BYTES
            {
                if !bucket
                    .additional
                    .as_mut()
                    .is_some_and(|value| value.shrink())
                {
                    bucket.additional = None;
                    break;
                }
            }
            if let Some(previous) = export
                .previous
                .iter()
                .find(|previous| previous.start_ms == at)
            {
                bucket.revision = previous.revision;
                if bucket != *previous {
                    bucket.revision = sequence;
                }
            }
            buckets.push(bucket);
        }
        if let Ok(detail) = self.detail.try_lock() {
            export.events = detail.events.iter().cloned().collect();
            export.events.sort_by_key(|event| event.sequence);
            export.event_sequence = self.event_sequence.load(Ordering::Acquire);
        }
        let events = export.events.clone();
        let event_sequence = export.event_sequence;
        let packet = StatisticsSnapshot {
            version: 3,
            source: self.source.clone(),
            sequence,
            observed_at_ms: now,
            started_at_ms: self.epoch_ms,
            clock_discontinuity,
            counters: counters(|index| self.cumulative[index].load(Ordering::Acquire)),
            active_connections,
            missed_updates: self.missed.load(Ordering::Relaxed),
            buckets,
            events,
            events_omitted: self.detail_omitted.load(Ordering::Relaxed),
            event_sequence,
            additional_missed_updates: Some(self.additional.missed()),
        };
        packet.validate()?;
        export.sequence = sequence;
        export.previous = packet.buckets.clone();
        Ok(packet)
    }
}

impl Default for Observations {
    fn default() -> Self {
        Self::new()
    }
}

/// Attribute the current request's upstream authentication failure to its
/// source-minute. The proxy calls this only after observing a `401`/`403` on a
/// configured authentication path.
pub fn auth_failure() {
    let _ = CURRENT.try_with(|cell| {
        if let Ok(mut value) = cell.try_borrow_mut() {
            value.auth_failure = true;
        }
    });
}

fn counters(load: impl Fn(usize) -> u64) -> Counters {
    Counters {
        rejection_classes: Some(rejection_classes(
            |index| load(ATTACK_CLASSES + index),
            |reason| load(REASONS + reason as usize),
        )),
        requests: Some(load(Count::Requests as usize)),
        rejected_requests: Some(load(Count::Rejected as usize)),
        log_requests: Some(load(Count::Logged as usize)),
        rule_matches: Some(load(Count::Matches as usize)),
        response_blocks: Some(load(Count::ResponseBlocks as usize)),
        rate_limited_requests: Some(load(Count::RateLimited as usize)),
        banned_requests: Some(load(Count::Banned as usize)),
        overloaded_requests: Some(load(Count::Overloaded as usize)),
        upstream_connection_failures: Some(load(Count::UpstreamFailures as usize)),
        upstream_timeouts: Some(load(Count::UpstreamTimeouts as usize)),
        decoy_credential_use_requests: Some(load(Count::DecoyCredential as usize)),
        decoy_occurrence_requests: Some(load(Count::DecoyOccurrence as usize)),
        decoy_blocked_requests: Some(load(Count::DecoyBlocked as usize)),
        decoy_issued: Some(load(Count::DecoyIssued as usize)),
        response_log_requests: Some(load(Count::ResponseLogged as usize)),
        aborted_requests: Some(load(Count::Aborted as usize)),
        rejection_reasons: Some(
            RejectionReason::ALL
                .into_iter()
                .map(|reason| (reason, load(REASONS + reason as usize)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

fn rejection_reason_class(reason: RejectionReason) -> &'static str {
    match reason {
        RejectionReason::Rule | RejectionReason::ResponseRule => "other",
        RejectionReason::RateLimit => "rate-limit",
        RejectionReason::Ban => "ban",
        RejectionReason::Overload => "overload",
        RejectionReason::ClientIdentity => "client-identity",
        RejectionReason::Host => "host",
        RejectionReason::AdminAccess => "admin-access",
        RejectionReason::Body => "body-limit",
        RejectionReason::Decode => "decode",
        RejectionReason::Form => "form",
        RejectionReason::Upload => "malicious-upload",
        RejectionReason::Graphql => "graphql",
        RejectionReason::Saml => "saml",
        RejectionReason::PhpRequest => "php-request",
        RejectionReason::PhpResponse => "php-response",
        RejectionReason::Hardening => "hardening",
        RejectionReason::Jwt => "jwt",
        RejectionReason::Decoy => "decoy",
        RejectionReason::Behavior => "behavior",
        RejectionReason::Protocol => "protocol",
        RejectionReason::ResponseInspection => "response-inspection",
        RejectionReason::CountryPolicy => "country-policy",
    }
}

fn rejection_class(reason: RejectionReason, category: Option<&str>) -> &'static str {
    if matches!(
        reason,
        RejectionReason::Rule | RejectionReason::ResponseRule
    ) {
        return crate::logs::observation_attack_name(category.unwrap_or(""));
    }
    rejection_reason_class(reason)
}

fn rejection_classes(
    load_attack: impl Fn(usize) -> u64,
    load_reason: impl Fn(RejectionReason) -> u64,
) -> BTreeMap<String, u64> {
    let mut classes = crate::logs::attack_class_names()
        .enumerate()
        .filter_map(|(index, name)| {
            let count = load_attack(index);
            (count != 0).then(|| (name.to_owned(), count))
        })
        .collect::<BTreeMap<_, _>>();
    for reason in RejectionReason::ALL {
        if matches!(
            reason,
            RejectionReason::Rule | RejectionReason::ResponseRule
        ) {
            continue;
        }
        let count = load_reason(reason);
        if count != 0 {
            *classes
                .entry(rejection_reason_class(reason).to_owned())
                .or_default() += count;
        }
    }
    classes
}

fn minute(time: u64) -> u64 {
    time / MINUTE_MS * MINUTE_MS
}

fn connection_gauge(values: &[u64; FIELDS]) -> Option<ConnectionGauge> {
    (values[CONNECTION_COVERAGE] != 0 || values[CONNECTION_SAMPLES] != 0).then_some(
        ConnectionGauge {
            connection_milliseconds: values[CONNECTION_MS],
            observed_ms: values[CONNECTION_COVERAGE].min(MINUTE_MS) as u32,
            observed_max: values[CONNECTION_MAX],
            observed_min: (values[CONNECTION_MIN] != u64::MAX).then_some(values[CONNECTION_MIN]),
        },
    )
}

struct RequestMeasurement {
    partition: usize,
    history: Arc<Observations>,
    generation: u64,
    start: u64,
    began: Instant,
    rejected: bool,
    logged: bool,
    response_logged: bool,
    auth_failure: bool,
    finished: bool,
    in_flight_counted: bool,
    client: Option<std::net::IpAddr>,
    peer: Option<std::net::IpAddr>,
    country: Option<String>,
    reason: Option<RejectionReason>,
    site: String,
    configuration: String,
    method: Option<String>,
    path: Option<String>,
    path_hash: Option<[u8; 32]>,
    upstream_failure: bool,
    upstream_timeout: bool,
}
impl RequestMeasurement {
    fn new(history: Arc<Observations>) -> Self {
        let generation = history.ring_generation.load(Ordering::Acquire);
        let start = minute(history.now_ms());
        let partition = history.additional.next_partition();
        history.cumulative[Count::Requests as usize].fetch_add(1, Ordering::Relaxed);
        history.newest.fetch_max(start, Ordering::Relaxed);
        let in_flight_counted = {
            let slot = &history.slots[(start / MINUTE_MS) as usize % MINUTE_SLOTS];
            if let Some(pinned) = slot.pin(generation, start, true) {
                pinned.0.values[Count::Requests as usize].fetch_add(1, Ordering::Relaxed);
                pinned.0.values[IN_FLIGHT].fetch_add(1, Ordering::Relaxed);
                true
            } else {
                history.lost(start);
                false
            }
        };
        Self {
            history,
            generation,
            partition,
            start,
            began: Instant::now(),
            rejected: false,
            logged: false,
            response_logged: false,
            auth_failure: false,
            finished: false,
            in_flight_counted,
            client: None,
            peer: None,
            country: None,
            reason: None,
            site: "unattributed".into(),
            configuration: String::new(),
            method: None,
            path: None,
            path_hash: None,
            upstream_failure: false,
            upstream_timeout: false,
        }
    }
    fn finish(&mut self, status: u16) {
        if self.finished {
            return;
        }
        self.finished = true;
        if !(100..=599).contains(&status) {
            self.history.lost(self.start);
            return;
        }
        let micros = self.began.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let bin = LATENCY_BOUNDS_US
            .iter()
            .position(|upper| micros <= *upper)
            .unwrap_or(14);
        self.history
            .update_slot(self.generation, self.start, |slot| {
                for (field, value) in [
                    (STATUS + usize::from(status - 100), 1),
                    (LATENCY_COUNT, 1),
                    (LATENCY_SUM, micros),
                    (LATENCY + bin, 1),
                ] {
                    slot.values[field].fetch_add(value, Ordering::Relaxed);
                }
                slot.values[LATENCY_MIN].fetch_min(micros, Ordering::Relaxed);
                slot.values[LATENCY_MAX].fetch_max(micros, Ordering::Relaxed);
            });
        self.record_additional(Some(micros));
    }

    fn record_additional(&self, micros: Option<u64>) {
        if self.generation != self.history.ring_generation.load(Ordering::Acquire) {
            return;
        }
        self.history.additional.request(
            self.start,
            additional::Request {
                partition: self.partition,
                site: &self.site,
                source: self.client,
                country: self.country.as_deref().unwrap_or("ZZ"),
                path: self.path.as_deref(),
                path_hash: self.path_hash.as_ref(),
                rejected: self.reason,
                logged: self.logged,
                auth_failure: self.auth_failure,
                micros,
                upstream_failure: self.upstream_failure,
                upstream_timeout: self.upstream_timeout,
            },
        );
    }
}
impl Drop for RequestMeasurement {
    fn drop(&mut self) {
        if !self.finished {
            self.history
                .count_for(self.generation, self.start, Count::Aborted);
            self.record_additional(None);
        }
        if self.in_flight_counted
            && self.generation == self.history.ring_generation.load(Ordering::Acquire)
        {
            let slot = &self.history.slots[(self.start / MINUTE_MS) as usize % MINUTE_SLOTS];
            if let Some(pinned) = slot.pin(self.generation, self.start, false) {
                pinned.0.values[IN_FLIGHT].fetch_sub(1, Ordering::Relaxed);
            } else {
                self.history.lost(self.start);
            }
        }
    }
}

tokio::task_local! { static CURRENT: RefCell<RequestMeasurement>; }

pub async fn observe<B>(
    history: Arc<Observations>,
    future: impl Future<Output = http::Response<B>>,
) -> http::Response<B> {
    if !history.enabled {
        return future.await;
    }
    CURRENT
        .scope(RefCell::new(RequestMeasurement::new(history)), async {
            let response = future.await;
            let _ = CURRENT.try_with(|measurement| {
                if let Ok(mut value) = measurement.try_borrow_mut() {
                    value.finish(response.status().as_u16());
                }
            });
            response
        })
        .await
}

pub fn request_minute() -> Option<u64> {
    CURRENT
        .try_with(|value| value.try_borrow().ok().map(|value| value.start))
        .ok()
        .flatten()
}

pub fn identity(source: crate::client_ip::ClientSource) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(mut value) = value.try_borrow_mut() {
            value.client = Some(source.client_ip);
            value.peer = Some(source.peer.ip());
        }
    });
}

/// Store the country resolved for this request so event records can carry it
/// without repeating a database lookup for every event.
pub fn country(country: Option<crate::geoip::CountryCode>) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(mut value) = value.try_borrow_mut() {
            value.country = country.map(|country| country.to_string());
        }
    });
}

fn current_country() -> Option<String> {
    CURRENT
        .try_with(|value| {
            value
                .try_borrow()
                .ok()
                .and_then(|value| value.country.clone())
        })
        .ok()
        .flatten()
}

pub fn request_head(config: &crate::config::CompiledConfig, parts: &http::request::Parts) {
    let _ = CURRENT.try_with(|cell| {
        if let Ok(mut value) = cell.try_borrow_mut() {
            value.configuration = config.observation_id.clone();
            value.method = event_method(parts.method.as_str());
            value.path = Some(additional::path(parts.uri.path()));
            let hash = ring::digest::digest(&ring::digest::SHA256, parts.uri.path().as_bytes());
            let mut bytes = [0; 32];
            bytes.copy_from_slice(hash.as_ref());
            value.path_hash = Some(bytes);
            value.site = match &config.allowed_hosts {
                None => "default".into(),
                Some(allowed) if allowed.check(parts).is_ok() => parts
                    .uri
                    .authority()
                    .map(|value| value.as_str())
                    .or_else(|| {
                        parts
                            .headers
                            .get(http::header::HOST)
                            .and_then(|value| value.to_str().ok())
                    })
                    .and_then(|host| allowed.observation_site(host))
                    .unwrap_or_else(|| "unattributed".into()),
                Some(_) => "unattributed".into(),
            };
        }
    });
}

fn event_site(site: &str) -> Option<String> {
    crate::console::model::site_identifier(site, 64)
        .ok()
        .map(|()| site.to_owned())
}

fn event_method(method: &str) -> Option<String> {
    (crate::console::model::text(method, 32).is_ok() && method.parse::<http::Method>().is_ok())
        .then(|| method.to_owned())
}

fn event_path(path: &Option<String>) -> Option<String> {
    path.as_ref()
        .filter(|value| crate::console::model::redacted_path(value).is_ok())
        .cloned()
}

pub fn upstream_status(status: u16) {
    let _ = CURRENT.try_with(|cell| {
        if let Ok(value) = cell.try_borrow() {
            value
                .history
                .additional
                .upstream(value.start, value.partition, status);
        }
    });
}

pub fn dimension_match(phase: Phase, category: &str, rule: &str, action: crate::config::Action) {
    let _ = CURRENT.try_with(|cell| {
        if let Ok(value) = cell.try_borrow() {
            value.history.additional.rule(
                value.start,
                value.partition,
                additional::RuleMatch {
                    configuration: &value.configuration,
                    phase,
                    category,
                    rule,
                    action,
                },
            );
        }
    });
}

pub fn reject(reason: RejectionReason) {
    reject_detail(reason, None);
}

/// Record a rule-based rejection together with the category that classified it.
pub fn reject_rule(reason: RejectionReason, category: &str, rule: &str) {
    reject_detail(reason, Some((category, rule)));
}

fn reject_detail(reason: RejectionReason, matched: Option<(&str, &str)>) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(mut value) = value.try_borrow_mut()
            && !value.rejected
        {
            let (category, rule) = matched.unzip();
            let attack_class = rejection_class(reason, category);
            value.rejected = true;
            value.reason = Some(reason);
            value
                .history
                .count_for(value.generation, value.start, Count::Rejected);
            value
                .history
                .update_for(value.generation, value.start, REASONS + reason as usize, 1);
            if matches!(
                reason,
                RejectionReason::Rule | RejectionReason::ResponseRule
            ) {
                value.history.update_for(
                    value.generation,
                    value.start,
                    ATTACK_CLASSES + crate::logs::attack_class_index(category.unwrap_or("")),
                    1,
                );
            }
            let counter = match reason {
                RejectionReason::ResponseRule => Some(Count::ResponseBlocks),
                RejectionReason::RateLimit => Some(Count::RateLimited),
                RejectionReason::Ban => Some(Count::Banned),
                RejectionReason::Overload => Some(Count::Overloaded),
                RejectionReason::Decoy => Some(Count::DecoyBlocked),
                _ => None,
            };
            if let Some(counter) = counter {
                value
                    .history
                    .count_for(value.generation, value.start, counter);
            }
            value
                .history
                .event_with(|sequence, time| crate::console::model::EventRecord {
                    id: format!("rejected-{sequence}"),
                    sequence,
                    occurred_at_ms: time,
                    kind: crate::console::model::EventKind::Rejection,
                    disposition: crate::console::model::Disposition::Reject,
                    phase: reason.phase(),
                    site: event_site(&value.site),
                    client: value.client,
                    peer: value.peer,
                    country: value.country.clone(),
                    method: value.method.clone(),
                    path: event_path(&value.path),
                    status: None,
                    category: category
                        .filter(|value| value.len() <= 128)
                        .map(str::to_owned),
                    rule: rule.filter(|value| value.len() <= 128).map(str::to_owned),
                    attack_class: Some(attack_class.to_owned()),
                    reason: Some(format!("{reason:?}")),
                    decoy: None,
                    gap: None,
                    incomplete: true,
                });
        }
    });
}

pub fn rule_match(phase: Phase, logged: bool) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(mut value) = value.try_borrow_mut() {
            value
                .history
                .count_for(value.generation, value.start, Count::Matches);
            if logged && !value.logged {
                value.logged = true;
                value
                    .history
                    .count_for(value.generation, value.start, Count::Logged);
            }
            if logged && phase == Phase::Response && !value.response_logged {
                value.response_logged = true;
                value
                    .history
                    .count_for(value.generation, value.start, Count::ResponseLogged);
            }
        }
    });
}

pub fn service_failure(timeout: bool) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(mut value) = value.try_borrow_mut() {
            value.upstream_failure |= !timeout;
            value.upstream_timeout |= timeout;
            value.history.count_for(
                value.generation,
                value.start,
                if timeout {
                    Count::UpstreamTimeouts
                } else {
                    Count::UpstreamFailures
                },
            );
            value.history.event_with(|sequence, time| EventRecord {
                id: format!("upstream-{sequence}"),
                sequence,
                occurred_at_ms: time,
                kind: crate::console::model::EventKind::UpstreamFailure,
                disposition: crate::console::model::Disposition::Error,
                phase: Phase::Service,
                site: event_site(&value.site),
                client: value.client,
                peer: value.peer,
                country: value.country.clone(),
                method: value.method.clone(),
                path: event_path(&value.path),
                status: Some(if timeout { 504 } else { 502 }),
                category: None,
                rule: None,
                attack_class: None,
                reason: Some(
                    if timeout {
                        "upstream timeout"
                    } else {
                        "upstream failure"
                    }
                    .into(),
                ),
                decoy: None,
                gap: None,
                incomplete: true,
            });
        }
    });
}

pub fn rule_detail(phase: Phase, category: &str, rule: &str, disposition: Disposition) {
    let _ = CURRENT.try_with(|value| {
        if let Ok(value) = value.try_borrow() {
            value.history.event_with(|sequence, time| EventRecord {
                id: format!("rule-{sequence}"),
                sequence,
                occurred_at_ms: time,
                kind: crate::console::model::EventKind::RuleMatch,
                disposition,
                phase,
                site: event_site(&value.site),
                client: value.client,
                peer: value.peer,
                country: value.country.clone(),
                method: value.method.clone(),
                path: event_path(&value.path),
                status: None,
                category: (category.len() <= 128).then(|| category.into()),
                rule: (rule.len() <= 128).then(|| rule.into()),
                attack_class: Some(crate::logs::observation_attack_name(category).to_owned()),
                reason: (disposition == Disposition::Observe)
                    .then(|| "detection-only BLOCK".to_owned()),
                decoy: None,
                gap: None,
                incomplete: true,
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;

    fn history() -> Arc<Observations> {
        let mut history = Observations::new();
        history.epoch_ms = 0;
        history.ring_floor_ms.store(0, Ordering::Relaxed);
        history.newest.store(0, Ordering::Relaxed);
        Arc::new(history)
    }

    #[test]
    fn a_new_ring_generation_discards_old_slot_state() {
        let slot = Slot::new();
        {
            let pinned = slot.pin(0, 60_000, true).expect("initial slot");
            pinned.0.values[Count::Requests as usize].store(7, Ordering::Relaxed);
        }
        {
            let pinned = slot.pin(1, 60_000, true).expect("new generation");
            assert_eq!(
                pinned.0.values[Count::Requests as usize].load(Ordering::Relaxed),
                0
            );
        }
        assert!(slot.pin(0, 60_000, true).is_none());
    }

    #[test]
    fn a_forward_clock_step_reanchors_the_ring_and_marks_the_transition() {
        let history = history();
        let actual = 10_000_000;
        history.reconcile_clock(actual);
        assert!(history.now_ms() >= actual);
        assert_eq!(history.ring_generation.load(Ordering::Relaxed), 1);
        assert_eq!(history.ring_floor_ms.load(Ordering::Relaxed), 9_960_000);

        let packet = history.snapshot_at(actual, actual, 0).unwrap();
        assert!(packet.clock_discontinuity);
        assert_eq!(packet.buckets[0].start_ms, 9_960_000);
        assert!(
            packet
                .buckets
                .iter()
                .all(|bucket| bucket.coverage.incomplete)
        );

        let next = history
            .snapshot_at(actual + 61_000, actual + 61_000, 0)
            .unwrap();
        assert!(!next.clock_discontinuity);
        assert!(
            next.buckets
                .iter()
                .any(|bucket| !bucket.coverage.incomplete)
        );
    }

    #[test]
    fn a_backward_clock_step_starts_a_new_ring_generation() {
        let history = history();
        history.reconcile_clock(10_000_000);
        history.reconcile_clock(9_000_000);
        assert!(history.now_ms() >= 9_000_000);
        assert_eq!(history.ring_generation.load(Ordering::Relaxed), 2);
        assert_eq!(history.ring_floor_ms.load(Ordering::Relaxed), 9_000_000);
        let packet = history.snapshot_at(9_001_000, 9_001_000, 0).unwrap();
        assert!(packet.clock_discontinuity);
        assert_eq!(packet.buckets[0].start_ms, 9_000_000);
    }

    #[test]
    fn an_unset_connection_minimum_is_not_exported_as_a_value() {
        let mut values = [0_u64; FIELDS];
        values[CONNECTION_COVERAGE] = 1_000;
        values[CONNECTION_MAX] = 3;
        values[CONNECTION_MIN] = u64::MAX;
        let gauge = connection_gauge(&values).expect("covered minute");
        assert_eq!(gauge.observed_min, None);
    }

    #[tokio::test]
    async fn supplementary_counts_keep_sites_match_multiplicity_status_origin_and_exact_latency() {
        use crate::console::measurements::DimensionKind;
        let history = history();
        let config=crate::config::parse("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\nallowed_hosts: [a.example,b.example,'*.other.example']\ncategories: []\n").unwrap();
        history.configure(&config);
        for (host, ip, rejected) in [
            ("a.example", "192.0.2.1", true),
            ("b.example", "192.0.2.2", false),
        ] {
            observe(history.clone(), async {
                let (parts, _) = http::Request::builder()
                    .uri("/token/private-value?secret=hidden")
                    .header("host", host)
                    .body(())
                    .unwrap()
                    .into_parts();
                request_head(&config, &parts);
                CURRENT.with(|value| value.borrow_mut().client = Some(ip.parse().unwrap()));
                rule_match(Phase::Request, true);
                rule_match(Phase::Request, true);
                dimension_match(
                    Phase::Request,
                    "sql-injection",
                    "first",
                    crate::config::Action::Log,
                );
                dimension_match(
                    Phase::Request,
                    "sql-injection",
                    "second",
                    crate::config::Action::Log,
                );
                upstream_status(200);
                if rejected {
                    reject(RejectionReason::ResponseRule);
                }
                Response::builder()
                    .status(if rejected { 403 } else { 200 })
                    .body(())
                    .unwrap()
            })
            .await;
        }
        let packet = history.snapshot_at(60_000, 60_000, 0).unwrap();
        let bucket = &packet.buckets[0];
        let values = bucket.additional.as_ref().unwrap();
        let outcomes = bucket.outcomes.as_ref().unwrap();
        assert_eq!(values.completed_requests, 2);
        assert_eq!(values.upstream_statuses.get(&200), Some(&2));
        assert!(!values.upstream_statuses.contains_key(&403));
        assert_eq!(
            values
                .dimensions
                .iter()
                .filter(|value| value.kind == DimensionKind::Site)
                .map(|value| value.counts.requests)
                .sum::<u64>(),
            2
        );
        assert_eq!(
            values
                .dimensions
                .iter()
                .filter(|value| value.kind == DimensionKind::Category)
                .map(|value| value.counts.log_matches)
                .sum::<u64>(),
            4
        );
        let sites: Vec<_> = values
            .dimensions
            .iter()
            .filter(|value| value.kind == DimensionKind::Site)
            .collect();
        assert_eq!(sites.len(), 2);
        assert_eq!(
            sites
                .iter()
                .map(|value| value.counts.latency.sum_us)
                .sum::<u64>(),
            outcomes.latency_sum_us
        );
        assert_eq!(
            sites
                .iter()
                .filter_map(|value| value.counts.latency.min_us)
                .min(),
            outcomes.latency_min_us
        );
        assert_eq!(
            sites
                .iter()
                .filter_map(|value| value.counts.latency.max_us)
                .max(),
            outcomes.latency_max_us
        );
        assert_eq!(
            values.reason_latency[&RejectionReason::ResponseRule].count,
            1
        );
        assert_eq!(values.paths.entries.len(), 1);
        assert_eq!(values.paths.entries[0].key, "/token/[redacted]");
        assert!(
            !serde_json::to_string(values)
                .unwrap()
                .contains("private-value")
        );
        assert!(!values.incomplete);
        assert_eq!(values.sources.entries.len(), 2);
    }

    #[tokio::test]
    async fn rejection_and_log_counts_are_once_per_request_and_status_is_separate() {
        let history = history();
        observe(history.clone(), async {
            rule_match(Phase::Request, true);
            rule_match(Phase::Request, true);
            reject(RejectionReason::Rule);
            reject(RejectionReason::Protocol);
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        observe(history.clone(), async {
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        observe(history.clone(), async {
            Response::builder().status(700).body(()).unwrap()
        })
        .await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.counters.requests, Some(3));
        assert_eq!(snapshot.counters.rejected_requests, Some(1));
        assert_eq!(snapshot.counters.log_requests, Some(1));
        assert_eq!(snapshot.counters.rule_matches, Some(2));
        let bucket = &snapshot.buckets[0];
        let outcome = bucket.outcomes.as_ref().unwrap();
        assert_eq!(outcome.statuses[303], 2);
        assert_eq!(outcome.statuses[499], 0);
        assert!(snapshot.missed_updates > 0);
        assert_eq!(outcome.latency_count, 2);
        assert_eq!(outcome.latency_bins.iter().sum::<u64>(), 2);
        assert_eq!(outcome.in_flight, 0);
        assert_eq!(
            snapshot.counters.rejection_reasons.as_ref().unwrap()[&RejectionReason::Rule],
            1
        );
        assert_eq!(
            snapshot.counters.rejection_classes.as_ref().unwrap()["other"],
            1
        );
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].attack_class.as_deref(), Some("other"));
    }

    #[tokio::test]
    async fn rejection_classes_partition_attack_and_builtin_causes() {
        let history = history();
        observe(history.clone(), async {
            reject_rule(RejectionReason::Rule, "sql-injection", "union-select");
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        observe(history.clone(), async {
            reject_rule(RejectionReason::ResponseRule, "response-leaks", "secret");
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        observe(history.clone(), async {
            reject(RejectionReason::Upload);
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        observe(history.clone(), async {
            reject(RejectionReason::RateLimit);
            Response::builder().status(429).body(()).unwrap()
        })
        .await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.counters.rejected_requests, Some(4));
        let classes = snapshot.counters.rejection_classes.as_ref().unwrap();
        assert_eq!(classes["sql-injection"], 1);
        assert_eq!(classes["info-disclosure"], 1);
        assert_eq!(classes["malicious-upload"], 1);
        assert_eq!(classes["rate-limit"], 1);
        assert_eq!(classes.values().sum::<u64>(), 4);
        let rules = snapshot
            .events
            .iter()
            .filter(|event| event.category.is_some())
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].category.as_deref(), Some("sql-injection"));
        assert_eq!(rules[0].rule.as_deref(), Some("union-select"));
        assert_eq!(rules[0].attack_class.as_deref(), Some("sql-injection"));
        assert_eq!(rules[1].category.as_deref(), Some("response-leaks"));
        assert_eq!(rules[1].attack_class.as_deref(), Some("info-disclosure"));
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.attack_class.as_deref() == Some("malicious-upload"))
        );
    }

    #[tokio::test]
    async fn events_preserve_site_method_and_redacted_path() {
        let history = history();
        let config = crate::config::parse(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\nallowed_hosts: [example.com]\ncategories: []\n",
        )
        .unwrap();
        history.configure(&config);
        observe(history.clone(), async {
            let (parts, _) = http::Request::builder()
                .method(http::Method::POST)
                .uri("/token/private-value?secret=hidden")
                .header("host", "example.com")
                .body(())
                .unwrap()
                .into_parts();
            request_head(&config, &parts);
            identity(crate::client_ip::ClientSource::direct(
                "192.0.2.10:4321".parse().unwrap(),
            ));
            rule_detail(Phase::Request, "probe", "admin-probe", Disposition::Log);
            service_failure(false);
            reject(RejectionReason::Rule);
            Response::builder().status(403).body(()).unwrap()
        })
        .await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.events.len(), 3);
        for event in &snapshot.events {
            assert_eq!(event.site.as_deref(), Some("example.com"));
            assert_eq!(event.method.as_deref(), Some("POST"));
            assert_eq!(event.path.as_deref(), Some("/token/[redacted]"));
            assert_eq!(event.client, Some("192.0.2.10".parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn wildcard_sites_keep_their_configured_identity_in_events() {
        let history = history();
        let config = crate::config::parse(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\nallowed_hosts: ['*.example.com']\ncategories: []\n",
        )
        .unwrap();
        history.configure(&config);
        observe(history.clone(), async {
            let (parts, _) = http::Request::builder()
                .method(http::Method::GET)
                .uri("/admin")
                .header("host", "blog.example.com")
                .body(())
                .unwrap()
                .into_parts();
            request_head(&config, &parts);
            rule_detail(Phase::Request, "probe", "admin-probe", Disposition::Log);
            Response::new(())
        })
        .await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].site.as_deref(), Some("*.example.com"));
        assert_eq!(snapshot.events[0].method.as_deref(), Some("GET"));
        assert_eq!(snapshot.events[0].path.as_deref(), Some("/admin"));
    }

    #[tokio::test]
    async fn decoy_events_include_the_current_request_method_and_path() {
        let history = history();
        let config = crate::config::parse(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\nallowed_hosts: [example.com]\ncategories: []\n",
        )
        .unwrap();
        history.configure(&config);
        let recorder = history.clone();
        observe(history.clone(), async move {
            let (parts, _) = http::Request::builder()
                .method(http::Method::GET)
                .uri("/.env")
                .header("host", "example.com")
                .body(())
                .unwrap()
                .into_parts();
            request_head(&config, &parts);
            recorder.decoy_detail(DecoyDetail {
                site: "dotenv",
                credential_id: "0123456789abcdef0123456789abcdef",
                context: crate::console::model::DecoyContext::Issued,
                age_seconds: None,
                lure: None,
                template: None,
                source: crate::client_ip::ClientSource::direct("192.0.2.11:4321".parse().unwrap()),
                blocked: false,
                incomplete: false,
            });
            Response::new(())
        })
        .await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.events.len(), 1);
        let event = &snapshot.events[0];
        assert_eq!(event.site.as_deref(), Some("dotenv"));
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(event.path.as_deref(), Some("/.env"));
    }

    #[tokio::test]
    async fn high_cardinality_exports_fit_the_record_budget_and_disclose_trimming() {
        let history = history();
        let config = crate::config::parse(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\ncategories: []\n",
        )
        .unwrap();
        history.configure(&config);
        for index in 0..200 {
            observe(history.clone(), async {
                let (parts, _) = http::Request::builder()
                    .uri(format!("/path-{index}"))
                    .body(())
                    .unwrap()
                    .into_parts();
                request_head(&config, &parts);
                CURRENT.with(|value| {
                    value.borrow_mut().client = Some(format!("192.0.2.{index}").parse().unwrap())
                });
                dimension_match(
                    Phase::Request,
                    &format!("category-{}", index % 40),
                    &format!("rule-{index}-{}", "x".repeat(80)),
                    crate::config::Action::Log,
                );
                upstream_status(100 + index as u16);
                Response::new(())
            })
            .await;
        }
        let packet = history.snapshot_at(60_000, 60_000, 0).unwrap();
        packet.validate().unwrap();
        let bucket = &packet.buckets[0];
        assert_eq!(bucket.counters.requests, Some(200));
        let values = bucket.additional.as_ref().unwrap();
        assert!(values.incomplete);
        assert!(values.export_omissions > 0);
        assert!(values.dimension_overflow > 0);
        assert!(
            serde_json::to_vec(bucket).unwrap().len() <= crate::console::model::MAX_RECORD_BYTES
        );
        assert_eq!(packet.additional_missed_updates, Some(0));
    }

    #[tokio::test]
    async fn late_response_uses_arrival_minute_and_expired_slots_are_not_recreated() {
        let history = history();
        let measurement = RequestMeasurement::new(history.clone());
        history.snapshot_at(61_000, 61_000, 0).unwrap();
        let mut measurement = measurement;
        measurement.finish(200);
        drop(measurement);
        let snapshot = history.snapshot_at(61_000, 61_000, 0).unwrap();
        assert_eq!(
            snapshot.buckets[0].outcomes.as_ref().unwrap().statuses[100],
            1
        );
        assert!(!snapshot.buckets[0].coverage.incomplete);
        assert_eq!(
            snapshot.buckets[1].outcomes.as_ref().unwrap().statuses[100],
            0
        );

        let mut old = RequestMeasurement::new(history.clone());
        history.snapshot_at(660_000, 660_000, 0).unwrap();
        old.finish(403);
        drop(old);
        let snapshot = history.snapshot_at(660_000, 660_000, 0).unwrap();
        assert_eq!(snapshot.buckets.len(), MINUTE_SLOTS);
        assert!(snapshot.buckets.iter().all(|bucket| bucket.start_ms > 0));
        assert!(snapshot.missed_updates > 0);
        assert_eq!(snapshot.counters.requests, Some(2));
    }

    #[test]
    fn contention_does_not_wait_or_lose_cumulative_counts() {
        let history = history();
        let pinned = history.slots[0].pin(0, 0, true).unwrap();
        let before = Instant::now();
        history.count(600_000, Count::Requests);
        assert!(before.elapsed() < std::time::Duration::from_millis(50));
        assert_eq!(history.cumulative[0].load(Ordering::Relaxed), 1);
        assert_eq!(history.missed.load(Ordering::Relaxed), 1);
        assert_eq!(pinned.0.minute.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn busy_minute_and_event_buffers_do_not_stop_live_cumulative_exports() {
        let history = history();
        history.count(0, Count::Requests);
        let _pinned = history.slots[0].pin(0, 0, true).unwrap();
        let _detail = history.detail.lock().unwrap();
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.counters.requests, Some(1));
        assert!(snapshot.buckets[0].counters.requests.is_none());
        assert!(snapshot.buckets[0].coverage.incomplete);
        assert!(snapshot.events.is_empty());
        assert_eq!(snapshot.event_sequence, 0);
    }

    #[test]
    fn concurrent_updates_and_multiple_readers_never_drain_counts() {
        let history = history();
        history.snapshot_at(0, 0, 0).unwrap();
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let history = history.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        history.count(0, Count::Requests);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let first = history.snapshot_at(1000, 1000, 0).unwrap();
        let second = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(first.counters.requests, Some(40_000));
        assert_eq!(first.counters, second.counters);
        assert_eq!(first.buckets[0].counters.requests, Some(40_000));
        assert_eq!(second.missed_updates, 0);
        assert!(second.sequence > first.sequence);
    }

    #[test]
    fn quiet_minutes_zero_counts_clock_gaps_and_weighted_gauges_are_explicit() {
        let history = history();
        history.snapshot_at(0, 0, 5).unwrap();
        let snapshot = history.snapshot_at(1000, 1000, 7).unwrap();
        let gauge = snapshot.buckets[0].connections.as_ref().unwrap();
        assert_eq!(gauge.connection_milliseconds, 5000);
        assert_eq!(gauge.observed_ms, 1000);
        assert_eq!(gauge.observed_max, 7);
        let snapshot = history.snapshot_at(61_000, 70_000, 0).unwrap();
        assert_eq!(snapshot.counters.requests, Some(0));
        assert_eq!(snapshot.buckets.len(), 2);
        assert!(snapshot.clock_discontinuity);
        assert!(
            snapshot
                .buckets
                .iter()
                .all(|bucket| bucket.coverage.incomplete)
        );
    }

    #[tokio::test]
    async fn detail_shedding_does_not_shed_request_statistics() {
        let history = history();
        for _ in 0..100 {
            observe(history.clone(), async {
                reject(RejectionReason::RateLimit);
                Response::builder().status(429).body(()).unwrap()
            })
            .await;
        }
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.counters.requests, Some(100));
        assert_eq!(snapshot.counters.rejected_requests, Some(100));
        assert_eq!(snapshot.counters.rate_limited_requests, Some(100));
        assert_eq!(snapshot.events.len(), 12);
        assert_eq!(snapshot.events_omitted, 88);
        assert_eq!(snapshot.event_sequence, 100);
        history.decoy_detail(DecoyDetail {
            site: "site",
            credential_id: "0123456789abcdef0123456789abcdef",
            context: crate::console::model::DecoyContext::Credential,
            age_seconds: Some(1),
            lure: None,
            template: None,
            source: crate::client_ip::ClientSource::direct("127.0.0.1:1234".parse().unwrap()),
            blocked: false,
            incomplete: false,
        });
        assert!(
            history
                .snapshot_at(1000, 1000, 0)
                .unwrap()
                .events
                .iter()
                .any(|event| event.decoy.is_some())
        );
    }

    #[test]
    fn invalid_detail_metadata_cannot_bypass_the_allocation_admission_budget() {
        let history = history();
        let mut built = 0;
        for _ in 0..100 {
            history.event_with(|sequence, time| {
                built += 1;
                EventRecord {
                    id: format!("invalid-{sequence}"),
                    sequence,
                    occurred_at_ms: time,
                    kind: crate::console::model::EventKind::Service,
                    disposition: crate::console::model::Disposition::Observe,
                    phase: Phase::Service,
                    site: None,
                    client: None,
                    peer: None,
                    country: None,
                    method: None,
                    path: None,
                    status: None,
                    category: None,
                    rule: None,
                    attack_class: None,
                    reason: Some("kdt1.secret".into()),
                    decoy: None,
                    gap: None,
                    incomplete: true,
                }
            });
        }
        assert_eq!(built, 12);
        let packet = history.snapshot_at(1000, 1000, 0).unwrap();
        assert!(packet.events.is_empty());
        assert_eq!(packet.events_omitted, 100);
    }

    #[tokio::test]
    async fn cancelled_request_releases_the_minute_inflight_marker() {
        let history = history();
        let future = observe(history.clone(), std::future::pending::<Response<()>>());
        let _ = tokio::time::timeout(std::time::Duration::from_millis(1), future).await;
        let snapshot = history.snapshot_at(1000, 1000, 0).unwrap();
        assert_eq!(snapshot.counters.aborted_requests, Some(1));
        assert_eq!(snapshot.buckets[0].outcomes.as_ref().unwrap().in_flight, 0);
    }
}
