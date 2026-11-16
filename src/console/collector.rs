//! Counter-based reception, bounded coalescing, and asynchronous persistence.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use bytes::Bytes;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use ring::digest::{SHA256, digest};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use super::model::{
    Checkpoint, CounterSnapshot, Counters, EventRecord, MINUTE_MS, MetricBucket, SourceIdentity,
    WriteBatch,
};
use super::{Error, Receipt, StorageConfig, Store, SubmitError, Writer, WriterConfig};
use crate::observations::{MAX_SNAPSHOT_BYTES, StatisticsSnapshot};
use crate::proxy::{BodyExt, Full};

#[derive(Clone, Debug)]
pub struct CollectorConfig {
    pub instance: String,
    pub sample_interval: Duration,
    pub persist_interval: Duration,
    pub max_generations: usize,
    pub max_pending_minutes: usize,
    pub max_pending_events: usize,
    pub max_event_bytes: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            instance: "local-waf".into(),
            sample_interval: Duration::from_secs(1),
            persist_interval: Duration::from_secs(10),
            max_generations: 2,
            max_pending_minutes: 10,
            max_pending_events: 128,
            max_event_bytes: 128 * 1024,
        }
    }
}

impl CollectorConfig {
    fn validate(&self) -> Result<(), Error> {
        SourceIdentity {
            instance: self.instance.clone(),
            generation: "validation".into(),
        }
        .validate()?;
        if self.instance.len() > 120
            || !(1..=4).contains(&self.max_generations)
            || !(10..=120).contains(&self.max_pending_minutes)
            || !(1..=128).contains(&self.max_pending_events)
            || !(16 * 1024..=128 * 1024).contains(&self.max_event_bytes)
        {
            return Err(Error::Invalid("invalid collector memory bounds"));
        }
        super::validate_duration(self.sample_interval, Duration::from_secs(60))?;
        super::validate_duration(self.persist_interval, Duration::from_secs(60))
    }
}

#[derive(Clone, Debug, Default)]
pub struct CollectorHealth {
    pub writer: Option<super::Health>,
    pub unconfirmed_metric_batches: usize,
    pub unconfirmed_event_batches: usize,
    pub persistence_lag_ms: Option<u64>,
    pub source_connected: bool,
    pub received_snapshots: u64,
    pub stale_snapshots: u64,
    pub last_observed_at_ms: Option<u64>,
    pub last_committed_at_ms: Option<u64>,
    pub pending_minutes: usize,
    pub pending_events: usize,
    pub pending_event_bytes: usize,
    pub omitted_metric_minutes: u64,
    pub omitted_events: u64,
    pub source_missed_updates: u64,
    pub source_omitted_events: u64,
    pub source_gap: Option<(u64, u64)>,
    pub storage_error: Option<Error>,
    pub source_error: Option<Error>,
}

enum ReadRequest {
    Checkpoint {
        source: SourceIdentity,
        reply: oneshot::Sender<Result<Option<Checkpoint>, Error>>,
    },
    History {
        query: super::HistoryQuery,
        reply: oneshot::Sender<Result<super::HistoryPage, Error>>,
    },
}

#[derive(Clone)]
pub struct HistoryReader {
    requests: mpsc::SyncSender<ReadRequest>,
}

impl HistoryReader {
    fn start(config: StorageConfig) -> Result<Self, Error> {
        let (requests, incoming) = mpsc::sync_channel::<ReadRequest>(4);
        std::thread::Builder::new()
            .name("kunato-history-read".into())
            .spawn(move || {
                let mut store = Store::open(config);
                while let Ok(request) = incoming.recv() {
                    match request {
                        ReadRequest::Checkpoint { source, reply } => {
                            let result = match &mut store {
                                Ok(store) => store.checkpoint(&source),
                                Err(error) => Err(error.clone()),
                            };
                            let _ = reply.send(result);
                        }
                        ReadRequest::History { query, reply } => {
                            let result = match &mut store {
                                Ok(store) => store.history(&query),
                                Err(error) => Err(error.clone()),
                            };
                            let _ = reply.send(result);
                        }
                    }
                }
            })?;
        Ok(Self { requests })
    }
    async fn checkpoint(&self, source: SourceIdentity) -> Result<Option<Checkpoint>, Error> {
        tokio::time::timeout(Duration::from_millis(750), async {
            for attempt in 0..8 {
                let (reply, result) = oneshot::channel();
                let value = match self.requests.try_send(ReadRequest::Checkpoint {
                    source: source.clone(),
                    reply,
                }) {
                    Ok(()) => result.await.map_err(|_| Error::WorkerStopped)?,
                    Err(mpsc::TrySendError::Full(_)) => Err(Error::Busy),
                    Err(mpsc::TrySendError::Disconnected(_)) => Err(Error::WorkerStopped),
                };
                if !matches!(value, Err(Error::Busy | Error::OperationTimeout)) || attempt == 7 {
                    return value;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(Error::Busy)
        })
        .await
        .map_err(|_| Error::OperationTimeout)?
    }

    /// Queue a bounded history read on the owned database thread, not the async executor.
    pub async fn history(&self, query: super::HistoryQuery) -> Result<super::HistoryPage, Error> {
        query.validate()?;
        let (reply, result) = oneshot::channel();
        self.requests
            .try_send(ReadRequest::History { query, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => Error::Busy,
                mpsc::TrySendError::Disconnected(_) => Error::WorkerStopped,
            })?;
        tokio::time::timeout(Duration::from_millis(750), result)
            .await
            .map_err(|_| Error::OperationTimeout)?
            .map_err(|_| Error::WorkerStopped)?
    }
}

struct Flight {
    receipt: Receipt,
    checkpoint: Checkpoint,
    revisions: Vec<(u64, u64)>,
}
struct State {
    committed_at_ms: Option<u64>,
    source_omitted_events: u64,
    source_missed_updates: u64,
    source: SourceIdentity,
    sequence: u64,
    fingerprint: Vec<u8>,
    at: u64,
    counters: Counters,
    committed: u64,
    event_received: u64,
    event_committed: u64,
    buckets: BTreeMap<u64, MetricBucket>,
    events: Vec<EventRecord>,
    metric_flight: Option<Flight>,
    event_flight: Option<Flight>,
    submitted: Instant,
}

pub struct Collector {
    config: CollectorConfig,
    reader: HistoryReader,
    writer: Option<Writer>,
    states: Vec<State>,
    live: watch::Sender<Option<Arc<StatisticsSnapshot>>>,
    health: CollectorHealth,
}

impl Collector {
    pub async fn start(
        storage: StorageConfig,
        writer_config: WriterConfig,
        config: CollectorConfig,
    ) -> Result<Self, Error> {
        config.validate()?;
        storage.validate()?;
        let metric_bytes =
            (config.max_pending_minutes + 1) * super::model::MAX_RECORD_BYTES * 2 + 8192;
        let event_bytes = (config.max_event_bytes + super::model::MAX_RECORD_BYTES) * 2 + 8192;
        if config.max_pending_minutes + 1 > writer_config.max_batch_records
            || config.max_pending_events + 1 > writer_config.max_batch_records
            || metric_bytes > writer_config.max_batch_bytes
            || event_bytes > writer_config.max_batch_bytes
        {
            return Err(Error::Invalid(
                "collector groups exceed writer transaction limits",
            ));
        }
        // Open the migration-capable reader before opening the writer connection.
        let reader = HistoryReader::start(storage.clone())?;
        reader
            .checkpoint(SourceIdentity {
                instance: config.instance.clone(),
                generation: "initialization".into(),
            })
            .await?;
        let writer = Writer::start(storage, writer_config).await?;
        let (live, _) = watch::channel(None);
        Ok(Self {
            config,
            reader,
            writer: Some(writer),
            states: Vec::new(),
            live,
            health: CollectorHealth::default(),
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<Arc<StatisticsSnapshot>>> {
        self.live.subscribe()
    }

    pub fn history_reader(&self) -> HistoryReader {
        self.reader.clone()
    }

    pub fn health(&self) -> CollectorHealth {
        let mut health = self.health.clone();
        health.last_committed_at_ms = self.states.last().and_then(|state| state.committed_at_ms);
        health.writer = self.writer.as_ref().map(Writer::health);
        health.unconfirmed_metric_batches = self
            .states
            .iter()
            .filter(|state| state.metric_flight.is_some())
            .count();
        health.unconfirmed_event_batches = self
            .states
            .iter()
            .filter(|state| state.event_flight.is_some())
            .count();
        health.persistence_lag_ms = health
            .last_observed_at_ms
            .zip(health.last_committed_at_ms)
            .map(|(observed, committed)| observed.saturating_sub(committed));
        health.pending_minutes = self.states.iter().map(|state| state.buckets.len()).sum();
        health.pending_events = self.states.iter().map(|state| state.events.len()).sum();
        health.pending_event_bytes = self
            .states
            .iter()
            .flat_map(|state| &state.events)
            .map(event_bytes)
            .sum();
        health
    }

    pub async fn receive(&mut self, packet: StatisticsSnapshot) -> Result<(), Error> {
        packet.validate()?;
        let encoded = serde_json::to_vec(&packet)
            .map_err(|_| Error::Invalid("invalid statistics encoding"))?;
        if encoded.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Invalid("statistics snapshot exceeds byte limit"));
        }
        let fingerprint = digest(&SHA256, &encoded).as_ref().to_vec();
        self.poll();
        let source = SourceIdentity {
            instance: self.config.instance.clone(),
            generation: packet.source.generation.clone(),
        };
        let index = match self.states.iter().position(|state| state.source == source) {
            Some(index) => index,
            None => {
                // A storage lookup must not delay publication of a valid new generation.
                self.live.send_replace(Some(Arc::new(packet.clone())));
                if self.states.len() >= self.config.max_generations {
                    let removable = self.states.iter().position(|state| {
                        state.buckets.is_empty()
                            && state.events.is_empty()
                            && state.metric_flight.is_none()
                            && state.event_flight.is_none()
                    });
                    if let Some(index) = removable {
                        self.states.remove(index);
                    } else {
                        self.tick(true);
                        self.health.omitted_metric_minutes = self
                            .health
                            .omitted_metric_minutes
                            .saturating_add(packet.buckets.len() as u64);
                        return Ok(());
                    }
                }
                let baseline = match self.reader.checkpoint(source.clone()).await {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        self.health.storage_error = Some(error);
                        None
                    }
                };
                let event_source = event_source(&source);
                let event_baseline = match self.reader.checkpoint(event_source).await {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        self.health.storage_error = Some(error);
                        None
                    }
                };
                if let Some(checkpoint) = &baseline
                    && let Some(snapshot) = &checkpoint.snapshot
                {
                    let first = packet
                        .buckets
                        .first()
                        .map_or(packet.observed_at_ms, |bucket| bucket.start_ms);
                    if first > snapshot.observed_at_ms.saturating_add(MINUTE_MS) {
                        self.health.source_gap = Some((snapshot.observed_at_ms, first));
                    }
                }
                self.states.push(State {
                    committed_at_ms: baseline
                        .as_ref()
                        .and_then(|checkpoint| checkpoint.snapshot.as_ref())
                        .map(|snapshot| snapshot.observed_at_ms),
                    source_omitted_events: packet.events_omitted,
                    source_missed_updates: packet.missed_updates,
                    source,
                    sequence: baseline
                        .as_ref()
                        .map_or(0, |checkpoint| checkpoint.sequence),
                    fingerprint: Vec::new(),
                    at: baseline
                        .as_ref()
                        .and_then(|checkpoint| checkpoint.snapshot.as_ref())
                        .map_or(0, |snapshot| snapshot.observed_at_ms),
                    counters: baseline
                        .as_ref()
                        .and_then(|checkpoint| checkpoint.snapshot.as_ref())
                        .map_or_else(Counters::default, |snapshot| snapshot.counters.clone()),
                    committed: baseline.map_or(0, |checkpoint| checkpoint.sequence),
                    event_received: event_baseline
                        .as_ref()
                        .map_or(0, |checkpoint| checkpoint.sequence),
                    event_committed: event_baseline.map_or(0, |checkpoint| checkpoint.sequence),
                    buckets: BTreeMap::new(),
                    events: Vec::new(),
                    metric_flight: None,
                    event_flight: None,
                    submitted: Instant::now(),
                });
                self.states.len() - 1
            }
        };
        if index + 1 != self.states.len() {
            self.health.stale_snapshots = self.health.stale_snapshots.saturating_add(1);
            return Ok(());
        }
        let state = &mut self.states[index];
        if packet.sequence < state.sequence {
            self.health.stale_snapshots = self.health.stale_snapshots.saturating_add(1);
            return Ok(());
        }
        if packet.sequence == state.sequence {
            if !state.fingerprint.is_empty() && fingerprint != state.fingerprint {
                return Err(Error::Conflict);
            }
            self.health.stale_snapshots = self.health.stale_snapshots.saturating_add(1);
            return Ok(());
        }
        if packet.observed_at_ms < state.at || counters_decreased(&state.counters, &packet.counters)
        {
            return Err(Error::Invalid(
                "counter source regressed without a generation change",
            ));
        }
        for bucket in &packet.buckets {
            if bucket.revision <= state.committed {
                continue;
            }
            if state
                .buckets
                .get(&bucket.start_ms)
                .is_none_or(|old| bucket.revision > old.revision)
            {
                state.buckets.insert(bucket.start_ms, bucket.clone());
            }
        }
        while state.buckets.len() > self.config.max_pending_minutes {
            if let Some((start, _)) = state.buckets.pop_first() {
                self.health.omitted_metric_minutes =
                    self.health.omitted_metric_minutes.saturating_add(1);
                self.health.source_gap = Some(match self.health.source_gap {
                    Some((from, until)) => (from.min(start), until.max(start + MINUTE_MS)),
                    None => (start, start + MINUTE_MS),
                });
            }
        }
        for event in &packet.events {
            if event.sequence <= state.event_received {
                continue;
            }
            while state.events.len() >= self.config.max_pending_events
                || state
                    .events
                    .iter()
                    .map(event_bytes)
                    .sum::<usize>()
                    .saturating_add(event_bytes(event))
                    > self.config.max_event_bytes
            {
                let replacement = if event.decoy.is_some() {
                    state.events.iter().position(|old| old.decoy.is_none())
                } else {
                    None
                };
                if let Some(index) = replacement {
                    state.events.remove(index);
                } else {
                    break;
                }
                self.health.omitted_events = self.health.omitted_events.saturating_add(1);
            }
            if state.events.len() >= self.config.max_pending_events
                || state
                    .events
                    .iter()
                    .map(event_bytes)
                    .sum::<usize>()
                    .saturating_add(event_bytes(event))
                    > self.config.max_event_bytes
            {
                self.health.omitted_events = self.health.omitted_events.saturating_add(1);
                continue;
            }
            state.events.push(event.clone());
        }
        state.events.sort_by_key(|event| event.sequence);
        state.event_received = state.event_received.max(packet.event_sequence);
        state.sequence = packet.sequence;
        state.fingerprint = fingerprint;
        state.at = packet.observed_at_ms;
        state.counters = packet.counters.clone();
        state.source_omitted_events = packet.events_omitted;
        state.source_missed_updates = packet.missed_updates;
        self.health.source_connected = true;
        self.health.source_error = None;
        self.health.received_snapshots = self.health.received_snapshots.saturating_add(1);
        self.health.last_observed_at_ms = Some(packet.observed_at_ms);
        self.health.source_missed_updates = packet.missed_updates;
        self.health.source_omitted_events = packet.events_omitted;
        self.live.send_replace(Some(Arc::new(packet)));
        self.tick(false);
        Ok(())
    }

    pub fn tick(&mut self, force: bool) {
        self.poll();
        if self.health.storage_error.is_some() {
            return;
        }
        let Some(writer) = &self.writer else {
            return;
        };
        for state in &mut self.states {
            let cursor = serde_json::json!({"omitted_metric_minutes":self.health.omitted_metric_minutes,"omitted_events":self.health.omitted_events,"source_gap":self.health.source_gap,
                "source_omitted_events":state.source_omitted_events,"source_missed_updates":state.source_missed_updates}).to_string();
            let due = force || state.submitted.elapsed() >= self.config.persist_interval;
            if state.metric_flight.is_none() && state.sequence > state.committed && due {
                let checkpoint = Checkpoint {
                    source: state.source.clone(),
                    sequence: state.sequence,
                    cursor: Some(cursor.clone()),
                    snapshot: Some(CounterSnapshot {
                        observed_at_ms: state.at,
                        counters: state.counters.clone(),
                    }),
                };
                let batch = WriteBatch {
                    checkpoint: checkpoint.clone(),
                    metrics: state.buckets.values().cloned().collect(),
                    events: Vec::new(),
                };
                match writer.try_submit(batch) {
                    Ok(receipt) => {
                        state.metric_flight = Some(Flight {
                            receipt,
                            checkpoint,
                            revisions: state
                                .buckets
                                .values()
                                .map(|bucket| (bucket.start_ms, bucket.revision))
                                .collect(),
                        });
                        state.submitted = Instant::now();
                        // The collector already performed the ten-second coalescing delay.
                        writer.request_flush();
                    }
                    Err(SubmitError::Full | SubmitError::Contended) => (),
                    Err(SubmitError::Closed) => {
                        self.health.storage_error = Some(Error::WorkerStopped)
                    }
                    Err(SubmitError::Invalid(error)) => self.health.storage_error = Some(error),
                }
            }
            if state.event_flight.is_none() && state.event_received > state.event_committed {
                let checkpoint = Checkpoint {
                    source: event_source(&state.source),
                    sequence: state.event_received,
                    cursor: Some(cursor.clone()),
                    snapshot: None,
                };
                let batch = WriteBatch {
                    checkpoint: checkpoint.clone(),
                    metrics: Vec::new(),
                    events: state.events.clone(),
                };
                match writer.try_submit(batch) {
                    Ok(receipt) => {
                        state.events.clear();
                        state.event_flight = Some(Flight {
                            receipt,
                            checkpoint,
                            revisions: Vec::new(),
                        });
                    }
                    Err(SubmitError::Full | SubmitError::Contended) => (),
                    Err(SubmitError::Closed) => {
                        self.health.storage_error = Some(Error::WorkerStopped)
                    }
                    Err(SubmitError::Invalid(error)) => self.health.storage_error = Some(error),
                }
            }
        }
    }

    fn poll(&mut self) {
        for state in &mut self.states {
            if let Some(flight) = &mut state.metric_flight
                && let Some(result) = flight.receipt.try_result()
            {
                match result {
                    Ok(_) => {
                        state.committed = flight.checkpoint.sequence;
                        state.committed_at_ms = flight
                            .checkpoint
                            .snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.observed_at_ms);
                        for (start, revision) in &flight.revisions {
                            if state
                                .buckets
                                .get(start)
                                .is_some_and(|bucket| bucket.revision == *revision)
                            {
                                state.buckets.remove(start);
                            }
                        }
                    }
                    Err(error) => self.health.storage_error = Some(error),
                }
                state.metric_flight = None;
            }
            if let Some(flight) = &mut state.event_flight
                && let Some(result) = flight.receipt.try_result()
            {
                match result {
                    Ok(_) => state.event_committed = flight.checkpoint.sequence,
                    Err(error) => self.health.storage_error = Some(error),
                }
                state.event_flight = None;
            }
        }
    }

    pub fn source_failed(&mut self, error: Error) {
        self.health.source_connected = false;
        self.health.source_error = Some(error);
    }

    pub async fn shutdown(mut self, timeout: Duration) -> Result<super::ShutdownReport, Error> {
        super::validate_duration(timeout, Duration::from_secs(30))?;
        let end = Instant::now() + timeout;
        loop {
            self.tick(true);
            if let Some(writer) = &self.writer {
                writer.request_flush();
            }
            let pending = self.states.iter().any(|state| {
                state.sequence > state.committed
                    || state.event_received > state.event_committed
                    || state.metric_flight.is_some()
                    || state.event_flight.is_some()
            });
            if !pending || self.health.storage_error.is_some() || Instant::now() >= end {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let remaining = end
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        let timed_out = Instant::now() >= end;
        let mut report = self
            .writer
            .take()
            .ok_or(Error::WorkerStopped)?
            .shutdown(remaining)
            .await?;
        report.timed_out |= timed_out;
        Ok(report)
    }
}

fn event_source(source: &SourceIdentity) -> SourceIdentity {
    SourceIdentity {
        instance: format!("{}:events", source.instance),
        generation: source.generation.clone(),
    }
}
fn event_bytes(event: &EventRecord) -> usize {
    serde_json::to_vec(event).map_or(super::model::MAX_RECORD_BYTES, |json| json.len())
}

fn counters_decreased(old: &Counters, new: &Counters) -> bool {
    let old = serde_json::to_value(old).unwrap_or_default();
    let new = serde_json::to_value(new).unwrap_or_default();
    fn regressed(old: &serde_json::Value, new: &serde_json::Value) -> bool {
        if let Some(value) = old.as_u64() {
            return new.as_u64().is_none_or(|current| current < value);
        }
        old.as_object().is_some_and(|object| {
            object.iter().any(|(name, old)| {
                regressed(old, new.get(name).unwrap_or(&serde_json::Value::Null))
            })
        })
    }
    regressed(&old, &new)
}

pub struct HttpSource {
    address: SocketAddr,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl HttpSource {
    pub fn new(address: SocketAddr) -> Result<Self, Error> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::Invalid(
                "statistics source must be a loopback socket",
            ));
        }
        Ok(Self {
            address,
            client: Client::builder(TokioExecutor::new()).build_http(),
        })
    }

    pub async fn fetch(&self) -> Result<StatisticsSnapshot, Error> {
        tokio::time::timeout(Duration::from_millis(750), async {
            let request = http::Request::builder()
                .uri(format!("http://{}/console/snapshot", self.address))
                .body(Full::new(Bytes::new()))
                .map_err(|_| Error::Invalid("invalid source request"))?;
            let response = self
                .client
                .request(request)
                .await
                .map_err(|_| Error::Io("statistics source connection failed".into()))?;
            if response.status() != http::StatusCode::OK {
                return Err(Error::Io("statistics source did not return success".into()));
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| Error::Io("statistics source body failed".into()))?;
                if let Some(data) = frame.data_ref() {
                    if bytes.len().saturating_add(data.len()) > MAX_SNAPSHOT_BYTES {
                        return Err(Error::Invalid("source response exceeds byte limit"));
                    }
                    bytes.extend_from_slice(data);
                }
            }
            let packet: StatisticsSnapshot = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Invalid("invalid source snapshot JSON"))?;
            packet.validate()?;
            Ok(packet)
        })
        .await
        .map_err(|_| Error::OperationTimeout)?
    }
}

pub async fn run(
    source: HttpSource,
    collector: &mut Collector,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(collector.config.sample_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow_and_update() { break; } },
            _ = interval.tick() => {
                let result = tokio::select! {
                    _ = shutdown.changed() => break,
                    result = source.fetch() => result,
                };
                match result {
                    Ok(packet) => if let Err(error) = collector.receive(packet).await { collector.source_failed(error); },
                    Err(error) => collector.source_failed(error),
                }
                collector.tick(false);
            }
        }
    }
}
