//! Nonblocking admission and batched persistence on an owned OS thread.

use std::collections::VecDeque;
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;

use super::model::{MAX_BATCH_BYTES, MAX_BATCH_RECORDS, WriteBatch};
use super::storage::PreparedBatch;
use super::{Error, StorageConfig, Store, WriteReport, validate_duration};

#[derive(Clone, Debug)]
pub struct WriterConfig {
    pub max_queue_items: usize,
    pub max_queue_bytes: usize,
    /// Counts events, metric buckets, and checkpoints together.
    pub max_batch_records: usize,
    pub max_batch_bytes: usize,
    pub event_flush: Duration,
    pub metric_flush: Duration,
    pub min_commit_interval: Duration,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            max_queue_items: 1024,
            max_queue_bytes: 4 * 1024 * 1024,
            max_batch_records: 200,
            max_batch_bytes: 512 * 1024,
            event_flush: Duration::from_secs(1),
            metric_flush: Duration::from_secs(10),
            min_commit_interval: Duration::from_millis(100),
        }
    }
}

impl WriterConfig {
    fn validate(&self) -> Result<(), Error> {
        if !(1..=4096).contains(&self.max_queue_items)
            || !(4096..=64 * 1024 * 1024).contains(&self.max_queue_bytes)
            || !(1..=MAX_BATCH_RECORDS).contains(&self.max_batch_records)
            || !(1024..=MAX_BATCH_BYTES).contains(&self.max_batch_bytes)
            || self.max_batch_bytes > self.max_queue_bytes
        {
            return Err(Error::Invalid("invalid writer queue or batch limits"));
        }
        validate_duration(self.event_flush, Duration::from_secs(60))?;
        validate_duration(self.metric_flush, Duration::from_secs(60))?;
        validate_duration(self.min_commit_interval, Duration::from_secs(1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    AtCapacity,
}

#[derive(Clone, Debug)]
pub struct Health {
    pub state: WriterState,
    pub queued_items: usize,
    pub in_flight_items: usize,
    /// Retained encoded payloads and their admission overhead, including in-flight work.
    pub outstanding_bytes: usize,
    pub accepted_batches: u64,
    pub rejected_batches: u64,
    pub committed_batches: u64,
    pub replayed_batches: u64,
    pub failed_batches: u64,
    pub oldest_pending_ms: Option<u64>,
    pub last_persisted_at_ms: Option<u64>,
    pub last_error: Option<Error>,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("console persistence queue is full")]
    Full,
    #[error("console persistence queue is momentarily contended")]
    Contended,
    #[error("console persistence is not accepting observations")]
    Closed,
    #[error(transparent)]
    Invalid(Error),
}

pub struct Receipt(oneshot::Receiver<Result<WriteReport, Error>>);

impl Receipt {
    pub fn try_result(&mut self) -> Option<Result<WriteReport, Error>> {
        match self.0.try_recv() {
            Ok(result) => Some(result),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => Some(Err(Error::WorkerStopped)),
        }
    }
    /// A timeout means the outcome is unknown; it does not cancel a commit.
    pub async fn wait(self, timeout: Duration) -> Result<WriteReport, Error> {
        validate_duration(timeout, Duration::from_secs(60))?;
        tokio::time::timeout(timeout, self.0)
            .await
            .map_err(|_| Error::ReceiptTimeout)?
            .map_err(|_| Error::WorkerStopped)?
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownReport {
    pub timed_out: bool,
    pub health: Health,
}

struct Pending {
    batch: PreparedBatch,
    queued_at: Instant,
    completion: oneshot::Sender<Result<WriteReport, Error>>,
}

struct Queue {
    force_flush: bool,
    pending: VecDeque<Pending>,
    in_flight: usize,
    in_flight_oldest: Option<Instant>,
    bytes: usize,
    health: Health,
}

struct Shared {
    queue: Mutex<Queue>,
    wake: Condvar,
    accepting: AtomicBool,
    stopping: AtomicBool,
    cancel: Arc<AtomicBool>,
    rejected: AtomicU64,
    config: WriterConfig,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn health(&self) -> Health {
        let queue = self.lock();
        let mut health = queue.health.clone();
        health.queued_items = queue.pending.len();
        health.in_flight_items = queue.in_flight;
        health.outstanding_bytes = queue.bytes;
        health.rejected_batches = self.rejected.load(Ordering::Relaxed);
        let oldest = queue
            .pending
            .front()
            .map(|item| item.queued_at)
            .into_iter()
            .chain(queue.in_flight_oldest)
            .min();
        health.oldest_pending_ms =
            oldest.map(|instant| instant.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        health
    }

    fn stop(&self) {
        let _queue = self.lock();
        self.accepting.store(false, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn fail(&self, error: Error) {
        self.accepting.store(false, Ordering::Release);
        let mut queue = self.lock();
        queue.health.state = if error == Error::Capacity {
            WriterState::AtCapacity
        } else {
            WriterState::Failed
        };
        queue.health.last_error = Some(error.clone());
        while let Some(pending) = queue.pending.pop_front() {
            queue.bytes = queue.bytes.saturating_sub(pending.batch.bytes);
            queue.health.failed_batches = queue.health.failed_batches.saturating_add(1);
            let _ = pending.completion.send(Err(error.clone()));
        }
    }
}

pub struct Writer {
    shared: Arc<Shared>,
    done: Option<oneshot::Receiver<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Writer {
    pub async fn start(storage: StorageConfig, config: WriterConfig) -> Result<Self, Error> {
        storage.validate()?;
        config.validate()?;
        let health = Health {
            state: WriterState::Starting,
            queued_items: 0,
            in_flight_items: 0,
            outstanding_bytes: 0,
            accepted_batches: 0,
            rejected_batches: 0,
            committed_batches: 0,
            replayed_batches: 0,
            failed_batches: 0,
            oldest_pending_ms: None,
            last_persisted_at_ms: None,
            last_error: None,
        };
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                force_flush: false,
                pending: VecDeque::new(),
                in_flight: 0,
                in_flight_oldest: None,
                bytes: 0,
                health,
            }),
            wake: Condvar::new(),
            accepting: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            rejected: AtomicU64::new(0),
            config,
        });
        let (started_tx, started_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let worker = shared.clone();
        let thread = std::thread::Builder::new()
            .name("kunato-history".into())
            .spawn(move || {
                match Store::open_cancellable(storage, worker.cancel.clone()) {
                    Ok(mut store) => {
                        {
                            let mut queue = worker.lock();
                            if !worker.stopping.load(Ordering::Acquire) {
                                queue.health.state = WriterState::Running;
                                worker.accepting.store(true, Ordering::Release);
                            }
                        }
                        if started_tx.send(Ok(())).is_ok() {
                            run(&worker, &mut store);
                        }
                    }
                    Err(error) => {
                        worker.fail(error.clone());
                        let _ = started_tx.send(Err(error));
                    }
                }
                worker.accepting.store(false, Ordering::Release);
                let _ = done_tx.send(());
            })?;
        let writer = Self {
            shared,
            done: Some(done_rx),
            thread: Some(thread),
        };
        match tokio::time::timeout(Duration::from_secs(5), started_rx).await {
            Ok(Ok(Ok(()))) => Ok(writer),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(Error::WorkerStopped),
            Err(_) => {
                writer.shared.cancel.store(true, Ordering::Release);
                Err(Error::StartupTimeout)
            }
        }
    }

    /// Performs bounded validation/encoding and a try-lock; never waits for disk or queue capacity.
    pub fn try_submit(&self, batch: WriteBatch) -> Result<Receipt, SubmitError> {
        let submit = || {
            if !self.shared.accepting.load(Ordering::Acquire) {
                return Err(SubmitError::Closed);
            }
            let prepared = PreparedBatch::new(&batch).map_err(SubmitError::Invalid)?;
            if prepared.bytes > self.shared.config.max_batch_bytes
                || prepared.records > self.shared.config.max_batch_records
            {
                return Err(SubmitError::Invalid(Error::Invalid(
                    "submission exceeds writer transaction limits",
                )));
            }
            let mut queue = match self.shared.queue.try_lock() {
                Ok(queue) => queue,
                Err(std::sync::TryLockError::WouldBlock) => return Err(SubmitError::Contended),
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            };
            if !self.shared.accepting.load(Ordering::Acquire) {
                return Err(SubmitError::Closed);
            }
            if queue.pending.len() + queue.in_flight >= self.shared.config.max_queue_items
                || queue.bytes.saturating_add(prepared.bytes) > self.shared.config.max_queue_bytes
            {
                return Err(SubmitError::Full);
            }
            let (completion, receipt) = oneshot::channel();
            queue.bytes += prepared.bytes;
            queue.pending.push_back(Pending {
                batch: prepared,
                queued_at: Instant::now(),
                completion,
            });
            queue.health.accepted_batches = queue.health.accepted_batches.saturating_add(1);
            self.shared.wake.notify_one();
            Ok(Receipt(receipt))
        };
        let result = submit();
        if result.is_err() {
            self.shared.rejected.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub fn health(&self) -> Health {
        self.shared.health()
    }

    /// Expedite queued batches without waiting for their SQLite commit.
    pub fn request_flush(&self) {
        self.shared.lock().force_flush = true;
        self.shared.wake.notify_one();
    }

    pub async fn shutdown(mut self, timeout: Duration) -> Result<ShutdownReport, Error> {
        validate_duration(timeout, Duration::from_secs(30))?;
        self.shared.stop();
        let done = self.done.take().ok_or(Error::WorkerStopped)?;
        let timed_out = tokio::time::timeout(timeout, done).await.is_err();
        if timed_out {
            self.shared.cancel.store(true, Ordering::Release);
            self.shared.wake.notify_all();
        }
        if let Some(thread) = self.thread.take()
            && thread.is_finished()
        {
            let _ = thread.join();
        }
        Ok(ShutdownReport {
            timed_out,
            health: self.health(),
        })
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.shared.stop();
    }
}

fn run(shared: &Shared, store: &mut Store) {
    let mut last_attempt: Option<Instant> = None;
    loop {
        let pending = {
            let mut queue = shared.lock();
            loop {
                if shared.cancel.load(Ordering::Acquire) {
                    drop(queue);
                    shared.fail(Error::Cancelled);
                    return;
                }
                let stopping = shared.stopping.load(Ordering::Acquire);
                if stopping {
                    queue.health.state = WriterState::Stopping;
                }
                if queue.pending.is_empty() {
                    queue.force_flush = false;
                    if stopping {
                        queue.health.state = WriterState::Stopped;
                        return;
                    }
                    queue = shared
                        .wake
                        .wait(queue)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    continue;
                }
                let mut records = 0_usize;
                let mut bytes = 0_usize;
                let mut count = 0;
                let mut due: Option<Instant> = None;
                for pending in &queue.pending {
                    if records + pending.batch.records > shared.config.max_batch_records
                        || bytes + pending.batch.bytes > shared.config.max_batch_bytes
                    {
                        break;
                    }
                    records += pending.batch.records;
                    bytes += pending.batch.bytes;
                    count += 1;
                    let delay = if pending.batch.has_events {
                        shared.config.event_flush
                    } else {
                        shared.config.metric_flush
                    };
                    let deadline = pending.queued_at + delay;
                    due = Some(due.map_or(deadline, |current| current.min(deadline)));
                }
                let threshold = count < queue.pending.len()
                    || records >= shared.config.max_batch_records
                    || bytes >= shared.config.max_batch_bytes;
                let mut deadline = if stopping || threshold || queue.force_flush {
                    Instant::now()
                } else {
                    due.unwrap_or_else(Instant::now)
                };
                if !stopping && let Some(last) = last_attempt {
                    deadline = deadline.max(last + shared.config.min_commit_interval);
                }
                let now = Instant::now();
                if deadline > now {
                    let (next, _) = shared
                        .wake
                        .wait_timeout(queue, deadline - now)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    queue = next;
                    continue;
                }
                let items: Vec<_> = queue.pending.drain(..count).collect();
                queue.in_flight = items.len();
                queue.in_flight_oldest = items.first().map(|pending| pending.queued_at);
                break items;
            }
        };
        // All SQLite work happens after releasing the queue mutex.
        let (batches, completions): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .map(|pending| (pending.batch, pending.completion))
            .unzip();
        last_attempt = Some(Instant::now());
        let result = store.write_many(&batches);
        let mut queue = shared.lock();
        queue.in_flight = 0;
        queue.in_flight_oldest = None;
        for batch in &batches {
            queue.bytes = queue.bytes.saturating_sub(batch.bytes);
        }
        match result {
            Ok(reports) => {
                queue.health.last_persisted_at_ms = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                );
                for (completion, report) in completions.into_iter().zip(reports) {
                    if report.replayed || report.stale {
                        queue.health.replayed_batches =
                            queue.health.replayed_batches.saturating_add(1);
                    } else {
                        queue.health.committed_batches =
                            queue.health.committed_batches.saturating_add(1);
                    }
                    let _ = completion.send(Ok(report));
                }
            }
            Err(error) => {
                shared.accepting.store(false, Ordering::Release);
                queue.health.state = if error == Error::Capacity {
                    WriterState::AtCapacity
                } else {
                    WriterState::Failed
                };
                queue.health.last_error = Some(error.clone());
                queue.health.failed_batches = queue
                    .health
                    .failed_batches
                    .saturating_add(completions.len() as u64);
                for completion in completions {
                    let _ = completion.send(Err(error.clone()));
                }
                drop(queue);
                shared.fail(error);
                return;
            }
        }
    }
}
