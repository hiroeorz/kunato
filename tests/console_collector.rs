use std::sync::Arc;
use std::time::Duration;

use kunato::console::collector::{Collector, CollectorConfig};
use kunato::console::model::{RejectionReason, SourceIdentity};
use kunato::console::{Error, ReadWindow, StorageConfig, Store, WriterConfig};
use kunato::observations::{self, Observations, StatisticsSnapshot};

fn fast_writer() -> WriterConfig {
    WriterConfig {
        metric_flush: Duration::from_millis(1),
        event_flush: Duration::from_millis(1),
        min_commit_interval: Duration::from_millis(1),
        ..WriterConfig::default()
    }
}

async fn requests(history: &Arc<Observations>, count: usize, rejected: bool) {
    for _ in 0..count {
        observations::observe(history.clone(), async {
            if rejected {
                observations::reject(RejectionReason::Rule);
            }
            http::Response::builder()
                .status(if rejected { 403 } else { 200 })
                .body(())
                .unwrap()
        })
        .await;
    }
}

fn source(packet: &StatisticsSnapshot) -> SourceIdentity {
    SourceIdentity {
        instance: CollectorConfig::default().instance,
        generation: packet.source.generation.clone(),
    }
}
fn window(packet: &StatisticsSnapshot) -> ReadWindow {
    ReadWindow {
        from_ms: packet.buckets[0].start_ms,
        until_ms: packet.observed_at_ms + 60_000,
        limit: 256,
    }
}

async fn committed(collector: &mut Collector) {
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        collector.tick(true);
        if collector.health().pending_minutes == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "{:?}",
            collector.health()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test]
async fn latest_values_are_live_before_persistence_and_revisions_replace_counts() {
    let temp = tempfile::tempdir().unwrap();
    let config = StorageConfig::new(temp.path().join("history"));
    let history = Arc::new(Observations::new());
    let mut collector = Collector::start(config.clone(), fast_writer(), CollectorConfig::default())
        .await
        .unwrap();
    let live = collector.subscribe();
    requests(&history, 10, false).await;
    let first = history.snapshot(0).unwrap();
    collector.receive(first.clone()).await.unwrap();
    assert_eq!(live.borrow().as_ref().unwrap().counters.requests, Some(10));
    assert!(collector.health().last_committed_at_ms.is_none());
    requests(&history, 8, false).await;
    collector
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    requests(&history, 6, false).await;
    let last = history.snapshot(0).unwrap();
    collector.receive(last.clone()).await.unwrap();
    collector.receive(last.clone()).await.unwrap();
    collector.receive(first).await.unwrap();
    assert_eq!(collector.health().stale_snapshots, 2);
    assert_eq!(live.borrow().as_ref().unwrap().counters.requests, Some(24));
    committed(&mut collector).await;
    let report = collector.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(!report.timed_out);
    let mut store = Store::open(config.clone()).unwrap();
    assert_eq!(
        store
            .metrics(&source(&last), window(&last))
            .unwrap()
            .iter()
            .map(|bucket| bucket.counters.requests.unwrap())
            .sum::<u64>(),
        24
    );
    assert_eq!(
        store.checkpoint(&source(&last)).unwrap().unwrap().sequence,
        last.sequence
    );
    drop(store);
    let mut reopened = Collector::start(config.clone(), fast_writer(), CollectorConfig::default())
        .await
        .unwrap();
    requests(&history, 1, false).await;
    let next = history.snapshot(0).unwrap();
    reopened.receive(next.clone()).await.unwrap();
    reopened.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(config).unwrap();
    assert_eq!(
        store
            .metrics(&source(&next), window(&next))
            .unwrap()
            .iter()
            .map(|bucket| bucket.counters.requests.unwrap())
            .sum::<u64>(),
        25
    );
}

#[tokio::test]
async fn generation_reset_and_late_old_packets_keep_histories_separate() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let first = Arc::new(Observations::new());
    let second = Arc::new(Observations::new());
    requests(&first, 5, false).await;
    requests(&second, 1, false).await;
    let a = first.snapshot(0).unwrap();
    let b = second.snapshot(0).unwrap();
    let mut collector =
        Collector::start(storage.clone(), fast_writer(), CollectorConfig::default())
            .await
            .unwrap();
    collector.receive(a.clone()).await.unwrap();
    committed(&mut collector).await;
    collector.receive(b.clone()).await.unwrap();
    assert!(collector.health().last_committed_at_ms.is_none());
    collector.receive(first.snapshot(0).unwrap()).await.unwrap();
    assert_eq!(
        collector
            .subscribe()
            .borrow()
            .as_ref()
            .unwrap()
            .source
            .generation,
        b.source.generation
    );
    collector.shutdown(Duration::from_secs(2)).await.unwrap();
    let mut store = Store::open(storage).unwrap();
    assert_eq!(
        store
            .checkpoint(&source(&a))
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap()
            .counters
            .requests,
        Some(5)
    );
    assert_eq!(
        store
            .checkpoint(&source(&b))
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap()
            .counters
            .requests,
        Some(1)
    );
}

#[tokio::test]
async fn malformed_conflicting_and_regressed_inputs_do_not_replace_live_values() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let history = Arc::new(Observations::new());
    requests(&history, 2, false).await;
    let packet = history.snapshot(0).unwrap();
    let mut collector = Collector::start(storage, fast_writer(), CollectorConfig::default())
        .await
        .unwrap();
    collector.receive(packet.clone()).await.unwrap();
    let mut conflict = packet.clone();
    conflict.counters.requests = Some(1);
    assert_eq!(collector.receive(conflict).await, Err(Error::Conflict));
    let mut regression = packet.clone();
    regression.sequence += 1;
    regression.counters.requests = Some(0);
    assert!(collector.receive(regression).await.is_err());
    let mut malformed = packet;
    malformed.buckets[0].start_ms += 1;
    assert!(collector.receive(malformed).await.is_err());
    assert_eq!(
        collector
            .subscribe()
            .borrow()
            .as_ref()
            .unwrap()
            .counters
            .requests,
        Some(2)
    );
    collector.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn locked_database_does_not_wait_in_tick_or_stop_live_statistics() {
    let temp = tempfile::tempdir().unwrap();
    let mut storage = StorageConfig::new(temp.path().join("history"));
    storage.busy_timeout = Duration::from_millis(200);
    storage.operation_timeout = Duration::from_millis(250);
    let history = Arc::new(Observations::new());
    requests(&history, 1, false).await;
    let mut collector =
        Collector::start(storage.clone(), fast_writer(), CollectorConfig::default())
            .await
            .unwrap();
    collector
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    let lock = rusqlite::Connection::open(storage.directory.join("history.sqlite3")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let begin = std::time::Instant::now();
    collector.tick(true);
    assert!(begin.elapsed() < Duration::from_millis(100));
    requests(&history, 10, false).await;
    collector
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    assert_eq!(
        collector
            .subscribe()
            .borrow()
            .as_ref()
            .unwrap()
            .counters
            .requests,
        Some(11)
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    collector.tick(false);
    assert!(collector.health().storage_error.is_some());
    assert!(collector.health().pending_minutes <= CollectorConfig::default().max_pending_minutes);
    lock.execute_batch("ROLLBACK").unwrap();
    collector.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(storage).unwrap();
    let packet = history.snapshot(0).unwrap();
    assert!(store.checkpoint(&source(&packet)).unwrap().is_none());
}

#[tokio::test]
async fn event_replay_has_separate_progress_and_never_increments_request_totals() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let history = Arc::new(Observations::new());
    requests(&history, 3, true).await;
    let packet = history.snapshot(0).unwrap();
    let mut collector =
        Collector::start(storage.clone(), fast_writer(), CollectorConfig::default())
            .await
            .unwrap();
    collector.receive(packet.clone()).await.unwrap();
    collector
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    collector.shutdown(Duration::from_secs(2)).await.unwrap();
    let mut store = Store::open(storage.clone()).unwrap();
    let events = SourceIdentity {
        instance: format!("{}:events", source(&packet).instance),
        generation: packet.source.generation.clone(),
    };
    assert_eq!(store.events(&events, window(&packet)).unwrap().len(), 3);
    assert_eq!(
        store
            .checkpoint(&source(&packet))
            .unwrap()
            .unwrap()
            .snapshot
            .unwrap()
            .counters
            .requests,
        Some(3)
    );
    drop(store);
    let mut reopened = Collector::start(storage.clone(), fast_writer(), CollectorConfig::default())
        .await
        .unwrap();
    reopened
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    reopened.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(storage).unwrap();
    assert_eq!(store.events(&events, window(&packet)).unwrap().len(), 3);
}

#[tokio::test]
async fn bounded_detail_loss_is_durable_without_affecting_minute_totals() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let history = Arc::new(Observations::new());
    requests(&history, 64, true).await;
    let packet = history.snapshot(0).unwrap();
    let config = CollectorConfig {
        max_pending_events: 1,
        ..CollectorConfig::default()
    };
    let mut collector = Collector::start(storage.clone(), fast_writer(), config)
        .await
        .unwrap();
    collector.receive(packet.clone()).await.unwrap();
    assert_eq!(
        collector.health().omitted_events,
        packet.events.len() as u64 - 1
    );
    assert_eq!(
        collector
            .subscribe()
            .borrow()
            .as_ref()
            .unwrap()
            .counters
            .requests,
        Some(64)
    );
    collector.shutdown(Duration::from_secs(2)).await.unwrap();
    let mut store = Store::open(storage).unwrap();
    let checkpoint = store.checkpoint(&source(&packet)).unwrap().unwrap();
    assert_eq!(
        checkpoint.snapshot.unwrap().counters.rejected_requests,
        Some(64)
    );
    let quality: serde_json::Value = serde_json::from_str(&checkpoint.cursor.unwrap()).unwrap();
    assert_eq!(quality["omitted_events"], packet.events.len() as u64 - 1);
    assert_eq!(quality["source_omitted_events"], packet.events_omitted);
}

#[tokio::test]
async fn collector_interval_does_not_stack_the_writers_metric_delay() {
    let temp = tempfile::tempdir().unwrap();
    let storage = StorageConfig::new(temp.path().join("history"));
    let config = CollectorConfig {
        persist_interval: Duration::from_millis(20),
        ..CollectorConfig::default()
    };
    let mut collector = Collector::start(storage, WriterConfig::default(), config)
        .await
        .unwrap();
    let history = Arc::new(Observations::new());
    requests(&history, 1, false).await;
    collector
        .receive(history.snapshot(0).unwrap())
        .await
        .unwrap();
    assert!(collector.health().last_committed_at_ms.is_none());
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    while collector.health().last_committed_at_ms.is_none() {
        assert!(tokio::time::Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(5)).await;
        collector.tick(false);
    }
    assert_eq!(collector.health().pending_minutes, 0);
    collector.shutdown(Duration::from_secs(1)).await.unwrap();
}
