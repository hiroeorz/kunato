use std::time::{Duration, Instant};

use kunato::console::model::*;
use kunato::console::{
    Error, ReadWindow, StorageConfig, Store, SubmitError, Writer, WriterConfig, WriterState,
};

fn source() -> SourceIdentity {
    SourceIdentity {
        instance: "waf-a:journal".into(),
        generation: "boot-a".into(),
    }
}

fn event(sequence: u64) -> EventRecord {
    EventRecord {
        id: format!("event-{sequence}"),
        sequence,
        occurred_at_ms: 60_000 + sequence,
        kind: EventKind::Rejection,
        disposition: Disposition::Block,
        phase: Phase::Request,
        site: Some("personal-blog".into()),
        client: Some("192.0.2.1".parse().unwrap()),
        peer: None,
        country: None,
        method: Some("GET".into()),
        path: Some("/admin".into()),
        status: Some(403),
        category: Some("probe".into()),
        rule: Some("admin-probe".into()),
        attack_class: Some("other".into()),
        reason: None,
        decoy: None,
        gap: None,
        incomplete: false,
    }
}

fn batch(sequence: u64) -> WriteBatch {
    WriteBatch {
        checkpoint: Checkpoint {
            source: source(),
            sequence,
            cursor: Some(format!("journal:{sequence}")),
            snapshot: Some(CounterSnapshot {
                observed_at_ms: 60_000 + sequence,
                counters: Counters {
                    requests: Some(sequence * 10),
                    ..Counters::default()
                },
            }),
        },
        events: vec![event(sequence)],
        metrics: vec![MetricBucket {
            additional: None,
            outcomes: None,
            start_ms: 60_000,
            site: None,
            revision: sequence,
            counters: Counters {
                requests: Some(sequence * 10),
                rejected_requests: Some(sequence),
                ..Counters::default()
            },
            connections: Some(ConnectionGauge {
                connection_milliseconds: 5000,
                observed_ms: 1000,
                observed_max: 6,
                observed_min: Some(1),
            }),
            coverage: Coverage {
                observed_ms: 1000,
                incomplete: true,
                omitted_events: None,
            },
        }],
    }
}

fn window() -> ReadWindow {
    ReadWindow {
        from_ms: 60_000,
        until_ms: 120_000,
        limit: 256,
    }
}

fn storage(temp: &tempfile::TempDir) -> StorageConfig {
    let mut config = StorageConfig::new(temp.path().join("history"));
    config.clock = || 120_000;
    config
}

#[test]
fn rejection_class_detail_is_bounded() {
    let mut value = batch(1);
    let metric = &mut value.metrics[0];
    metric.counters.rejection_classes = Some([("xss".to_owned(), 2)].into_iter().collect());
    metric.validate().unwrap();
    metric.counters.rejection_classes = Some([("x".repeat(65), 1)].into_iter().collect());
    assert!(metric.validate().is_err());
    metric.counters.rejection_classes =
        Some((0..65).map(|index| (format!("class-{index}"), 1)).collect());
    assert!(metric.validate().is_err());
}

#[test]
fn compact_decoy_evidence_is_idempotent_bounded_and_expires_without_extending_its_lifetime() {
    use kunato::console::correlations::CorrelationQuery;
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let mut store = Store::open(config.clone()).unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let mut value = batch(7);
    value.metrics.clear();
    value.events = (1..=7)
        .map(|sequence| {
            let mut record = event(sequence);
            record.kind = EventKind::Decoy;
            record.client = Some(format!("192.0.2.{sequence}").parse().unwrap());
            record.decoy = Some(DecoyEvidence {
                credential_id: id.into(),
                context: if sequence == 1 {
                    DecoyContext::Issued
                } else {
                    DecoyContext::Credential
                },
                issued_at_ms: Some(60_001),
                age_seconds: Some(0),
                lure: Some("/.env".into()),
                template: Some("dotenv".into()),
            });
            record
        })
        .collect();
    store.write_batch(&value).unwrap();
    assert!(store.write_batch(&value).unwrap().replayed);
    drop(store);
    let mut store = Store::open(config.clone()).unwrap();
    let query = CorrelationQuery {
        source: source().instance,
        credential_id: Some(id.to_uppercase()),
        from_ms: 0,
        until_ms: 120_000,
        limit: 128,
    };
    let page = store.correlations(&query).unwrap();
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.issued_at_ms, Some(60_001));
    assert_eq!(record.credential_evidence_count, 6);
    assert_eq!(record.blocked_evidence_count, 6);
    assert_eq!(record.reuse_clients.len(), 4);
    assert!(record.addresses_incomplete);
    assert_eq!(record.issuance_clients.len(), 1);
    let mut reuse = batch(8);
    reuse.metrics.clear();
    reuse.events[0].kind = EventKind::Decoy;
    reuse.events[0].decoy = value.events[1].decoy.clone();
    store.write_batch(&reuse).unwrap();
    assert_eq!(
        store.correlations(&query).unwrap().records[0].first_seen_ms,
        60_001
    );
    assert_eq!(
        store.correlations(&query).unwrap().records[0].credential_evidence_count,
        7
    );
    store
        .maintain_at(kunato::console::history::RETENTION_MS + 3_600_000)
        .unwrap();
    assert!(store.correlations(&query).unwrap().records.is_empty());
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM decoy_correlations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn compact_evidence_without_issuance_does_not_invent_an_issuance_trail() {
    use kunato::console::correlations::CorrelationQuery;
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    let mut value = batch(1);
    value.events[0].kind = EventKind::Decoy;
    value.events[0].decoy = Some(DecoyEvidence {
        credential_id: "0123456789abcdef0123456789abcdef".into(),
        context: DecoyContext::Credential,
        issued_at_ms: Some(59_000),
        age_seconds: Some(1),
        lure: None,
        template: None,
    });
    store.write_batch(&value).unwrap();
    let page = store
        .correlations(&CorrelationQuery {
            source: source().instance,
            credential_id: None,
            from_ms: 0,
            until_ms: 120_000,
            limit: 128,
        })
        .unwrap();
    assert_eq!(page.records[0].issued_at_ms, None);
    assert!(page.records[0].issuance_clients.is_empty());
    assert_eq!(page.records[0].credential_evidence_count, 1);
    assert_eq!(
        store.metrics(&source(), window()).unwrap()[0]
            .counters
            .requests,
        Some(10)
    );
}

fn slow_writer() -> WriterConfig {
    WriterConfig {
        event_flush: Duration::from_secs(60),
        metric_flush: Duration::from_secs(60),
        ..WriterConfig::default()
    }
}

async fn submit(writer: &Writer, batch: WriteBatch) -> kunato::console::Receipt {
    for _ in 0..100 {
        match writer.try_submit(batch.clone()) {
            Ok(receipt) => return receipt,
            Err(SubmitError::Contended) => tokio::task::yield_now().await,
            Err(error) => panic!("unexpected admission error: {error}"),
        }
    }
    panic!("worker queue remained contended");
}

#[test]
fn history_survives_reopen_and_retains_unknown_values_and_decoy_hashes() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let mut value = batch(1);
    value.events[0].kind = EventKind::Decoy;
    value.events[0].decoy = Some(DecoyEvidence {
        credential_id: "0123456789abcdef0123456789abcdef".into(),
        context: DecoyContext::Credential,
        issued_at_ms: Some(59_000),
        age_seconds: Some(1),
        lure: Some("/.env".into()),
        template: Some("dotenv".into()),
    });
    let mut store = Store::open(config.clone()).unwrap();
    let report = store.write_batch(&value).unwrap();
    assert_eq!(report.events_inserted, 1);
    assert_eq!(report.metrics_written, 1);
    drop(store);
    let mut reopened = Store::open(config).unwrap();
    assert_eq!(
        reopened.checkpoint(&source()).unwrap(),
        Some(value.checkpoint.clone())
    );
    assert_eq!(reopened.events(&source(), window()).unwrap(), value.events);
    assert_eq!(
        reopened.metrics(&source(), window()).unwrap(),
        value.metrics
    );
    assert_eq!(value.metrics[0].counters.log_requests, None);
    assert_eq!(
        reopened
            .events(
                &source(),
                ReadWindow {
                    from_ms: 60_002,
                    ..window()
                }
            )
            .unwrap()
            .len(),
        0
    );
    assert!(
        reopened
            .metrics(
                &source(),
                ReadWindow {
                    limit: 257,
                    ..window()
                }
            )
            .is_err()
    );
}

#[test]
fn replay_is_idempotent_and_bucket_updates_are_absolute() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    let first = batch(1);
    store.write_batch(&first).unwrap();
    assert!(store.write_batch(&first).unwrap().replayed);
    let second = batch(2);
    store.write_batch(&second).unwrap();
    assert!(store.write_batch(&first).unwrap().stale);
    let metrics = store.metrics(&source(), window()).unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].counters.requests, Some(20));
    assert_eq!(store.events(&source(), window()).unwrap().len(), 2);
    let mut conflicting = second.clone();
    conflicting.metrics[0].counters.requests = Some(999);
    assert_eq!(store.write_batch(&conflicting), Err(Error::Conflict));
    assert_eq!(
        store.checkpoint(&source()).unwrap(),
        Some(second.checkpoint)
    );
}

#[test]
fn generation_change_is_independent_of_counter_resets_and_prior_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    store.write_batch(&batch(10)).unwrap();
    let mut next = batch(1);
    next.checkpoint.source.generation = "boot-b".into();
    store.write_batch(&next).unwrap();
    assert_eq!(store.checkpoint(&source()).unwrap().unwrap().sequence, 10);
    assert_eq!(
        store
            .checkpoint(&next.checkpoint.source)
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        store
            .events(&next.checkpoint.source, window())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn event_failure_rolls_back_new_rows_metrics_and_checkpoint_together() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    let first = batch(1);
    store.write_batch(&first).unwrap();
    let mut bad = batch(3);
    bad.events.insert(0, event(2));
    bad.events[1].id = first.events[0].id.clone();
    assert_eq!(store.write_batch(&bad), Err(Error::Conflict));
    assert_eq!(store.events(&source(), window()).unwrap(), first.events);
    assert_eq!(store.metrics(&source(), window()).unwrap(), first.metrics);
    assert_eq!(store.checkpoint(&source()).unwrap(), Some(first.checkpoint));
}

#[test]
fn read_limits_time_bounds_and_site_keys_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    let mut value = batch(2);
    value.events.insert(0, event(1));
    let mut site = value.metrics[0].clone();
    site.site = Some("personal-blog".into());
    value.metrics.push(site);
    store.write_batch(&value).unwrap();
    assert_eq!(
        store
            .events(
                &source(),
                ReadWindow {
                    limit: 1,
                    ..window()
                }
            )
            .unwrap()[0]
            .sequence,
        1
    );
    assert_eq!(
        store
            .events(
                &source(),
                ReadWindow {
                    until_ms: 60_002,
                    ..window()
                }
            )
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.metrics(&source(), window()).unwrap().len(), 2);
    assert!(
        store
            .events(
                &source(),
                ReadWindow {
                    until_ms: 60_000,
                    ..window()
                }
            )
            .is_err()
    );
}

#[test]
fn invalid_or_sensitive_inputs_never_advance_storage() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(storage(&temp)).unwrap();
    for path in [
        "/login?password=secret",
        "/kdt1.secret",
        "/%6bdt1.secret",
        "/%256bdt1.secret",
        "/path#secret",
    ] {
        let mut value = batch(1);
        value.events[0].path = Some(path.into());
        assert!(
            store.write_batch(&value).is_err(),
            "accepted sensitive path: {path}"
        );
    }
    let mut value = batch(1);
    value.events[0].kind = EventKind::Decoy;
    assert!(store.write_batch(&value).is_err());
    value = batch(1);
    value.metrics[0].start_ms += 1;
    assert!(store.write_batch(&value).is_err());
    value = batch(1);
    value.events[0].reason = Some("x".repeat(513));
    assert!(store.write_batch(&value).is_err());
    value = batch(1);
    value.events = vec![event(1); MAX_BATCH_RECORDS];
    assert!(store.write_batch(&value).is_err());
    assert!(store.checkpoint(&source()).unwrap().is_none());
    assert_eq!(
        serde_json::from_str::<Counters>("{\"requests\":0}")
            .unwrap()
            .requests,
        Some(0)
    );
    assert_eq!(
        serde_json::from_str::<Counters>("{}").unwrap().requests,
        None
    );
}

#[test]
fn foreign_and_future_databases_are_rejected_without_erasing_them() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    drop(Store::open(config.clone()).unwrap());
    let path = config.directory.join("history.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Store::open(config.clone()),
        Err(Error::UnsupportedSchema(999))
    ));
    assert_eq!(before, std::fs::read(&path).unwrap());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "application_id", 123)
        .unwrap();
    drop(connection);
    assert!(matches!(Store::open(config), Err(Error::ForeignDatabase)));
}

#[test]
fn version_one_history_migrates_without_inventing_new_measurements() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let mut store = Store::open(config.clone()).unwrap();
    store.write_batch(&batch(1)).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    let payload: String = connection
        .query_row("SELECT payload FROM metric_buckets", [], |row| row.get(0))
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&payload).unwrap();
    value.as_object_mut().unwrap().remove("outcomes");
    for key in [
        "decoy_issued",
        "response_log_requests",
        "aborted_requests",
        "rejection_reasons",
    ] {
        value["counters"].as_object_mut().unwrap().remove(key);
    }
    connection
        .execute(
            "UPDATE metric_buckets SET payload=?1",
            [serde_json::to_string(&value).unwrap()],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    connection.execute_batch("DROP TABLE decoy_correlations; DROP TABLE correlation_state; DROP TABLE rejection_buckets; DROP TABLE history_buckets; DROP TABLE history_dirty; DROP TABLE history_state; DROP TABLE history_sources; DROP INDEX metric_scope_time; DROP INDEX metric_expiry; DROP INDEX events_expiry;").unwrap();
    drop(connection);
    let mut store = Store::open(config.clone()).unwrap();
    let rows = store.metrics(&source(), window()).unwrap();
    assert_eq!(rows[0].counters.requests, Some(10));
    assert!(rows[0].counters.rejection_reasons.is_none());
    assert!(rows[0].outcomes.is_none());
    while store.maintain().unwrap().more_work {}
    let history = store
        .history(&kunato::console::HistoryQuery {
            instance: source().instance,
            site: None,
            from_ms: 60_000,
            until_ms: 120_000,
            range_ms: None,
            limit: 128,
            revision: None,
        })
        .unwrap();
    assert_eq!(
        history.buckets[0].counters[&kunato::console::history::CountMetric::Requests].total(),
        Some(10)
    );
    assert_eq!(
        history.buckets[0].reasons[&RejectionReason::Rule].total(),
        None
    );
    drop(store);
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
}

#[cfg(unix)]
#[test]
fn data_files_are_private_and_symlinks_are_refused() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    drop(Store::open(config.clone()).unwrap());
    assert_eq!(
        std::fs::metadata(&config.directory).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(config.directory.join("history.sqlite3"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    symlink(&config.directory, temp.path().join("linked")).unwrap();
    assert!(Store::open(StorageConfig::new(temp.path().join("linked"))).is_err());
    std::fs::set_permissions(&config.directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(config).is_err());
}

#[test]
fn minimum_capacity_covers_schema_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = storage(&temp);
    config.max_bytes = 256 * 1024;
    assert!(matches!(Store::open(config), Err(Error::Invalid(_))));

    let mut config = storage(&temp);
    config.max_bytes = 512 * 1024;
    drop(Store::open(config).unwrap());
}

#[test]
fn open_refuses_a_database_missing_a_history_table() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    drop(Store::open(config.clone()).unwrap());
    let path = config.directory.join("history.sqlite3");
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TABLE history_dirty;")
            .unwrap();
    }
    assert!(Store::open(config).is_err());
}

#[test]
fn capacity_failure_preserves_committed_history_and_stays_within_budget() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = storage(&temp);
    config.max_bytes = 512 * 1024;
    let mut store = Store::open(config.clone()).unwrap();
    let mut committed = 0;
    for sequence in 1..2000 {
        let mut value = batch(sequence);
        value.events[0].reason = Some("x".repeat(512));
        match store.write_batch(&value) {
            Ok(_) => committed = sequence,
            Err(Error::Capacity) => break,
            Err(error) => panic!("unexpected capacity error: {error}"),
        }
    }
    assert!(committed > 0 && committed < 1999);
    assert_eq!(
        store.checkpoint(&source()).unwrap().unwrap().sequence,
        committed
    );
    drop(store);
    let bytes: u64 = std::fs::read_dir(&config.directory)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(bytes <= config.max_bytes);
    let mut store = Store::open(config).unwrap();
    assert_eq!(
        store.checkpoint(&source()).unwrap().unwrap().sequence,
        committed
    );
}

#[tokio::test]
async fn pending_and_committed_states_differ_and_shutdown_flushes() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let writer = Writer::start(config.clone(), slow_writer()).await.unwrap();
    let receipt = submit(&writer, batch(1)).await;
    let health = writer.health();
    assert_eq!(health.accepted_batches, 1);
    assert_eq!(health.committed_batches, 0);
    assert_eq!(health.queued_items, 1);
    assert!(health.last_persisted_at_ms.is_none());
    let shutdown = writer.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!shutdown.timed_out);
    assert_eq!(shutdown.health.state, WriterState::Stopped);
    assert_eq!(shutdown.health.outstanding_bytes, 0);
    assert_eq!(
        receipt
            .wait(Duration::from_secs(1))
            .await
            .unwrap()
            .events_inserted,
        1
    );
    let mut store = Store::open(config).unwrap();
    assert_eq!(store.checkpoint(&source()).unwrap().unwrap().sequence, 1);
}

#[tokio::test]
async fn a_conflicting_batch_fails_only_its_own_submission() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let options = WriterConfig {
        max_batch_records: 6,
        event_flush: Duration::from_millis(10),
        ..slow_writer()
    };
    let writer = Writer::start(config.clone(), options).await.unwrap();
    let first = submit(&writer, batch(1)).await;
    let mut conflicting = batch(2);
    conflicting.events[0].id = "event-1".into();
    let second = submit(&writer, conflicting).await;
    let third = submit(&writer, batch(3)).await;
    writer.request_flush();

    assert_eq!(
        first
            .wait(Duration::from_secs(2))
            .await
            .unwrap()
            .events_inserted,
        1
    );
    assert_eq!(
        second.wait(Duration::from_secs(2)).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        third
            .wait(Duration::from_secs(2))
            .await
            .unwrap()
            .events_inserted,
        1
    );
    let health = writer.health();
    assert_eq!(health.failed_batches, 1);
    assert_eq!(health.committed_batches, 2);
    assert_eq!(health.state, WriterState::Running);
    assert!(writer.try_submit(batch(4)).is_ok());
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(config).unwrap();
    assert_eq!(store.checkpoint(&source()).unwrap().unwrap().sequence, 4);
    let events = store.events(&source(), window()).unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.id.as_str())
            .collect::<Vec<_>>(),
        ["event-1", "event-3", "event-4"]
    );
}

#[tokio::test]
async fn event_timer_flushes_and_receipt_timeout_does_not_cancel_pending_work() {
    let temp = tempfile::tempdir().unwrap();
    let config = storage(&temp);
    let options = WriterConfig {
        event_flush: Duration::from_millis(60),
        ..slow_writer()
    };
    let writer = Writer::start(config.clone(), options).await.unwrap();
    let receipt = submit(&writer, batch(1)).await;
    assert_eq!(
        receipt.wait(Duration::from_millis(1)).await,
        Err(Error::ReceiptTimeout)
    );
    let until = Instant::now() + Duration::from_secs(2);
    while writer.health().committed_batches == 0 {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(writer.health().last_persisted_at_ms.is_some());
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(config).unwrap();
    assert_eq!(store.checkpoint(&source()).unwrap().unwrap().sequence, 1);
}

#[tokio::test]
async fn metric_only_work_uses_its_own_flush_timer() {
    let temp = tempfile::tempdir().unwrap();
    let options = WriterConfig {
        event_flush: Duration::from_millis(1),
        metric_flush: Duration::from_millis(150),
        ..slow_writer()
    };
    let writer = Writer::start(storage(&temp), options).await.unwrap();
    let mut value = batch(1);
    value.events.clear();
    let receipt = submit(&writer, value).await;
    assert_eq!(
        receipt.wait(Duration::from_millis(15)).await,
        Err(Error::ReceiptTimeout)
    );
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn queue_item_and_byte_limits_reject_without_waiting() {
    let temp = tempfile::tempdir().unwrap();
    let options = WriterConfig {
        max_queue_items: 1,
        ..slow_writer()
    };
    let writer = Writer::start(storage(&temp), options).await.unwrap();
    let _receipt = submit(&writer, batch(1)).await;
    let before = Instant::now();
    assert!(matches!(
        writer.try_submit(batch(2)),
        Err(SubmitError::Full | SubmitError::Contended)
    ));
    assert!(before.elapsed() < Duration::from_millis(100));
    assert_eq!(writer.health().rejected_batches, 1);
    writer.shutdown(Duration::from_secs(1)).await.unwrap();

    let second_temp = tempfile::tempdir().unwrap();
    let options = WriterConfig {
        max_queue_items: 10,
        max_queue_bytes: 4096,
        max_batch_bytes: 4096,
        ..slow_writer()
    };
    let writer = Writer::start(storage(&second_temp), options).await.unwrap();
    let _first = submit(&writer, batch(1)).await;
    let mut full = false;
    for sequence in 2..10 {
        match writer.try_submit(batch(sequence)) {
            Ok(_) => (),
            Err(SubmitError::Full) => {
                full = true;
                break;
            }
            Err(SubmitError::Contended) => tokio::task::yield_now().await,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
    assert!(full);
    assert!(writer.health().outstanding_bytes <= 4096);
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn disk_lock_keeps_inflight_work_bounded_and_shutdown_has_a_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = storage(&temp);
    config.busy_timeout = Duration::from_millis(500);
    config.operation_timeout = Duration::from_secs(1);
    let options = WriterConfig {
        max_queue_items: 1,
        event_flush: Duration::from_millis(1),
        ..slow_writer()
    };
    let writer = Writer::start(config.clone(), options).await.unwrap();
    let blocker = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let receipt = submit(&writer, batch(1)).await;
    let until = Instant::now() + Duration::from_secs(1);
    while writer.health().in_flight_items == 0 {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let before = Instant::now();
    assert!(matches!(
        writer.try_submit(batch(2)),
        Err(SubmitError::Full | SubmitError::Contended)
    ));
    assert!(before.elapsed() < Duration::from_millis(100));
    let before = Instant::now();
    let shutdown = writer.shutdown(Duration::from_millis(10)).await.unwrap();
    assert!(shutdown.timed_out);
    assert!(before.elapsed() < Duration::from_millis(200));
    assert_eq!(shutdown.health.in_flight_items, 0);
    assert!(shutdown.health.state == WriterState::Failed);
    blocker.execute_batch("ROLLBACK").unwrap();
    // The SQLite lock wait is bounded separately. Cancellation prevents later statements.
    assert!(matches!(
        receipt.wait(Duration::from_secs(2)).await,
        Err(Error::Cancelled | Error::Busy | Error::OperationTimeout)
    ));
    let mut store = Store::open(config).unwrap();
    assert!(store.checkpoint(&source()).unwrap().is_none());
}

#[tokio::test]
async fn writer_stops_admission_at_capacity_and_keeps_its_last_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = storage(&temp);
    config.max_bytes = 512 * 1024;
    let options = WriterConfig {
        max_batch_records: 3,
        min_commit_interval: Duration::from_millis(1),
        ..slow_writer()
    };
    let writer = Writer::start(config.clone(), options).await.unwrap();
    let mut committed = 0;
    for sequence in 1..1000 {
        let receipt = submit(&writer, batch(sequence)).await;
        match receipt.wait(Duration::from_secs(2)).await {
            Ok(_) => committed = sequence,
            Err(Error::Capacity) => break,
            Err(error) => panic!("unexpected worker error: {error}"),
        }
    }
    assert!(committed > 0 && committed < 999);
    assert_eq!(writer.health().state, WriterState::AtCapacity);
    assert!(matches!(
        writer.try_submit(batch(committed + 1)),
        Err(SubmitError::Closed)
    ));
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
    let mut store = Store::open(config).unwrap();
    assert_eq!(
        store.checkpoint(&source()).unwrap().unwrap().sequence,
        committed
    );
}

#[tokio::test]
async fn queue_contention_and_invalid_configuration_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let invalid = WriterConfig {
        max_queue_items: 0,
        ..WriterConfig::default()
    };
    assert!(matches!(
        Writer::start(storage(&temp), invalid).await,
        Err(Error::Invalid(_))
    ));
    assert!(!storage(&temp).directory.exists());
    let writer = Writer::start(storage(&temp), slow_writer()).await.unwrap();
    let mut oversized = batch(1);
    oversized.events[0].reason = Some("x".repeat(513));
    assert!(matches!(
        writer.try_submit(oversized),
        Err(SubmitError::Invalid(_))
    ));
    assert_eq!(writer.health().accepted_batches, 0);
    assert_eq!(writer.health().rejected_batches, 1);
    writer.shutdown(Duration::from_secs(1)).await.unwrap();
}
