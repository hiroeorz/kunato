use std::time::Duration;

use kunato::console::history::{CountMetric, Grain, HOUR_MS, RETENTION_MS};
use kunato::console::model::*;
use kunato::console::{
    Error, HistoryQuery, StorageConfig, Store, SubmitError, Writer, WriterConfig,
};

const BASE: u64 = 1_800_000_000_000;
const NOW: u64 = BASE + 13 * HOUR_MS;
const FULL_DAY_NOW: u64 = BASE + 24 * HOUR_MS;

fn now() -> u64 {
    NOW
}
fn full_day_now() -> u64 {
    FULL_DAY_NOW
}
fn early() -> u64 {
    BASE + 2 * HOUR_MS
}
fn expired_now() -> u64 {
    BASE + RETENTION_MS + 24 * HOUR_MS + 17 * MINUTE_MS
}
fn before_expiry() -> u64 {
    BASE + 2 * 24 * HOUR_MS
}

fn config(temp: &tempfile::TempDir, clock: fn() -> u64) -> StorageConfig {
    let mut config = StorageConfig::new(temp.path().join("history"));
    config.clock = clock;
    config
}

fn minute(start_ms: u64, requests: u64, reason: RejectionReason, rejected: u64) -> MetricBucket {
    let mut reasons = RejectionReason::ALL
        .into_iter()
        .map(|reason| (reason, 0))
        .collect::<std::collections::BTreeMap<_, _>>();
    reasons.insert(reason, rejected);
    let mut statuses = vec![0; 500];
    statuses[100] = requests - rejected;
    statuses[303] = rejected;
    MetricBucket {
        additional: None,
        start_ms,
        site: None,
        revision: 1,
        counters: Counters {
            requests: Some(requests),
            rejected_requests: Some(rejected),
            rejection_reasons: Some(reasons),
            ..Counters::default()
        },
        connections: Some(ConnectionGauge {
            connection_milliseconds: 2 * MINUTE_MS,
            observed_ms: MINUTE_MS as u32,
            observed_max: 3,
            observed_min: Some(1),
        }),
        outcomes: Some(Outcomes {
            statuses,
            latency_count: requests,
            latency_sum_us: requests * 1000,
            latency_bins: {
                let mut bins = [0; 15];
                bins[0] = requests;
                bins
            },
            in_flight: 0,
            latency_min_us: (requests > 0).then_some(1000),
            latency_max_us: (requests > 0).then_some(1000),
        }),
        coverage: Coverage {
            observed_ms: MINUTE_MS as u32,
            incomplete: false,
            omitted_events: Some(0),
        },
    }
}

fn classes(values: &[(&str, u64)]) -> std::collections::BTreeMap<String, u64> {
    values
        .iter()
        .map(|(name, count)| ((*name).to_owned(), *count))
        .collect()
}

fn batch(generation: &str, sequence: u64, mut metrics: Vec<MetricBucket>) -> WriteBatch {
    for metric in &mut metrics {
        metric.revision = sequence;
    }
    WriteBatch {
        checkpoint: Checkpoint {
            source: SourceIdentity {
                instance: "waf".into(),
                generation: generation.into(),
            },
            sequence,
            cursor: None,
            snapshot: None,
        },
        metrics,
        events: vec![],
    }
}

fn query(from: u64, until: u64) -> HistoryQuery {
    HistoryQuery {
        instance: "waf".into(),
        site: None,
        from_ms: from,
        until_ms: until,
        range_ms: None,
        limit: 128,
        revision: None,
    }
}

fn drain(store: &mut Store, at: u64) {
    for _ in 0..20_000 {
        let report = store.maintain_at(at).unwrap();
        assert!(report.mutated_rows <= 1000);
        if !report.more_work {
            return;
        }
    }
    panic!("bounded maintenance did not converge");
}

#[test]
fn supplementary_history_survives_coarsening_reopen_and_missing_old_measurements() {
    use kunato::console::measurements::*;
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let mut minutes = Vec::new();
    for index in 0..5 {
        let requests = index + 1;
        let mut metric = minute(BASE + index * MINUTE_MS, requests, RejectionReason::Rule, 0);
        let mut additional = AdditionalMeasurements::measured();
        additional.completed_requests = requests;
        additional.country("JP", index % 2 == 0).unwrap();
        additional.country("US", false).unwrap();
        additional.upstream_statuses.insert(200, requests);
        additional.unique_sources.insert("source", b"192.0.2.1");
        additional.sources.record("192.0.2.1", false, false);
        additional.operations.insert(Operation::RulesUnchanged, 1);
        let mut latency = LatencyMeasurements::default();
        for _ in 0..requests {
            latency.record(1000);
        }
        additional
            .dimension(DimensionMeasurements {
                kind: DimensionKind::Site,
                id: identity("blog"),
                label: "blog".into(),
                phase: Phase::Request,
                counts: DimensionCounts {
                    requests,
                    latency,
                    ..DimensionCounts::default()
                },
            })
            .unwrap();
        metric.additional = Some(Box::new(additional));
        minutes.push(metric);
    }
    store.write_batch(&batch("a", 1, minutes.clone())).unwrap();
    drain(&mut store, early());
    drop(store);
    let mut store = Store::open(config.clone()).unwrap();
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.grain, Grain::FiveMinutes);
    let value = bucket.additional.as_ref().unwrap();
    assert_eq!(value.completed_requests, 15);
    assert_eq!(value.upstream_statuses[&200], 15);
    assert_eq!(value.countries["JP"].requests, 5);
    assert_eq!(value.countries["JP"].rejected, 3);
    assert_eq!(value.countries["US"].requests, 5);
    assert_eq!(value.operations[&Operation::RulesUnchanged], 5);
    assert_eq!(value.dimensions[0].counts.latency.mean_us(), Some(1000.0));
    assert!(value.unique_sources.estimate().unwrap() < 1.1);
    assert!(!value.incomplete);
    assert_eq!(bucket.outcomes.as_ref().unwrap().latency_min_us, Some(1000));
    assert_eq!(bucket.connections.observed_min, Some(1));
    // A historical producer did not measure supplementary fields or exact extrema.
    drop(store);
    let other = tempfile::tempdir().unwrap();
    let mut store = Store::open(self::config(&other, early)).unwrap();
    minutes[0].additional = None;
    minutes[0].outcomes.as_mut().unwrap().latency_min_us = None;
    minutes[0].outcomes.as_mut().unwrap().latency_max_us = None;
    minutes[0].connections.as_mut().unwrap().observed_min = None;
    store.write_batch(&batch("a", 1, minutes)).unwrap();
    drain(&mut store, early());
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.additional.as_ref().unwrap().completed_requests, 14);
    assert!(bucket.additional.as_ref().unwrap().incomplete);
    assert_eq!(bucket.outcomes.as_ref().unwrap().latency_min_us, None);
    assert_eq!(bucket.outcomes.as_ref().unwrap().latency_max_us, None);
    assert_eq!(bucket.connections.observed_min, None);
}

#[test]
fn version_three_migration_preserves_checkpoints_and_unknown_extrema() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let value = batch("a", 1, vec![minute(BASE, 5, RejectionReason::Rule, 2)]);
    store.write_batch(&value).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    let raw: String = connection
        .query_row("SELECT payload FROM metric_buckets", [], |row| row.get(0))
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_str(&raw).unwrap();
    payload.as_object_mut().unwrap().remove("additional");
    payload["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("latency_min_us");
    payload["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("latency_max_us");
    payload["connections"]
        .as_object_mut()
        .unwrap()
        .remove("observed_min");
    connection
        .execute(
            "UPDATE metric_buckets SET payload=?1",
            [payload.to_string()],
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE decoy_correlations; DROP TABLE correlation_state; PRAGMA user_version=3;",
        )
        .unwrap();
    drop(connection);
    let mut store = Store::open(config.clone()).unwrap();
    assert_eq!(
        store.checkpoint(&value.checkpoint.source).unwrap(),
        Some(value.checkpoint)
    );
    drain(&mut store, early());
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    assert!(page.buckets[0].additional.is_none());
    assert_eq!(
        page.buckets[0].outcomes.as_ref().unwrap().latency_min_us,
        None
    );
    assert_eq!(sql_count(&config, "PRAGMA user_version"), 4);
}

fn sql_count(config: &StorageConfig, sql: &str) -> u64 {
    rusqlite::Connection::open(config.directory.join("history.sqlite3"))
        .unwrap()
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .unwrap() as u64
}

#[test]
fn utc_tiers_preserve_all_reasons_totals_extrema_and_distributions() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, now);
    let mut store = Store::open(config.clone()).unwrap();
    let minutes = (0..780)
        .map(|index| {
            minute(
                BASE + index * MINUTE_MS,
                10 + index % 5,
                RejectionReason::ALL[index as usize % RejectionReason::ALL.len()],
                1,
            )
        })
        .collect::<Vec<_>>();
    for (index, chunk) in minutes.chunks(100).enumerate() {
        store
            .write_batch(&batch("a", index as u64 + 1, chunk.to_vec()))
            .unwrap();
    }
    drain(&mut store, NOW);
    let page = store.history(&query(BASE, NOW)).unwrap();
    assert_eq!(page.pending_minutes, 0);
    assert_eq!(page.buckets.len(), 124);
    let counts = Grain::ALL.map(|grain| {
        page.buckets
            .iter()
            .filter(|bucket| bucket.grain == grain)
            .count()
    });
    assert_eq!(counts, [60, 30, 15, 18, 1]);
    let mut end = BASE;
    for bucket in &page.buckets {
        assert_eq!(bucket.start_ms, end);
        assert_eq!(bucket.start_ms % bucket.grain.milliseconds(), 0);
        assert!(!bucket.coverage.incomplete);
        assert_eq!(
            bucket.counters[&CountMetric::RejectedRequests].min_minute,
            Some(1)
        );
        assert_eq!(
            bucket.counters[&CountMetric::RejectedRequests].max_minute,
            Some(1)
        );
        assert_eq!(
            bucket.reasons.values().map(|value| value.sum).sum::<u64>(),
            bucket.counters[&CountMetric::RejectedRequests].sum
        );
        assert_eq!(bucket.connection_average(), Some(2.0));
        let outcome = bucket.outcomes.as_ref().unwrap();
        assert_eq!(outcome.latency_bins[0], outcome.latency_count);
        assert_eq!(outcome.latency_sum_us, outcome.latency_count * 1000);
        end = bucket.end_ms();
    }
    assert_eq!(end, NOW);
    assert_eq!(
        page.buckets
            .iter()
            .map(|bucket| bucket.counters[&CountMetric::Requests].sum)
            .sum::<u64>(),
        9360
    );
    let hour = &page.buckets[0];
    assert_eq!(hour.grain, Grain::Hour);
    assert_eq!(hour.counters[&CountMetric::Requests].min_minute, Some(10));
    assert_eq!(hour.counters[&CountMetric::Requests].max_minute, Some(14));
    assert_eq!(
        hour.counters[&CountMetric::Requests].complete_minute_mean(),
        Some(12.0)
    );
    assert_eq!(hour.complete_rate(CountMetric::Requests), Some(0.2));
    assert_eq!(
        serde_json::to_value(hour).unwrap()["reasons"]["rule"]["known_minutes"],
        60
    );
    assert_eq!(
        hour.reasons
            .values()
            .map(|value| value.max_minute.unwrap())
            .sum::<u64>(),
        RejectionReason::ALL.len() as u64
    );
    assert_eq!(
        hour.counters[&CountMetric::RejectedRequests].max_minute,
        Some(1)
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        124 * RejectionReason::ALL.len() as u64
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM metric_buckets"),
        60
    );
    assert!(!store.maintain_at(NOW).unwrap().more_work);
    drop(store);
    let mut reopened = Store::open(config).unwrap();
    assert_eq!(
        reopened.history(&query(BASE, NOW)).unwrap().buckets,
        page.buckets
    );
}

#[test]
fn rejection_classes_merge_across_coarsening_and_keep_unknown_minutes() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let mut first = minute(BASE, 10, RejectionReason::Rule, 4);
    first.counters.rejection_classes = Some(classes(&[("sql-injection", 3), ("xss", 1)]));
    let mut second = minute(BASE + MINUTE_MS, 10, RejectionReason::Rule, 2);
    second.counters.rejection_classes = Some(classes(&[("sql-injection", 2)]));
    let unknown = minute(BASE + 2 * MINUTE_MS, 10, RejectionReason::Rule, 1);
    store
        .write_batch(&batch("a", 1, vec![first, second, unknown]))
        .unwrap();
    drain(&mut store, early());
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.grain, Grain::FiveMinutes);
    let sql = &bucket.rejection_classes["sql-injection"];
    assert_eq!(sql.sum, 5);
    assert_eq!(sql.known_minutes, 2);
    assert_eq!(bucket.rejection_classes["xss"].sum, 1);
    assert_eq!(bucket.rejection_classes["xss"].known_minutes, 1);
    assert_eq!(
        bucket
            .rejection_classes
            .values()
            .map(|value| value.sum)
            .sum::<u64>(),
        6
    );
    assert_eq!(
        serde_json::to_value(bucket).unwrap()["rejection_classes"]["sql-injection"]["known_minutes"],
        2
    );
}

#[test]
fn missing_partial_and_unsupported_values_do_not_become_zero_extrema_or_rates() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    let zero = minute(BASE, 0, RejectionReason::Rule, 0);
    let five = minute(BASE + MINUTE_MS, 10, RejectionReason::Rule, 5);
    let mut partial = minute(BASE + 3 * MINUTE_MS, 100, RejectionReason::Rule, 100);
    partial.coverage.incomplete = true;
    partial.coverage.observed_ms = 30_000;
    let mut unknown = minute(BASE + 4 * MINUTE_MS, 1, RejectionReason::Rule, 0);
    unknown.counters.rejection_reasons = None;
    store
        .write_batch(&batch("a", 1, vec![zero, five, partial, unknown]))
        .unwrap();
    drain(&mut store, early());
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.grain, Grain::FiveMinutes);
    assert!(bucket.coverage.incomplete);
    assert_eq!(bucket.coverage.represented_minutes, 4);
    let reason = &bucket.reasons[&RejectionReason::Rule];
    assert_eq!(reason.sum, 105);
    assert_eq!(reason.known_minutes, 3);
    assert_eq!(reason.complete_minutes, 2);
    assert_eq!(reason.min_minute, Some(0));
    assert_eq!(reason.max_minute, Some(5));
    assert_eq!(reason.complete_minute_mean(), Some(2.5));
    assert_eq!(bucket.complete_rate(CountMetric::Requests), None);
    assert_eq!(bucket.reason_share(RejectionReason::Rule), None);
    assert_eq!(bucket.connection_average(), None);
    let unsupported = minute(BASE + 10 * MINUTE_MS, 1, RejectionReason::Rule, 0);
    let mut unsupported = batch("a", 2, vec![unsupported]);
    unsupported.metrics[0].counters.rejection_reasons = None;
    store.write_batch(&unsupported).unwrap();
    drain(&mut store, early());
    let page = store
        .history(&query(BASE + 10 * MINUTE_MS, BASE + 15 * MINUTE_MS))
        .unwrap();
    assert_eq!(
        page.buckets[0].reasons[&RejectionReason::Rule].total(),
        None
    );
    assert_eq!(
        page.buckets[0].reasons[&RejectionReason::Rule].min_minute,
        None
    );
}

#[test]
fn generation_contributions_and_absolute_revisions_are_not_added_twice() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let at = early() - MINUTE_MS;
    let a = batch("a", 1, vec![minute(at, 50, RejectionReason::Rule, 5)]);
    let b = batch("b", 1, vec![minute(at, 70, RejectionReason::Host, 7)]);
    store.write_batch(&a).unwrap();
    store.write_batch(&b).unwrap();
    assert!(store.write_batch(&b).unwrap().replayed);
    drain(&mut store, early());
    let page = store.history(&query(at, early())).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.counters[&CountMetric::Requests].total(), Some(120));
    assert_eq!(bucket.counters[&CountMetric::Requests].known_minutes, 1);
    assert_eq!(bucket.reasons[&RejectionReason::Rule].sum, 5);
    assert_eq!(bucket.reasons[&RejectionReason::Host].sum, 7);
    assert!(bucket.coverage.incomplete);
    assert_eq!(bucket.counters[&CountMetric::Requests].max_minute, None);
    store
        .write_batch(&batch(
            "a",
            2,
            vec![minute(at, 60, RejectionReason::Rule, 6)],
        ))
        .unwrap();
    drain(&mut store, early());
    assert_eq!(
        store.history(&query(at, early())).unwrap().buckets[0].counters[&CountMetric::Requests].sum,
        130
    );
    drop(store);
    let mut reopened = Store::open(config).unwrap();
    assert_eq!(
        reopened.history(&query(at, early())).unwrap().buckets[0].reasons[&RejectionReason::Rule]
            .sum,
        6
    );
}

#[test]
fn compaction_rejects_unreconstructable_late_input_without_advancing_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    let first = batch("a", 1, vec![minute(BASE, 5, RejectionReason::Rule, 5)]);
    store.write_batch(&first).unwrap();
    drain(&mut store, early());
    let late = batch("a", 2, vec![minute(BASE, 8, RejectionReason::Rule, 8)]);
    assert_eq!(store.write_batch(&late), Err(Error::CompactedInput));
    assert_eq!(
        store
            .checkpoint(&first.checkpoint.source)
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        store
            .history(&query(BASE, BASE + 5 * MINUTE_MS))
            .unwrap()
            .buckets[0]
            .reasons[&RejectionReason::Rule]
            .sum,
        5
    );
}

#[test]
fn reason_rows_and_child_deletion_roll_back_together() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    store
        .write_batch(&batch(
            "a",
            1,
            (0..5)
                .map(|index| minute(BASE + index * MINUTE_MS, 1, RejectionReason::Rule, 1))
                .collect(),
        ))
        .unwrap();
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_reason BEFORE INSERT ON rejection_buckets WHEN NEW.reason='host' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(store.maintain_at(early()).is_err());
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        0
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        0
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM history_dirty"), 5);
    connection
        .execute_batch("DROP TRIGGER fail_reason;")
        .unwrap();
    for _ in 0..5 {
        store.maintain_at(BASE + 30 * MINUTE_MS).unwrap();
    }
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        5
    );
    connection.execute_batch("CREATE TRIGGER fail_parent BEFORE INSERT ON history_buckets WHEN NEW.grain_ms=300000 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(store.maintain_at(early()).is_err());
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        5
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        5 * RejectionReason::ALL.len() as u64
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM metric_buckets"), 5);
    connection
        .execute_batch("DROP TRIGGER fail_parent;")
        .unwrap();
    drain(&mut store, early());
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        1
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        RejectionReason::ALL.len() as u64
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM metric_buckets"), 0);
}

#[test]
fn logical_expiry_precedes_cleanup_and_survives_clock_rollback_and_replay() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config(&temp, before_expiry);
    let mut store = Store::open(config.clone()).unwrap();
    let day = BASE + 24 * HOUR_MS;
    store
        .write_batch(&batch(
            "a",
            1,
            vec![
                minute(day, 10, RejectionReason::Rule, 1),
                minute(day + HOUR_MS, 20, RejectionReason::Host, 2),
            ],
        ))
        .unwrap();
    drain(&mut store, before_expiry());
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        2
    );
    drop(store);
    config.clock = expired_now;
    let mut store = Store::open(config.clone()).unwrap();
    let page = store.history(&query(BASE, expired_now())).unwrap();
    assert_eq!(page.expiry_ms, day + HOUR_MS);
    assert_eq!(page.buckets.len(), 1);
    assert_eq!(page.buckets[0].start_ms, day + HOUR_MS);
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        2
    );
    drop(store);
    config.clock = before_expiry;
    let mut store = Store::open(config.clone()).unwrap();
    assert_eq!(
        store
            .history(&query(BASE, expired_now()))
            .unwrap()
            .buckets
            .len(),
        1
    );
    let report = store
        .write_batch(&batch(
            "a",
            2,
            vec![minute(day + 30 * MINUTE_MS, 99, RejectionReason::Rule, 99)],
        ))
        .unwrap();
    assert_eq!(report.expired_metrics, 1);
    drain(&mut store, before_expiry());
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        1
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        RejectionReason::ALL.len() as u64
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM history_dirty"), 0);
}

#[test]
fn full_day_history_pages_cover_the_range_and_rates_are_grain_invariant() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, full_day_now);
    let mut store = Store::open(config.clone()).unwrap();
    let minutes = (0..24 * 60)
        .map(|index| minute(BASE + index * MINUTE_MS, 60, RejectionReason::Rule, 6))
        .collect::<Vec<_>>();
    for (index, chunk) in minutes.chunks(100).enumerate() {
        store
            .write_batch(&batch("a", index as u64 + 1, chunk.to_vec()))
            .unwrap();
    }
    drain(&mut store, FULL_DAY_NOW);

    let mut request = query(BASE, FULL_DAY_NOW);
    let first = store.history(&request).unwrap();
    assert_eq!(first.buckets.len(), 128);
    let next = first
        .next_start_ms
        .expect("a full day exceeds one history page");
    assert_eq!(FULL_DAY_NOW - next, 7 * MINUTE_MS);
    request.from_ms = next;
    request.revision = Some(first.revision);
    let second = store.history(&request).unwrap();
    assert!(second.next_start_ms.is_none());

    let mut buckets = first.buckets;
    buckets.extend(second.buckets);
    assert_eq!(buckets.len(), 135);
    let counts = Grain::ALL.map(|grain| {
        buckets
            .iter()
            .filter(|bucket| bucket.grain == grain)
            .count()
    });
    assert_eq!(counts, [60, 30, 15, 18, 12]);
    assert_eq!(
        buckets
            .iter()
            .map(|bucket| bucket.counters[&CountMetric::Requests].sum)
            .sum::<u64>(),
        24 * 60 * 60
    );
    assert_eq!(
        buckets
            .iter()
            .map(|bucket| bucket.counters[&CountMetric::RejectedRequests].sum)
            .sum::<u64>(),
        24 * 60 * 6
    );
    for bucket in &buckets {
        assert!(!bucket.coverage.incomplete);
        let requests = bucket
            .complete_rate(CountMetric::Requests)
            .expect("complete requests rate");
        let rejected = bucket
            .complete_rate(CountMetric::RejectedRequests)
            .expect("complete rejection rate");
        assert!((requests - 1.0).abs() < 1e-9);
        assert!((rejected - 0.1).abs() < 1e-9);
    }
    assert_eq!(
        buckets.first().map(|bucket| bucket.grain),
        Some(Grain::Hour)
    );
    assert_eq!(
        buckets.last().map(|bucket| bucket.grain),
        Some(Grain::Minute)
    );
}

#[test]
fn history_queries_are_bounded_and_do_not_split_or_double_count_intervals() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    store
        .write_batch(&batch(
            "a",
            1,
            (0..10)
                .map(|index| minute(BASE + index * MINUTE_MS, 1, RejectionReason::Rule, 1))
                .collect(),
        ))
        .unwrap();
    drain(&mut store, early());
    let mut request = query(BASE, BASE + 10 * MINUTE_MS);
    request.limit = 1;
    let first = store.history(&request).unwrap();
    assert_eq!(first.buckets.len(), 1);
    assert_eq!(first.next_start_ms, Some(BASE + 5 * MINUTE_MS));
    request.from_ms = first.next_start_ms.unwrap();
    request.revision = Some(first.revision);
    let second = store.history(&request).unwrap();
    assert_eq!(second.buckets[0].start_ms, BASE + 5 * MINUTE_MS);
    assert!(second.next_start_ms.is_none());
    store
        .write_batch(&batch(
            "a",
            2,
            vec![minute(early() - MINUTE_MS, 1, RejectionReason::Rule, 1)],
        ))
        .unwrap();
    drain(&mut store, early());
    assert!(matches!(
        store.history(&request),
        Err(Error::HistoryChanged)
    ));
    assert!(
        store
            .history(&query(BASE + MINUTE_MS, BASE + 4 * MINUTE_MS))
            .unwrap()
            .buckets
            .is_empty()
    );
    request.limit = 129;
    assert!(store.history(&request).is_err());
    request.limit = 0;
    assert!(store.history(&request).is_err());
}

#[test]
fn precision_changes_only_when_the_whole_utc_parent_is_eligible() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    store
        .write_batch(&batch(
            "a",
            1,
            (0..60)
                .map(|index| minute(BASE + index * MINUTE_MS, 1, RejectionReason::Rule, 1))
                .collect(),
        ))
        .unwrap();
    let transitions = [
        (HOUR_MS + 5 * MINUTE_MS, Grain::Minute, Grain::FiveMinutes),
        (220 * MINUTE_MS, Grain::FiveMinutes, Grain::TenMinutes),
        (
            6 * HOUR_MS + 20 * MINUTE_MS,
            Grain::TenMinutes,
            Grain::TwentyMinutes,
        ),
        (13 * HOUR_MS, Grain::TwentyMinutes, Grain::Hour),
    ];
    for (offset, before, after) in transitions {
        drain(&mut store, BASE + offset - 1);
        assert_eq!(
            store.history(&query(BASE, BASE + HOUR_MS)).unwrap().buckets[0].grain,
            before
        );
        drain(&mut store, BASE + offset);
        assert_eq!(
            store.history(&query(BASE, BASE + HOUR_MS)).unwrap().buckets[0].grain,
            after
        );
    }
}

#[test]
fn means_keep_sample_weights_and_inconsistent_partitions_are_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    let mut values = vec![minute(BASE, 1, RejectionReason::Rule, 1)];
    values
        .extend((5..10).map(|index| minute(BASE + index * MINUTE_MS, 9, RejectionReason::Rule, 9)));
    store.write_batch(&batch("a", 1, values)).unwrap();
    drain(&mut store, BASE + 4 * HOUR_MS);
    let page = store.history(&query(BASE, BASE + 10 * MINUTE_MS)).unwrap();
    let count = &page.buckets[0].counters[&CountMetric::Requests];
    assert_eq!(count.sum, 46);
    assert_eq!(count.complete_minute_mean(), Some(46.0 / 6.0));
    assert!(page.buckets[0].coverage.incomplete);
    let mut bad = minute(early() - MINUTE_MS, 10, RejectionReason::Rule, 5);
    bad.counters.rejected_requests = Some(4);
    store.write_batch(&batch("a", 2, vec![bad])).unwrap();
    drain(&mut store, early());
    let bad = store.history(&query(early() - MINUTE_MS, early())).unwrap();
    assert!(bad.buckets[0].coverage.incomplete);
    assert_eq!(bad.buckets[0].reasons[&RejectionReason::Rule].sum, 5);
    assert_eq!(bad.buckets[0].reason_share(RejectionReason::Rule), None);
    let mut partial = minute(early() - MINUTE_MS, 10, RejectionReason::Rule, 5);
    partial.counters.rejected_requests = Some(4);
    partial
        .counters
        .rejection_reasons
        .as_mut()
        .unwrap()
        .remove(&RejectionReason::Host);
    store.write_batch(&batch("a", 3, vec![partial])).unwrap();
    drain(&mut store, early());
    let partial = store.history(&query(early() - MINUTE_MS, early())).unwrap();
    assert!(partial.buckets[0].coverage.incomplete);
    assert_eq!(partial.buckets[0].reason_share(RejectionReason::Rule), None);
}

#[test]
fn version_two_migration_backfills_without_losing_raw_rows_or_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let value = batch("a", 1, vec![minute(BASE, 5, RejectionReason::Rule, 2)]);
    store.write_batch(&value).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    connection.execute_batch("DROP TABLE decoy_correlations; DROP TABLE correlation_state; DROP TABLE rejection_buckets; DROP TABLE history_buckets; DROP TABLE history_dirty; DROP TABLE history_state; DROP TABLE history_sources; DROP INDEX metric_scope_time; DROP INDEX metric_expiry; DROP INDEX events_expiry; PRAGMA user_version=2;").unwrap();
    connection
        .execute_batch("CREATE TABLE history_dirty(unexpected INTEGER);")
        .unwrap();
    assert!(matches!(
        Store::open(config.clone()),
        Err(Error::Database(_))
    ));
    assert_eq!(sql_count(&config, "PRAGMA user_version"), 2);
    assert_eq!(
        sql_count(
            &config,
            "SELECT count(*) FROM sqlite_schema WHERE name='history_buckets'"
        ),
        0
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM metric_buckets"), 1);
    connection
        .execute_batch("DROP TABLE history_dirty;")
        .unwrap();
    drop(connection);
    let mut store = Store::open(config.clone()).unwrap();
    assert_eq!(
        store.checkpoint(&value.checkpoint.source).unwrap(),
        Some(value.checkpoint)
    );
    assert_eq!(
        store
            .history(&query(BASE, BASE + 5 * MINUTE_MS))
            .unwrap()
            .pending_minutes,
        1
    );
    drain(&mut store, early());
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    assert_eq!(
        page.buckets[0].reasons[&RejectionReason::Rule].total(),
        Some(2)
    );
    assert_eq!(sql_count(&config, "PRAGMA user_version"), 4);
}

#[test]
fn arithmetic_overflow_rolls_back_compaction_instead_of_wrapping() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let mut values = vec![
        minute(BASE, 0, RejectionReason::Rule, 0),
        minute(BASE + MINUTE_MS, 0, RejectionReason::Rule, 0),
    ];
    for value in &mut values {
        value.counters.requests = Some(u64::MAX);
        value.outcomes = None;
    }
    store.write_batch(&batch("a", 1, values)).unwrap();
    store.maintain_at(early()).unwrap();
    store.maintain_at(early()).unwrap();
    assert!(matches!(
        store.maintain_at(early()),
        Err(Error::Invalid("history counter overflow"))
    ));
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM history_buckets"),
        2
    );
    assert_eq!(
        sql_count(&config, "SELECT count(*) FROM rejection_buckets"),
        2 * RejectionReason::ALL.len() as u64
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM metric_buckets"), 2);
}

#[test]
fn dense_restart_provenance_still_obeys_the_transaction_row_bound() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    for generation in 0..64 {
        store
            .write_batch(&batch(
                &format!("g-{generation}"),
                1,
                (0..5)
                    .map(|index| minute(BASE + index * MINUTE_MS, 1, RejectionReason::Rule, 1))
                    .collect(),
            ))
            .unwrap();
    }
    let mut largest = 0;
    for _ in 0..20 {
        let report = store.maintain_at(early()).unwrap();
        largest = largest.max(report.mutated_rows);
        assert!(report.mutated_rows <= 1000);
        if !report.more_work {
            break;
        }
    }
    assert!(largest >= 400);
    let page = store.history(&query(BASE, BASE + 5 * MINUTE_MS)).unwrap();
    assert_eq!(page.buckets.len(), 1);
    assert_eq!(page.buckets[0].reasons[&RejectionReason::Rule].sum, 320);
    assert!(page.buckets[0].coverage.incomplete);
    assert_eq!(sql_count(&config, "SELECT count(*) FROM metric_buckets"), 0);
}

#[test]
fn event_expiry_does_not_erase_statistics_and_expired_replay_is_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    let mut value = batch("a", 1, vec![minute(BASE, 10, RejectionReason::Rule, 1)]);
    value.events.push(EventRecord {
        id: "event-1".into(),
        sequence: 1,
        occurred_at_ms: BASE,
        kind: EventKind::RuleMatch,
        disposition: Disposition::Log,
        phase: Phase::Request,
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
        reason: None,
        decoy: None,
        gap: None,
        incomplete: false,
    });
    store.write_batch(&value).unwrap();
    drain(&mut store, early());
    drop(store);
    config.clock = || BASE + 8 * 24 * HOUR_MS;
    let mut store = Store::open(config.clone()).unwrap();
    assert!(
        store
            .events(
                &value.checkpoint.source,
                kunato::console::ReadWindow {
                    from_ms: BASE,
                    until_ms: BASE + HOUR_MS,
                    limit: 128
                }
            )
            .unwrap()
            .is_empty()
    );
    assert_eq!(sql_count(&config, "SELECT count(*) FROM events"), 1);
    let mut replay = value.clone();
    replay.checkpoint.sequence = 2;
    replay.metrics.clear();
    replay.events[0].sequence = 2;
    replay.events[0].id = "event-2".into();
    assert_eq!(store.write_batch(&replay).unwrap().expired_events, 1);
    drain(&mut store, (config.clock)());
    assert_eq!(sql_count(&config, "SELECT count(*) FROM events"), 0);
    assert_eq!(
        store.history(&query(BASE, BASE + HOUR_MS)).unwrap().buckets[0].counters
            [&CountMetric::Requests]
            .sum,
        10
    );
}

#[tokio::test]
async fn brief_database_lock_is_retried_without_losing_admitted_work() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let writer = Writer::start(
        config.clone(),
        WriterConfig {
            metric_flush: Duration::from_millis(1),
            min_commit_interval: Duration::from_millis(1),
            ..WriterConfig::default()
        },
    )
    .await
    .unwrap();
    let connection = rusqlite::Connection::open(config.directory.join("history.sqlite3")).unwrap();
    connection.busy_timeout(Duration::from_secs(1)).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let value = batch(
        "a",
        1,
        vec![minute(early() - MINUTE_MS, 10, RejectionReason::Rule, 1)],
    );
    let receipt = loop {
        match writer.try_submit(value.clone()) {
            Ok(receipt) => break receipt,
            Err(SubmitError::Contended) => tokio::task::yield_now().await,
            Err(error) => panic!("{error}"),
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while writer.health().in_flight_items == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            writer.health()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    connection.execute_batch("ROLLBACK").unwrap();
    receipt.wait(Duration::from_secs(2)).await.unwrap();
    let report = writer.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!report.timed_out);
    assert!(report.health.last_error.is_none());
    let mut store = Store::open(config).unwrap();
    assert_eq!(
        store
            .history(&query(early() - MINUTE_MS, early()))
            .unwrap()
            .buckets[0]
            .reasons[&RejectionReason::Rule]
            .sum,
        1
    );
}

#[tokio::test]
async fn writer_materializes_reason_history_and_flushes_it_on_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let writer = Writer::start(
        config.clone(),
        WriterConfig {
            metric_flush: Duration::from_millis(1),
            min_commit_interval: Duration::from_millis(1),
            ..WriterConfig::default()
        },
    )
    .await
    .unwrap();
    let value = batch(
        "a",
        1,
        vec![minute(early() - MINUTE_MS, 100, RejectionReason::Decoy, 10)],
    );
    let receipt = loop {
        match writer.try_submit(value.clone()) {
            Ok(receipt) => break receipt,
            Err(SubmitError::Contended) => tokio::task::yield_now().await,
            Err(error) => panic!("{error}"),
        }
    };
    receipt.wait(Duration::from_secs(2)).await.unwrap();
    let report = writer.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!report.timed_out);
    assert_eq!(report.health.maintenance.unwrap().pending_minutes, 0);
    let mut store = Store::open(config).unwrap();
    let page = store.history(&query(early() - MINUTE_MS, early())).unwrap();
    let bucket = &page.buckets[0];
    assert_eq!(bucket.reasons[&RejectionReason::Decoy].total(), Some(10));
    assert_eq!(
        bucket.reason_rejection_fraction(RejectionReason::Decoy),
        Some(0.1)
    );
    assert_eq!(bucket.reason_share(RejectionReason::Decoy), Some(1.0));
}

#[test]
fn a_server_selected_range_anchors_to_retained_history_across_a_clock_step() {
    let temp = tempfile::tempdir().unwrap();
    let config = config(&temp, early);
    let mut store = Store::open(config.clone()).unwrap();
    store
        .write_batch(&batch(
            "a",
            1,
            vec![
                minute(BASE, 4, RejectionReason::Rule, 1),
                minute(BASE + MINUTE_MS, 6, RejectionReason::Rule, 2),
            ],
        ))
        .unwrap();
    drain(&mut store, early());
    drop(store);
    let mut store = Store::open(config).unwrap();

    // A caller clock that moved forward, as after a WAF wall-clock change,
    // selects a window that contains no retained interval.
    let live = early() + 8 * 24 * HOUR_MS;
    let caller_window = query(live - 7 * 24 * HOUR_MS, live);
    assert!(store.history(&caller_window).unwrap().buckets.is_empty());

    // A range query is anchored to the newest retained interval instead.
    let page = store
        .history(&HistoryQuery {
            instance: "waf".into(),
            site: None,
            from_ms: 0,
            until_ms: 0,
            range_ms: Some(7 * 24 * HOUR_MS),
            limit: 128,
            revision: None,
        })
        .unwrap();
    assert_eq!(page.until_ms, BASE + 5 * MINUTE_MS);
    assert_eq!(page.from_ms, page.until_ms - 7 * 24 * HOUR_MS);
    assert_eq!(page.buckets.len(), 1);
    assert_eq!(
        page.buckets[0].counters[&CountMetric::Requests].total(),
        Some(10)
    );
}

#[test]
fn a_server_selected_range_rejects_an_invalid_span_before_reading() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(config(&temp, early)).unwrap();
    for range in [0, RETENTION_MS + 1] {
        let error = store
            .history(&HistoryQuery {
                instance: "waf".into(),
                site: None,
                from_ms: 0,
                until_ms: 0,
                range_ms: Some(range),
                limit: 128,
                revision: None,
            })
            .unwrap_err();
        assert!(matches!(error, Error::Invalid(_)), "{error}");
    }
}
