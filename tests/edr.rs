use kunato::console::measurements::AdditionalMeasurements;
use kunato::console::model::{
    Checkpoint, Counters, Coverage, EventRecord, MetricBucket, SourceIdentity, WriteBatch,
};
use kunato::console::{StorageConfig, Store};
use kunato::edr::{self, Evidence, Options, TelemetryState, Window};

const HOUR_MS: u64 = 60 * 60 * 1000;
const MINUTE_MS: u64 = 60 * 1000;
const NOW: u64 = 1_700_000_040_000;

fn source() -> SourceIdentity {
    SourceIdentity {
        instance: "edr-test".into(),
        generation: "boot".into(),
    }
}

fn bucket(start_ms: u64, failures: u64, source: &str, version: u32) -> MetricBucket {
    let mut additional = AdditionalMeasurements::measured();
    additional.version = version;
    additional.completed_requests = failures + 10;
    if version >= 2 {
        additional.auth_failures = failures;
        for _ in 0..failures {
            additional.auth_sources.record(source, false, false);
            additional.auth_paths.record("/login", false, false);
            additional
                .unique_auth_sources
                .insert("auth-source-ip-v1", source.as_bytes());
        }
    }
    additional.validate().unwrap();
    MetricBucket {
        start_ms,
        site: None,
        revision: 1,
        counters: Counters {
            requests: Some(failures + 10),
            ..Counters::default()
        },
        connections: None,
        coverage: Coverage {
            observed_ms: MINUTE_MS as u32,
            incomplete: false,
            omitted_events: None,
        },
        outcomes: None,
        additional: Some(Box::new(additional)),
    }
}

fn write_database(temp: &tempfile::TempDir, buckets: Vec<MetricBucket>) -> std::path::PathBuf {
    let mut config = StorageConfig::new(temp.path().join("history"));
    config.clock = || NOW;
    let mut store = Store::open(config.clone()).unwrap();
    let batch = WriteBatch {
        checkpoint: Checkpoint {
            source: source(),
            sequence: 1,
            cursor: None,
            snapshot: None,
        },
        events: Vec::<EventRecord>::new(),
        metrics: buckets,
    };
    store.write_batch(&batch).unwrap();
    temp.path().join("history").join("history.sqlite3")
}

fn window() -> Window {
    Window {
        from_ms: NOW - HOUR_MS,
        until_ms: NOW,
    }
}

#[test]
fn slow_authentication_source_is_detected_without_flagging_single_failures() {
    let temp = tempfile::tempdir().unwrap();
    let mut buckets = Vec::new();
    for minute in 0..60 {
        let start = NOW - HOUR_MS + minute * MINUTE_MS;
        if minute % 5 == 0 {
            buckets.push(bucket(start, 1, "203.0.113.7", 2));
        } else if minute % 17 == 0 {
            buckets.push(bucket(start, 1, "198.51.100.2", 2));
        } else {
            buckets.push(bucket(start, 0, "198.51.100.1", 2));
        }
    }

    let database = write_database(&temp, buckets);
    let options = Options::new(
        database,
        Window {
            from_ms: NOW - HOUR_MS,
            until_ms: NOW,
        },
    );
    let report = edr::analyze(&options).unwrap();
    assert_eq!(report.telemetry, TelemetryState::Present);
    assert_eq!(report.summary.auth_failures, 15);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].source,
        Some("203.0.113.7".parse().unwrap())
    );
    assert!(matches!(
        report.findings[0].evidence,
        Evidence::SlowAuthentication(_)
    ));
}

#[test]
fn distributed_single_failure_campaign_is_reverse_brute_force() {
    let temp = tempfile::tempdir().unwrap();
    let mut buckets = Vec::new();
    for minute in 0..60 {
        let start = NOW - HOUR_MS + minute * MINUTE_MS;
        let mut failures = 0;
        if minute < 40 {
            failures = 1;
        }
        buckets.push(bucket(
            start,
            failures,
            &format!("198.51.100.{}", minute + 1),
            2,
        ));
    }
    let database = write_database(&temp, buckets);
    let report = edr::analyze(&Options::new(database, window())).unwrap();
    assert_eq!(report.summary.auth_failures, 40);
    assert_eq!(report.findings.len(), 1);
    assert!(matches!(
        report.findings[0].evidence,
        Evidence::ReverseBruteForce(_)
    ));
}

#[test]
fn version_one_records_do_not_invent_findings() {
    let temp = tempfile::tempdir().unwrap();
    let mut buckets = Vec::new();
    for minute in 0..60 {
        buckets.push(bucket(
            NOW - HOUR_MS + minute * MINUTE_MS,
            1,
            "203.0.113.7",
            1,
        ));
    }
    let database = write_database(&temp, buckets);
    let report = edr::analyze(&Options::new(database, window())).unwrap();
    assert_eq!(report.telemetry, TelemetryState::Missing);
    assert!(report.findings.is_empty());
    assert!(report.notes.iter().any(|note| note.contains("version 2")));
}

#[test]
fn analyzer_rejects_an_unrelated_sqlite_database() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("other.sqlite3");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TABLE unrelated(value TEXT);")
        .unwrap();
    drop(connection);
    let error = edr::analyze(&Options::new(path, window())).unwrap_err();
    assert!(error.to_string().contains("not a Kunato console database"));
}
