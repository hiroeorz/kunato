//! Simulation of the resident in-memory EDR fed by five-minute WAF snapshots.

use std::collections::BTreeSet;
use std::net::IpAddr;

use kunato::console::measurements::AdditionalMeasurements;
use kunato::console::model::{
    Checkpoint, Counters, Coverage, EventRecord, MetricBucket, SourceIdentity, WriteBatch,
};
use kunato::console::{StorageConfig, Store};
use kunato::edr::live::{LiveConfig, LiveEdr};
use kunato::edr::{self, FindingKind, Options, Thresholds};
use kunato::observations::StatisticsSnapshot;

const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const BASE: u64 = 1_700_000_040_000;
const HOURS: usize = 18;
const SLOW_SOURCE: &str = "203.0.113.7";

#[derive(Clone, Default)]
struct Minute {
    requests: u64,
    failures: Vec<(String, String)>,
}

impl Minute {
    fn failure(&mut self, source: &str, path: &str) {
        self.failures.push((source.to_owned(), path.to_owned()));
    }
}

fn traffic() -> Vec<Minute> {
    let mut minutes = vec![Minute::default(); HOURS * 60];
    for minute in &mut minutes {
        minute.requests = 3;
    }
    for index in 0..5_u64 {
        let minute = ((index * 97 + 13) % (HOURS as u64 * 60)) as usize;
        minutes[minute].failure(&format!("10.0.0.{}", index + 1), "/login");
    }
    for offset in [0, 4, 9, 15, 21, 27, 34, 40, 46, 52, 55, 58] {
        minutes[9 * 60 + offset].failure("198.51.100.10", "/login");
    }
    for hour in 10..14 {
        for offset in (0..60).step_by(6) {
            minutes[hour * 60 + offset].failure(SLOW_SOURCE, "/login");
        }
    }
    for index in 0..60 {
        minutes[14 * 60 + index].failure(&format!("192.0.2.{}", index + 1), "/login");
    }
    for index in 0..20 {
        minutes[15 * 60 + index].failure(&format!("198.18.0.{}", index + 1), "/login");
    }
    for offset in 0..20 {
        minutes[16 * 60 + offset].failure("10.0.0.10", "/login");
    }
    minutes
}

fn full_bucket(start_ms: u64, minute: &Minute, revision: u64) -> MetricBucket {
    let requests = minute.requests + minute.failures.len() as u64;
    let mut additional = AdditionalMeasurements::measured();
    additional.completed_requests = requests;
    additional.auth_failures = minute.failures.len() as u64;
    for (source, path) in &minute.failures {
        additional.auth_sources.record(source, false, false);
        additional.auth_paths.record(path, false, false);
        additional
            .unique_auth_sources
            .insert("auth-source-ip-v1", source.as_bytes());
    }
    additional.validate().unwrap();
    MetricBucket {
        start_ms,
        site: None,
        revision,
        counters: Counters {
            requests: Some(requests),
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

fn partial_bucket(start_ms: u64, revision: u64) -> MetricBucket {
    MetricBucket {
        start_ms,
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
        additional: Some(Box::new(AdditionalMeasurements::measured())),
    }
}

fn snapshot(poll_ms: u64, sequence: u64, minutes: &[Minute]) -> StatisticsSnapshot {
    let mut buckets = Vec::new();
    let first = poll_ms.saturating_sub(9 * MINUTE_MS);
    for index in 0..10 {
        let start = first + index * MINUTE_MS;
        if start < BASE {
            continue;
        }
        if start < poll_ms {
            let hour = ((start - BASE) / HOUR_MS) as usize;
            let minute = ((start - BASE) % HOUR_MS / MINUTE_MS) as usize;
            buckets.push(full_bucket(start, &minutes[hour * 60 + minute], sequence));
        } else {
            buckets.push(partial_bucket(start, sequence));
        }
    }
    StatisticsSnapshot {
        version: 3,
        source: SourceIdentity {
            instance: "live-test".into(),
            generation: "g1".into(),
        },
        sequence,
        observed_at_ms: poll_ms,
        started_at_ms: BASE,
        clock_discontinuity: false,
        counters: Counters::default(),
        active_connections: 0,
        missed_updates: 0,
        buckets,
        events: Vec::new(),
        events_omitted: 0,
        event_sequence: 0,
        additional_missed_updates: Some(0),
    }
}

fn write_offline_database(temp: &tempfile::TempDir, minutes: &[Minute]) -> std::path::PathBuf {
    let mut config = StorageConfig::new(temp.path().join("history"));
    config.clock = || BASE + HOURS as u64 * HOUR_MS;
    let mut store = Store::open(config).unwrap();
    for hour in 0..HOURS {
        let sequence = (hour + 1) as u64;
        let metrics = (0..60)
            .map(|minute| {
                full_bucket(
                    BASE + hour as u64 * HOUR_MS + minute as u64 * MINUTE_MS,
                    &minutes[hour * 60 + minute],
                    sequence,
                )
            })
            .collect();
        store
            .write_batch(&WriteBatch {
                checkpoint: Checkpoint {
                    source: SourceIdentity {
                        instance: "live-test".into(),
                        generation: "g1".into(),
                    },
                    sequence,
                    cursor: None,
                    snapshot: None,
                },
                events: Vec::<EventRecord>::new(),
                metrics,
            })
            .unwrap();
    }
    temp.path().join("history").join("history.sqlite3")
}

fn finding_keys(report: &edr::Report) -> BTreeSet<(String, Option<IpAddr>)> {
    report
        .findings
        .iter()
        .map(|finding| (finding.kind.as_str().to_owned(), finding.source))
        .collect()
}

fn config() -> LiveConfig {
    LiveConfig {
        window: std::time::Duration::from_secs(3600),
        baseline: std::time::Duration::from_secs(7 * 24 * 3600),
        poll_interval: std::time::Duration::from_secs(300),
        ring: std::time::Duration::from_secs(720),
        thresholds: Thresholds::default(),
    }
}

#[test]
fn five_minute_snapshots_match_the_expected_hourly_findings() {
    let minutes = traffic();
    let mut live = LiveEdr::new(config()).unwrap();
    let mut reports = Vec::new();
    let mut sequence = 0;
    let mut poll = BASE;
    let end = BASE + (HOURS as u64 - 1) * HOUR_MS + 5 * MINUTE_MS;
    while poll <= end {
        sequence += 1;
        live.ingest(&snapshot(poll, sequence, &minutes)).unwrap();
        if poll >= BASE + HOUR_MS + 5 * MINUTE_MS && (poll - BASE) % HOUR_MS == 5 * MINUTE_MS {
            let until = poll - 5 * MINUTE_MS;
            let report = live.report(until).unwrap();
            reports.push((until, report));
        }
        poll += 5 * MINUTE_MS;
    }
    assert!(live.gaps().is_empty(), "unexpected gaps: {:?}", live.gaps());
    for (until, report) in &reports {
        if report.telemetry.as_str() != "present" {
            println!(
                "DEBUG until={until} telemetry={} buckets={} minutes={} findings={} notes={:?}",
                report.telemetry.as_str(),
                report.summary.buckets,
                report.summary.minutes_covered,
                report.findings.len(),
                report.notes
            );
        }
        assert_eq!(report.telemetry.as_str(), "present");
        assert!(!report.summary.incomplete, "{:?}", report.notes);
    }

    let slow_hours: Vec<usize> = reports
        .iter()
        .filter(|(_, report)| {
            report.findings.iter().any(|finding| {
                finding.kind == FindingKind::SlowAuthentication
                    && finding.source == Some(SLOW_SOURCE.parse().unwrap())
            })
        })
        .map(|(until, _)| ((*until - BASE) / HOUR_MS) as usize)
        .collect();
    assert_eq!(slow_hours, vec![11, 12, 13, 14]);

    let reverse: Vec<usize> = reports
        .iter()
        .filter(|(_, report)| {
            report
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::ReverseBruteForce)
        })
        .map(|(until, _)| ((*until - BASE) / HOUR_MS) as usize)
        .collect();
    assert_eq!(reverse, vec![15]);

    let false_slow: Vec<String> = reports
        .iter()
        .flat_map(|(_, report)| {
            report
                .findings
                .iter()
                .filter(|finding| finding.kind == FindingKind::SlowAuthentication)
                .filter(|finding| finding.source != Some(SLOW_SOURCE.parse().unwrap()))
                .filter_map(|finding| finding.source.map(|source| source.to_string()))
        })
        .collect();
    assert_eq!(false_slow, vec!["198.51.100.10"]);

    let temp = tempfile::tempdir().unwrap();
    let database = write_offline_database(&temp, &minutes);
    for (until, live_report) in &reports {
        let offline = edr::analyze(&Options {
            database: database.clone(),
            window: live_report.window,
            baseline: std::time::Duration::from_secs(7 * 24 * 3600),
            thresholds: Thresholds::default(),
        })
        .unwrap();
        assert_eq!(
            finding_keys(live_report),
            finding_keys(&offline),
            "finding mismatch at until {until}"
        );
    }

    let state_path = temp.path().join("edr-state.json");
    live.save(&state_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(&state_path).unwrap().mode() & 0o077,
            0,
            "EDR state must not be group/world accessible"
        );
    }
    let loaded = LiveEdr::load(&state_path, config())
        .unwrap()
        .expect("saved state");
    assert_eq!(loaded.retained_minutes(), live.retained_minutes());
    assert_eq!(loaded.retained_hours(), live.retained_hours());
    let (until, last_live) = reports.last().expect("a report");
    let loaded_report = loaded.report(*until).unwrap();
    assert_eq!(finding_keys(last_live), finding_keys(&loaded_report));

    println!(
        "snapshots={} retained_minutes={} retained_hours={} retained_bytes={} gaps={}",
        live.snapshots(),
        live.retained_minutes(),
        live.retained_hours(),
        live.retained_bytes(),
        live.gaps().len()
    );
    for (until, report) in &reports {
        if !report.findings.is_empty() {
            println!(
                "hour {} findings={:?}",
                (*until - BASE) / HOUR_MS,
                report
                    .findings
                    .iter()
                    .map(|finding| (finding.kind, finding.source))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn one_missed_five_minute_poll_loses_the_boundary_minute() {
    let minutes = traffic();
    let mut live = LiveEdr::new(config()).unwrap();
    let mut sequence = 0;
    let mut poll = BASE;
    let skip = BASE + 12 * HOUR_MS + 5 * MINUTE_MS;
    let end = BASE + 13 * HOUR_MS + 5 * MINUTE_MS;
    while poll <= end {
        if poll != skip {
            sequence += 1;
            live.ingest(&snapshot(poll, sequence, &minutes)).unwrap();
        }
        poll += 5 * MINUTE_MS;
    }
    assert!(!live.gaps().is_empty());
    let report = live.report(BASE + 13 * HOUR_MS).unwrap();
    assert!(report.summary.incomplete);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("Collection gap")),
        "{:?}",
        report.notes
    );
}

#[test]
fn restart_loses_the_window_and_baseline() {
    let minutes = traffic();
    let mut fresh = LiveEdr::new(config()).unwrap();
    let poll = BASE + 11 * HOUR_MS + 5 * MINUTE_MS;
    fresh.ingest(&snapshot(poll, 1, &minutes)).unwrap();
    let report = fresh.report(BASE + 11 * HOUR_MS).unwrap();
    assert!(report.summary.minutes_covered < 60);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.kind != FindingKind::SlowAuthentication)
    );
    assert!(report.notes.iter().any(|note| note.contains("warming up")));
    assert!(fresh.baseline_warming_up());
}

#[test]
fn seven_days_of_hourly_evidence_stays_small() {
    let empty = Minute {
        requests: 3,
        failures: Vec::new(),
    };
    let mut live = LiveEdr::new(config()).unwrap();
    let mut sequence = 0;
    let end = BASE + 7 * 24 * HOUR_MS;
    let mut poll = BASE;
    while poll <= end {
        sequence += 1;
        let mut buckets = Vec::new();
        for index in 0..10 {
            let start = poll.saturating_sub(9 * MINUTE_MS) + index * MINUTE_MS;
            if start < BASE {
                continue;
            }
            if start < poll {
                buckets.push(full_bucket(start, &empty, sequence));
            } else {
                buckets.push(partial_bucket(start, sequence));
            }
        }
        let snapshot = StatisticsSnapshot {
            version: 3,
            source: SourceIdentity {
                instance: "live-test".into(),
                generation: "g1".into(),
            },
            sequence,
            observed_at_ms: poll,
            started_at_ms: BASE,
            clock_discontinuity: false,
            counters: Counters::default(),
            active_connections: 0,
            missed_updates: 0,
            buckets,
            events: Vec::new(),
            events_omitted: 0,
            event_sequence: 0,
            additional_missed_updates: Some(0),
        };
        live.ingest(&snapshot).unwrap();
        poll += 5 * MINUTE_MS;
    }
    assert!(live.retained_hours() <= 169, "{}", live.retained_hours());
    assert!(live.retained_minutes() <= 73, "{}", live.retained_minutes());
    assert!(
        live.retained_bytes() < 2 * 1024 * 1024,
        "{}",
        live.retained_bytes()
    );
    println!(
        "7d retained_minutes={} retained_hours={} retained_bytes={}",
        live.retained_minutes(),
        live.retained_hours(),
        live.retained_bytes()
    );
}

#[test]
fn four_minute_poll_cadence_survives_one_missed_poll() {
    // A four-minute cadence gives two snapshots for the oldest complete
    // minute even when one poll is skipped. The full ring arithmetic is
    // covered here with direct snapshots rather than a whole day.
    let minutes = traffic();
    let mut live = LiveEdr::new(config()).unwrap();
    let polls = [
        BASE + 10 * MINUTE_MS,
        BASE + 14 * MINUTE_MS,
        BASE + 22 * MINUTE_MS, // 14: the 18-minute poll was skipped.
    ];
    for (index, poll) in polls.iter().enumerate() {
        live.ingest(&snapshot(*poll, index as u64 + 1, &minutes))
            .unwrap();
    }
    assert!(live.gaps().is_empty(), "{:?}", live.gaps());
}
