//! Deterministic 24-hour evaluation of the offline EDR analyzer.

use kunato::console::measurements::AdditionalMeasurements;
use kunato::console::model::{
    Checkpoint, Counters, Coverage, EventRecord, MetricBucket, SourceIdentity, WriteBatch,
};
use kunato::console::{StorageConfig, Store};
use kunato::edr::{self, Evidence, FindingKind, Options, Window};

const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const HOURS: usize = 24;
const NOW: u64 = 1_700_000_040_000;
const BASE: u64 = NOW - HOURS as u64 * HOUR_MS;
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

fn source() -> SourceIdentity {
    SourceIdentity {
        instance: "edr-eval".into(),
        generation: "boot".into(),
    }
}

fn bucket(start_ms: u64, minute: &Minute, revision: u64) -> MetricBucket {
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

fn traffic() -> Vec<Minute> {
    let mut minutes = vec![Minute::default(); HOURS * 60];
    for minute in &mut minutes {
        minute.requests = 3;
    }

    for index in 0..5_u64 {
        let minute = ((index * 97 + 13) % (HOURS as u64 * 60)) as usize;
        minutes[minute].failure(&format!("10.0.0.{}", index + 1), "/login");
    }
    // A shared egress address with twelve failures spread over one hour. This
    // is the deliberate false-positive probe for the slow detector.
    for offset in [0, 4, 9, 15, 21, 27, 34, 40, 46, 52, 55, 58] {
        minutes[5 * 60 + offset].failure("198.51.100.10", "/login");
    }
    // A burst from one source stays below the slow span threshold.
    for offset in 10..18 {
        minutes[7 * 60 + offset].failure("10.0.0.9", "/login");
    }

    // A slower source (one failure every fifteen minutes) stays below the
    // one-hour slow threshold; the six-hour window is the sensitivity control.
    for hour in 2..9 {
        for offset in (0..60).step_by(15) {
            minutes[hour * 60 + offset].failure("203.0.113.8", "/login");
        }
    }

    // Slow attack: one failure every six minutes for six hours.
    for hour in 10..16 {
        for offset in (0..60).step_by(6) {
            minutes[hour * 60 + offset].failure(SLOW_SOURCE, "/login");
        }
    }

    // Reverse brute force: sixty sources, one failure each, in one hour.
    for index in 0..60 {
        minutes[18 * 60 + index].failure(&format!("192.0.2.{}", index + 1), "/login");
    }

    // A benign password-reset wave of twenty sources stays below the campaign
    // volume threshold.
    for index in 0..20 {
        minutes[21 * 60 + index].failure(&format!("198.18.0.{}", index + 1), "/login");
    }

    // One user retrying twenty times is a burst, not a slow or distributed
    // pattern.
    for offset in 0..20 {
        minutes[22 * 60 + offset].failure("10.0.0.10", "/login");
    }
    minutes
}

fn write_database(temp: &tempfile::TempDir) -> std::path::PathBuf {
    let mut config = StorageConfig::new(temp.path().join("history"));
    config.clock = || NOW;
    let mut store = Store::open(config).unwrap();
    let minutes = traffic();
    for hour in 0..HOURS {
        let sequence = (hour + 1) as u64;
        let metrics = (0..60)
            .map(|minute| {
                let minute = minute as usize;
                bucket(
                    BASE + hour as u64 * HOUR_MS + minute as u64 * MINUTE_MS,
                    &minutes[hour * 60 + minute],
                    sequence,
                )
            })
            .collect();
        store
            .write_batch(&WriteBatch {
                checkpoint: Checkpoint {
                    source: source(),
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

#[test]
fn hourly_analysis_finds_both_patterns_with_one_known_false_positive() {
    let temp = tempfile::tempdir().unwrap();
    let database = write_database(&temp);
    let mut slow_true = 0;
    let mut slow_false = 0;
    let mut reverse_true = 0;
    let mut reverse_false = 0;
    let mut first_slow_hour = None;
    let mut first_reverse_hour = None;
    println!("hour  expected        slow_findings                    reverse   false");
    for hour in 0..HOURS {
        let until = BASE + (hour as u64 + 1) * HOUR_MS;
        let report = edr::analyze(&Options {
            database: database.clone(),
            window: Window {
                from_ms: until - HOUR_MS,
                until_ms: until,
            },
            baseline: std::time::Duration::from_secs(24 * 3600),
            thresholds: edr::Thresholds::default(),
        })
        .unwrap();
        let slow_sources: Vec<String> = report
            .findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::SlowAuthentication)
            .filter_map(|finding| finding.source.map(|source| source.to_string()))
            .collect();
        let reverse = report
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::ReverseBruteForce);
        let slow_attack = (10..16).contains(&hour);
        let reverse_attack = hour == 18;
        let slow_hit = slow_sources.iter().any(|source| source == SLOW_SOURCE);
        if slow_attack && slow_hit {
            slow_true += 1;
            first_slow_hour.get_or_insert(hour);
        }
        if !slow_attack {
            slow_false += slow_sources.len();
        }
        if reverse_attack && reverse {
            reverse_true += 1;
            first_reverse_hour.get_or_insert(hour);
        }
        if !reverse_attack && reverse {
            reverse_false += 1;
        }
        println!(
            "{hour:02}    slow={:<5} reverse={:<5}  {:<32} {:<8} {}",
            slow_attack,
            reverse_attack,
            if slow_sources.is_empty() {
                "-".to_owned()
            } else {
                slow_sources.join(",")
            },
            reverse,
            report.telemetry.as_str()
        );
        for finding in &report.findings {
            match &finding.evidence {
                Evidence::SlowAuthentication(evidence) => println!(
                    "       slow {} failures={} active={} span={}m max/min={} cv={:?} z={:?}",
                    finding
                        .source
                        .map_or_else(|| "-".to_owned(), |source| source.to_string()),
                    evidence.failures,
                    evidence.active_buckets,
                    evidence.span_minutes,
                    evidence.max_failures_per_minute,
                    evidence.gap_cv,
                    evidence.baseline_z
                ),
                Evidence::ReverseBruteForce(evidence) => println!(
                    "       reverse failures={} sources={:.0} mean={:.2} share={:.2} z={:?}",
                    evidence.failures,
                    evidence.distinct_sources,
                    evidence.mean_failures_per_source,
                    evidence.top_path_share,
                    evidence.baseline_z
                ),
            }
        }
    }
    println!(
        "summary: slow true={slow_true} false={slow_false} first={first_slow_hour:?}; \
         reverse true={reverse_true} false={reverse_false} first={first_reverse_hour:?}"
    );
    assert_eq!(slow_true, 6);
    assert_eq!(reverse_true, 1);
    assert_eq!(reverse_false, 0);
    assert_eq!(first_slow_hour, Some(10));
    assert_eq!(first_reverse_hour, Some(18));
    assert!(
        slow_false <= 1,
        "expected at most the shared-egress probe as a false positive, got {slow_false}"
    );
}

#[test]
fn six_hour_window_catches_a_source_that_evades_the_one_hour_threshold() {
    let temp = tempfile::tempdir().unwrap();
    let database = write_database(&temp);
    let from = BASE + 2 * HOUR_MS;
    let until = BASE + 8 * HOUR_MS;
    let report = edr::analyze(&Options {
        database,
        window: Window {
            from_ms: from,
            until_ms: until,
        },
        baseline: std::time::Duration::from_secs(24 * 3600),
        thresholds: edr::Thresholds::default(),
    })
    .unwrap();
    let slow = report
        .findings
        .iter()
        .find(|finding| {
            finding.kind == FindingKind::SlowAuthentication
                && finding.source == Some("203.0.113.8".parse().unwrap())
        })
        .expect("six-hour slow finding");
    assert_eq!(slow.source, Some("203.0.113.8".parse().unwrap()));
    match &slow.evidence {
        Evidence::SlowAuthentication(evidence) => {
            assert_eq!(evidence.failures, 24);
            assert_eq!(evidence.active_buckets, 24);
            assert_eq!(evidence.max_failures_per_minute, 1);
        }
        _ => panic!("expected slow evidence"),
    }
}
