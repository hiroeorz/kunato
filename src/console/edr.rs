//! Bounded, read-only EDR state for the console UI.
//!
//! The live EDR task owns the detection state. This module turns the latest
//! hourly report and the persisted finding ring into one small JSON view: the
//! four detector lamps, the latest findings with their age and recurrence, and
//! the telemetry states that explain when a lamp cannot be evaluated.
//!
//! Country codes come from the console's GeoIP database at view-build time.
//! They describe geolocation, not the attacker's identity or location.

use std::net::IpAddr;

use serde::Serialize;

use crate::config::ConsoleEdr;
use crate::edr::live::{LiveEdr, StoredReport};
use crate::edr::{Evidence, FindingKind, Severity, Summary, TelemetryState, Window};
use crate::geoip::GeoIp;

/// The hourly report is published five minutes after the UTC hour ends.
pub const REPORT_DELAY_MS: u64 = 5 * 60 * 1000;
pub const VIEW_VERSION: u32 = 1;

/// The detector cards, in display order.
pub const DETECTOR_KINDS: [FindingKind; 4] = [
    FindingKind::SlowAuthentication,
    FindingKind::ReverseBruteForce,
    FindingKind::AuthSuccessAfterFailures,
    FindingKind::CampaignSuccess,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Disabled,
    Starting,
    Running,
    Failed,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorState {
    /// A finding is present in the latest evaluated window.
    Detected,
    /// The latest window was evaluated and no finding is present.
    Quiet,
    /// The detector could not be evaluated, or its telemetry is missing or
    /// incomplete. The UI must not render this as "clear".
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct EdrView {
    pub version: u32,
    pub enabled: bool,
    pub state: TaskState,
    pub error: Option<String>,
    pub schedule: ScheduleView,
    pub task: TaskView,
    pub telemetry: TelemetryView,
    pub detectors: Vec<DetectorView>,
    pub findings: Vec<FindingView>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScheduleView {
    pub window_ms: u64,
    pub baseline_ms: u64,
    pub report_delay_ms: u64,
    /// Wall-clock time when the latest report was recorded by the console.
    pub last_evaluated_at_ms: Option<u64>,
    /// Data window covered by that report.
    pub last_window: Option<Window>,
    pub next_evaluation_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskView {
    pub snapshots: u64,
    pub retained_minutes: usize,
    pub retained_hours: usize,
    pub baseline_warming_up: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetryView {
    pub failure: TelemetryState,
    pub success: TelemetryState,
    pub summary: Option<Summary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectorView {
    pub kind: FindingKind,
    pub state: DetectorState,
    pub count: u64,
    pub severity: Option<Severity>,
    pub last_detected_at_ms: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindingView {
    pub kind: FindingKind,
    pub severity: Severity,
    pub source: Option<IpAddr>,
    pub country: Option<String>,
    pub success_source: Option<IpAddr>,
    pub success_country: Option<String>,
    pub title: String,
    pub evidence: Evidence,
    pub recommendation: String,
    pub first_seen_ms: u64,
    pub episode_started_ms: u64,
    pub last_seen_ms: u64,
    pub observed_windows: u64,
    pub episodes: u64,
}

/// A view for a task that could not start (invalid configuration). The API
/// still returns a bounded payload so the page can explain the failure instead
/// of showing an empty or "clear" board.
pub fn failed(config: ConsoleEdr, error: &str) -> EdrView {
    EdrView {
        version: VIEW_VERSION,
        enabled: config.enabled,
        state: TaskState::Failed,
        error: Some(error.chars().take(512).collect()),
        schedule: ScheduleView {
            window_ms: millis(config.window),
            baseline_ms: millis(config.baseline),
            report_delay_ms: REPORT_DELAY_MS,
            last_evaluated_at_ms: None,
            last_window: None,
            next_evaluation_at_ms: None,
        },
        task: TaskView {
            snapshots: 0,
            retained_minutes: 0,
            retained_hours: 0,
            baseline_warming_up: true,
        },
        telemetry: TelemetryView {
            failure: TelemetryState::Missing,
            success: TelemetryState::Missing,
            summary: None,
        },
        detectors: DETECTOR_KINDS
            .iter()
            .map(|kind| DetectorView {
                kind: *kind,
                state: DetectorState::Unknown,
                count: 0,
                severity: None,
                last_detected_at_ms: None,
                reason: Some("The EDR task failed; checks are not running.".to_owned()),
            })
            .collect(),
        findings: Vec::new(),
        notes: Vec::new(),
    }
}

pub struct ViewInput<'a> {
    pub enabled: bool,
    pub state: TaskState,
    pub error: Option<&'a str>,
    pub config: ConsoleEdr,
    pub live: &'a LiveEdr,
    pub geoip: &'a GeoIp,
    pub next_evaluation_at_ms: Option<u64>,
}

pub fn build(input: ViewInput<'_>) -> EdrView {
    let stored = input.live.last_report();
    let last_report_at = input.live.last_report_at_ms();
    let (failure, success, summary, pinned) = match stored {
        Some(value) => (
            value.report.telemetry,
            value.report.success_telemetry,
            Some(value.report.summary.clone()),
            Some(value),
        ),
        None => (TelemetryState::Missing, TelemetryState::Missing, None, None),
    };
    let detectors = DETECTOR_KINDS
        .iter()
        .map(|kind| detector_view(*kind, input.enabled, input.state, stored, last_report_at))
        .collect();
    let findings = pinned
        .map(|value| finding_views(value, input.live, input.geoip))
        .unwrap_or_default();
    let notes = stored
        .map(|value| value.report.notes.clone())
        .unwrap_or_default();
    EdrView {
        version: VIEW_VERSION,
        enabled: input.enabled,
        state: input.state,
        error: input
            .error
            .map(|value| value.chars().take(512).collect::<String>()),
        schedule: ScheduleView {
            window_ms: millis(input.config.window),
            baseline_ms: millis(input.config.baseline),
            report_delay_ms: REPORT_DELAY_MS,
            last_evaluated_at_ms: (last_report_at != 0).then_some(last_report_at),
            last_window: stored.map(|value| value.report.window),
            next_evaluation_at_ms: input.next_evaluation_at_ms,
        },
        task: TaskView {
            snapshots: input.live.snapshots(),
            retained_minutes: input.live.retained_minutes(),
            retained_hours: input.live.retained_hours(),
            baseline_warming_up: input.live.baseline_warming_up(),
        },
        telemetry: TelemetryView {
            failure,
            success,
            summary,
        },
        detectors,
        findings,
        notes,
    }
}

fn detector_view(
    kind: FindingKind,
    enabled: bool,
    task: TaskState,
    stored: Option<&StoredReport>,
    last_report_at: u64,
) -> DetectorView {
    let count = stored
        .and_then(|value| value.counts.get(&kind).copied())
        .unwrap_or(0);
    let severity = stored.and_then(|value| value.severities.get(&kind).copied());
    let last_detected_at_ms = (count != 0).then_some(last_report_at);
    let (state, reason) = if !enabled {
        (
            DetectorState::Unknown,
            Some("EDR is disabled by console.edr.enabled: false.".to_owned()),
        )
    } else if task == TaskState::Failed {
        (
            DetectorState::Unknown,
            Some("The EDR task failed; checks are not running.".to_owned()),
        )
    } else if stored.is_none() {
        (
            DetectorState::Unknown,
            Some("No hourly evaluation has completed yet.".to_owned()),
        )
    } else if count != 0 {
        (DetectorState::Detected, None)
    } else {
        let telemetry = if success_kind(kind) {
            stored.map(|value| value.report.success_telemetry)
        } else {
            stored.map(|value| value.report.telemetry)
        };
        match telemetry {
            Some(TelemetryState::Present) => (DetectorState::Quiet, None),
            Some(TelemetryState::Partial) => (
                DetectorState::Unknown,
                Some(if success_kind(kind) {
                    "Authentication-success telemetry is incomplete; no finding is a lower bound."
                        .to_owned()
                } else {
                    "Authentication-failure telemetry is incomplete; no finding is a lower bound."
                        .to_owned()
                }),
            ),
            Some(TelemetryState::Missing) | None => (
                DetectorState::Unknown,
                Some(if success_kind(kind) {
                    "Authentication-success telemetry is missing or not configured; this detector cannot run."
                        .to_owned()
                } else {
                    "Authentication-failure telemetry is missing; this detector cannot run."
                        .to_owned()
                }),
            ),
        }
    };
    DetectorView {
        kind,
        state,
        count,
        severity,
        last_detected_at_ms,
        reason,
    }
}

fn success_kind(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::AuthSuccessAfterFailures | FindingKind::CampaignSuccess
    )
}

fn finding_views(stored: &StoredReport, live: &LiveEdr, geoip: &GeoIp) -> Vec<FindingView> {
    let history = live.finding_history();
    stored
        .report
        .findings
        .iter()
        .map(|finding| {
            let record = history
                .iter()
                .find(|record| record.kind == finding.kind && record.source == finding.source);
            let success_source = match &finding.evidence {
                Evidence::CampaignSuccess(evidence) => evidence.success_source,
                _ => None,
            };
            FindingView {
                kind: finding.kind,
                severity: finding.severity,
                source: finding.source,
                country: country(geoip, finding.source),
                success_source,
                success_country: country(geoip, success_source),
                title: finding.title.clone(),
                evidence: finding.evidence.clone(),
                recommendation: finding.recommendation.clone(),
                first_seen_ms: record.map_or(live.last_report_at_ms(), |value| value.first_seen_ms),
                episode_started_ms: record
                    .map_or(live.last_report_at_ms(), |value| value.episode_started_ms),
                last_seen_ms: record.map_or(live.last_report_at_ms(), |value| value.last_seen_ms),
                observed_windows: record.map_or(1, |value| value.observed_windows),
                episodes: record.map_or(1, |value| value.episodes),
            }
        })
        .collect()
}

fn country(geoip: &GeoIp, source: Option<IpAddr>) -> Option<String> {
    source
        .and_then(|address| geoip.lookup(address))
        .map(|code| code.as_str().to_owned())
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::live::LiveConfig;
    use crate::edr::{AuthSuccessEvidence, Finding, PathCount, Report};
    use std::time::Duration;

    fn config() -> ConsoleEdr {
        ConsoleEdr {
            enabled: true,
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(7 * 24 * 3600),
        }
    }

    fn geoip() -> std::sync::Arc<GeoIp> {
        // The embedded database is deterministic and available in tests. The
        // documentation addresses used below have no country mapping, so tests
        // assert the optional shape rather than a specific country.
        crate::geoip::GeoIp::embedded().expect("embedded GeoIP")
    }

    fn report(until: u64, findings: Vec<Finding>) -> Report {
        Report {
            generated_at_ms: until,
            database: "live-memory".into(),
            site: None,
            window: Window {
                from_ms: until - 3600 * 1000,
                until_ms: until,
            },
            telemetry: TelemetryState::Present,
            success_telemetry: TelemetryState::Present,
            summary: Summary {
                buckets: 60,
                minutes_covered: 60,
                incomplete: false,
                coarse: false,
                requests: 100,
                auth_failures: 10,
                auth_successes: 1,
                distinct_auth_sources: Some(2),
                status_401: 10,
                status_403: 0,
                auth_paths: vec![PathCount {
                    path: "/login".into(),
                    count: 10,
                }],
                baseline_hours: 24,
            },
            findings,
            notes: vec!["note".into()],
        }
    }

    fn success_finding(source: &str) -> Finding {
        Finding {
            kind: FindingKind::AuthSuccessAfterFailures,
            severity: Severity::High,
            source: Some(source.parse().expect("IP")),
            title: "authentication success after sustained failures".into(),
            evidence: Evidence::AuthSuccessAfterFailures(AuthSuccessEvidence {
                failures: 8,
                active_buckets: 8,
                first_failure_ms: 1_000,
                last_failure_ms: 2_000,
                success_ms: 3_000,
                successes: 1,
                total_failures: 8,
            }),
            recommendation: "review".into(),
        }
    }

    #[test]
    fn lamps_are_unknown_until_a_report_exists() {
        let live = LiveEdr::new(LiveConfig {
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(3600),
            poll_interval: Duration::from_secs(1),
            ring: Duration::from_secs(720),
            thresholds: Default::default(),
        })
        .expect("live state");
        let geoip = geoip();
        let view = build(ViewInput {
            enabled: true,
            state: TaskState::Starting,
            error: None,
            config: config(),
            live: &live,
            geoip: &geoip,
            next_evaluation_at_ms: Some(10_000),
        });
        assert_eq!(view.findings.len(), 0);
        assert!(
            view.detectors
                .iter()
                .all(|d| d.state == DetectorState::Unknown)
        );
        assert_eq!(view.schedule.last_evaluated_at_ms, None);
    }

    #[test]
    fn detected_and_quiet_lamps_follow_the_latest_report() {
        let mut live = LiveEdr::new(LiveConfig {
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(3600),
            poll_interval: Duration::from_secs(1),
            ring: Duration::from_secs(720),
            thresholds: Default::default(),
        })
        .expect("live state");
        live.record_report(
            report(1_700_000_000_000, vec![success_finding("203.0.113.7")]),
            1_700_000_300_000,
        );
        let geoip = geoip();
        let view = build(ViewInput {
            enabled: true,
            state: TaskState::Running,
            error: None,
            config: config(),
            live: &live,
            geoip: &geoip,
            next_evaluation_at_ms: Some(1_700_003_900_000),
        });
        let success = view
            .detectors
            .iter()
            .find(|detector| detector.kind == FindingKind::AuthSuccessAfterFailures)
            .expect("success detector");
        assert_eq!(success.state, DetectorState::Detected);
        assert_eq!(success.count, 1);
        assert_eq!(success.severity, Some(Severity::High));
        let slow = view
            .detectors
            .iter()
            .find(|detector| detector.kind == FindingKind::SlowAuthentication)
            .expect("slow detector");
        assert_eq!(slow.state, DetectorState::Quiet);
        assert_eq!(view.findings.len(), 1);
        assert_eq!(view.findings[0].observed_windows, 1);
        assert_eq!(view.findings[0].episodes, 1);
    }

    #[test]
    fn missing_success_telemetry_makes_only_success_lamps_unknown() {
        let mut live = LiveEdr::new(LiveConfig {
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(3600),
            poll_interval: Duration::from_secs(1),
            ring: Duration::from_secs(720),
            thresholds: Default::default(),
        })
        .expect("live state");
        let mut value = report(1_700_000_000_000, Vec::new());
        value.success_telemetry = TelemetryState::Missing;
        live.record_report(value, 1_700_000_300_000);
        let geoip = geoip();
        let view = build(ViewInput {
            enabled: true,
            state: TaskState::Running,
            error: None,
            config: config(),
            live: &live,
            geoip: &geoip,
            next_evaluation_at_ms: Some(1_700_003_900_000),
        });
        for detector in &view.detectors {
            let expected = if success_kind(detector.kind) {
                DetectorState::Unknown
            } else {
                DetectorState::Quiet
            };
            assert_eq!(detector.state, expected, "{:?}", detector.kind);
        }
    }

    #[test]
    fn disabled_edr_marks_every_lamp_unknown() {
        let live = LiveEdr::new(LiveConfig {
            window: Duration::from_secs(3600),
            baseline: Duration::from_secs(3600),
            poll_interval: Duration::from_secs(1),
            ring: Duration::from_secs(720),
            thresholds: Default::default(),
        })
        .expect("live state");
        let geoip = geoip();
        let view = build(ViewInput {
            enabled: false,
            state: TaskState::Disabled,
            error: None,
            config: ConsoleEdr {
                enabled: false,
                window: Duration::from_secs(3600),
                baseline: Duration::from_secs(3600),
            },
            live: &live,
            geoip: &geoip,
            next_evaluation_at_ms: None,
        });
        assert!(!view.enabled);
        assert!(
            view.detectors
                .iter()
                .all(|d| d.state == DetectorState::Unknown)
        );
    }
}
