//! JSON encodings for the console HTTP API.

use serde_json::{Value, json};

use crate::config::Console;
use crate::console::HistoryPage;
use crate::console::asn::AsnLookup;
use crate::console::correlations::CorrelationPage;
use crate::console::edr::{EdrView, REPORT_DELAY_MS};
use crate::console::writer::WriterState;

use super::super::runtime::LiveState;

/// Bounded encoded history page size.
pub const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024;
/// Bounded encoded correlation page size.
pub const MAX_CORRELATION_BYTES: usize = 1024 * 1024;
/// Bound for the EDR view. The view itself caps findings and notes; this is the
/// outer response guard.
pub const MAX_EDR_BYTES: usize = 1024 * 1024;
/// Bound for the IP-information response. It carries only the ASN record.
pub const MAX_IP_INFO_BYTES: usize = 4 * 1024;
const ASN_STALE_MS: u64 = 45 * 24 * 60 * 60 * 1000;

pub fn health(
    console: &Console,
    state: Option<&LiveState>,
    now_ms: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    let collection = state.map(|state| collection_json(&state.health));
    let writer = state
        .and_then(|state| state.health.writer.as_ref())
        .map(writer_json);
    serde_json::to_vec(&json!({
        "version": 1,
        "now_ms": now_ms,
        "console": {
            "listen": console.listen.to_string(),
            "source": console.source.to_string(),
            "instance": console.instance,
            "tls": console.tls_enabled(),
            "auth": console.auth_enabled(),
            "remote": console.is_remote(),
        },
        "collection": collection,
        "writer": writer,
    }))
}

/// One immutable state object for an SSE frame.
pub fn state(
    console: &Console,
    state: &LiveState,
    replayed: bool,
    generation_changed: bool,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "version": 1,
        "console": {"instance": console.instance},
        "replayed": replayed,
        "generation_changed": generation_changed,
        "snapshot": state.snapshot,
        "collection": collection_json(&state.health),
        "writer": state.health.writer.as_ref().map(writer_json),
    }))
}

/// Encode the read-only EDR view. Disabled EDR still returns its schedule so the
/// page can explain why no lamp can be evaluated.
pub fn edr(
    console: &Console,
    view: Option<&EdrView>,
    now_ms: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    let config = json!({
        "window_ms": millis(console.edr.window),
        "baseline_ms": millis(console.edr.baseline),
        "report_delay_ms": REPORT_DELAY_MS,
    });
    let stale = view.is_some_and(|value| edr_stale(value, now_ms));
    let value = if !console.edr.enabled {
        json!({
            "version": 1,
            "now_ms": now_ms,
            "enabled": false,
            "stale": false,
            "config": config,
            "view": null,
        })
    } else {
        json!({
            "version": 1,
            "now_ms": now_ms,
            "enabled": true,
            "stale": stale,
            "config": config,
            "view": view,
        })
    };
    serde_json::to_vec(&value)
}

const HOUR_MS: u64 = 60 * 60 * 1000;
const STALE_GRACE_MS: u64 = 15 * 60 * 1000;

/// Encode the ASN record for one source address. The embedded or external
/// database never leaves the process; only the bounded result is returned.
pub fn ip_info(
    address: std::net::IpAddr,
    lookup: &AsnLookup,
    now_ms: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    let stale = lookup
        .built_at_ms
        .is_some_and(|built| now_ms.saturating_sub(built) > ASN_STALE_MS);
    serde_json::to_vec(&json!({
        "version": 1,
        "now_ms": now_ms,
        "ip": address.to_string(),
        "state": lookup.state,
        "asn": lookup.asn,
        "organization": lookup.organization,
        "database": lookup.database,
        "source": lookup.source,
        "built_at_ms": lookup.built_at_ms,
        "stale": stale,
    }))
}

/// The window end that should have been reported at `now_ms`. Reports run five
/// minutes after each UTC hour, so before :05 the expected end is the previous
/// hour end.
fn expected_report_window_end(now_ms: u64) -> u64 {
    let hour_end = now_ms / HOUR_MS * HOUR_MS;
    if now_ms >= hour_end.saturating_add(REPORT_DELAY_MS) {
        hour_end
    } else {
        hour_end.saturating_sub(HOUR_MS)
    }
}

/// Whether the view no longer describes the window the operator expects. This
/// is true when the task missed an evaluation or a restored report is older
/// than the expected hourly window.
fn edr_stale(view: &EdrView, now_ms: u64) -> bool {
    let schedule = &view.schedule;
    let Some(last) = schedule.last_evaluated_at_ms else {
        return false;
    };
    let Some(window) = schedule.last_window else {
        return true;
    };
    let age_limit = schedule
        .window_ms
        .saturating_add(schedule.report_delay_ms)
        .saturating_add(STALE_GRACE_MS);
    now_ms > last.saturating_add(age_limit)
        || window.until_ms < expected_report_window_end(now_ms.saturating_sub(STALE_GRACE_MS))
        || schedule
            .next_evaluation_at_ms
            .is_some_and(|next| now_ms > next.saturating_add(STALE_GRACE_MS))
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn collection_json(health: &crate::console::collector::CollectorHealth) -> Value {
    json!({
        "connected": health.source_connected,
        "received_snapshots": health.received_snapshots,
        "stale_snapshots": health.stale_snapshots,
        "last_observed_at_ms": health.last_observed_at_ms,
        "last_committed_at_ms": health.last_committed_at_ms,
        "persistence_lag_ms": health.persistence_lag_ms,
        "pending_minutes": health.pending_minutes,
        "pending_events": health.pending_events,
        "pending_event_bytes": health.pending_event_bytes,
        "unconfirmed_metric_batches": health.unconfirmed_metric_batches,
        "unconfirmed_event_batches": health.unconfirmed_event_batches,
        "omitted_metric_minutes": health.omitted_metric_minutes,
        "omitted_events": health.omitted_events,
        "source_missed_updates": health.source_missed_updates,
        "source_additional_missed_updates": health.source_additional_missed_updates,
        "source_omitted_events": health.source_omitted_events,
        "source_gap": health.source_gap.map(|(start, end)| json!([start, end])),
        "source_error": health.source_error.as_ref().map(ToString::to_string),
        "storage_error": health.storage_error.as_ref().map(ToString::to_string),
        "batch_error": health.batch_error.as_ref().map(ToString::to_string),
        "checkpoint_error": health.checkpoint_error.as_ref().map(ToString::to_string),
    })
}

fn writer_json(health: &crate::console::Health) -> Value {
    json!({
        "state": match health.state {
            WriterState::Starting => "starting",
            WriterState::Running => "running",
            WriterState::Stopping => "stopping",
            WriterState::Stopped => "stopped",
            WriterState::Failed => "failed",
            WriterState::AtCapacity => "at_capacity",
        },
        "queued_items": health.queued_items,
        "in_flight_items": health.in_flight_items,
        "outstanding_bytes": health.outstanding_bytes,
        "accepted_batches": health.accepted_batches,
        "rejected_batches": health.rejected_batches,
        "committed_batches": health.committed_batches,
        "replayed_batches": health.replayed_batches,
        "failed_batches": health.failed_batches,
        "oldest_pending_ms": health.oldest_pending_ms,
        "last_persisted_at_ms": health.last_persisted_at_ms,
        "last_error": health.last_error.as_ref().map(ToString::to_string),
    })
}

/// Encode a history page, dropping whole trailing buckets when the page would
/// exceed the response budget. The response reports the cut and the next start.
pub fn history(
    page: &HistoryPage,
    instance: &str,
    from_ms: u64,
    until_ms: u64,
) -> Result<(Vec<u8>, usize, bool), serde_json::Error> {
    let mut encoded = Vec::new();
    let mut total = 0usize;
    let mut truncated = false;
    let mut next_start_ms = page.next_start_ms;
    for (index, bucket) in page.buckets.iter().enumerate() {
        let bytes = serde_json::to_vec(bucket)?;
        let needed = bytes.len() + usize::from(index != 0);
        let over = total + needed > MAX_HISTORY_BYTES;
        if over && !encoded.is_empty() {
            truncated = true;
            next_start_ms = Some(bucket.start_ms);
            break;
        }
        total += needed;
        encoded.push(bytes);
    }
    let head = json!({
        "version": 1,
        "instance": instance,
        "from_ms": from_ms,
        "until_ms": until_ms,
        "expiry_ms": page.expiry_ms,
        "oldest_available_ms": page.oldest_available_ms,
        "pending_minutes": page.pending_minutes,
        "revision": page.revision,
        "returned": encoded.len(),
        "truncated": truncated,
    });
    let mut text = serde_json::to_vec(&head)?;
    text.pop();
    text.extend_from_slice(b",\"next_start_ms\":");
    text.extend_from_slice(
        serde_json::to_string(&next_start_ms)
            .unwrap_or_else(|_| "null".to_owned())
            .as_bytes(),
    );
    text.extend_from_slice(b",\"buckets\":[");
    for (index, bucket) in encoded.iter().enumerate() {
        if index != 0 {
            text.push(b',');
        }
        text.extend_from_slice(bucket);
    }
    text.extend_from_slice(b"]}");
    Ok((text, encoded.len(), truncated))
}

pub fn correlations(page: &CorrelationPage) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "version": 1,
        "expiry_ms": page.expiry_ms,
        "evicted_records": page.evicted_records,
        "has_more": page.has_more,
        "records": page.records,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::history::{Grain, HistoryBucket};

    #[test]
    fn ip_info_marks_stale_asn_data() {
        let lookup = crate::console::asn::AsnLookup {
            state: crate::console::asn::AsnState::Ok,
            asn: Some(15169),
            organization: Some("Google LLC".to_owned()),
            database: Some("DB-IP ASN Lite".to_owned()),
            source: Some("embedded"),
            built_at_ms: Some(1_000),
        };
        let json = ip_info(
            "8.8.8.8".parse().expect("ip"),
            &lookup,
            1_000 + ASN_STALE_MS + 1,
        )
        .expect("encode");
        let value: Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(value["stale"], true);
        assert_eq!(value["asn"], 15169);
        assert_eq!(value["state"], "ok");
    }

    #[test]
    fn expected_report_window_end_follows_the_five_minute_delay() {
        let hour = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
        assert_eq!(expected_report_window_end(hour), hour - HOUR_MS);
        assert_eq!(
            expected_report_window_end(hour + 4 * 60 * 1000),
            hour - HOUR_MS
        );
        assert_eq!(expected_report_window_end(hour + 5 * 60 * 1000), hour);
        assert_eq!(expected_report_window_end(hour + 59 * 60 * 1000), hour);
    }

    #[test]
    fn stale_view_detection_uses_the_last_window_and_next_evaluation() {
        let config = crate::config::parse(
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nconsole: { enabled: true, listen: 127.0.0.1:0, source: 127.0.0.1:9090, edr: { enabled: true } }\n",
        )
        .expect("config");
        let hour = 1_700_000_000_000 / HOUR_MS * HOUR_MS;
        let mut view = crate::console::edr::failed(config.console.edr, "test");
        assert!(!edr_stale(&view, hour));
        view.state = crate::console::edr::TaskState::Running;
        view.schedule.last_evaluated_at_ms = Some(hour + 5 * 60 * 1000);
        view.schedule.last_window = Some(crate::edr::Window {
            from_ms: hour - HOUR_MS,
            until_ms: hour,
        });
        view.schedule.next_evaluation_at_ms = Some(hour + HOUR_MS + 5 * 60 * 1000);
        assert!(!edr_stale(&view, hour + 20 * 60 * 1000));
        // A report at :05 is not instantly stale while the task is running.
        assert!(!edr_stale(&view, hour + 5 * 60 * 1000 + 30_000));
        // The next report was missed.
        assert!(edr_stale(&view, hour + HOUR_MS + 20 * 60 * 1000));
        // A restored report from before the expected window is stale even
        // while the next evaluation is still in the future.
        view.schedule.last_window = Some(crate::edr::Window {
            from_ms: hour - 2 * HOUR_MS,
            until_ms: hour - HOUR_MS,
        });
        view.schedule.last_evaluated_at_ms = Some(hour - HOUR_MS + 5 * 60 * 1000);
        assert!(edr_stale(&view, hour + 20 * 60 * 1000));
    }

    #[test]
    fn edr_disabled_response_includes_the_schedule_without_a_view() {
        let config = crate::config::parse(
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nconsole: { enabled: true, listen: 127.0.0.1:0, source: 127.0.0.1:9090 }\n",
        )
        .expect("config");
        let bytes = edr(&config.console, None, 1234).expect("encode");
        let value: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(value["version"], 1);
        assert_eq!(value["enabled"], false);
        assert_eq!(value["view"], Value::Null);
        assert_eq!(value["now_ms"], 1234);
        assert!(value["config"]["window_ms"].as_u64().expect("window") > 0);
        assert!(value["config"]["baseline_ms"].as_u64().expect("baseline") > 0);
    }

    #[test]
    fn edr_view_encoding_keeps_the_failed_state_and_bounded_shape() {
        let config = crate::config::parse(
            "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\nconsole: { enabled: true, listen: 127.0.0.1:0, source: 127.0.0.1:9090, edr: { enabled: true } }\n",
        )
        .expect("config");
        let view = crate::console::edr::failed(config.console.edr, "test failure");
        let bytes = edr(&config.console, Some(&view), 99).expect("encode");
        assert!(bytes.len() <= MAX_EDR_BYTES);
        let value: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["now_ms"], 99);
        assert_eq!(value["view"]["state"], "failed");
        assert_eq!(value["view"]["error"], "test failure");
        assert_eq!(value["view"]["detectors"].as_array().map(Vec::len), Some(4));
        assert_eq!(value["view"]["findings"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn history_encoding_is_bounded_and_reports_the_cut() {
        let bucket = HistoryBucket::empty(0, Grain::Minute);
        let page = HistoryPage {
            buckets: vec![bucket.clone(), bucket.clone(), bucket],
            expiry_ms: 1000,
            oldest_available_ms: Some(0),
            next_start_ms: Some(180_000),
            pending_minutes: 1,
            revision: 7,
        };
        let (json, returned, truncated) = history(&page, "local-waf", 0, 180_000).expect("encode");
        assert_eq!(returned, 3);
        assert!(!truncated);
        let value: Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(value["revision"], 7);
        assert_eq!(value["buckets"].as_array().map(Vec::len), Some(3));
        assert_eq!(value["next_start_ms"], 180_000);
    }
}
