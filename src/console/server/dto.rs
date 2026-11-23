//! JSON encodings for the console HTTP API.

use serde_json::{Value, json};

use crate::config::Console;
use crate::console::HistoryPage;
use crate::console::correlations::CorrelationPage;
use crate::console::writer::WriterState;

use super::super::runtime::LiveState;

/// Bounded encoded history page size.
pub const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024;
/// Bounded encoded correlation page size.
pub const MAX_CORRELATION_BYTES: usize = 1024 * 1024;

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
