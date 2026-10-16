use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub logged: AtomicU64,
    pub response_blocked: AtomicU64,
    pub response_logged: AtomicU64,
    pub response_truncated: AtomicU64,
    pub request_truncated: AtomicU64,
    pub response_decode_truncated: AtomicU64,
    pub request_decode_truncated: AtomicU64,
    pub rate_limited: AtomicU64,
    pub rule_limited: AtomicU64,
    pub banned: AtomicU64,
    pub overloaded: AtomicU64,
    pub upstream_connect_errors: AtomicU64,
    pub upstream_timeouts: AtomicU64,
    pub reload_success: AtomicU64,
    pub reload_failure: AtomicU64,
    pub rules_update_success: AtomicU64,
    pub rules_update_failure: AtomicU64,
    pub rules_update_not_modified: AtomicU64,
    pub rules_last_success: AtomicU64,
    pub acme_issued: AtomicU64,
    pub acme_cached: AtomicU64,
    pub acme_errors: AtomicU64,
    pub acme_last_success: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            logged: AtomicU64::new(0),
            response_blocked: AtomicU64::new(0),
            response_logged: AtomicU64::new(0),
            response_truncated: AtomicU64::new(0),
            request_truncated: AtomicU64::new(0),
            response_decode_truncated: AtomicU64::new(0),
            request_decode_truncated: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            rule_limited: AtomicU64::new(0),
            banned: AtomicU64::new(0),
            overloaded: AtomicU64::new(0),
            upstream_connect_errors: AtomicU64::new(0),
            upstream_timeouts: AtomicU64::new(0),
            reload_success: AtomicU64::new(0),
            reload_failure: AtomicU64::new(0),
            rules_update_success: AtomicU64::new(0),
            rules_update_failure: AtomicU64::new(0),
            rules_update_not_modified: AtomicU64::new(0),
            rules_last_success: AtomicU64::new(0),
            acme_issued: AtomicU64::new(0),
            acme_cached: AtomicU64::new(0),
            acme_errors: AtomicU64::new(0),
            acme_last_success: AtomicU64::new(0),
        }
    }

    pub fn render(&self, active_connections: u64) -> String {
        let mut out = String::with_capacity(1024);

        counter(
            &mut out,
            "kunato_requests_total",
            "Total HTTP requests handled.",
            self.requests.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_blocked_total",
            "Requests rejected by BLOCK rules.",
            self.blocked.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_logged_total",
            "Requests with at least one LOG rule match.",
            self.logged.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_response_blocked_total",
            "Upstream responses replaced by BLOCK rules.",
            self.response_blocked.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_response_logged_total",
            "Responses with at least one LOG rule match.",
            self.response_logged.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_response_truncated_total",
            "Response bodies truncated for inspection.",
            self.response_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_request_truncated_total",
            "Request bodies truncated for inspection; the remainder was streamed.",
            self.request_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_response_decode_truncated_total",
            "Decompressed response bodies truncated for inspection.",
            self.response_decode_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_request_decode_truncated_total",
            "Decompressed request bodies truncated for inspection.",
            self.request_decode_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rate_limited_total",
            "Requests rejected by the per-IP rate limiter.",
            self.rate_limited.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rule_limited_total",
            "Requests blocked by a rule's own rate limit.",
            self.rule_limited.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_banned_total",
            "Requests rejected because the client is banned.",
            self.banned.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_overloaded_total",
            "Requests shed by the global rate guard.",
            self.overloaded.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_upstream_connect_errors_total",
            "Upstream connection failures.",
            self.upstream_connect_errors.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_upstream_timeouts_total",
            "Upstream response timeouts.",
            self.upstream_timeouts.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_reload_success_total",
            "Successful configuration reloads.",
            self.reload_success.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_reload_failure_total",
            "Failed configuration reloads.",
            self.reload_failure.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rules_update_success_total",
            "Rules files downloaded and applied.",
            self.rules_update_success.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rules_update_failure_total",
            "Failed rules file updates.",
            self.rules_update_failure.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rules_update_not_modified_total",
            "Rules update checks that found no new version.",
            self.rules_update_not_modified.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "kunato_rules_last_success_timestamp_seconds",
            "Unix time of the last successful rules update check.",
            self.rules_last_success.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_acme_issued_total",
            "Certificates issued through ACME.",
            self.acme_issued.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_acme_cached_total",
            "ACME certificates loaded from the cache.",
            self.acme_cached.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_acme_errors_total",
            "ACME certificate acquisition and renewal errors.",
            self.acme_errors.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "kunato_acme_last_success_timestamp_seconds",
            "Unix time of the last deployed ACME certificate.",
            self.acme_last_success.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "kunato_active_connections",
            "Active client connections.",
            active_connections,
        );
        gauge(
            &mut out,
            "kunato_uptime_seconds",
            "Process uptime in seconds.",
            self.started.elapsed().as_secs(),
        );

        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let metrics = Metrics::new();
        metrics.requests.fetch_add(2, Ordering::Relaxed);
        metrics.blocked.fetch_add(1, Ordering::Relaxed);
        metrics.acme_issued.fetch_add(1, Ordering::Relaxed);

        let text = metrics.render(3);

        assert!(text.contains("# TYPE kunato_requests_total counter"));
        assert!(text.contains("kunato_requests_total 2"));
        assert!(text.contains("kunato_blocked_total 1"));
        assert!(text.contains("kunato_acme_issued_total 1"));
        assert!(text.contains("kunato_acme_last_success_timestamp_seconds 0"));
        assert!(text.contains("# TYPE kunato_active_connections gauge"));
        assert!(text.contains("kunato_active_connections 3"));
        assert!(text.contains("kunato_uptime_seconds"));
    }
}
