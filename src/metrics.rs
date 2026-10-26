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
    pub request_body_rejected: AtomicU64,
    pub upload_rejected: AtomicU64,
    pub form_rejected: AtomicU64,
    pub php_request_rejected: AtomicU64,
    pub php_response_rejected: AtomicU64,
    pub host_rejected: AtomicU64,
    pub response_decode_truncated: AtomicU64,
    pub request_decode_truncated: AtomicU64,
    pub response_decode_skipped: AtomicU64,
    pub request_decode_skipped: AtomicU64,
    pub rate_limited: AtomicU64,
    pub rule_limited: AtomicU64,
    pub graphql_rejected: AtomicU64,
    pub banned: AtomicU64,
    pub behavior_not_found: AtomicU64,
    pub behavior_auth_failures: AtomicU64,
    pub behavior_enumeration_flags: AtomicU64,
    pub behavior_auth_flags: AtomicU64,
    pub behavior_global_auth_flags: AtomicU64,
    pub behavior_scraping_flags: AtomicU64,
    pub behavior_blocked: AtomicU64,
    pub overloaded: AtomicU64,
    pub upstream_connect_errors: AtomicU64,
    pub upstream_timeouts: AtomicU64,
    pub reload_success: AtomicU64,
    pub reload_failure: AtomicU64,
    pub rules_update_success: AtomicU64,
    pub rules_update_failure: AtomicU64,
    pub rules_update_incompatible: AtomicU64,
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
            request_body_rejected: AtomicU64::new(0),
            upload_rejected: AtomicU64::new(0),
            form_rejected: AtomicU64::new(0),
            php_request_rejected: AtomicU64::new(0),
            php_response_rejected: AtomicU64::new(0),
            host_rejected: AtomicU64::new(0),
            response_decode_truncated: AtomicU64::new(0),
            request_decode_truncated: AtomicU64::new(0),
            response_decode_skipped: AtomicU64::new(0),
            request_decode_skipped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            rule_limited: AtomicU64::new(0),
            graphql_rejected: AtomicU64::new(0),
            banned: AtomicU64::new(0),
            behavior_not_found: AtomicU64::new(0),
            behavior_auth_failures: AtomicU64::new(0),
            behavior_enumeration_flags: AtomicU64::new(0),
            behavior_auth_flags: AtomicU64::new(0),
            behavior_global_auth_flags: AtomicU64::new(0),
            behavior_scraping_flags: AtomicU64::new(0),
            behavior_blocked: AtomicU64::new(0),
            overloaded: AtomicU64::new(0),
            upstream_connect_errors: AtomicU64::new(0),
            upstream_timeouts: AtomicU64::new(0),
            reload_success: AtomicU64::new(0),
            reload_failure: AtomicU64::new(0),
            rules_update_success: AtomicU64::new(0),
            rules_update_failure: AtomicU64::new(0),
            rules_update_incompatible: AtomicU64::new(0),
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
        for (name, help, count) in [
            (
                "kunato_form_rejected_total",
                "Requests rejected by form structure limits.",
                &self.form_rejected,
            ),
            (
                "kunato_php_request_rejected_total",
                "Requests rejected by the PHP profile.",
                &self.php_request_rejected,
            ),
            (
                "kunato_php_response_rejected_total",
                "Responses rejected by PHP session cookie validation.",
                &self.php_response_rejected,
            ),
        ] {
            counter(&mut out, name, help, count.load(Ordering::Relaxed));
        }

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
            "Request bodies that exceeded the inspection limit.",
            self.request_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_request_body_rejected_total",
            "Request bodies rejected because they exceeded the inspection limit.",
            self.request_body_rejected.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_upload_rejected_total",
            "Multipart uploads rejected because their content is executable, script, or active markup.",
            self.upload_rejected.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_host_rejected_total",
            "Requests rejected by the Host/authority allowlist (missing, malformed, duplicate, or unlisted).",
            self.host_rejected.load(Ordering::Relaxed),
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
            "Decompressed request bodies that exceeded the inspection limit; the request was rejected.",
            self.request_decode_truncated.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_response_decode_skipped_total",
            "Response bodies with an encoding that could not be decoded for inspection.",
            self.response_decode_skipped.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_request_decode_skipped_total",
            "Request bodies with an encoding that could not be inspected; the request was rejected.",
            self.request_decode_skipped.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_rate_limited_total",
            "Requests rejected by the per-IP rate limiter, including inspection cost.",
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
            "kunato_graphql_rejected_total",
            "GraphQL requests rejected by the depth and field guard.",
            self.graphql_rejected.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_banned_total",
            "Requests rejected because the client is banned.",
            self.banned.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_not_found_total",
            "404 responses on non-static paths observed for behavioral detection.",
            self.behavior_not_found.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_auth_failures_total",
            "401/403 responses on authentication paths observed for behavioral detection.",
            self.behavior_auth_failures.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_enumeration_flags_total",
            "Sources flagged for enumeration (transitions, not every observation).",
            self.behavior_enumeration_flags.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_auth_flags_total",
            "Sources flagged for authentication abuse (transitions, not every observation).",
            self.behavior_auth_flags.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_global_auth_flags_total",
            "Global authentication-abuse windows flagged.",
            self.behavior_global_auth_flags.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_scraping_flags_total",
            "Sources flagged for 200-only scraping (transitions, not every observation).",
            self.behavior_scraping_flags.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_behavior_blocked_total",
            "Behavioral flags that applied a ban.",
            self.behavior_blocked.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "kunato_overloaded_total",
            "Requests shed by the global rate guard or the inspection budget.",
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
            "kunato_rules_update_incompatible_total",
            "Rules updates rejected because the published rule set needs a newer build.",
            self.rules_update_incompatible.load(Ordering::Relaxed),
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
        metrics
            .rules_update_incompatible
            .fetch_add(1, Ordering::Relaxed);

        let text = metrics.render(3);

        assert!(text.contains("# TYPE kunato_requests_total counter"));
        assert!(text.contains("kunato_requests_total 2"));
        assert!(text.contains("kunato_blocked_total 1"));
        assert!(text.contains("kunato_acme_issued_total 1"));
        assert!(text.contains("kunato_acme_last_success_timestamp_seconds 0"));
        assert!(text.contains("kunato_rules_update_incompatible_total 1"));
        assert!(text.contains("kunato_graphql_rejected_total 0"));
        assert!(text.contains("kunato_request_body_rejected_total 0"));
        assert!(text.contains("kunato_upload_rejected_total 0"));
        assert!(text.contains("kunato_host_rejected_total 0"));
        assert!(text.contains("kunato_behavior_not_found_total 0"));
        assert!(text.contains("kunato_behavior_auth_failures_total 0"));
        assert!(text.contains("kunato_behavior_enumeration_flags_total 0"));
        assert!(text.contains("kunato_behavior_auth_flags_total 0"));
        assert!(text.contains("kunato_behavior_scraping_flags_total 0"));
        assert!(text.contains("kunato_behavior_global_auth_flags_total 0"));
        assert!(text.contains("kunato_behavior_blocked_total 0"));
        assert!(text.contains("# TYPE kunato_active_connections gauge"));
        assert!(text.contains("kunato_active_connections 3"));
        assert!(text.contains("kunato_uptime_seconds"));
    }
}
