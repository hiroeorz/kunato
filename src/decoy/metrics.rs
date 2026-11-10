use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub responses: [AtomicU64; 3],
    pub issued: AtomicU64,
    pub reuse: [AtomicU64; 2],
    pub blocked: AtomicU64,
    pub limited: [AtomicU64; 5],
    pub incomplete: [AtomicU64; 7],
    pub invalid: [AtomicU64; 4],
    pub errors: AtomicU64,
    pub suppressed: [AtomicU64; 3],
}

pub(super) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl Metrics {
    pub(crate) fn render(&self, out: &mut String) {
        for (name, label, values, counters) in [
            (
                "responses",
                "kind",
                &["trap", "sink", "fallback"][..],
                &self.responses[..],
            ),
            (
                "reuse",
                "context",
                &["credential", "occurrence"][..],
                &self.reuse[..],
            ),
            (
                "limited",
                "reason",
                &[
                    "global-issuance",
                    "source-issuance",
                    "tracking",
                    "verification",
                    "inspection",
                ][..],
                &self.limited[..],
            ),
            (
                "scan_incomplete",
                "reason",
                &[
                    "bytes",
                    "candidates",
                    "body-prefix",
                    "encoding",
                    "verification",
                    "ambiguous",
                    "inspection",
                ][..],
                &self.incomplete[..],
            ),
            (
                "invalid_tokens",
                "reason",
                &["syntax", "mac", "expired", "scope"][..],
                &self.invalid[..],
            ),
            (
                "logs_suppressed",
                "event",
                &["issued", "reuse", "error"][..],
                &self.suppressed[..],
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP kunato_decoy_{name}_total Bounded decoy {name} events.\n# TYPE kunato_decoy_{name}_total counter"
            );
            for (value, count) in values.iter().zip(counters) {
                let _ = writeln!(
                    out,
                    "kunato_decoy_{name}_total{{{label}=\"{value}\"}} {}",
                    count.load(Ordering::Relaxed)
                );
            }
        }
        for (name, count) in [
            ("tokens_issued", &self.issued),
            ("blocked", &self.blocked),
            ("token_errors", &self.errors),
        ] {
            let _ = writeln!(
                out,
                "# HELP kunato_decoy_{name}_total Bounded decoy {name} events.\n# TYPE kunato_decoy_{name}_total counter\nkunato_decoy_{name}_total {}",
                count.load(Ordering::Relaxed)
            );
        }
    }
}
