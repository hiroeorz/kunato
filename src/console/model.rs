//! Version-one observation contracts. Missing measurements remain `None`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::Error;

pub const MINUTE_MS: u64 = 60_000;
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_BATCH_RECORDS: usize = 256;
pub const LATENCY_BOUNDS_US: [u64; 14] = [
    1000, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 2500000, 5000000, 10000000,
    30000000, 60000000,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum RejectionReason {
    Rule,
    ResponseRule,
    RateLimit,
    Ban,
    Overload,
    ClientIdentity,
    Host,
    AdminAccess,
    Body,
    Decode,
    Form,
    Upload,
    Graphql,
    Saml,
    PhpRequest,
    PhpResponse,
    Hardening,
    Jwt,
    Decoy,
    Behavior,
    Protocol,
    ResponseInspection,
}

impl RejectionReason {
    pub const ALL: [Self; 22] = [
        Self::Rule,
        Self::ResponseRule,
        Self::RateLimit,
        Self::Ban,
        Self::Overload,
        Self::ClientIdentity,
        Self::Host,
        Self::AdminAccess,
        Self::Body,
        Self::Decode,
        Self::Form,
        Self::Upload,
        Self::Graphql,
        Self::Saml,
        Self::PhpRequest,
        Self::PhpResponse,
        Self::Hardening,
        Self::Jwt,
        Self::Decoy,
        Self::Behavior,
        Self::Protocol,
        Self::ResponseInspection,
    ];
    pub fn phase(self) -> Phase {
        if matches!(
            self,
            Self::ResponseRule | Self::PhpResponse | Self::ResponseInspection
        ) {
            Phase::Response
        } else {
            Phase::Request
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcomes {
    /// Exactly 500 client-visible status counters, indexed by status minus 100.
    pub statuses: Vec<u64>,
    pub latency_count: u64,
    pub latency_sum_us: u64,
    /// Exclusive bins with inclusive upper bounds in LATENCY_BOUNDS_US, then +Inf.
    pub latency_bins: [u64; 15],
    pub in_flight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub instance: String,
    pub generation: String,
}

impl SourceIdentity {
    pub fn validate(&self) -> Result<(), Error> {
        identifier(&self.instance, 128)?;
        identifier(&self.generation, 128)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Counters {
    pub requests: Option<u64>,
    pub rejected_requests: Option<u64>,
    pub log_requests: Option<u64>,
    pub rule_matches: Option<u64>,
    pub response_blocks: Option<u64>,
    pub rate_limited_requests: Option<u64>,
    pub banned_requests: Option<u64>,
    pub overloaded_requests: Option<u64>,
    pub upstream_connection_failures: Option<u64>,
    pub upstream_timeouts: Option<u64>,
    pub decoy_credential_use_requests: Option<u64>,
    pub decoy_occurrence_requests: Option<u64>,
    pub decoy_blocked_requests: Option<u64>,
    pub decoy_issued: Option<u64>,
    pub response_log_requests: Option<u64>,
    pub aborted_requests: Option<u64>,
    pub rejection_reasons: Option<BTreeMap<RejectionReason, u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterSnapshot {
    pub observed_at_ms: u64,
    pub counters: Counters,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub source: SourceIdentity,
    /// Monotonic position within one source generation; zero is not a position.
    pub sequence: u64,
    pub cursor: Option<String>,
    pub snapshot: Option<CounterSnapshot>,
}

impl Checkpoint {
    pub fn validate(&self) -> Result<(), Error> {
        self.source.validate()?;
        position(self.sequence)?;
        if let Some(cursor) = &self.cursor {
            text(cursor, 4096)?;
        }
        if let Some(snapshot) = &self.snapshot {
            timestamp(snapshot.observed_at_ms)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub observed_ms: u32,
    pub incomplete: bool,
    pub omitted_events: Option<u64>,
}

impl Default for Coverage {
    fn default() -> Self {
        Self {
            observed_ms: 0,
            incomplete: true,
            omitted_events: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionGauge {
    pub connection_milliseconds: u64,
    pub observed_ms: u32,
    pub observed_max: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricBucket {
    pub start_ms: u64,
    pub site: Option<String>,
    /// Increasing absolute-bucket revision, not an increment to add on replay.
    pub revision: u64,
    pub counters: Counters,
    pub connections: Option<ConnectionGauge>,
    pub coverage: Coverage,
    #[serde(default)]
    pub outcomes: Option<Outcomes>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    RuleMatch,
    Rejection,
    RateLimit,
    Ban,
    Behavior,
    Decoy,
    UpstreamFailure,
    Service,
    CollectionGap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Block,
    Log,
    Reject,
    Error,
    Observe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
    Service,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyContext {
    Issued,
    Credential,
    Occurrence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyEvidence {
    /// The existing decoy protocol's 128-bit hash, represented by 32 hex digits.
    pub credential_id: String,
    pub context: DecoyContext,
    pub issued_at_ms: Option<u64>,
    pub age_seconds: Option<u64>,
    pub lure: Option<String>,
    pub template: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapEvidence {
    pub from_ms: u64,
    pub until_ms: u64,
    pub lost_events: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub id: String,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub kind: EventKind,
    pub disposition: Disposition,
    pub phase: Phase,
    pub site: Option<String>,
    pub client: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub method: Option<String>,
    /// Redacted path only; query strings and fragments are rejected.
    pub path: Option<String>,
    pub status: Option<u16>,
    pub category: Option<String>,
    pub rule: Option<String>,
    pub reason: Option<String>,
    pub decoy: Option<DecoyEvidence>,
    pub gap: Option<GapEvidence>,
    pub incomplete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteBatch {
    pub checkpoint: Checkpoint,
    pub events: Vec<EventRecord>,
    pub metrics: Vec<MetricBucket>,
}

impl WriteBatch {
    pub fn record_count(&self) -> usize {
        self.events
            .len()
            .saturating_add(self.metrics.len())
            .saturating_add(1)
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.checkpoint.validate()?;
        if self.record_count() > MAX_BATCH_RECORDS {
            return Err(Error::Invalid("too many records in one batch"));
        }
        for event in &self.events {
            event.validate()?;
            if event.sequence > self.checkpoint.sequence {
                return Err(Error::Invalid("event exceeds checkpoint position"));
            }
        }
        let mut bucket_keys = std::collections::HashSet::new();
        for metric in &self.metrics {
            metric.validate()?;
            if !bucket_keys.insert((metric.site.as_deref(), metric.start_ms)) {
                return Err(Error::Invalid("duplicate metric bucket in one batch"));
            }
            if metric.revision > self.checkpoint.sequence {
                return Err(Error::Invalid("metric exceeds checkpoint position"));
            }
        }
        Ok(())
    }
}

impl MetricBucket {
    pub fn validate(&self) -> Result<(), Error> {
        timestamp(self.start_ms)?;
        position(self.revision)?;
        if !self.start_ms.is_multiple_of(MINUTE_MS) || self.start_ms > i64::MAX as u64 - MINUTE_MS {
            return Err(Error::Invalid(
                "metric bucket must be an aligned UTC minute",
            ));
        }
        if let Some(site) = &self.site {
            identifier(site, 64)?;
        }
        if u64::from(self.coverage.observed_ms) > MINUTE_MS {
            return Err(Error::Invalid("coverage exceeds one minute"));
        }
        if let Some(outcomes) = &self.outcomes
            && (outcomes.statuses.len() != 500
                || outcomes
                    .statuses
                    .iter()
                    .try_fold(0_u64, |sum, value| sum.checked_add(*value))
                    != Some(outcomes.latency_count)
                || outcomes
                    .latency_bins
                    .iter()
                    .try_fold(0_u64, |sum, value| sum.checked_add(*value))
                    != Some(outcomes.latency_count))
        {
            return Err(Error::Invalid(
                "inconsistent status or latency distribution",
            ));
        }
        if let Some(gauge) = &self.connections
            && (u64::from(gauge.observed_ms) > MINUTE_MS
                || gauge.observed_ms == 0 && gauge.connection_milliseconds != 0)
        {
            return Err(Error::Invalid("invalid connection gauge coverage"));
        }
        Ok(())
    }
}

impl EventRecord {
    pub fn validate(&self) -> Result<(), Error> {
        identifier(&self.id, 256)?;
        position(self.sequence)?;
        timestamp(self.occurred_at_ms)?;
        if let Some(site) = &self.site {
            identifier(site, 64)?;
        }
        if let Some(method) = &self.method {
            text(method, 32)?;
            if method.parse::<http::Method>().is_err() {
                return Err(Error::Invalid("invalid HTTP method"));
            }
        }
        if let Some(path) = &self.path {
            redacted_path(path)?;
        }
        if self
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(Error::Invalid("invalid HTTP status"));
        }
        if let Some(category) = &self.category {
            text(category, 128)?;
        }
        if let Some(rule) = &self.rule {
            text(rule, 128)?;
        }
        if let Some(reason) = &self.reason {
            text(reason, 512)?;
        }
        if (self.kind == EventKind::Decoy) != self.decoy.is_some()
            || (self.kind == EventKind::CollectionGap) != self.gap.is_some()
        {
            return Err(Error::Invalid("event evidence does not match event kind"));
        }
        if let Some(decoy) = &self.decoy {
            if decoy.credential_id.len() != 32
                || !decoy
                    .credential_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(Error::Invalid("decoy credential ID must be a 128-bit hash"));
            }
            if let Some(time) = decoy.issued_at_ms {
                timestamp(time)?;
            }
            if let Some(lure) = &decoy.lure {
                redacted_path(lure)?;
            }
            if let Some(template) = &decoy.template {
                identifier(template, 64)?;
            }
        }
        if let Some(gap) = &self.gap {
            timestamp(gap.from_ms)?;
            timestamp(gap.until_ms)?;
            if gap.from_ms > gap.until_ms {
                return Err(Error::Invalid("reversed observation gap"));
            }
        }
        Ok(())
    }
}

pub(super) fn identifier(value: &str, max: usize) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > max
        || value.contains("kdt1")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/".contains(&byte))
    {
        return Err(Error::Invalid(
            "invalid or oversized observation identifier",
        ));
    }
    Ok(())
}

fn text(value: &str, max: usize) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(char::is_control)
        || crate::decoy::log_path(value) != value
    {
        return Err(Error::Invalid(
            "invalid, sensitive, or oversized observation text",
        ));
    }
    Ok(())
}

fn redacted_path(value: &str) -> Result<(), Error> {
    text(value, 2048)?;
    if value != "[redacted]"
        && (!value.starts_with('/')
            || value.contains(['?', '#'])
            || crate::decoy::log_path(value) != value)
    {
        return Err(Error::Invalid(
            "event path must omit queries and decoy credentials",
        ));
    }
    Ok(())
}

pub(crate) fn timestamp(value: u64) -> Result<(), Error> {
    if value > i64::MAX as u64 {
        return Err(Error::Invalid("timestamp exceeds database range"));
    }
    Ok(())
}

fn position(value: u64) -> Result<(), Error> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(Error::Invalid("invalid source position"));
    }
    Ok(())
}
