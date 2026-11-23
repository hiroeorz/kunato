//! Non-waiting supplementary capture with a fixed source-minute horizon.

use crate::console::measurements::*;
use crate::console::model::{MINUTE_MS, Phase, RejectionReason};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

struct Slot {
    at: u64,
    values: AdditionalMeasurements,
}
struct State {
    slots: Vec<Slot>,
    state: OperationalState,
}
struct Partition {
    state: Mutex<State>,
    missed: AtomicU64,
    first_missed: AtomicU64,
    last_missed: AtomicU64,
    newest: AtomicU64,
}

pub(super) struct Request<'a> {
    pub partition: usize,
    pub site: &'a str,
    pub source: Option<std::net::IpAddr>,
    pub country: &'a str,
    pub path: Option<&'a str>,
    pub path_hash: Option<&'a [u8; 32]>,
    pub rejected: Option<RejectionReason>,
    pub logged: bool,
    pub auth_failure: bool,
    pub auth_success: bool,
    pub micros: Option<u64>,
    pub upstream_failure: bool,
    pub upstream_timeout: bool,
}

pub(super) struct RuleMatch<'a> {
    pub configuration: &'a str,
    pub phase: Phase,
    pub category: &'a str,
    pub rule: &'a str,
    pub action: crate::config::Action,
}

impl Partition {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                slots: (0..super::MINUTE_SLOTS)
                    .map(|_| Slot {
                        at: u64::MAX,
                        values: AdditionalMeasurements::measured(),
                    })
                    .collect(),
                state: OperationalState::default(),
            }),
            missed: AtomicU64::new(0),
            first_missed: AtomicU64::new(u64::MAX),
            last_missed: AtomicU64::new(0),
            newest: AtomicU64::new(0),
        }
    }
    fn lost(&self, at: u64) {
        self.missed.fetch_add(1, Ordering::Relaxed);
        self.first_missed.fetch_min(at, Ordering::Relaxed);
        self.last_missed.fetch_max(at, Ordering::Relaxed);
    }
    fn update(
        &self,
        at: u64,
        record: impl FnOnce(&mut AdditionalMeasurements) -> Result<(), crate::console::Error>,
    ) {
        let at = at / MINUTE_MS * MINUTE_MS;
        let newest = self.newest.fetch_max(at, Ordering::Relaxed).max(at);
        if newest.saturating_sub(at) >= super::MINUTE_SLOTS as u64 * MINUTE_MS {
            self.lost(at);
            return;
        }
        let Ok(mut state) = self.state.try_lock() else {
            self.lost(at);
            return;
        };
        let slot = &mut state.slots[(at / MINUTE_MS) as usize % super::MINUTE_SLOTS];
        if slot.at != at {
            if slot.at != u64::MAX && slot.at > at {
                self.lost(at);
                return;
            }
            slot.at = at;
            slot.values = AdditionalMeasurements::measured();
        }
        if record(&mut slot.values).is_err() {
            slot.values.incomplete = true;
            self.lost(at);
        }
    }
    pub fn request(&self, at: u64, request: Request<'_>) {
        self.update(at, |values| {
            values.completed_requests = values.completed_requests.saturating_add(1);
            let mut counts = DimensionCounts {
                requests: 1,
                rejected: u64::from(request.rejected.is_some()),
                logged_requests: u64::from(request.logged),
                upstream_failures: u64::from(request.upstream_failure),
                upstream_timeouts: u64::from(request.upstream_timeout),
                ..DimensionCounts::default()
            };
            if let Some(micros) = request.micros {
                counts.latency.record(micros);
                if let Some(reason) = request.rejected {
                    values
                        .reason_latency
                        .entry(reason)
                        .or_default()
                        .record(micros);
                }
            }
            values.dimension(DimensionMeasurements {
                kind: DimensionKind::Site,
                id: identity(request.site),
                label: label(request.site, 96),
                phase: Phase::Request,
                counts,
            })?;
            values.country(request.country, request.rejected.is_some())?;
            if request.auth_failure {
                values.auth_failures = values.auth_failures.saturating_add(1);
                if let Some(source) = request.source {
                    let source = source.to_string();
                    values.auth_sources.record(&source, false, false);
                    values
                        .unique_auth_sources
                        .insert("auth-source-ip-v1", source.as_bytes());
                }
                if let Some(path) = request.path {
                    values.auth_paths.record(path, false, false);
                }
            }
            if request.auth_success {
                values.auth_successes = values.auth_successes.saturating_add(1);
                if let Some(source) = request.source {
                    let source = source.to_string();
                    values.auth_success_sources.record(&source, false, false);
                }
            }
            if let Some(source) = request.source {
                let source = source.to_string();
                values
                    .unique_sources
                    .insert("source-ip-v1", source.as_bytes());
                values
                    .sources
                    .record(&source, request.rejected.is_some(), request.logged);
            }
            if let Some(hash) = request.path_hash {
                values.unique_paths.insert("path-hash-v1", hash);
            }
            if let Some(path) = request.path {
                values
                    .paths
                    .record(path, request.rejected.is_some(), request.logged);
            }
            values.incomplete |= request.source.is_none() || request.path.is_none();
            Ok(())
        });
    }
    pub fn rule(
        &self,
        at: u64,
        configuration: &str,
        phase: Phase,
        category: &str,
        rule: &str,
        action: crate::config::Action,
    ) {
        self.update(at, |values| {
            let counts = DimensionCounts {
                allow_matches: u64::from(action == crate::config::Action::Allow),
                log_matches: u64::from(action == crate::config::Action::Log),
                block_matches: u64::from(action == crate::config::Action::Block),
                ..DimensionCounts::default()
            };
            let class = crate::logs::observation_attack_name(category);
            for (kind, key, label_value) in [
                (
                    DimensionKind::AttackClass,
                    format!("{phase:?}:{class}"),
                    class.to_owned(),
                ),
                (
                    DimensionKind::Category,
                    format!("{configuration}:{phase:?}:{category}"),
                    category.to_owned(),
                ),
                (
                    DimensionKind::Rule,
                    format!("{configuration}:{phase:?}:{category}/{rule}"),
                    format!("{category}/{rule}"),
                ),
            ] {
                values.dimension(DimensionMeasurements {
                    kind,
                    id: identity(&key),
                    label: label(&label_value, 96),
                    phase,
                    counts: counts.clone(),
                })?;
            }
            Ok(())
        });
    }
    pub fn upstream(&self, at: u64, status: u16) {
        self.update(at, |values| {
            if (100..=599).contains(&status) {
                let counter = values.upstream_statuses.entry(status).or_default();
                *counter = counter.saturating_add(1);
            } else {
                values.incomplete = true;
            }
            Ok(())
        });
    }
    pub fn operation(&self, at: u64, kind: Operation) {
        if let Ok(mut state) = self.state.lock() {
            state.state.observed_at_ms = at;
            let counter = state.state.operation_totals.entry(kind).or_default();
            *counter = counter.saturating_add(1);
            state.state.last_operations.insert(kind, at);
        }
        self.update(at, |values| {
            let counter = values.operations.entry(kind).or_default();
            *counter = counter.saturating_add(1);
            Ok(())
        });
    }
    pub fn credential(&self, at: u64, id: &str) {
        self.update(at, |values| {
            values
                .unique_credentials
                .insert("verified-credential-v1", id.as_bytes());
            Ok(())
        });
    }
    pub fn configure(&self, at: u64, config: &crate::config::CompiledConfig) {
        if let Ok(mut state) = self.state.lock() {
            state.state.observed_at_ms = at;
            state.state.configuration_id = config.observation_id.clone();
            state.state.categories = Some(config.categories.len() as u64);
            state.state.rules = Some(
                config
                    .categories
                    .iter()
                    .map(|category| category.rules.len() as u64)
                    .sum(),
            );
            state.state.protection_enabled = Some(config.protection.enabled);
            state.state.decoys_enabled = Some(crate::decoy::active(config));
            state.state.rules_update_enabled = Some(config.rules_update.enabled);
            state.state.tls_enabled = Some(config.tls.is_some());
            state.state.acme_enabled =
                Some(config.tls.as_ref().is_some_and(|tls| tls.acme.is_some()));
        }
    }
    pub fn certificate(&self, at: u64, expires: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.state.observed_at_ms = at;
            state.state.certificate_expires_at_ms = Some(expires.saturating_mul(1000));
            state.state.certificate_last_success_ms = Some(at);
        }
    }
    pub fn rules_success(&self, at: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.state.observed_at_ms = at;
            state.state.rules_last_success_ms = Some(at);
        }
    }
    pub fn capture(&self, at: u64) -> Option<Box<AdditionalMeasurements>> {
        let mut state = self.state.try_lock().ok()?;
        let operational = state.state.clone();
        let slot = &mut state.slots[(at / MINUTE_MS) as usize % super::MINUTE_SLOTS];
        if slot.at != at {
            if slot.at != u64::MAX && slot.at > at {
                return None;
            }
            slot.at = at;
            slot.values = AdditionalMeasurements::measured();
        }
        if operational.observed_at_ms < at + MINUTE_MS
            && (!operational.configuration_id.is_empty()
                || operational.certificate_expires_at_ms.is_some())
        {
            slot.values.state = Some(operational);
        }
        let mut values = slot.values.clone();
        if at >= self.first_missed.load(Ordering::Relaxed)
            && at <= self.last_missed.load(Ordering::Relaxed)
        {
            values.missed_updates = None;
            values.incomplete = true;
        }
        Some(Box::new(values))
    }
    pub fn reset(&self, at: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for slot in &mut state.slots {
            slot.at = u64::MAX;
            slot.values = AdditionalMeasurements::measured();
        }
        self.newest.store(at, Ordering::Release);
        self.first_missed.store(u64::MAX, Ordering::Release);
        self.last_missed.store(0, Ordering::Release);
    }

    pub fn missed(&self) -> u64 {
        self.missed.load(Ordering::Relaxed)
    }
}

pub(super) struct Recorder {
    partitions: Box<[Partition; 8]>,
    next: AtomicU64,
}
impl Recorder {
    pub fn new(generation: &str) -> Self {
        let result = Self {
            partitions: Box::new(std::array::from_fn(|_| Partition::new())),
            next: AtomicU64::new(0),
        };
        if let Ok(mut state) = result.partitions[0].state.lock() {
            state.state.generation = generation.into();
        }
        result
    }
    pub fn reset(&self, at: u64) {
        for partition in self.partitions.iter() {
            partition.reset(at);
        }
    }
    pub fn next_partition(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) as usize % 8
    }
    pub fn request(&self, at: u64, request: Request<'_>) {
        self.partitions[request.partition % 8].request(at, request);
    }
    pub fn rule(&self, at: u64, partition: usize, matched: RuleMatch<'_>) {
        self.partitions[partition % 8].rule(
            at,
            matched.configuration,
            matched.phase,
            matched.category,
            matched.rule,
            matched.action,
        );
    }
    pub fn upstream(&self, at: u64, partition: usize, status: u16) {
        self.partitions[partition % 8].upstream(at, status);
    }
    pub fn credential(&self, at: u64, partition: usize, id: &str) {
        self.partitions[partition % 8].credential(at, id);
    }
    pub fn configure(&self, at: u64, config: &crate::config::CompiledConfig) {
        self.partitions[0].configure(at, config);
    }
    pub fn certificate(&self, at: u64, expires: u64) {
        self.partitions[0].certificate(at, expires);
    }
    pub fn rules_success(&self, at: u64) {
        self.partitions[0].rules_success(at);
    }
    pub fn operation(&self, at: u64, kind: Operation) {
        self.partitions[0].operation(at, kind);
    }
    pub fn missed(&self) -> u64 {
        self.partitions
            .iter()
            .map(Partition::missed)
            .fold(0, u64::saturating_add)
    }
    pub fn capture(&self, at: u64) -> Option<Box<AdditionalMeasurements>> {
        let mut result = AdditionalMeasurements::measured();
        let mut any = false;
        for partition in self.partitions.iter() {
            match partition.capture(at) {
                Some(value) => {
                    any = true;
                    if result.merge(&value).is_err() {
                        result.incomplete = true;
                        result.missed_updates = None;
                    }
                }
                None => {
                    result.incomplete = true;
                    result.missed_updates = None;
                }
            }
        }
        any.then(|| Box::new(result))
    }
}

pub(super) fn path(value: &str) -> String {
    let value = crate::decoy::log_path(value);
    if value == "[redacted]" {
        return value.into_owned();
    }
    let mut result = String::with_capacity(128);
    let mut sensitive = false;
    for component in value.split('/').filter(|value| !value.is_empty()).take(32) {
        if result.len() >= 128 {
            break;
        }
        if !result.is_empty() || value.starts_with('/') {
            result.push('/');
        }
        let secret =
            sensitive || component.len() >= 32 || component.to_ascii_lowercase().contains("kdt1");
        let part = if secret { "[redacted]" } else { component };
        let room = 128_usize.saturating_sub(result.len());
        result.push_str(&label(part, room));
        sensitive = matches!(
            component.to_ascii_lowercase().as_str(),
            "token"
                | "secret"
                | "password"
                | "credential"
                | "credentials"
                | "api-key"
                | "api_key"
                | "reset"
                | "password-reset"
                | "reset-password"
                | "invite"
                | "invitation"
                | "activation"
                | "confirm"
        );
    }
    if result.is_empty() && value.starts_with('/') {
        result.push('/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_partition_reports_a_gap_and_never_waits_for_a_request() {
        let recorder = Recorder::new("boot");
        let _held = recorder.partitions[0].state.lock().unwrap();
        recorder.upstream(0, 0, 403);
        assert_eq!(recorder.missed(), 1);
        let values = recorder.capture(0).unwrap();
        assert!(values.incomplete);
        assert_eq!(values.missed_updates, None);
    }

    #[test]
    fn request_records_the_resolved_country() {
        let partition = Partition::new();
        partition.request(
            0,
            Request {
                partition: 0,
                site: "example",
                source: None,
                country: "JP",
                path: Some("/account"),
                path_hash: None,
                rejected: Some(RejectionReason::Rule),
                logged: false,
                auth_failure: false,
                auth_success: false,
                micros: Some(10),
                upstream_failure: false,
                upstream_timeout: false,
            },
        );
        partition.request(
            0,
            Request {
                partition: 0,
                site: "example",
                source: None,
                country: "US",
                path: Some("/"),
                path_hash: None,
                rejected: None,
                logged: false,
                auth_failure: false,
                auth_success: false,
                micros: Some(10),
                upstream_failure: false,
                upstream_timeout: false,
            },
        );
        let values = partition.capture(0).unwrap();
        assert_eq!(values.countries["JP"].requests, 1);
        assert_eq!(values.countries["JP"].rejected, 1);
        assert_eq!(values.countries["US"].requests, 1);
        assert!(values.incomplete);
    }

    #[test]
    fn authentication_failures_keep_bounded_source_and_path_evidence() {
        let partition = Partition::new();
        for _ in 0..2 {
            partition.request(
                0,
                Request {
                    partition: 0,
                    site: "example",
                    source: Some("203.0.113.7".parse().unwrap()),
                    country: "JP",
                    path: Some("/login"),
                    path_hash: None,
                    rejected: None,
                    logged: false,
                    auth_failure: true,
                    auth_success: false,
                    micros: Some(10),
                    upstream_failure: false,
                    upstream_timeout: false,
                },
            );
        }
        let values = partition.capture(0).unwrap();
        values.validate().unwrap();
        assert_eq!(values.auth_failures, 2);
        assert_eq!(values.auth_sources.entries[0].key, "203.0.113.7");
        assert_eq!(values.auth_sources.entries[0].estimate, 2);
        assert_eq!(values.auth_paths.entries[0].key, "/login");
        assert!(values.unique_auth_sources.estimate().unwrap() >= 0.5);
    }

    #[test]
    fn authentication_successes_keep_bounded_source_evidence() {
        let partition = Partition::new();
        for _ in 0..2 {
            partition.request(
                0,
                Request {
                    partition: 0,
                    site: "example",
                    source: Some("203.0.113.7".parse().unwrap()),
                    country: "JP",
                    path: Some("/login"),
                    path_hash: None,
                    rejected: None,
                    logged: false,
                    auth_failure: false,
                    auth_success: true,
                    micros: Some(10),
                    upstream_failure: false,
                    upstream_timeout: false,
                },
            );
        }
        let values = partition.capture(0).unwrap();
        values.validate().unwrap();
        assert_eq!(values.auth_successes, 2);
        assert_eq!(values.auth_success_sources.entries[0].key, "203.0.113.7");
        assert_eq!(values.auth_success_sources.entries[0].estimate, 2);
        assert_eq!(values.auth_failures, 0);
        assert!(values.auth_sources.entries.is_empty());
    }

    #[test]
    fn operational_state_is_not_backdated_and_missed_minutes_are_not_assigned_counts() {
        let recorder = Recorder::new("boot");
        let config = crate::config::parse(
            "listen: 127.0.0.1:0\nupstream: http://127.0.0.1:8000\ncategories: []\n",
        )
        .unwrap();
        recorder.configure(1000, &config);
        recorder.operation(1000, Operation::ReloadSuccess);
        assert_eq!(
            recorder
                .capture(0)
                .unwrap()
                .state
                .as_ref()
                .unwrap()
                .operation_totals[&Operation::ReloadSuccess],
            1
        );
        recorder.operation(61_000, Operation::ReloadFailure);
        assert!(
            !recorder
                .capture(0)
                .unwrap()
                .state
                .unwrap()
                .operation_totals
                .contains_key(&Operation::ReloadFailure)
        );
        let current = recorder.capture(60_000).unwrap();
        assert_eq!(current.operations[&Operation::ReloadFailure], 1);
        assert_eq!(current.state.unwrap().generation, "boot");
        assert!(recorder.capture(120_000).unwrap().operations.is_empty());
    }

    #[test]
    fn rankings_redact_secret_shapes_and_bound_utf8_paths() {
        assert_eq!(
            path("/reset/secret-value/profile"),
            "/reset/[redacted]/profile"
        );
        assert_eq!(path("/token/another-secret"), "/token/[redacted]");
        assert_eq!(path("/"), "/");
        assert!(path(&format!("/{}", "é".repeat(100))).len() <= 128);
        assert!(!path("/api/abcdefghijklmnopqrstuvwxyz1234567890").contains("abcdefgh"));
    }
}
