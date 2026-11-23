//! Bounded supplementary measurements and mergeable estimation contracts.

use super::{Error, model::RejectionReason};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_DIMENSIONS: usize = 128;
pub const MAX_RANKS: usize = 16;
pub const MAX_COUNTRIES: usize = 64;
pub const SKETCH_REGISTERS: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyMeasurements {
    pub count: u64,
    pub sum_us: u64,
    pub min_us: Option<u64>,
    pub max_us: Option<u64>,
}

impl LatencyMeasurements {
    pub fn record(&mut self, micros: u64) {
        self.count = self.count.saturating_add(1);
        self.sum_us = self.sum_us.saturating_add(micros);
        self.min_us = Some(self.min_us.map_or(micros, |value| value.min(micros)));
        self.max_us = Some(self.max_us.map_or(micros, |value| value.max(micros)));
    }
    pub fn mean_us(&self) -> Option<f64> {
        (self.count != 0).then(|| self.sum_us as f64 / self.count as f64)
    }
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.count = add(self.count, other.count)?;
        self.sum_us = add(self.sum_us, other.sum_us)?;
        self.min_us = minimum(self.min_us, other.min_us);
        self.max_us = maximum(self.max_us, other.max_us);
        Ok(())
    }
    fn validate(&self) -> Result<(), Error> {
        if self.min_us.is_some() != (self.count != 0)
            || self.max_us.is_some() != (self.count != 0)
            || self.min_us > self.max_us
            || (self.count == 0 && self.sum_us != 0)
            || self.min_us.is_some_and(|min| {
                u128::from(min) * u128::from(self.count) > u128::from(self.sum_us)
            })
            || self.max_us.is_some_and(|max| {
                u128::from(max) * u128::from(self.count) < u128::from(self.sum_us)
            })
        {
            return Err(Error::Invalid("invalid supplementary latency"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionKind {
    Site,
    AttackClass,
    Category,
    Rule,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionCounts {
    pub requests: u64,
    pub rejected: u64,
    pub logged_requests: u64,
    pub allow_matches: u64,
    pub log_matches: u64,
    pub block_matches: u64,
    pub upstream_failures: u64,
    pub upstream_timeouts: u64,
    pub latency: LatencyMeasurements,
}

impl DimensionCounts {
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.requests = add(self.requests, other.requests)?;
        self.rejected = add(self.rejected, other.rejected)?;
        self.logged_requests = add(self.logged_requests, other.logged_requests)?;
        self.allow_matches = add(self.allow_matches, other.allow_matches)?;
        self.log_matches = add(self.log_matches, other.log_matches)?;
        self.block_matches = add(self.block_matches, other.block_matches)?;
        self.upstream_failures = add(self.upstream_failures, other.upstream_failures)?;
        self.upstream_timeouts = add(self.upstream_timeouts, other.upstream_timeouts)?;
        self.latency.merge(&other.latency)
    }
    fn weight(&self) -> u64 {
        self.requests
            .saturating_add(self.allow_matches)
            .saturating_add(self.log_matches)
            .saturating_add(self.block_matches)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionMeasurements {
    pub kind: DimensionKind,
    pub id: String,
    pub label: String,
    pub phase: super::model::Phase,
    pub counts: DimensionCounts,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistinctSketch {
    pub registers: Vec<u8>,
}

impl Default for DistinctSketch {
    fn default() -> Self {
        Self {
            registers: vec![0; SKETCH_REGISTERS],
        }
    }
}
impl DistinctSketch {
    pub fn insert(&mut self, domain: &str, value: &[u8]) {
        let mut bytes = Vec::with_capacity(domain.len() + value.len() + 1);
        bytes.extend_from_slice(domain.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(value);
        let hash = digest(&SHA256, &bytes);
        let mut first = [0; 8];
        first.copy_from_slice(&hash.as_ref()[..8]);
        let hash = u64::from_be_bytes(first);
        let index = (hash & 63) as usize;
        let rank = ((hash >> 6).leading_zeros().saturating_sub(6) + 1) as u8;
        if let Some(register) = self.registers.get_mut(index) {
            *register = (*register).max(rank);
        }
    }
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.validate()?;
        other.validate()?;
        for (a, b) in self.registers.iter_mut().zip(&other.registers) {
            *a = (*a).max(*b);
        }
        Ok(())
    }
    pub fn estimate(&self) -> Option<f64> {
        if self.validate().is_err() {
            return None;
        }
        let m = SKETCH_REGISTERS as f64;
        let raw = 0.709 * m * m
            / self
                .registers
                .iter()
                .map(|value| 2_f64.powi(-i32::from(*value)))
                .sum::<f64>();
        let zeros = self.registers.iter().filter(|value| **value == 0).count();
        Some(if raw <= 2.5 * m && zeros != 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        })
    }
    pub fn relative_standard_error(&self) -> f64 {
        1.04 / (SKETCH_REGISTERS as f64).sqrt()
    }
    fn validate(&self) -> Result<(), Error> {
        if self.registers.len() != SKETCH_REGISTERS
            || self.registers.iter().any(|value| *value > 59)
        {
            Err(Error::Invalid("invalid distinct sketch"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankingEntry {
    pub key: String,
    pub estimate: u64,
    pub error: u64,
    /// Recorded lower bounds; omitted occurrences may have either disposition.
    pub observed_rejected: u64,
    pub observed_logged: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ranking {
    pub entries: Vec<RankingEntry>,
    pub replacements: u64,
    pub omitted_upper_bound: u64,
}

impl Ranking {
    pub fn record(&mut self, key: &str, rejected: bool, logged: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.key == key) {
            entry.estimate = entry.estimate.saturating_add(1);
            entry.observed_rejected = entry.observed_rejected.saturating_add(u64::from(rejected));
            entry.observed_logged = entry.observed_logged.saturating_add(u64::from(logged));
            return;
        }
        let error = if self.entries.len() >= MAX_RANKS {
            let index = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.estimate)
                .map_or(0, |(index, _)| index);
            self.replacements = self.replacements.saturating_add(1);
            self.entries.swap_remove(index).estimate
        } else {
            self.omitted_upper_bound
        };
        self.entries.push(RankingEntry {
            key: key.into(),
            estimate: error.saturating_add(1),
            error,
            observed_rejected: u64::from(rejected),
            observed_logged: u64::from(logged),
        });
    }
    fn minimum_when_full(&self) -> u64 {
        (if self.entries.len() == MAX_RANKS {
            self.entries
                .iter()
                .map(|entry| entry.estimate)
                .min()
                .unwrap_or(0)
        } else {
            0
        })
        .max(self.omitted_upper_bound)
    }
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        let a = self.minimum_when_full();
        let b = other.minimum_when_full();
        let mut merged = Vec::with_capacity(MAX_RANKS * 2);
        for entry in &self.entries {
            let mut value = entry.clone();
            if let Some(other) = other.entries.iter().find(|other| other.key == entry.key) {
                value.estimate = add(value.estimate, other.estimate)?;
                value.error = add(value.error, other.error)?;
                value.observed_rejected = add(value.observed_rejected, other.observed_rejected)?;
                value.observed_logged = add(value.observed_logged, other.observed_logged)?;
            } else {
                value.estimate = add(value.estimate, b)?;
                value.error = add(value.error, b)?;
            }
            merged.push(value);
        }
        for entry in &other.entries {
            if self.entries.iter().any(|old| old.key == entry.key) {
                continue;
            }
            let mut value = entry.clone();
            value.estimate = add(value.estimate, a)?;
            value.error = add(value.error, a)?;
            merged.push(value);
        }
        merged.sort_by(|a, b| b.estimate.cmp(&a.estimate).then_with(|| a.key.cmp(&b.key)));
        self.omitted_upper_bound =
            add(a, b)?.max(merged.get(MAX_RANKS).map_or(0, |entry| entry.estimate));
        merged.truncate(MAX_RANKS);
        self.entries = merged;
        self.replacements = add(self.replacements, other.replacements)?;
        Ok(())
    }
    fn validate(&self) -> Result<(), Error> {
        let mut seen = std::collections::BTreeSet::new();
        if self.entries.len() > MAX_RANKS {
            return Err(Error::Invalid("ranking exceeds bound"));
        }
        for entry in &self.entries {
            safe_text(&entry.key, 160)?;
            if !seen.insert(&entry.key)
                || entry.error > entry.estimate
                || entry.observed_rejected > entry.estimate
                || entry.observed_logged > entry.estimate
            {
                return Err(Error::Invalid("invalid ranking entry"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ReloadSuccess,
    ReloadFailure,
    RulesApplied,
    RulesUnchanged,
    RulesFailure,
    RulesIncompatible,
    RulesSignatureFailure,
    CertificateIssued,
    CertificateCached,
    CertificateFailure,
    RulesCheckStarted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalState {
    pub generation: String,
    pub observed_at_ms: u64,
    pub configuration_id: String,
    pub categories: Option<u64>,
    pub rules: Option<u64>,
    pub protection_enabled: Option<bool>,
    pub decoys_enabled: Option<bool>,
    pub rules_update_enabled: Option<bool>,
    pub tls_enabled: Option<bool>,
    pub acme_enabled: Option<bool>,
    pub certificate_expires_at_ms: Option<u64>,
    pub certificate_last_success_ms: Option<u64>,
    pub rules_last_success_ms: Option<u64>,
    pub operation_totals: BTreeMap<Operation, u64>,
    pub last_operations: BTreeMap<Operation, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountryCounts {
    pub requests: u64,
    pub rejected: u64,
}

impl CountryCounts {
    fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.requests = add(self.requests, other.requests)?;
        self.rejected = add(self.rejected, other.rejected)?;
        if self.rejected > self.requests {
            return Err(Error::Invalid("invalid country rejection count"));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.rejected > self.requests {
            return Err(Error::Invalid("invalid country rejection count"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdditionalMeasurements {
    pub version: u32,
    pub completed_requests: u64,
    pub dimensions: Vec<DimensionMeasurements>,
    pub dimension_overflow: u64,
    #[serde(default)]
    pub countries: BTreeMap<String, CountryCounts>,
    #[serde(default)]
    pub country_overflow: u64,
    pub upstream_statuses: BTreeMap<u16, u64>,
    pub reason_latency: BTreeMap<RejectionReason, LatencyMeasurements>,
    pub sources: Ranking,
    pub paths: Ranking,
    pub unique_sources: DistinctSketch,
    pub unique_paths: DistinctSketch,
    pub unique_credentials: DistinctSketch,
    pub operations: BTreeMap<Operation, u64>,
    pub state: Option<OperationalState>,
    pub missed_updates: Option<u64>,
    pub export_omissions: u64,
    pub incomplete: bool,
}

impl AdditionalMeasurements {
    pub fn measured() -> Self {
        Self {
            version: 1,
            missed_updates: Some(0),
            ..Self::default()
        }
    }
    pub fn dimension(&mut self, value: DimensionMeasurements) -> Result<(), Error> {
        if let Some(old) = self
            .dimensions
            .iter_mut()
            .find(|old| old.kind == value.kind && old.id == value.id && old.phase == value.phase)
        {
            return old.counts.merge(&value.counts);
        }
        let cap = match value.kind {
            DimensionKind::Site => 16,
            DimensionKind::AttackClass => 24,
            DimensionKind::Category => 32,
            DimensionKind::Rule => 56,
        };
        if self.dimensions.len() >= MAX_DIMENSIONS
            || self
                .dimensions
                .iter()
                .filter(|old| old.kind == value.kind)
                .count()
                >= cap
        {
            self.dimension_overflow = add(self.dimension_overflow, value.counts.weight())?;
            self.incomplete = true;
        } else {
            self.dimensions.push(value);
        }
        Ok(())
    }
    pub fn country(&mut self, code: &str, rejected: bool) -> Result<(), Error> {
        if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(Error::Invalid("invalid country code"));
        }
        if let Some(counts) = self.countries.get_mut(code) {
            counts.requests = add(counts.requests, 1)?;
            if rejected {
                counts.rejected = add(counts.rejected, 1)?;
            }
            return Ok(());
        }
        if self.countries.len() >= MAX_COUNTRIES {
            self.country_overflow = add(self.country_overflow, 1)?;
            self.incomplete = true;
            return Ok(());
        }
        self.countries.insert(
            code.to_owned(),
            CountryCounts {
                requests: 1,
                rejected: u64::from(rejected),
            },
        );
        Ok(())
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        other.validate()?;
        self.completed_requests = add(self.completed_requests, other.completed_requests)?;
        self.dimension_overflow = add(self.dimension_overflow, other.dimension_overflow)?;
        self.missed_updates = match (self.missed_updates, other.missed_updates) {
            (Some(a), Some(b)) => Some(add(a, b)?),
            _ => None,
        };
        self.export_omissions = add(self.export_omissions, other.export_omissions)?;
        self.incomplete |= other.incomplete;
        for value in &other.dimensions {
            self.dimension(value.clone())?;
        }
        self.country_overflow = add(self.country_overflow, other.country_overflow)?;
        for (code, counts) in &other.countries {
            if let Some(existing) = self.countries.get_mut(code) {
                existing.merge(counts)?;
            } else if self.countries.len() < MAX_COUNTRIES {
                self.countries.insert(code.clone(), counts.clone());
            } else {
                self.country_overflow = add(self.country_overflow, counts.requests)?;
                self.incomplete = true;
            }
        }
        for (status, count) in &other.upstream_statuses {
            *self.upstream_statuses.entry(*status).or_default() = add(
                self.upstream_statuses.get(status).copied().unwrap_or(0),
                *count,
            )?;
        }
        for (reason, latency) in &other.reason_latency {
            self.reason_latency
                .entry(*reason)
                .or_default()
                .merge(latency)?;
        }
        self.sources.merge(&other.sources)?;
        self.paths.merge(&other.paths)?;
        self.unique_sources.merge(&other.unique_sources)?;
        self.unique_paths.merge(&other.unique_paths)?;
        self.unique_credentials.merge(&other.unique_credentials)?;
        for (kind, count) in &other.operations {
            *self.operations.entry(*kind).or_default() =
                add(self.operations.get(kind).copied().unwrap_or(0), *count)?;
        }
        if other.state.as_ref().is_some_and(|other| {
            self.state
                .as_ref()
                .is_none_or(|old| other.observed_at_ms >= old.observed_at_ms)
        }) {
            self.state = other.state.clone();
        }
        Ok(())
    }
    /// Drop bounded optional detail to meet the enclosing record budget; counts remain explicit.
    pub fn shrink(&mut self) -> bool {
        if !self.dimensions.is_empty() {
            let index = self
                .dimensions
                .iter()
                .enumerate()
                .min_by_key(|(_, value)| {
                    (
                        match value.kind {
                            DimensionKind::Rule => 0,
                            DimensionKind::Category => 1,
                            DimensionKind::AttackClass => 2,
                            DimensionKind::Site => 3,
                        },
                        value.counts.weight(),
                    )
                })
                .map_or(0, |(index, _)| index);
            self.dimensions.swap_remove(index);
        } else if let Some(entry) = self.paths.entries.pop() {
            self.paths.omitted_upper_bound = self.paths.omitted_upper_bound.max(entry.estimate);
        } else if let Some(entry) = self.sources.entries.pop() {
            self.sources.omitted_upper_bound = self.sources.omitted_upper_bound.max(entry.estimate);
        } else if let Some(key) = self.upstream_statuses.keys().next_back().copied() {
            self.upstream_statuses.remove(&key);
        } else if let Some(key) = self.reason_latency.keys().next_back().copied() {
            self.reason_latency.remove(&key);
        } else if let Some((code, counts)) = self
            .countries
            .iter()
            .min_by_key(|(_, counts)| counts.requests)
            .map(|(code, counts)| (code.clone(), counts.clone()))
        {
            self.countries.remove(&code);
            self.country_overflow = self.country_overflow.saturating_add(counts.requests);
        } else {
            return false;
        }
        self.export_omissions = self.export_omissions.saturating_add(1);
        self.incomplete = true;
        true
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || self.dimensions.len() > MAX_DIMENSIONS
            || self.countries.len() > MAX_COUNTRIES
            || self.countries.iter().any(|(code, counts)| {
                code.len() != 2
                    || !code.bytes().all(|byte| byte.is_ascii_uppercase())
                    || counts.validate().is_err()
            })
            || self.upstream_statuses.len() > 500
            || self
                .upstream_statuses
                .keys()
                .any(|status| !(100..=599).contains(status))
            || self.reason_latency.len() > RejectionReason::ALL.len()
            || self.operations.len() > 11
        {
            return Err(Error::Invalid("invalid supplementary measurements"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for value in &self.dimensions {
            hash_id(&value.id)?;
            safe_text(&value.label, 96)?;
            if !seen.insert((value.kind, &value.id, value.phase as u8)) {
                return Err(Error::Invalid("duplicate measurement dimension"));
            }
            value.counts.latency.validate()?;
        }
        for value in self.reason_latency.values() {
            value.validate()?;
        }
        self.sources.validate()?;
        self.paths.validate()?;
        self.unique_sources.validate()?;
        self.unique_paths.validate()?;
        self.unique_credentials.validate()?;
        if let Some(state) = &self.state {
            super::model::identifier(&state.generation, 128)?;
            if !state.configuration_id.is_empty() {
                hash_id(&state.configuration_id)?;
            }
            super::model::timestamp(state.observed_at_ms)?;
            if state.operation_totals.len() > 11 || state.last_operations.len() > 11 {
                return Err(Error::Invalid("invalid operational counters"));
            }
            for at in state
                .last_operations
                .values()
                .copied()
                .chain(state.certificate_last_success_ms)
                .chain(state.rules_last_success_ms)
            {
                super::model::timestamp(at)?;
                if at > state.observed_at_ms {
                    return Err(Error::Invalid("operational timestamp exceeds observation"));
                }
            }
            if let Some(at) = state.certificate_expires_at_ms {
                super::model::timestamp(at)?;
            }
        }
        Ok(())
    }
}

fn hash_id(value: &str) -> Result<(), Error> {
    if value.len() != 32 || !value.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        Err(Error::Invalid("invalid supplementary identity"))
    } else {
        Ok(())
    }
}

pub fn identity(value: &str) -> String {
    digest(&SHA256, value.as_bytes()).as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub fn label(value: &str, max: usize) -> String {
    if crate::decoy::log_path(value) != value {
        return "[redacted]".into();
    }
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .scan(0, |size, ch| {
            *size += ch.len_utf8();
            (*size <= max).then_some(ch)
        })
        .collect()
}
fn safe_text(value: &str, max: usize) -> Result<(), Error> {
    if value.len() > max
        || value.chars().any(char::is_control)
        || crate::decoy::log_path(value) != value
    {
        Err(Error::Invalid("invalid supplementary text"))
    } else {
        Ok(())
    }
}
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b)
        .ok_or(Error::Invalid("supplementary measurement overflow"))
}
fn minimum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn maximum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_merges_weights_and_exact_extrema_and_rejects_impossible_sums() {
        let mut a = LatencyMeasurements::default();
        for micros in [1, 1, 1] {
            a.record(micros);
        }
        let mut b = LatencyMeasurements::default();
        b.record(101);
        a.merge(&b).unwrap();
        assert_eq!(
            (a.count, a.sum_us, a.min_us, a.max_us),
            (4, 104, Some(1), Some(101))
        );
        assert_eq!(a.mean_us(), Some(26.0));
        a.validate().unwrap();
        a.sum_us = 0;
        assert!(a.validate().is_err());
    }

    #[test]
    fn every_rejection_reason_fits_the_supplementary_latency_map() {
        let mut values = AdditionalMeasurements::measured();
        for reason in RejectionReason::ALL {
            let mut latency = LatencyMeasurements::default();
            latency.record(1);
            values.reason_latency.insert(reason, latency);
        }
        assert_eq!(values.reason_latency.len(), RejectionReason::ALL.len());
        values.validate().unwrap();
    }

    #[test]
    fn distinct_sketch_unions_repeated_values_instead_of_adding_estimates() {
        let mut a = DistinctSketch::default();
        let mut b = DistinctSketch::default();
        let mut all = DistinctSketch::default();
        for index in 0_u64..10_000 {
            all.insert("test", &index.to_be_bytes());
            if index < 7_000 {
                a.insert("test", &index.to_be_bytes());
            }
            if index >= 3_000 {
                b.insert("test", &index.to_be_bytes());
            }
        }
        a.merge(&b).unwrap();
        assert_eq!(a, all);
        a.merge(&all).unwrap();
        assert_eq!(a, all);
        assert!((a.estimate().unwrap() / 10_000.0 - 1.0).abs() < 3.0 * a.relative_standard_error());
        assert_eq!(DistinctSketch::default().estimate(), Some(0.0));
    }

    #[test]
    fn ranking_bounds_survive_replacements_truncation_and_multilevel_merge() {
        let mut exact = BTreeMap::<String, u64>::new();
        let mut combined = Ranking::default();
        for partition in 0..17 {
            let mut rank = Ranking::default();
            for index in 0..1000 {
                let key = if index % 3 == 0 {
                    "dominant".into()
                } else {
                    format!("key-{}", (index * 17 + partition) % 137)
                };
                *exact.entry(key.clone()).or_default() += 1;
                rank.record(&key, index % 2 == 0, index % 5 == 0);
            }
            // Simulate optional export trimming before the next aggregation layer.
            if partition % 2 == 0 {
                let removed = rank.entries.pop().unwrap();
                rank.omitted_upper_bound = rank.omitted_upper_bound.max(removed.estimate);
            }
            combined.merge(&rank).unwrap();
            combined.validate().unwrap();
            for entry in &combined.entries {
                let count = exact[&entry.key];
                assert!(
                    entry.estimate - entry.error <= count && count <= entry.estimate,
                    "{entry:?}: {count}"
                );
                assert!(entry.observed_rejected <= count && entry.observed_logged <= count);
            }
            for (key, count) in &exact {
                if !combined.entries.iter().any(|entry| &entry.key == key) {
                    assert!(*count <= combined.omitted_upper_bound);
                }
            }
        }
        assert_eq!(combined.entries[0].key, "dominant");
    }

    #[test]
    fn country_counts_merge_validate_and_bound() {
        let mut values = AdditionalMeasurements::measured();
        values.country("JP", false).unwrap();
        values.country("JP", true).unwrap();
        values.country("US", false).unwrap();
        assert_eq!(values.countries["JP"].requests, 2);
        assert_eq!(values.countries["JP"].rejected, 1);
        assert_eq!(values.countries["US"].requests, 1);

        let mut other = AdditionalMeasurements::measured();
        other.country("JP", true).unwrap();
        values.merge(&other).unwrap();
        assert_eq!(values.countries["JP"].requests, 3);
        assert_eq!(values.countries["JP"].rejected, 2);
        values.validate().unwrap();

        for index in 0..=MAX_COUNTRIES {
            let code = format!(
                "{}{}",
                char::from(b'A' + (index / 26) as u8),
                char::from(b'A' + (index % 26) as u8)
            );
            values.country(&code, false).unwrap();
        }
        assert_eq!(values.countries.len(), MAX_COUNTRIES);
        assert!(values.country_overflow > 0);
        assert!(values.incomplete);
        values.validate().unwrap();
        assert!(values.shrink());
        assert_eq!(values.countries.len(), MAX_COUNTRIES - 1);
    }

    #[test]
    fn dimension_quotas_protect_sites_and_report_missing_detail() {
        let mut values = AdditionalMeasurements::measured();
        for index in 0..200 {
            values
                .dimension(DimensionMeasurements {
                    kind: DimensionKind::Rule,
                    id: identity(&index.to_string()),
                    label: index.to_string(),
                    phase: super::super::model::Phase::Request,
                    counts: DimensionCounts {
                        log_matches: 1,
                        ..DimensionCounts::default()
                    },
                })
                .unwrap();
        }
        values
            .dimension(DimensionMeasurements {
                kind: DimensionKind::Site,
                id: identity("blog"),
                label: "blog".into(),
                phase: super::super::model::Phase::Request,
                counts: DimensionCounts {
                    requests: 1,
                    ..DimensionCounts::default()
                },
            })
            .unwrap();
        assert_eq!(values.dimensions.len(), 57);
        assert_eq!(values.dimension_overflow, 144);
        assert!(values.incomplete);
        values.validate().unwrap();
        assert!(values.shrink());
        assert_eq!(values.export_omissions, 1);
        assert!(
            values
                .dimensions
                .iter()
                .any(|value| value.kind == DimensionKind::Site)
        );
    }
}
