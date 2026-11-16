//! UTC history contracts and merge inputs, independent of storage and request handling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Error;
use super::model::{Counters, MINUTE_MS, MetricBucket, Outcomes, RejectionReason};

pub const HOUR_MS: u64 = 60 * MINUTE_MS;
pub const RETENTION_MS: u64 = 30 * 24 * HOUR_MS;
pub const MAX_HISTORY_BYTES: usize = 64 * 1024;
pub const MAX_HISTORY_PAGE: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grain {
    Minute,
    FiveMinutes,
    TenMinutes,
    TwentyMinutes,
    Hour,
}

impl Grain {
    pub const ALL: [Self; 5] = [
        Self::Minute,
        Self::FiveMinutes,
        Self::TenMinutes,
        Self::TwentyMinutes,
        Self::Hour,
    ];

    pub const fn milliseconds(self) -> u64 {
        MINUTE_MS
            * match self {
                Self::Minute => 1,
                Self::FiveMinutes => 5,
                Self::TenMinutes => 10,
                Self::TwentyMinutes => 20,
                Self::Hour => 60,
            }
    }

    pub fn from_milliseconds(value: u64) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|grain| grain.milliseconds() == value)
            .ok_or(Error::Invalid("unsupported history grain"))
    }

    pub const fn parent(self) -> Option<(Self, u64)> {
        match self {
            Self::Minute => Some((Self::FiveMinutes, HOUR_MS)),
            Self::FiveMinutes => Some((Self::TenMinutes, 210 * MINUTE_MS)),
            Self::TenMinutes => Some((Self::TwentyMinutes, 6 * HOUR_MS)),
            Self::TwentyMinutes => Some((Self::Hour, 12 * HOUR_MS)),
            Self::Hour => None,
        }
    }
}

macro_rules! count_metrics {
    ($($variant:ident => $field:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum CountMetric { $($variant),+ }
        impl CountMetric {
            pub const ALL: [Self; 16] = [$(Self::$variant),+];
            fn value(self, counters: &Counters) -> Option<u64> {
                match self { $(Self::$variant => counters.$field),+ }
            }
        }
    };
}

count_metrics! {
    Requests => requests, RejectedRequests => rejected_requests,
    LogRequests => log_requests, RuleMatches => rule_matches,
    ResponseBlocks => response_blocks, RateLimitedRequests => rate_limited_requests,
    BannedRequests => banned_requests, OverloadedRequests => overloaded_requests,
    UpstreamConnectionFailures => upstream_connection_failures, UpstreamTimeouts => upstream_timeouts,
    DecoyCredentialUseRequests => decoy_credential_use_requests, DecoyOccurrenceRequests => decoy_occurrence_requests,
    DecoyBlockedRequests => decoy_blocked_requests, DecoyIssued => decoy_issued,
    ResponseLogRequests => response_log_requests, AbortedRequests => aborted_requests,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountStatistics {
    /// Sum of known contributions; inspect known_minutes and interval coverage.
    pub sum: u64,
    pub known_minutes: u32,
    pub complete_minutes: u32,
    pub complete_sum: u64,
    pub min_minute: Option<u64>,
    pub max_minute: Option<u64>,
}

impl CountStatistics {
    pub fn total(&self) -> Option<u64> {
        (self.known_minutes != 0).then_some(self.sum)
    }

    /// Mean over complete base minutes only, not an estimate of missing traffic.
    pub fn complete_minute_mean(&self) -> Option<f64> {
        (self.complete_minutes != 0)
            .then(|| self.complete_sum as f64 / f64::from(self.complete_minutes))
    }

    fn sample(value: Option<u64>, complete: bool) -> Self {
        let Some(value) = value else {
            return Self::default();
        };
        Self {
            sum: value,
            known_minutes: 1,
            complete_minutes: u32::from(complete),
            complete_sum: if complete { value } else { 0 },
            min_minute: complete.then_some(value),
            max_minute: complete.then_some(value),
        }
    }

    fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.sum = add(self.sum, other.sum)?;
        self.complete_sum = add(self.complete_sum, other.complete_sum)?;
        self.known_minutes = self
            .known_minutes
            .checked_add(other.known_minutes)
            .ok_or(Error::Invalid("history count overflow"))?;
        self.complete_minutes = self
            .complete_minutes
            .checked_add(other.complete_minutes)
            .ok_or(Error::Invalid("history count overflow"))?;
        self.min_minute = option_min(self.min_minute, other.min_minute);
        self.max_minute = option_max(self.max_minute, other.max_minute);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCoverage {
    pub represented_minutes: u32,
    pub complete_minutes: u32,
    pub observed_ms: u64,
    pub incomplete: bool,
    pub omitted_events: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionStatistics {
    pub connection_milliseconds: u64,
    pub observed_ms: u64,
    pub observed_max: Option<u64>,
    #[serde(default)]
    pub observed_min: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryBucket {
    pub start_ms: u64,
    pub grain: Grain,
    pub counters: BTreeMap<CountMetric, CountStatistics>,
    /// Stored in separate reason rows; populated by the history read API.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reasons: BTreeMap<RejectionReason, CountStatistics>,
    pub coverage: HistoryCoverage,
    pub connections: ConnectionStatistics,
    pub outcomes: Option<Outcomes>,
    pub outcome_minutes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional: Option<Box<super::measurements::AdditionalMeasurements>>,
}

impl HistoryBucket {
    pub fn end_ms(&self) -> u64 {
        self.start_ms + self.grain.milliseconds()
    }

    pub fn expected_minutes(&self) -> u32 {
        (self.grain.milliseconds() / MINUTE_MS) as u32
    }

    pub fn complete_rate(&self, metric: CountMetric) -> Option<f64> {
        let count = self.counters.get(&metric)?;
        (!self.coverage.incomplete && count.complete_minutes == self.expected_minutes())
            .then(|| count.sum as f64 * 1000.0 / self.grain.milliseconds() as f64)
    }

    pub fn connection_average(&self) -> Option<f64> {
        (!self.coverage.incomplete && self.connections.observed_ms == self.grain.milliseconds())
            .then(|| {
                self.connections.connection_milliseconds as f64
                    / self.connections.observed_ms as f64
            })
    }

    pub fn reason_rejection_fraction(&self, reason: RejectionReason) -> Option<f64> {
        self.reason_fraction(reason, CountMetric::Requests)
    }

    pub fn reason_share(&self, reason: RejectionReason) -> Option<f64> {
        self.reason_fraction(reason, CountMetric::RejectedRequests)
    }

    fn reason_fraction(&self, reason: RejectionReason, denominator: CountMetric) -> Option<f64> {
        let numerator = self.reasons.get(&reason)?;
        let denominator = self.counters.get(&denominator)?;
        if numerator.sum > denominator.sum {
            return None;
        }
        (!self.coverage.incomplete
            && numerator.complete_minutes == self.expected_minutes()
            && denominator.complete_minutes == self.expected_minutes()
            && denominator.sum != 0)
            .then(|| numerator.sum as f64 / denominator.sum as f64)
    }

    pub(crate) fn minute(values: &[MetricBucket]) -> Result<Self, Error> {
        let first = values
            .first()
            .ok_or(Error::Invalid("empty history minute"))?;
        let mut result = Self::empty(first.start_ms, Grain::Minute);
        let mut complete = values.len() == 1
            && !first.coverage.incomplete
            && first.coverage.observed_ms == MINUTE_MS as u32;
        if let (Some(requests), Some(rejected)) =
            (first.counters.requests, first.counters.rejected_requests)
        {
            complete &= rejected <= requests;
        }
        if let (Some(reasons), Some(rejected)) = (
            &first.counters.rejection_reasons,
            first.counters.rejected_requests,
        ) {
            let known = RejectionReason::ALL
                .into_iter()
                .filter_map(|reason| reasons.get(&reason).copied())
                .try_fold(0, add)?;
            complete &= known <= rejected;
            let counts = RejectionReason::ALL
                .into_iter()
                .map(|reason| reasons.get(&reason).copied())
                .collect::<Option<Vec<_>>>();
            if let Some(counts) = counts {
                complete &= counts.into_iter().try_fold(0, add)? == rejected;
            }
        }
        result.coverage = HistoryCoverage {
            represented_minutes: 1,
            complete_minutes: u32::from(complete),
            observed_ms: values
                .iter()
                .map(|value| u64::from(value.coverage.observed_ms))
                .max()
                .unwrap_or(0),
            incomplete: !complete,
            omitted_events: Some(0),
        };
        for value in values {
            value.validate()?;
            if value.start_ms != first.start_ms || value.site != first.site {
                return Err(Error::Invalid("mixed history minute"));
            }
            for metric in CountMetric::ALL {
                result
                    .counters
                    .get_mut(&metric)
                    .ok_or(Error::Invalid("missing history metric"))?
                    .merge(&CountStatistics::sample(
                        metric.value(&value.counters),
                        complete,
                    ))?;
            }
            for reason in RejectionReason::ALL {
                let count = value
                    .counters
                    .rejection_reasons
                    .as_ref()
                    .and_then(|reasons| reasons.get(&reason))
                    .copied();
                result
                    .reasons
                    .get_mut(&reason)
                    .ok_or(Error::Invalid("missing history reason"))?
                    .merge(&CountStatistics::sample(count, complete))?;
            }
            result.coverage.omitted_events = option_sum(
                result.coverage.omitted_events,
                value.coverage.omitted_events,
            )?;
            if let Some(gauge) = &value.connections {
                let unknown = (result.connections.observed_max.is_some()
                    && result.connections.observed_min.is_none())
                    || gauge.observed_min.is_none();
                result.connections.observed_min = if unknown {
                    None
                } else {
                    option_min(result.connections.observed_min, gauge.observed_min)
                };
                result.connections.connection_milliseconds = add(
                    result.connections.connection_milliseconds,
                    gauge.connection_milliseconds,
                )?;
                result.connections.observed_ms =
                    add(result.connections.observed_ms, u64::from(gauge.observed_ms))?;
                result.connections.observed_max =
                    option_max(result.connections.observed_max, Some(gauge.observed_max));
            }
            result.merge_outcomes(value.outcomes.as_ref())?;
            if let Some(additional) = &value.additional {
                result
                    .additional
                    .get_or_insert_with(|| {
                        Box::new(super::measurements::AdditionalMeasurements::measured())
                    })
                    .merge(additional)?;
            }
        }
        // Multiple generations contribute to one base minute, not several minutes.
        for statistics in result
            .counters
            .values_mut()
            .chain(result.reasons.values_mut())
        {
            statistics.known_minutes = u32::from(statistics.known_minutes != 0);
        }
        result.outcome_minutes = u32::from(result.outcome_minutes != 0);
        if let Some(additional) = &mut result.additional {
            additional.incomplete |=
                !complete || values.iter().any(|value| value.additional.is_none());
        }
        Ok(result)
    }

    pub(crate) fn merge(start_ms: u64, grain: Grain, children: &[Self]) -> Result<Self, Error> {
        let mut result = Self::empty(start_ms, grain);
        result.coverage.omitted_events = Some(0);
        let mut end = start_ms;
        for child in children {
            child.validate()?;
            if child.start_ms < end
                || child.end_ms() > result.end_ms()
                || child.grain.milliseconds() >= grain.milliseconds()
            {
                return Err(Error::Invalid("overlapping or incompatible history input"));
            }
            end = child.end_ms();
            for metric in CountMetric::ALL {
                result
                    .counters
                    .get_mut(&metric)
                    .ok_or(Error::Invalid("missing history metric"))?
                    .merge(
                        child
                            .counters
                            .get(&metric)
                            .ok_or(Error::Invalid("missing history metric"))?,
                    )?;
            }
            for reason in RejectionReason::ALL {
                result
                    .reasons
                    .get_mut(&reason)
                    .ok_or(Error::Invalid("missing history reason"))?
                    .merge(
                        child
                            .reasons
                            .get(&reason)
                            .ok_or(Error::Invalid("missing history reason"))?,
                    )?;
            }
            result.coverage.represented_minutes += child.coverage.represented_minutes;
            result.coverage.complete_minutes += child.coverage.complete_minutes;
            result.coverage.observed_ms =
                add(result.coverage.observed_ms, child.coverage.observed_ms)?;
            result.coverage.incomplete |= child.coverage.incomplete;
            result.coverage.omitted_events = option_sum(
                result.coverage.omitted_events,
                child.coverage.omitted_events,
            )?;
            result.connections.connection_milliseconds = add(
                result.connections.connection_milliseconds,
                child.connections.connection_milliseconds,
            )?;
            result.connections.observed_ms = add(
                result.connections.observed_ms,
                child.connections.observed_ms,
            )?;
            let unknown = (result.connections.observed_max.is_some()
                && result.connections.observed_min.is_none())
                || (child.connections.observed_max.is_some()
                    && child.connections.observed_min.is_none());
            result.connections.observed_max = option_max(
                result.connections.observed_max,
                child.connections.observed_max,
            );
            result.connections.observed_min = if unknown {
                None
            } else {
                option_min(
                    result.connections.observed_min,
                    child.connections.observed_min,
                )
            };
            result.merge_outcomes(child.outcomes.as_ref())?;
            if let Some(additional) = &child.additional {
                result
                    .additional
                    .get_or_insert_with(|| {
                        Box::new(super::measurements::AdditionalMeasurements::measured())
                    })
                    .merge(additional)?;
            }
            result.outcome_minutes += child
                .outcome_minutes
                .saturating_sub(u32::from(child.outcomes.is_some()));
        }
        result.coverage.incomplete |= result.coverage.complete_minutes != result.expected_minutes();
        if let Some(additional) = &mut result.additional {
            additional.incomplete |= result.coverage.incomplete
                || children.iter().any(|child| child.additional.is_none());
        }
        result.validate()?;
        Ok(result)
    }

    fn empty(start_ms: u64, grain: Grain) -> Self {
        Self {
            start_ms,
            grain,
            counters: CountMetric::ALL
                .into_iter()
                .map(|metric| (metric, CountStatistics::default()))
                .collect(),
            reasons: RejectionReason::ALL
                .into_iter()
                .map(|reason| (reason, CountStatistics::default()))
                .collect(),
            coverage: HistoryCoverage::default(),
            connections: ConnectionStatistics::default(),
            outcomes: None,
            outcome_minutes: 0,
            additional: None,
        }
    }

    fn merge_outcomes(&mut self, value: Option<&Outcomes>) -> Result<(), Error> {
        let Some(value) = value else {
            return Ok(());
        };
        self.outcome_minutes += 1;
        let current = self.outcomes.get_or_insert_with(|| Outcomes {
            statuses: vec![0; 500],
            latency_count: 0,
            latency_sum_us: 0,
            latency_bins: [0; 15],
            in_flight: 0,
            latency_min_us: None,
            latency_max_us: None,
        });
        let min_unknown = (current.latency_count > 0 && current.latency_min_us.is_none())
            || (value.latency_count > 0 && value.latency_min_us.is_none());
        let max_unknown = (current.latency_count > 0 && current.latency_max_us.is_none())
            || (value.latency_count > 0 && value.latency_max_us.is_none());
        current.latency_min_us = if min_unknown {
            None
        } else {
            option_min(current.latency_min_us, value.latency_min_us)
        };
        current.latency_max_us = if max_unknown {
            None
        } else {
            option_max(current.latency_max_us, value.latency_max_us)
        };
        if value.statuses.len() != 500 {
            return Err(Error::Invalid("invalid history status distribution"));
        }
        for (a, b) in current.statuses.iter_mut().zip(&value.statuses) {
            *a = add(*a, *b)?;
        }
        for (a, b) in current.latency_bins.iter_mut().zip(&value.latency_bins) {
            *a = add(*a, *b)?;
        }
        current.latency_count = add(current.latency_count, value.latency_count)?;
        current.latency_sum_us = add(current.latency_sum_us, value.latency_sum_us)?;
        current.in_flight = add(current.in_flight, value.in_flight)?;
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if let Some(additional) = &self.additional {
            additional.validate()?;
        }
        let width = self.grain.milliseconds();
        if !self.start_ms.is_multiple_of(width)
            || self.start_ms > i64::MAX as u64 - width
            || self.coverage.represented_minutes > self.expected_minutes()
            || self.coverage.complete_minutes > self.coverage.represented_minutes
            || self.coverage.observed_ms > width
            || self.coverage.observed_ms < u64::from(self.coverage.complete_minutes) * MINUTE_MS
            || (!self.coverage.incomplete
                && self.coverage.complete_minutes != self.expected_minutes())
            || self.outcome_minutes > self.coverage.represented_minutes
            || self.counters.len() != CountMetric::ALL.len()
        {
            return Err(Error::Invalid("invalid history interval or coverage"));
        }
        for value in self.counters.values().chain(self.reasons.values()) {
            if value.known_minutes > self.coverage.represented_minutes
                || value.complete_minutes > value.known_minutes
                || value.complete_minutes > self.coverage.complete_minutes
                || value.complete_sum > value.sum
                || (value.known_minutes == 0 && value.sum != 0)
                || (value.complete_minutes == 0 && value.complete_sum != 0)
                || value.min_minute.is_some() != (value.complete_minutes != 0)
                || value.max_minute.is_some() != (value.complete_minutes != 0)
                || value.min_minute > value.max_minute
            {
                return Err(Error::Invalid("invalid history count statistics"));
            }
        }
        if self.outcomes.is_some() != (self.outcome_minutes != 0) {
            return Err(Error::Invalid("invalid history outcome coverage"));
        }
        if let Some(outcomes) = &self.outcomes
            && (outcomes.statuses.len() != 500
                || outcomes
                    .statuses
                    .iter()
                    .try_fold(0, |sum, value| add(sum, *value))
                    .ok()
                    != Some(outcomes.latency_count)
                || outcomes
                    .latency_bins
                    .iter()
                    .try_fold(0, |sum, value| add(sum, *value))
                    .ok()
                    != Some(outcomes.latency_count))
        {
            return Err(Error::Invalid("invalid history outcome distribution"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub instance: String,
    pub site: Option<String>,
    pub from_ms: u64,
    pub until_ms: u64,
    pub limit: usize,
    /// Reuse the first page's revision when continuing a paginated read.
    pub revision: Option<u64>,
}

impl HistoryQuery {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        super::model::identifier(&self.instance, 128)?;
        if let Some(site) = &self.site {
            super::model::identifier(site, 64)?;
        }
        super::model::timestamp(self.from_ms)?;
        super::model::timestamp(self.until_ms)?;
        if self.from_ms >= self.until_ms || self.limit == 0 || self.limit > MAX_HISTORY_PAGE {
            return Err(Error::Invalid("invalid history query"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HistoryPage {
    pub buckets: Vec<HistoryBucket>,
    pub expiry_ms: u64,
    pub oldest_available_ms: Option<u64>,
    pub next_start_ms: Option<u64>,
    pub pending_minutes: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MaintenanceReport {
    pub materialized_minutes: u64,
    pub compacted_intervals: u64,
    pub deleted_rows: u64,
    pub pending_minutes: u64,
    pub expiry_ms: u64,
    pub oldest_expired_ms: Option<u64>,
    pub more_work: bool,
    /// Includes trigger/foreign-key changes, checked against the per-step bound.
    pub mutated_rows: u64,
}

pub(crate) fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b)
        .ok_or(Error::Invalid("history counter overflow"))
}
fn option_sum(a: Option<u64>, b: Option<u64>) -> Result<Option<u64>, Error> {
    match (a, b) {
        (Some(a), Some(b)) => Ok(Some(add(a, b)?)),
        _ => Ok(None),
    }
}
fn option_min(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn option_max(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}
