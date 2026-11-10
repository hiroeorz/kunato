use std::fmt;
use std::sync::{Mutex, OnceLock, PoisonError};
use tokio::time::Instant;

use super::config::{Issuance, Verification};
use super::token::Key;

#[derive(Clone, Copy)]
pub(crate) struct QuotaPolicy {
    generation: u64,
    effective: Instant,
    rate: f64,
    capacity: u32,
}

impl QuotaPolicy {
    fn new(rate: f64, capacity: u32, now: Instant) -> Self {
        Self {
            generation: 0,
            effective: now,
            rate,
            capacity,
        }
    }

    fn update(&mut self, rate: f64, capacity: u32, now: Instant) {
        self.generation = self.generation.saturating_add(1);
        self.effective = now;
        self.rate = rate;
        self.capacity = capacity;
    }
}

pub(crate) struct Bucket {
    policy: QuotaPolicy,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(policy: QuotaPolicy, now: Instant) -> Self {
        Self {
            tokens: f64::from(policy.capacity),
            policy,
            last: now,
        }
    }

    fn refill(&mut self, until: Instant) {
        self.tokens = (self.tokens
            + until.saturating_duration_since(self.last).as_secs_f64() * self.policy.rate)
            .min(f64::from(self.policy.capacity));
        self.last = self.last.max(until);
    }

    pub(crate) fn take(&mut self, policy: QuotaPolicy, now: Instant) -> bool {
        if policy.generation > self.policy.generation {
            if policy.generation == self.policy.generation.saturating_add(1) {
                self.refill(policy.effective);
            }
            self.tokens = self.tokens.min(f64::from(policy.capacity));
            self.last = self.last.max(policy.effective);
            self.policy = policy;
        }
        self.refill(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct Global {
    issuance: Issuance,
    verification: Verification,
    issue: Bucket,
    verify: Bucket,
    source: QuotaPolicy,
    logs: [Bucket; 3],
}

pub struct Runtime {
    started: Instant,
    key: OnceLock<Key>,
    initialize: Mutex<()>,
    global: Mutex<Global>,
    #[cfg(test)]
    failures: [std::sync::atomic::AtomicBool; 2],
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecoyRuntime")
            .field("key_ready", &self.key.get().is_some())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    pub fn new(issuance: Issuance, verification: Verification) -> Self {
        let now = Instant::now();
        let policy = |rate, capacity| QuotaPolicy::new(rate, capacity, now);
        Self {
            #[cfg(test)]
            failures: Default::default(),
            started: now,
            key: OnceLock::new(),
            initialize: Mutex::new(()),
            global: Mutex::new(Global {
                issuance,
                verification,
                issue: Bucket::new(
                    policy(f64::from(issuance.per_minute) / 60.0, issuance.burst),
                    now,
                ),
                verify: Bucket::new(
                    policy(f64::from(verification.per_second), verification.burst),
                    now,
                ),
                source: policy(
                    f64::from(issuance.per_source_per_minute) / 60.0,
                    issuance.per_source_burst,
                ),
                logs: [
                    Bucket::new(policy(1.0, 10), now),
                    Bucket::new(policy(1.0, 10), now),
                    Bucket::new(policy(1.0 / 60.0, 1), now),
                ],
            }),
        }
    }

    pub fn ensure_key(&self) -> Result<(), &'static str> {
        let _guard = self
            .initialize
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.key.get().is_none() {
            #[cfg(test)]
            if self.failures[0].load(std::sync::atomic::Ordering::Relaxed) {
                return Err("injected key entropy failure");
            }
            let key = Key::generate()?;
            let _ = self.key.set(key);
        }
        Ok(())
    }

    pub(super) fn key(&self) -> Option<&Key> {
        self.key.get()
    }
    pub fn elapsed(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub(super) fn mint(&self, site: [u8; 16], ttl: u64) -> Result<String, &'static str> {
        #[cfg(test)]
        if self.failures[1].load(std::sync::atomic::Ordering::Relaxed) {
            return Err("injected nonce entropy failure");
        }
        self.key()
            .ok_or("signing key unavailable")?
            .mint(site, self.elapsed(), ttl)
    }

    #[cfg(test)]
    pub(super) fn fail_entropy(&self, key: bool) {
        self.failures[if key { 0 } else { 1 }].store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn install(&self, issuance: Issuance, verification: Verification) {
        let now = Instant::now();
        let mut global = self.global.lock().unwrap_or_else(PoisonError::into_inner);
        if global.issuance != issuance {
            let mut policy = global.issue.policy;
            policy.update(f64::from(issuance.per_minute) / 60.0, issuance.burst, now);
            global.issue.refill(now);
            global.issue.tokens = global.issue.tokens.min(f64::from(policy.capacity));
            global.issue.policy = policy;
            global.source.update(
                f64::from(issuance.per_source_per_minute) / 60.0,
                issuance.per_source_burst,
                now,
            );
            global.issuance = issuance;
        }
        if global.verification != verification {
            let mut policy = global.verify.policy;
            policy.update(f64::from(verification.per_second), verification.burst, now);
            global.verify.refill(now);
            global.verify.tokens = global.verify.tokens.min(f64::from(policy.capacity));
            global.verify.policy = policy;
            global.verification = verification;
        }
    }

    pub(crate) fn issue_quota(&self) -> Option<QuotaPolicy> {
        let mut global = self.global.lock().unwrap_or_else(PoisonError::into_inner);
        let policy = global.issue.policy;
        global
            .issue
            .take(policy, Instant::now())
            .then_some(global.source)
    }

    pub(crate) fn verification_quota(&self) -> bool {
        let mut global = self.global.lock().unwrap_or_else(PoisonError::into_inner);
        let policy = global.verify.policy;
        global.verify.take(policy, Instant::now())
    }

    pub(crate) fn log_quota(&self, kind: usize) -> bool {
        let mut global = self.global.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = &mut global.logs[kind];
        bucket.take(bucket.policy, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn quota_reload_does_not_create_bursts_or_retroactive_credit() {
        let now = Instant::now();
        let mut policy = QuotaPolicy::new(1.0, 2, now);
        let mut bucket = Bucket::new(policy, now);
        assert!(bucket.take(policy, now));
        assert!(bucket.take(policy, now));
        assert!(!bucket.take(policy, now));
        policy.update(100.0, 10, now);
        assert!(!bucket.take(policy, now));
        policy.update(100.0, 1, now + Duration::from_secs(1));
        policy.update(100.0, 10, now + Duration::from_secs(2));
        assert!(!bucket.take(policy, now + Duration::from_secs(2)));
        assert!(bucket.take(policy, now + Duration::from_secs(3)));
    }

    #[test]
    fn runtime_keeps_key_and_spent_global_capacity_on_policy_changes() {
        let runtime = Runtime::new(Issuance::default(), Verification::default());
        runtime.ensure_key().unwrap();
        let key = runtime.key().unwrap() as *const Key;
        for _ in 0..10 {
            assert!(runtime.issue_quota().is_some());
        }
        assert!(runtime.issue_quota().is_none());
        runtime.install(
            Issuance {
                burst: 20,
                ..Issuance::default()
            },
            Verification::default(),
        );
        assert!(runtime.issue_quota().is_none());
        runtime.ensure_key().unwrap();
        assert_eq!(runtime.key().unwrap() as *const Key, key);
    }
}
