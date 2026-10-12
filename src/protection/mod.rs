use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ipnet::IpNet;
use tokio::time::Instant;

use crate::config::Protection;

const SHARD_COUNT: usize = 16;
const STALE_AFTER: Duration = Duration::from_secs(600);
const GLOBAL_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    RateLimited { retry_after: Duration },
    Banned { retry_after: Duration },
    Overloaded { retry_after: Duration },
}

pub struct ProtectionState {
    shards: Vec<Mutex<Shard>>,
    global_connections: AtomicU32,
    global_requests: Mutex<GlobalWindow>,
}

impl ProtectionState {
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Shard::default()))
            .collect();
        Self {
            shards,
            global_connections: AtomicU32::new(0),
            global_requests: Mutex::new(GlobalWindow {
                started: Instant::now(),
                count: 0,
            }),
        }
    }

    pub fn active_connections(&self) -> u64 {
        u64::from(self.global_connections.load(Ordering::Relaxed))
    }

    pub fn check_request(&self, ip: IpAddr, config: &Protection) -> Decision {
        if !config.enabled || is_allowlisted(ip, &config.allowlist) {
            return Decision::Allow;
        }

        if let Some(decision) = self.check_client(ip, config) {
            return decision;
        }

        self.check_global(config)
    }

    pub fn try_acquire_connection(
        self: &Arc<Self>,
        ip: IpAddr,
        config: &Protection,
    ) -> Option<ConnectionGuard> {
        if !config.enabled {
            return Some(ConnectionGuard {
                state: Arc::clone(self),
                ip,
                per_ip: false,
                counted: false,
            });
        }

        if self.global_connections.fetch_add(1, Ordering::AcqRel) + 1 > config.max_connections {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        if is_allowlisted(ip, &config.allowlist) {
            return Some(ConnectionGuard {
                state: Arc::clone(self),
                ip,
                per_ip: false,
                counted: true,
            });
        }

        let now = Instant::now();
        let mut shard = lock(&self.shards[shard_index(ip)]);

        if !shard.entries.contains_key(&ip) {
            if shard.entries.len() >= config.max_tracked_ips {
                evict_stale(&mut shard.entries, now);
            }
            if shard.entries.len() >= config.max_tracked_ips {
                drop(shard);
                return Some(ConnectionGuard {
                    state: Arc::clone(self),
                    ip,
                    per_ip: false,
                    counted: true,
                });
            }
            shard.entries.insert(ip, Entry::new(now, config.burst));
        }

        let Some(entry) = shard.entries.get_mut(&ip) else {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return None;
        };

        if entry.connections >= config.max_connections_per_ip {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        entry.connections += 1;
        entry.last_seen = now;
        drop(shard);

        Some(ConnectionGuard {
            state: Arc::clone(self),
            ip,
            per_ip: true,
            counted: true,
        })
    }

    fn check_client(&self, ip: IpAddr, config: &Protection) -> Option<Decision> {
        let now = Instant::now();
        let mut shard = lock(&self.shards[shard_index(ip)]);

        if !shard.entries.contains_key(&ip) {
            if shard.entries.len() >= config.max_tracked_ips {
                evict_stale(&mut shard.entries, now);
            }
            if shard.entries.len() >= config.max_tracked_ips {
                return None;
            }
            shard.entries.insert(ip, Entry::new(now, config.burst));
        }

        let entry = shard.entries.get_mut(&ip)?;
        entry.last_seen = now;

        if let Some(until) = entry.banned_until {
            if now < until {
                return Some(Decision::Banned {
                    retry_after: until.saturating_duration_since(now),
                });
            }
            entry.banned_until = None;
            entry.violations = 0;
            entry.window_start = now;
        }

        let elapsed = now
            .saturating_duration_since(entry.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            entry.tokens = (entry.tokens + elapsed * config.requests_per_second).min(config.burst);
            entry.last_refill = now;
        }

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            return None;
        }

        if now.saturating_duration_since(entry.window_start) > config.ban.window {
            entry.window_start = now;
            entry.violations = 0;
        }
        entry.violations += 1;

        if entry.violations >= config.ban.violations {
            entry.violations = 0;
            entry.window_start = now;
            entry.ban_count = entry.ban_count.saturating_add(1);
            let duration = escalated_duration(
                config.ban.duration,
                config.ban.max_duration,
                entry.ban_count,
            );
            entry.banned_until = Some(now + duration);
            return Some(Decision::Banned {
                retry_after: duration,
            });
        }

        let deficit = (1.0 - entry.tokens).max(0.001);
        let retry_after = Duration::from_secs_f64(deficit / config.requests_per_second);
        Some(Decision::RateLimited { retry_after })
    }

    fn check_global(&self, config: &Protection) -> Decision {
        let now = Instant::now();
        let mut window = lock(&self.global_requests);

        if now.saturating_duration_since(window.started) >= GLOBAL_WINDOW {
            window.started = now;
            window.count = 0;
        }
        window.count += 1;

        if window.count as f64 > config.global_requests_per_second {
            return Decision::Overloaded {
                retry_after: GLOBAL_WINDOW,
            };
        }

        Decision::Allow
    }
}

impl Default for ProtectionState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConnectionGuard {
    state: Arc<ProtectionState>,
    ip: IpAddr,
    per_ip: bool,
    counted: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.counted {
            self.state.global_connections.fetch_sub(1, Ordering::AcqRel);
        }
        if self.per_ip {
            let mut shard = lock(&self.state.shards[shard_index(self.ip)]);
            if let Some(entry) = shard.entries.get_mut(&self.ip) {
                entry.connections = entry.connections.saturating_sub(1);
            }
        }
    }
}

#[derive(Default)]
struct Shard {
    entries: HashMap<IpAddr, Entry>,
}

struct Entry {
    tokens: f64,
    last_refill: Instant,
    violations: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
    ban_count: u32,
    connections: u32,
    last_seen: Instant,
}

impl Entry {
    fn new(now: Instant, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
            violations: 0,
            window_start: now,
            banned_until: None,
            ban_count: 0,
            connections: 0,
            last_seen: now,
        }
    }
}

struct GlobalWindow {
    started: Instant,
    count: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn is_allowlisted(ip: IpAddr, allowlist: &[IpNet]) -> bool {
    allowlist.iter().any(|network| network.contains(&ip))
}

fn shard_index(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(address) => (u32::from(address) as usize) % SHARD_COUNT,
        IpAddr::V6(address) => {
            let mut hash = 0usize;
            for chunk in address.octets().chunks(8) {
                let mut value = 0u64;
                for byte in chunk {
                    value = value.wrapping_mul(31).wrapping_add(u64::from(*byte));
                }
                hash = hash.wrapping_mul(31).wrapping_add(value as usize);
            }
            hash % SHARD_COUNT
        }
    }
}

fn evict_stale(entries: &mut HashMap<IpAddr, Entry>, now: Instant) {
    entries.retain(|_, entry| {
        entry.connections > 0
            || entry.banned_until.is_some_and(|until| until > now)
            || now.saturating_duration_since(entry.last_seen) < STALE_AFTER
    });
}

fn escalated_duration(base: Duration, max: Duration, ban_count: u32) -> Duration {
    let shift = ban_count.saturating_sub(1).min(16);
    let factor = 1u32 << shift;
    base.checked_mul(factor).unwrap_or(max).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BanConfig;

    fn config() -> Protection {
        Protection {
            enabled: true,
            allowlist: Vec::new(),
            max_connections_per_ip: 32,
            max_connections: 1024,
            requests_per_second: 1.0,
            burst: 2.0,
            global_requests_per_second: 1000.0,
            max_tracked_ips: 100,
            ban: BanConfig {
                violations: 2,
                window: Duration::from_secs(10),
                duration: Duration::from_secs(60),
                max_duration: Duration::from_secs(600),
            },
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("valid IP")
    }

    #[tokio::test(start_paused = true)]
    async fn burst_allows_then_rate_limits() {
        let state = ProtectionState::new();
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config()),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config()),
            Decision::Allow
        );
        let decision = state.check_request(ip("10.0.0.1"), &config());
        assert!(matches!(decision, Decision::RateLimited { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn tokens_refill_over_time() {
        let state = ProtectionState::new();
        let config = config();
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::RateLimited { .. }
        ));

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_violations_lead_to_ban() {
        let state = ProtectionState::new();
        let config = config();

        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::RateLimited { .. }
        ));
        let decision = state.check_request(ip("10.0.0.1"), &config);
        assert!(matches!(decision, Decision::Banned { .. }));

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Banned { .. }
        ));

        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
    }

    #[tokio::test(start_paused = true)]
    async fn allowlist_is_exempt() {
        let state = ProtectionState::new();
        let mut config = config();
        config.allowlist = vec!["10.0.0.0/8".parse().expect("valid CIDR")];
        for _ in 0..10 {
            assert_eq!(
                state.check_request(ip("10.0.0.1"), &config),
                Decision::Allow
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_protection_allows_everything() {
        let state = ProtectionState::new();
        let mut config = config();
        config.enabled = false;
        for _ in 0..10 {
            assert_eq!(
                state.check_request(ip("10.0.0.1"), &config),
                Decision::Allow
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn global_connection_budget_is_enforced() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_connections = 2;

        let first = state.try_acquire_connection(ip("10.0.0.1"), &config);
        let second = state.try_acquire_connection(ip("10.0.0.2"), &config);
        assert!(first.is_some());
        assert!(second.is_some());
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.3"), &config)
                .is_none()
        );

        drop(first);
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.3"), &config)
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn per_ip_connection_budget_is_enforced() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_connections_per_ip = 1;

        let guard = state.try_acquire_connection(ip("10.0.0.1"), &config);
        assert!(guard.is_some());
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.1"), &config)
                .is_none()
        );
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.2"), &config)
                .is_some()
        );

        drop(guard);
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.1"), &config)
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn global_rate_guard_sheds_load() {
        let state = ProtectionState::new();
        let mut config = config();
        config.global_requests_per_second = 2.0;

        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("10.0.0.2"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.3"), &config),
            Decision::Overloaded { .. }
        ));

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            state.check_request(ip("10.0.0.4"), &config),
            Decision::Allow
        );
    }

    #[test]
    fn lock_recovers_from_poisoned_mutex() {
        let mutex = Arc::new(Mutex::new(1u32));
        let clone = Arc::clone(&mutex);
        let _ = std::thread::spawn(move || {
            let _guard = clone.lock().expect("lock");
            panic!("poison the mutex");
        })
        .join();
        assert_eq!(*lock(&mutex), 1);
    }
}
