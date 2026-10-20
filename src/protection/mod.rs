use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use http::StatusCode;
use ipnet::IpNet;
use regex::RegexSet;
use tokio::time::Instant;

use crate::config::{BehaviorAction, BehaviorConfig, Protection, RuleLimit, RuleLimitKey};
use crate::decoding::{normalize_path, percent_decode_forms};

const SHARD_COUNT: usize = 16;
const STALE_AFTER: Duration = Duration::from_secs(600);
const GLOBAL_WINDOW: Duration = Duration::from_secs(1);
/// One rate-limit token covers this many inspected body bytes. A 1 MiB body
/// therefore costs about four extra tokens on top of the admission token.
const INSPECTION_BYTES_PER_TOKEN: f64 = 256.0 * 1024.0;
const MAX_INSPECTION_COST: f64 = 64.0;

fn inspection_cost(bytes: usize) -> f64 {
    (bytes as f64 / INSPECTION_BYTES_PER_TOKEN).min(MAX_INSPECTION_COST)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    RateLimited { retry_after: Duration },
    Banned { retry_after: Duration },
    Overloaded { retry_after: Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorSignal {
    Enumeration,
    AuthAbuse,
}

impl BehaviorSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enumeration => "enumeration",
            Self::AuthAbuse => "auth-abuse",
        }
    }
}

#[derive(Debug)]
pub struct BehaviorFlag {
    pub signal: BehaviorSignal,
    pub action: BehaviorAction,
    pub requests: u32,
    pub not_found: u32,
    pub distinct_paths: u32,
    pub auth_failures: u32,
    pub ban: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalAuthFlag {
    pub failures: u32,
    pub window: Duration,
}

#[derive(Debug, Default)]
pub struct BehaviorOutcome {
    pub observed_not_found: bool,
    pub observed_auth_failure: bool,
    pub source: Option<BehaviorFlag>,
    pub global: Option<GlobalAuthFlag>,
}

pub struct ProtectionState {
    shards: Vec<Mutex<Shard>>,
    rule_shards: Vec<Mutex<RuleShard>>,
    global_connections: AtomicU32,
    active_connections: AtomicU64,
    tracked_ips: AtomicUsize,
    tracked_rules: AtomicUsize,
    global_requests: Mutex<GlobalWindow>,
    global_auth: Mutex<GlobalAuthWindow>,
}

impl ProtectionState {
    pub fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Shard::default()))
            .collect();
        let rule_shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(RuleShard::default()))
            .collect();
        Self {
            shards,
            rule_shards,
            global_connections: AtomicU32::new(0),
            active_connections: AtomicU64::new(0),
            tracked_ips: AtomicUsize::new(0),
            tracked_rules: AtomicUsize::new(0),
            global_requests: Mutex::new(GlobalWindow {
                started: Instant::now(),
                count: 0.0,
            }),
            global_auth: Mutex::new(GlobalAuthWindow {
                started: Instant::now(),
                failures: 0,
                logged: false,
            }),
        }
    }

    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn check_request(&self, ip: IpAddr, config: &Protection) -> Decision {
        if !config.enabled || is_allowlisted(normalize_ip(ip), &config.allowlist) {
            return Decision::Allow;
        }

        if let Some(decision) = self.check_client(tracking_key(ip, config), config, 1.0) {
            return decision;
        }

        self.check_global(config, 1.0)
    }

    /// Charge the source for inspecting a body of `bytes` bytes. Admission has
    /// already paid one token, so this only bills the extra inspection work;
    /// large bodies therefore consume the rate budget faster than small ones.
    pub fn charge_inspection(&self, ip: IpAddr, config: &Protection, bytes: usize) -> Decision {
        if !config.enabled || is_allowlisted(normalize_ip(ip), &config.allowlist) {
            return Decision::Allow;
        }

        let cost = inspection_cost(bytes);
        if cost <= 0.0 {
            return Decision::Allow;
        }
        if let Some(decision) = self.check_client(tracking_key(ip, config), config, cost) {
            return decision;
        }

        self.check_global(config, cost)
    }

    /// Ban-only check for callers that need to reject a banned source without
    /// consuming rate budget. Normal request handling uses the full admission
    /// check, which also charges the rate budget.
    pub fn check_banned(&self, ip: IpAddr, config: &Protection) -> Option<Decision> {
        if !config.enabled || is_allowlisted(normalize_ip(ip), &config.allowlist) {
            return None;
        }

        let key = tracking_key(ip, config);
        let now = Instant::now();
        let mut shard = lock(&self.shards[shard_index(key)]);
        let entry = shard.entries.get_mut(&key)?;
        let until = entry.banned_until?;
        if now < until {
            Some(Decision::Banned {
                retry_after: until.saturating_duration_since(now),
            })
        } else {
            entry.banned_until = None;
            entry.violations = 0;
            entry.window_start = now;
            None
        }
    }

    /// Observe an upstream response for the behavioral signals. The returned
    /// outcome tells the proxy layer which counters to increment and which
    /// flags to log. Local responses (rule blocks, errors) are never passed
    /// here.
    pub fn observe_response(
        &self,
        ip: IpAddr,
        path: &str,
        status: StatusCode,
        config: &Protection,
    ) -> BehaviorOutcome {
        let behavior = &config.behavior;
        if !config.enabled
            || !behavior.enabled
            || is_allowlisted(normalize_ip(ip), &config.allowlist)
        {
            return BehaviorOutcome::default();
        }

        let enumeration_enabled = behavior.enumeration.enabled;
        let auth_enabled = behavior.auth.enabled;
        let global_enabled = behavior.global_auth.enabled;
        let auth_failure = (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN)
            && (auth_enabled || global_enabled)
            && auth_path_matches(&behavior.auth.paths, path);

        if !enumeration_enabled && !auth_failure {
            return BehaviorOutcome::default();
        }

        let mut outcome = BehaviorOutcome::default();
        let now = Instant::now();
        let key = tracking_key(ip, config);

        {
            let mut shard = lock(&self.shards[shard_index(key)]);
            let Some(entry) = shard.entries.get_mut(&key) else {
                drop(shard);
                self.observe_global_auth(auth_failure, now, config, &mut outcome);
                return outcome;
            };

            if entry.banned_until.is_some_and(|until| until > now) {
                return outcome;
            }

            entry.last_seen = now;
            entry.behavior.roll(now, behavior.window);

            if enumeration_enabled {
                entry.behavior.requests = entry.behavior.requests.saturating_add(1);
                if status == StatusCode::NOT_FOUND {
                    let normalized = normalize_path(path);
                    let normalized = normalized.as_deref().unwrap_or(path);
                    if !is_static_asset(normalized) {
                        entry.behavior.not_found = entry.behavior.not_found.saturating_add(1);
                        entry.behavior.add_path(normalized);
                        outcome.observed_not_found = true;
                    }
                }
            }

            if auth_enabled && auth_failure {
                entry.behavior.auth_failures = entry.behavior.auth_failures.saturating_add(1);
                outcome.observed_auth_failure = true;
            }

            if enumeration_enabled
                && entry.behavior.flags & BehaviorEntry::ENUMERATION_FLAG == 0
                && enumeration_flagged(entry, behavior)
            {
                entry.behavior.flags |= BehaviorEntry::ENUMERATION_FLAG;
                let mut flag = BehaviorFlag {
                    signal: BehaviorSignal::Enumeration,
                    action: behavior.enumeration.action,
                    requests: entry.behavior.requests,
                    not_found: entry.behavior.not_found,
                    distinct_paths: entry.behavior.distinct_paths(),
                    auth_failures: entry.behavior.auth_failures,
                    ban: None,
                };
                if behavior.enumeration.action == BehaviorAction::Block {
                    flag.ban = Some(apply_behavior_ban(entry, config, now));
                    entry.behavior.reset(now);
                }
                outcome.source = Some(flag);
            }

            if auth_enabled
                && auth_failure
                && entry.behavior.flags & BehaviorEntry::AUTH_FLAG == 0
                && entry.behavior.auth_failures >= behavior.auth.min_failures
            {
                entry.behavior.flags |= BehaviorEntry::AUTH_FLAG;
                let mut flag = BehaviorFlag {
                    signal: BehaviorSignal::AuthAbuse,
                    action: behavior.auth.action,
                    requests: entry.behavior.requests,
                    not_found: entry.behavior.not_found,
                    distinct_paths: entry.behavior.distinct_paths(),
                    auth_failures: entry.behavior.auth_failures,
                    ban: None,
                };
                if behavior.auth.action == BehaviorAction::Block {
                    flag.ban = Some(apply_behavior_ban(entry, config, now));
                    entry.behavior.reset(now);
                }
                outcome.source = Some(flag);
            }
        }

        self.observe_global_auth(auth_failure, now, config, &mut outcome);
        outcome
    }

    fn observe_global_auth(
        &self,
        auth_failure: bool,
        now: Instant,
        config: &Protection,
        outcome: &mut BehaviorOutcome,
    ) {
        if !auth_failure || !config.behavior.global_auth.enabled {
            return;
        }

        outcome.observed_auth_failure = true;
        let mut window = lock(&self.global_auth);
        if now.saturating_duration_since(window.started) >= config.behavior.global_auth.window {
            window.started = now;
            window.failures = 0;
            window.logged = false;
        }
        window.failures = window.failures.saturating_add(1);
        if !window.logged && window.failures >= config.behavior.global_auth.min_failures {
            window.logged = true;
            outcome.global = Some(GlobalAuthFlag {
                failures: window.failures,
                window: config.behavior.global_auth.window,
            });
        }
    }

    pub fn try_acquire_connection(
        self: &Arc<Self>,
        ip: IpAddr,
        config: &Protection,
    ) -> Option<ConnectionGuard> {
        let key = tracking_key(ip, config);

        if !config.enabled || is_allowlisted(normalize_ip(ip), &config.allowlist) {
            return Some(self.connection_guard(key, false, false));
        }

        if self
            .global_connections
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |count| {
                (count < config.max_connections).then(|| count + 1)
            })
            .is_err()
        {
            return None;
        }

        let now = Instant::now();
        let Some(mut shard) = self.client_shard(key, config, now) else {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return None;
        };

        let Some(entry) = shard.entries.get_mut(&key) else {
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

        Some(self.connection_guard(key, true, true))
    }

    fn connection_guard(
        self: &Arc<Self>,
        key: IpAddr,
        per_ip: bool,
        counted: bool,
    ) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard {
            state: Arc::clone(self),
            key,
            per_ip,
            counted,
        }
    }

    fn client_shard(
        &self,
        key: IpAddr,
        config: &Protection,
        now: Instant,
    ) -> Option<MutexGuard<'_, Shard>> {
        let mut shard = lock(&self.shards[shard_index(key)]);
        if shard.entries.contains_key(&key) {
            return Some(shard);
        }
        if !reserve_slot(&self.tracked_ips, config.max_tracked_ips) {
            drop(shard);
            for shard in &self.shards {
                let mut shard = lock(shard);
                let before = shard.entries.len();
                evict_stale(&mut shard.entries, now);
                self.tracked_ips
                    .fetch_sub(before - shard.entries.len(), Ordering::AcqRel);
            }
            shard = lock(&self.shards[shard_index(key)]);
            if shard.entries.contains_key(&key) {
                return Some(shard);
            }
            if !reserve_slot(&self.tracked_ips, config.max_tracked_ips) {
                // The table is full of recently active sources. Evict the
                // least recently seen idle entry in this shard so a new client
                // is still tracked; active connections and live bans stay.
                if !evict_oldest(&mut shard.entries, now) {
                    return None;
                }
                shard.entries.insert(key, Entry::new(now, config.burst));
                return Some(shard);
            }
        }
        shard.entries.insert(key, Entry::new(now, config.burst));
        Some(shard)
    }

    fn check_client(&self, key: IpAddr, config: &Protection, cost: f64) -> Option<Decision> {
        let now = Instant::now();
        let Some(mut shard) = self.client_shard(key, config, now) else {
            return Some(Decision::Overloaded {
                retry_after: GLOBAL_WINDOW,
            });
        };

        let entry = shard.entries.get_mut(&key)?;
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

        if entry.tokens >= cost {
            entry.tokens -= cost;
            return None;
        }

        if now.saturating_duration_since(entry.window_start) > config.ban.window {
            entry.window_start = now;
            entry.violations = 0;
        }
        entry.violations = entry.violations.saturating_add(1);

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
            entry.behavior.reset(now);
            return Some(Decision::Banned {
                retry_after: duration,
            });
        }

        let deficit = (cost - entry.tokens).max(0.001);
        let retry_after = Duration::try_from_secs_f64(deficit / config.requests_per_second)
            .unwrap_or(Duration::MAX);
        Some(Decision::RateLimited { retry_after })
    }

    fn check_global(&self, config: &Protection, cost: f64) -> Decision {
        let now = Instant::now();
        let mut window = lock(&self.global_requests);

        if now.saturating_duration_since(window.started) >= GLOBAL_WINDOW {
            window.started = now;
            window.count = 0.0;
        }
        window.count += cost;

        if window.count > config.global_requests_per_second {
            return Decision::Overloaded {
                retry_after: GLOBAL_WINDOW,
            };
        }

        Decision::Allow
    }

    /// Returns `true` while `ip` stays within the rule's budget of
    /// `limit.requests` per `limit.window` (burst up to `requests`).
    pub fn check_rule_limit(
        &self,
        key: &RuleLimitKey,
        ip: IpAddr,
        limit: &RuleLimit,
        config: &Protection,
    ) -> bool {
        if !config.enabled || is_allowlisted(normalize_ip(ip), &config.allowlist) {
            return true;
        }

        let now = Instant::now();
        let tracking = tracking_key(ip, config);
        let map_key = (Arc::clone(key), tracking);
        let mut shard = lock(&self.rule_shards[shard_index(tracking)]);

        if !shard.entries.contains_key(&map_key) {
            if !reserve_slot(&self.tracked_rules, config.max_tracked_ips) {
                drop(shard);
                for shard in &self.rule_shards {
                    let mut shard = lock(shard);
                    let before = shard.entries.len();
                    shard.entries.retain(|_, bucket| {
                        now.saturating_duration_since(bucket.last_seen) < bucket.retention
                    });
                    self.tracked_rules
                        .fetch_sub(before - shard.entries.len(), Ordering::AcqRel);
                }
                shard = lock(&self.rule_shards[shard_index(tracking)]);
                if !shard.entries.contains_key(&map_key) {
                    if !reserve_slot(&self.tracked_rules, config.max_tracked_ips) {
                        return false;
                    }
                    let burst = f64::from(limit.requests);
                    shard
                        .entries
                        .insert(map_key.clone(), RuleBucket::new(now, burst, limit.window));
                }
            } else {
                let burst = f64::from(limit.requests);
                shard
                    .entries
                    .insert(map_key.clone(), RuleBucket::new(now, burst, limit.window));
            }
        }

        let Some(bucket) = shard.entries.get_mut(&map_key) else {
            return false;
        };
        bucket.last_seen = now;
        bucket.retention = limit.window.max(STALE_AFTER);

        let burst = f64::from(limit.requests);
        let rate = burst / limit.window.as_secs_f64().max(0.001);
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Rule-conditioned rate limiting as seen by the evaluation engine: a rule
/// stays transparent while its source is within budget and fires beyond it.
pub trait RuleLimitCheck {
    /// Returns `true` while `ip` stays within the rule's budget.
    fn permit(
        &self,
        key: &RuleLimitKey,
        ip: IpAddr,
        limit: &RuleLimit,
        protection: &Protection,
    ) -> bool;
}

impl RuleLimitCheck for ProtectionState {
    fn permit(
        &self,
        key: &RuleLimitKey,
        ip: IpAddr,
        limit: &RuleLimit,
        protection: &Protection,
    ) -> bool {
        self.check_rule_limit(key, ip, limit, protection)
    }
}

impl Default for ProtectionState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConnectionGuard {
    state: Arc<ProtectionState>,
    key: IpAddr,
    per_ip: bool,
    counted: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        if self.counted {
            self.state.global_connections.fetch_sub(1, Ordering::AcqRel);
        }
        if self.per_ip {
            let mut shard = lock(&self.state.shards[shard_index(self.key)]);
            if let Some(entry) = shard.entries.get_mut(&self.key) {
                entry.connections = entry.connections.saturating_sub(1);
            }
        }
    }
}

#[derive(Default)]
struct Shard {
    entries: HashMap<IpAddr, Entry>,
}

#[derive(Default)]
struct RuleShard {
    entries: HashMap<(RuleLimitKey, IpAddr), RuleBucket>,
}

struct RuleBucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
    retention: Duration,
}

impl RuleBucket {
    fn new(now: Instant, burst: f64, window: Duration) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
            last_seen: now,
            retention: window.max(STALE_AFTER),
        }
    }
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
    behavior: BehaviorEntry,
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
            behavior: BehaviorEntry::new(now),
        }
    }
}

struct BehaviorEntry {
    window_start: Instant,
    requests: u32,
    not_found: u32,
    auth_failures: u32,
    not_found_paths: [u64; 4],
    flags: u8,
}

impl BehaviorEntry {
    const ENUMERATION_FLAG: u8 = 1;
    const AUTH_FLAG: u8 = 2;

    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            requests: 0,
            not_found: 0,
            auth_failures: 0,
            not_found_paths: [0; 4],
            flags: 0,
        }
    }

    fn reset(&mut self, now: Instant) {
        *self = Self::new(now);
    }

    fn roll(&mut self, now: Instant, window: Duration) {
        if now.saturating_duration_since(self.window_start) >= window {
            self.reset(now);
        }
    }

    fn add_path(&mut self, path: &str) {
        let hash = mix64(fnv1a64(path));
        let first = (hash & 0xff) as usize;
        let second = ((hash >> 32) & 0xff) as usize;
        self.not_found_paths[first / 64] |= 1u64 << (first % 64);
        self.not_found_paths[second / 64] |= 1u64 << (second % 64);
    }

    fn distinct_paths(&self) -> u32 {
        let set_bits: u32 = self
            .not_found_paths
            .iter()
            .map(|word| word.count_ones())
            .sum();
        if set_bits >= 256 {
            return 256;
        }
        let ratio = f64::from(set_bits) / 256.0;
        let estimate = -128.0 * (1.0 - ratio).ln();
        estimate.round().clamp(0.0, 256.0) as u32
    }
}

struct GlobalAuthWindow {
    started: Instant,
    failures: u32,
    logged: bool,
}

struct GlobalWindow {
    started: Instant,
    count: f64,
}

fn enumeration_flagged(entry: &Entry, behavior: &BehaviorConfig) -> bool {
    if entry.behavior.requests == 0 {
        return false;
    }
    entry.behavior.requests >= behavior.min_requests
        && f64::from(entry.behavior.not_found) / f64::from(entry.behavior.requests)
            >= behavior.enumeration.not_found_ratio
        && entry.behavior.distinct_paths() >= behavior.enumeration.distinct_paths
}

fn apply_behavior_ban(entry: &mut Entry, config: &Protection, now: Instant) -> Duration {
    entry.violations = 0;
    entry.window_start = now;
    entry.ban_count = entry.ban_count.saturating_add(1);
    let duration = escalated_duration(
        config.ban.duration,
        config.ban.max_duration,
        entry.ban_count,
    );
    entry.banned_until = Some(now + duration);
    duration
}

fn fnv1a64(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// SplitMix64 finalizer: FNV-1a has weak diffusion in the low bits for short
/// strings, which would make the two Bloom-filter bit positions correlate.
fn mix64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
}

fn auth_path_matches(paths: &RegexSet, path: &str) -> bool {
    for form in percent_decode_forms(path) {
        let normalized = normalize_path(form.as_ref());
        let candidate = normalized.as_deref().unwrap_or(form.as_ref());
        if paths.is_match(candidate) {
            return true;
        }
    }
    false
}

fn is_static_asset(path: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/static/",
        "/assets/",
        "/build/",
        "/dist/",
        "/_next/static/",
        "/images/",
        "/img/",
        "/fonts/",
        "/media/",
    ];
    const EXACT: &[&str] = &[
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap.xml.gz",
        "/manifest.json",
        "/site.webmanifest",
    ];
    const EXTENSIONS: &[&str] = &[
        "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico",
        "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "wav", "ogg", "flac", "m4a",
    ];

    if PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }
    if EXACT
        .iter()
        .any(|candidate| path.eq_ignore_ascii_case(candidate))
    {
        return true;
    }
    let basename = path.rsplit('/').next().unwrap_or(path);
    let Some((_, extension)) = basename.rsplit_once('.') else {
        return false;
    };
    let extension = extension.to_ascii_lowercase();
    EXTENSIONS.contains(&extension.as_str())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn is_allowlisted(ip: IpAddr, allowlist: &[IpNet]) -> bool {
    allowlist.iter().any(|network| network.contains(&ip))
}

pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(address),
        },
        address => address,
    }
}

fn tracking_key(ip: IpAddr, config: &Protection) -> IpAddr {
    match normalize_ip(ip) {
        IpAddr::V6(address) => IpAddr::V6(mask_ipv6(address, config.aggregate_ipv6_prefix)),
        address => address,
    }
}

fn mask_ipv6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix >= 128 {
        return address;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    Ipv6Addr::from(u128::from(address) & mask)
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

/// Remove the least recently seen entry that is neither connected nor banned.
/// Used only when the tracking table is otherwise full, so an attacker that
/// occupies every slot cannot deny service to new sources.
fn evict_oldest(entries: &mut HashMap<IpAddr, Entry>, now: Instant) -> bool {
    let candidate = entries
        .iter()
        .filter(|(_, entry)| {
            entry.connections == 0 && !entry.banned_until.is_some_and(|until| until > now)
        })
        .min_by_key(|(_, entry)| entry.last_seen)
        .map(|(key, _)| *key);
    candidate.is_some_and(|key| entries.remove(&key).is_some())
}

fn reserve_slot(counter: &AtomicUsize, limit: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |count| {
            (count < limit).then(|| count + 1)
        })
        .is_ok()
}

fn escalated_duration(base: Duration, max: Duration, ban_count: u32) -> Duration {
    let shift = ban_count.saturating_sub(1).min(16);
    let factor = 1u32 << shift;
    base.checked_mul(factor).unwrap_or(max).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, BanConfig, EnumerationConfig, GlobalAuthConfig};

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
            aggregate_ipv6_prefix: 64,
            ban: BanConfig {
                violations: 2,
                window: Duration::from_secs(10),
                duration: Duration::from_secs(60),
                max_duration: Duration::from_secs(600),
            },
            behavior: BehaviorConfig::default(),
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
    async fn inspection_cost_consumes_extra_tokens() {
        let state = ProtectionState::new();
        let config = config();
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.charge_inspection(ip("10.0.0.1"), &config, 256 * 1024),
            Decision::Allow
        );
        assert!(matches!(
            state.charge_inspection(ip("10.0.0.1"), &config, 256 * 1024),
            Decision::RateLimited { .. }
        ));

        let mut allowlisted = config;
        allowlisted.allowlist = vec!["10.0.0.0/8".parse().expect("valid CIDR")];
        assert_eq!(
            state.charge_inspection(ip("10.0.0.2"), &allowlisted, 1024 * 1024),
            Decision::Allow
        );
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
    async fn ban_precheck_reports_tracked_bans_only() {
        let state = ProtectionState::new();
        let config = config();
        assert!(state.check_banned(ip("10.0.0.1"), &config).is_none());

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
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Banned { .. }
        ));

        assert!(matches!(
            state.check_banned(ip("10.0.0.1"), &config),
            Some(Decision::Banned { .. })
        ));
        assert!(state.check_banned(ip("10.0.0.2"), &config).is_none());

        let mut allowlisted = config.clone();
        allowlisted.allowlist = vec!["10.0.0.0/8".parse().expect("valid CIDR")];
        assert!(state.check_banned(ip("10.0.0.1"), &allowlisted).is_none());

        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(state.check_banned(ip("10.0.0.1"), &config).is_none());
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

    #[tokio::test(start_paused = true)]
    async fn ipv6_addresses_in_one_prefix_share_budget() {
        let state = ProtectionState::new();
        let config = config();

        assert_eq!(
            state.check_request(ip("2001:db8:1:2::1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("2001:db8:1:2::2"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("2001:db8:1:2::3"), &config),
            Decision::RateLimited { .. }
        ));
        assert!(matches!(
            state.check_request(ip("2001:db8:1:2::4"), &config),
            Decision::Banned { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_prefixes_are_tracked_separately() {
        let state = ProtectionState::new();
        let config = config();

        assert_eq!(
            state.check_request(ip("2001:db8:1:2::1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("2001:db8:1:3::1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("2001:db8:1:3::2"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("2001:db8:1:3::3"), &config),
            Decision::RateLimited { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_prefix_128_tracks_each_address() {
        let state = ProtectionState::new();
        let mut config = config();
        config.aggregate_ipv6_prefix = 128;

        assert_eq!(
            state.check_request(ip("2001:db8::1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("2001:db8::2"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("2001:db8::1"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("2001:db8::1"), &config),
            Decision::RateLimited { .. }
        ));
        assert_eq!(
            state.check_request(ip("2001:db8::2"), &config),
            Decision::Allow
        );
    }

    #[tokio::test(start_paused = true)]
    async fn v4_mapped_addresses_share_ipv4_state() {
        let state = ProtectionState::new();
        let config = config();

        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert_eq!(
            state.check_request(ip("::ffff:10.0.0.1"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::RateLimited { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn v4_mapped_addresses_match_ipv4_allowlist() {
        let state = ProtectionState::new();
        let mut config = config();
        config.allowlist = vec!["10.0.0.0/8".parse().expect("valid CIDR")];
        for _ in 0..10 {
            assert_eq!(
                state.check_request(ip("::ffff:10.0.0.1"), &config),
                Decision::Allow
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn per_ip_connection_budget_aggregates_ipv6_prefix() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_connections_per_ip = 1;

        let guard = state.try_acquire_connection(ip("2001:db8::1"), &config);
        assert!(guard.is_some());
        assert!(
            state
                .try_acquire_connection(ip("2001:db8::2"), &config)
                .is_none()
        );
        assert!(
            state
                .try_acquire_connection(ip("2001:db8:0:1::1"), &config)
                .is_some()
        );

        drop(guard);
        assert!(
            state
                .try_acquire_connection(ip("2001:db8::2"), &config)
                .is_some()
        );
    }

    fn rule_limit(requests: u32, window_secs: u64) -> RuleLimit {
        RuleLimit {
            requests,
            window: Duration::from_secs(window_secs),
        }
    }

    fn rule_key(number: u32) -> RuleLimitKey {
        Arc::new(("test".to_owned(), number.to_string()))
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limit_allows_burst_then_blocks() {
        let state = ProtectionState::new();
        let config = config();
        let limit = rule_limit(2, 10);

        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
        assert!(!state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limit_refills_over_time() {
        let state = ProtectionState::new();
        let config = config();
        let limit = rule_limit(2, 10);

        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
        assert!(!state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limits_are_isolated_per_rule_and_source() {
        let state = ProtectionState::new();
        let config = config();
        let limit = rule_limit(1, 10);

        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));
        assert!(!state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &config));

        assert!(state.check_rule_limit(&rule_key(8), ip("10.0.0.1"), &limit, &config));
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.2"), &limit, &config));
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limit_aggregates_ipv6_prefixes() {
        let state = ProtectionState::new();
        let config = config();
        let limit = rule_limit(1, 10);

        assert!(state.check_rule_limit(&rule_key(7), ip("2001:db8:1:2::1"), &limit, &config));
        assert!(!state.check_rule_limit(&rule_key(7), ip("2001:db8:1:2::2"), &limit, &config));
    }

    #[tokio::test(start_paused = true)]
    async fn rule_limit_skips_allowlisted_and_disabled_sources() {
        let state = ProtectionState::new();
        let limit = rule_limit(1, 10);

        let mut allowlisted = config();
        allowlisted.allowlist = vec!["10.0.0.0/8".parse().expect("valid CIDR")];
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &allowlisted));
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.1"), &limit, &allowlisted));

        let mut disabled = config();
        disabled.enabled = false;
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.9"), &limit, &disabled));
        assert!(state.check_rule_limit(&rule_key(7), ip("10.0.0.9"), &limit, &disabled));
    }

    #[tokio::test(start_paused = true)]
    async fn full_tracking_is_global_and_does_not_permit_untracked_sources() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_tracked_ips = 1;
        let first = state
            .try_acquire_connection(ip("10.0.0.1"), &config)
            .expect("first connection");
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.2"), &config)
                .is_none()
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.2"), &config),
            Decision::Overloaded { .. }
        ));
        assert_eq!(state.tracked_ips.load(Ordering::Relaxed), 1);
        drop(first);
        tokio::time::advance(STALE_AFTER).await;
        assert!(
            state
                .try_acquire_connection(ip("10.0.0.2"), &config)
                .is_some()
        );
        assert_eq!(state.tracked_ips.load(Ordering::Relaxed), 1);

        let limit = rule_limit(1, 3600);
        assert!(state.check_rule_limit(&rule_key(1), ip("10.0.0.1"), &limit, &config));
        assert!(!state.check_rule_limit(&rule_key(2), ip("10.0.0.2"), &limit, &config));
        tokio::time::advance(STALE_AFTER).await;
        assert!(!state.check_rule_limit(&rule_key(2), ip("10.0.0.2"), &limit, &config));
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(state.check_rule_limit(&rule_key(2), ip("10.0.0.2"), &limit, &config));
        assert_eq!(state.tracked_rules.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn full_tracking_evicts_the_oldest_idle_source() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_tracked_ips = 2;

        // These IPv4 addresses share one shard: 10.0.0.1, .17, and .33 all
        // hash to shard 1, so the third admission must evict within the shard.
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            state.check_request(ip("10.0.0.17"), &config),
            Decision::Allow
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            matches!(
                state.check_request(ip("10.0.0.33"), &config),
                Decision::Allow
            ),
            "a full table must admit a new source by evicting an idle one"
        );
        assert_eq!(state.tracked_ips.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn exempt_connections_are_measured_without_consuming_budgets() {
        let state = Arc::new(ProtectionState::new());
        let mut config = config();
        config.max_connections = 1;
        config.allowlist = vec!["10.0.0.0/8".parse().expect("allowlist")];
        let first = state
            .try_acquire_connection(ip("10.0.0.1"), &config)
            .expect("regular connection");
        let exempt = state
            .try_acquire_connection(ip("10.0.0.2"), &config)
            .expect("exempt connection");
        config.enabled = false;
        let disabled = state
            .try_acquire_connection(ip("10.0.0.3"), &config)
            .expect("disabled protection");
        assert_eq!(state.active_connections(), 3);
        drop((first, exempt, disabled));
        assert_eq!(state.active_connections(), 0);
    }

    #[tokio::test]
    async fn tiny_positive_rates_never_panic() {
        let state = ProtectionState::new();
        let mut config = config();
        config.requests_per_second = 1e-300;
        config.burst = 1.0;
        assert_eq!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Allow
        );
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::RateLimited { .. }
        ));
    }

    #[test]
    fn tracking_key_masks_ipv6_to_prefix() {
        let mut config = config();
        config.aggregate_ipv6_prefix = 56;
        assert_eq!(
            tracking_key(ip("2001:db8:aa:bb::1"), &config),
            ip("2001:db8:aa::")
        );
        assert_eq!(tracking_key(ip("10.0.0.1"), &config), ip("10.0.0.1"));
        assert_eq!(tracking_key(ip("::ffff:10.0.0.1"), &config), ip("10.0.0.1"));
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

    fn auth_paths(patterns: &[&str]) -> RegexSet {
        RegexSet::new(patterns).expect("valid auth paths")
    }

    fn behavior_config() -> BehaviorConfig {
        BehaviorConfig {
            enabled: true,
            window: Duration::from_secs(60),
            min_requests: 3,
            enumeration: EnumerationConfig {
                enabled: true,
                action: BehaviorAction::Log,
                not_found_ratio: 0.5,
                distinct_paths: 2,
            },
            auth: AuthConfig {
                enabled: false,
                action: BehaviorAction::Log,
                min_failures: 2,
                paths: auth_paths(&[r"^/login$"]),
            },
            global_auth: GlobalAuthConfig {
                enabled: false,
                window: Duration::from_secs(60),
                min_failures: 2,
            },
        }
    }

    fn behavior_state(config: &Protection) -> ProtectionState {
        let state = ProtectionState::new();
        assert_eq!(state.check_request(ip("10.0.0.1"), config), Decision::Allow);
        state
    }

    #[tokio::test(start_paused = true)]
    async fn enumeration_flags_after_all_thresholds() {
        let mut config = config();
        config.behavior = behavior_config();
        let state = behavior_state(&config);

        let first =
            state.observe_response(ip("10.0.0.1"), "/missing-a", StatusCode::NOT_FOUND, &config);
        assert!(first.source.is_none());
        assert!(first.observed_not_found);
        let second =
            state.observe_response(ip("10.0.0.1"), "/missing-b", StatusCode::NOT_FOUND, &config);
        assert!(second.source.is_none());
        let third =
            state.observe_response(ip("10.0.0.1"), "/missing-c", StatusCode::NOT_FOUND, &config);
        let flag = third.source.expect("enumeration flag");
        assert_eq!(flag.signal, BehaviorSignal::Enumeration);
        assert_eq!(flag.action, BehaviorAction::Log);
        assert_eq!(flag.requests, 3);
        assert_eq!(flag.not_found, 3);
        assert!(flag.distinct_paths >= 2);
        assert!(flag.ban.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn normal_traffic_does_not_flag_enumeration() {
        let mut config = config();
        config.behavior = behavior_config();
        let state = behavior_state(&config);

        for path in ["/", "/api/items", "/api/items/1"] {
            let outcome = state.observe_response(ip("10.0.0.1"), path, StatusCode::OK, &config);
            assert!(outcome.source.is_none());
            assert!(!outcome.observed_not_found);
        }
        let outcome = state.observe_response(
            ip("10.0.0.1"),
            "/api/items/2",
            StatusCode::NOT_FOUND,
            &config,
        );
        assert!(outcome.source.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn static_404s_are_excluded_from_the_numerator() {
        let mut config = config();
        config.behavior = behavior_config();
        let state = behavior_state(&config);

        for path in ["/app.js", "/style.css", "/favicon.ico", "/missing.png"] {
            let outcome =
                state.observe_response(ip("10.0.0.1"), path, StatusCode::NOT_FOUND, &config);
            assert!(outcome.source.is_none());
            assert!(!outcome.observed_not_found);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failures_flag_only_on_auth_paths() {
        let mut config = config();
        let mut behavior = behavior_config();
        behavior.enumeration.enabled = false;
        behavior.auth.enabled = true;
        behavior.auth.min_failures = 2;
        config.behavior = behavior;
        let state = behavior_state(&config);

        let first = state.observe_response(
            ip("10.0.0.1"),
            "/api/users",
            StatusCode::UNAUTHORIZED,
            &config,
        );
        assert!(first.source.is_none());
        assert!(!first.observed_auth_failure);

        let second =
            state.observe_response(ip("10.0.0.1"), "/login", StatusCode::UNAUTHORIZED, &config);
        assert!(second.source.is_none());
        assert!(second.observed_auth_failure);

        let third =
            state.observe_response(ip("10.0.0.1"), "/login", StatusCode::FORBIDDEN, &config);
        let flag = third.source.expect("auth flag");
        assert_eq!(flag.signal, BehaviorSignal::AuthAbuse);
        assert_eq!(flag.auth_failures, 2);
        assert!(flag.ban.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn auth_paths_are_normalized_and_percent_decoded() {
        let mut config = config();
        let mut behavior = behavior_config();
        behavior.enumeration.enabled = false;
        behavior.auth.enabled = true;
        behavior.auth.min_failures = 2;
        config.behavior = behavior;
        let state = behavior_state(&config);

        let encoded = state.observe_response(
            ip("10.0.0.1"),
            "/%6cogin",
            StatusCode::UNAUTHORIZED,
            &config,
        );
        assert!(encoded.source.is_none());
        assert!(encoded.observed_auth_failure);

        let duplicate_slash =
            state.observe_response(ip("10.0.0.1"), "//login", StatusCode::UNAUTHORIZED, &config);
        assert!(duplicate_slash.source.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn global_auth_failures_aggregate_across_sources() {
        let mut config = config();
        let mut behavior = behavior_config();
        behavior.enumeration.enabled = false;
        behavior.auth.enabled = false;
        behavior.global_auth.enabled = true;
        behavior.global_auth.min_failures = 2;
        config.behavior = behavior;
        let state = ProtectionState::new();

        let first =
            state.observe_response(ip("10.0.0.1"), "/login", StatusCode::UNAUTHORIZED, &config);
        assert!(first.global.is_none());
        assert!(first.observed_auth_failure);

        let second =
            state.observe_response(ip("10.0.0.2"), "/login", StatusCode::UNAUTHORIZED, &config);
        let flag = second.global.expect("global auth flag");
        assert_eq!(flag.failures, 2);
        assert!(second.source.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn behavior_block_applies_a_ban() {
        let mut config = config();
        let mut behavior = behavior_config();
        behavior.min_requests = 1;
        behavior.enumeration.distinct_paths = 1;
        behavior.enumeration.not_found_ratio = 0.0;
        behavior.enumeration.action = BehaviorAction::Block;
        config.behavior = behavior;
        let state = behavior_state(&config);

        let outcome =
            state.observe_response(ip("10.0.0.1"), "/missing", StatusCode::NOT_FOUND, &config);
        let flag = outcome.source.expect("enumeration flag");
        assert_eq!(flag.action, BehaviorAction::Block);
        assert_eq!(flag.ban, Some(Duration::from_secs(60)));
        assert!(matches!(
            state.check_request(ip("10.0.0.1"), &config),
            Decision::Banned { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn behavior_window_rollover_resets_counters() {
        let mut config = config();
        let mut behavior = behavior_config();
        behavior.min_requests = 2;
        behavior.enumeration.distinct_paths = 1;
        behavior.enumeration.not_found_ratio = 0.5;
        config.behavior = behavior;
        let state = behavior_state(&config);

        let first =
            state.observe_response(ip("10.0.0.1"), "/missing", StatusCode::NOT_FOUND, &config);
        assert!(first.source.is_none());
        let second = state.observe_response(
            ip("10.0.0.1"),
            "/missing-two",
            StatusCode::NOT_FOUND,
            &config,
        );
        assert!(second.source.is_some());

        tokio::time::advance(Duration::from_secs(61)).await;

        let third = state.observe_response(
            ip("10.0.0.1"),
            "/other-missing",
            StatusCode::NOT_FOUND,
            &config,
        );
        assert!(third.source.is_none());
        assert!(third.observed_not_found);
    }

    #[tokio::test(start_paused = true)]
    async fn allowlisted_and_disabled_sources_observe_nothing() {
        let mut config = config();
        config.behavior = behavior_config();
        config.allowlist = vec!["10.0.0.0/8".parse().expect("allowlist")];
        let state = ProtectionState::new();
        let outcome =
            state.observe_response(ip("10.0.0.1"), "/missing", StatusCode::NOT_FOUND, &config);
        assert!(outcome.source.is_none());
        assert!(!outcome.observed_not_found);

        config.allowlist.clear();
        config.enabled = false;
        let outcome =
            state.observe_response(ip("10.0.0.1"), "/missing", StatusCode::NOT_FOUND, &config);
        assert!(outcome.source.is_none());
        assert!(!outcome.observed_not_found);
    }

    #[test]
    fn behavior_estimate_is_approximately_the_distinct_path_count() {
        let mut entry = BehaviorEntry::new(Instant::now());
        for index in 0..40 {
            entry.add_path(&format!("/missing-{index}"));
        }
        let estimate = entry.distinct_paths();
        assert!((35..=45).contains(&estimate), "estimate: {estimate}");
    }

    #[tokio::test(start_paused = true)]
    async fn observing_a_missing_source_entry_is_a_no_op() {
        let mut config = config();
        config.behavior = behavior_config();
        let state = ProtectionState::new();
        let outcome =
            state.observe_response(ip("10.0.0.1"), "/missing", StatusCode::NOT_FOUND, &config);
        assert!(outcome.source.is_none());
    }
}
