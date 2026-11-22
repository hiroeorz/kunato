//! Bounded session-country tracking. A session is identified only by a
//! configured cookie's hashed value; the raw cookie is never retained.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use http::HeaderMap;
use http::header::SET_COOKIE;
use ring::digest::{Context, SHA256};

use crate::config::SessionConfig;
use crate::geoip::CountryCode;

const SHARD_COUNT: usize = 16;
const MAX_SEEN_COUNTRIES: usize = 8;
const MAX_COOKIE_VALUE_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct SessionEvidence {
    pub(crate) from: CountryCode,
    pub(crate) to: CountryCode,
    pub(crate) key: [u8; 16],
}

impl SessionEvidence {
    pub(crate) fn fingerprint(&self) -> String {
        self.key[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

struct Entry {
    identity: [u8; 16],
    baseline: CountryCode,
    observations: u32,
    confirmed: bool,
    ambiguous: bool,
    seen: Vec<CountryCode>,
    seen_overflow: bool,
    updated: Instant,
}

#[derive(Default)]
struct Shard {
    entries: HashMap<[u8; 16], Entry>,
}

pub(crate) struct SessionTracker {
    shards: Vec<Mutex<Shard>>,
    tracked: AtomicUsize,
}

impl SessionTracker {
    pub(crate) fn new() -> Self {
        Self {
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
            tracked: AtomicUsize::new(0),
        }
    }

    pub(crate) fn observe_request(
        &self,
        host: &str,
        cookies: &[(Cow<'_, str>, Cow<'_, str>)],
        country: CountryCode,
        config: &SessionConfig,
    ) -> Option<SessionEvidence> {
        self.observe_request_at(host, cookies, country, config, Instant::now())
    }

    pub(crate) fn observe_response(
        &self,
        host: &str,
        headers: &HeaderMap,
        country: CountryCode,
        config: &SessionConfig,
    ) {
        self.observe_response_at(host, headers, country, config, Instant::now());
    }

    fn observe_request_at(
        &self,
        host: &str,
        cookies: &[(Cow<'_, str>, Cow<'_, str>)],
        country: CountryCode,
        config: &SessionConfig,
        now: Instant,
    ) -> Option<SessionEvidence> {
        if !config.enabled {
            return None;
        }
        let (name, value) = selected_cookie(cookies, &config.cookies)?;
        if value.len() > MAX_COOKIE_VALUE_BYTES {
            return None;
        }
        let key = session_key(host, name, value);
        let mut shard = lock(&self.shards[shard_index(&key)]);
        self.prune(&mut shard, &key, config, now);
        if let Some(entry) = shard.entries.get_mut(&key) {
            entry.updated = now;
            if entry.ambiguous {
                return None;
            }
            if !entry.confirmed {
                if country == entry.baseline {
                    entry.observations = entry.observations.saturating_add(1);
                    if entry.observations >= config.baseline_min_observations {
                        entry.confirmed = true;
                    }
                } else {
                    entry.ambiguous = true;
                }
                return None;
            }
            if country == entry.baseline || entry.seen.contains(&country) {
                return None;
            }
            if entry.seen_overflow || entry.seen.len() >= MAX_SEEN_COUNTRIES {
                entry.seen_overflow = true;
                return None;
            }
            entry.seen.push(country);
            return Some(SessionEvidence {
                from: entry.baseline,
                to: country,
                key,
            });
        }

        let entry = Entry {
            identity: session_identity(host, name),
            baseline: country,
            observations: 1,
            confirmed: config.baseline_min_observations <= 1,
            ambiguous: false,
            seen: Vec::new(),
            seen_overflow: false,
            updated: now,
        };
        self.insert(&mut shard, key, entry, config.max_tracked);
        None
    }

    fn observe_response_at(
        &self,
        host: &str,
        headers: &HeaderMap,
        country: CountryCode,
        config: &SessionConfig,
        now: Instant,
    ) {
        if !config.enabled {
            return;
        }
        for header in headers.get_all(SET_COOKIE) {
            let Ok(header) = header.to_str() else {
                continue;
            };
            let Some((name, value, deletion)) = parse_set_cookie(header) else {
                continue;
            };
            if !config.cookies.iter().any(|cookie| cookie == name)
                || value.len() > MAX_COOKIE_VALUE_BYTES
            {
                continue;
            }
            let key = session_key(host, name, value);
            if deletion {
                self.remove_identity(&session_identity(host, name));
                continue;
            }
            let mut shard = lock(&self.shards[shard_index(&key)]);
            self.prune(&mut shard, &key, config, now);
            if let Some(entry) = shard.entries.get_mut(&key) {
                // A server often refreshes the same session cookie on every
                // response. Do not let a refresh from another country move an
                // established baseline; that would let a stolen cookie's new
                // source become the baseline and reverse the verdict.
                if entry.baseline == country {
                    entry.observations = config.baseline_min_observations.max(1);
                    entry.confirmed = true;
                    entry.ambiguous = false;
                }
                entry.updated = now;
                continue;
            }
            let entry = Entry {
                identity: session_identity(host, name),
                baseline: country,
                observations: config.baseline_min_observations.max(1),
                confirmed: true,
                ambiguous: false,
                seen: Vec::new(),
                seen_overflow: false,
                updated: now,
            };
            self.insert(&mut shard, key, entry, config.max_tracked);
        }
    }

    fn remove_identity(&self, identity: &[u8; 16]) {
        for mutex in &self.shards {
            let mut shard = lock(mutex);
            let keys = shard
                .entries
                .iter()
                .filter(|(_, entry)| &entry.identity == identity)
                .map(|(key, _)| *key)
                .collect::<Vec<_>>();
            for key in keys {
                if shard.entries.remove(&key).is_some() {
                    self.tracked.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn prune(&self, shard: &mut Shard, key: &[u8; 16], config: &SessionConfig, now: Instant) {
        let stale = shard.entries.get(key).is_some_and(|entry| {
            now.saturating_duration_since(entry.updated) >= config.baseline_ttl
        });
        if stale && shard.entries.remove(key).is_some() {
            self.tracked.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn insert(&self, shard: &mut Shard, key: [u8; 16], entry: Entry, max_tracked: usize) {
        if !shard.entries.contains_key(&key)
            && self.tracked.load(Ordering::Relaxed) >= max_tracked
            && !self.evict_one(shard)
        {
            return;
        }
        if shard.entries.insert(key, entry).is_none() {
            self.tracked.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn evict_one(&self, shard: &mut Shard) -> bool {
        let oldest = shard
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.updated)
            .map(|(key, _)| *key);
        if let Some(key) = oldest
            && shard.entries.remove(&key).is_some()
        {
            self.tracked.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
        false
    }
}

fn selected_cookie<'a>(
    cookies: &'a [(Cow<'a, str>, Cow<'a, str>)],
    names: &[String],
) -> Option<(&'a str, &'a str)> {
    for name in names {
        let mut values = cookies
            .iter()
            .filter(|(cookie_name, _)| cookie_name.as_ref() == name);
        let Some(first) = values.next() else {
            continue;
        };
        if values.next().is_some() {
            continue;
        }
        let value = unquote(first.1.as_ref());
        if value.is_empty() {
            continue;
        }
        return Some((first.0.as_ref(), value));
    }
    None
}

fn parse_set_cookie(header: &str) -> Option<(&str, &str, bool)> {
    let mut parts = header.split(';');
    let pair = parts.next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let value = unquote(value);
    let mut deletion = value.is_empty();
    for attribute in parts {
        if let Some((key, value)) = attribute.trim().split_once('=')
            && key.trim().eq_ignore_ascii_case("max-age")
            && value.trim() == "0"
        {
            deletion = true;
        }
    }
    Some((name, value, deletion))
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn session_identity(host: &str, name: &str) -> [u8; 16] {
    let mut context = Context::new(&SHA256);
    context.update(b"kunato-session-identity\0");
    context.update(host.trim_end_matches('.').to_ascii_lowercase().as_bytes());
    context.update(b"\0");
    context.update(name.as_bytes());
    let digest = context.finish();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest.as_ref()[..16]);
    identity
}

fn session_key(host: &str, name: &str, value: &str) -> [u8; 16] {
    let mut context = Context::new(&SHA256);
    context.update(b"kunato-session\0");
    context.update(host.trim_end_matches('.').to_ascii_lowercase().as_bytes());
    context.update(b"\0");
    context.update(name.as_bytes());
    context.update(b"\0");
    context.update(value.as_bytes());
    let digest = context.finish();
    let mut key = [0; 16];
    key.copy_from_slice(&digest.as_ref()[..16]);
    key
}

fn shard_index(key: &[u8; 16]) -> usize {
    usize::from(key[0]) % SHARD_COUNT
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::Duration;

    use http::HeaderValue;

    use super::*;

    fn config() -> SessionConfig {
        SessionConfig {
            enabled: true,
            cookies: vec!["session".to_owned()],
            baseline_min_observations: 2,
            baseline_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            max_tracked: 100,
        }
    }

    fn cookies(value: &str) -> Vec<(Cow<'_, str>, Cow<'_, str>)> {
        vec![(Cow::Borrowed("session"), Cow::Borrowed(value))]
    }

    fn japan() -> CountryCode {
        CountryCode::parse("JP").expect("JP")
    }

    fn united_states() -> CountryCode {
        CountryCode::parse("US").expect("US")
    }

    #[test]
    fn request_side_baseline_requires_observations_before_scoring() {
        let tracker = SessionTracker::new();
        let config = config();
        let now = Instant::now();
        assert!(
            tracker
                .observe_request_at("example.test", &cookies("abc"), japan(), &config, now)
                .is_none()
        );
        assert!(
            tracker
                .observe_request_at(
                    "example.test",
                    &cookies("abc"),
                    united_states(),
                    &config,
                    now + Duration::from_secs(1)
                )
                .is_none(),
            "a different country before confirmation makes the session ambiguous"
        );
        assert!(
            tracker
                .observe_request_at(
                    "example.test",
                    &cookies("abc"),
                    japan(),
                    &config,
                    now + Duration::from_secs(2)
                )
                .is_none()
        );
    }

    #[test]
    fn confirmed_baseline_scores_only_the_new_country_source() {
        let tracker = SessionTracker::new();
        let config = config();
        let now = Instant::now();
        tracker.observe_request_at("example.test", &cookies("abc"), japan(), &config, now);
        tracker.observe_request_at(
            "example.test",
            &cookies("abc"),
            japan(),
            &config,
            now + Duration::from_secs(1),
        );
        let evidence = tracker
            .observe_request_at(
                "example.test",
                &cookies("abc"),
                united_states(),
                &config,
                now + Duration::from_secs(2),
            )
            .expect("country mismatch");
        assert_eq!(evidence.from, japan());
        assert_eq!(evidence.to, united_states());
        assert_eq!(evidence.fingerprint().len(), 8);
        assert!(
            tracker
                .observe_request_at(
                    "example.test",
                    &cookies("abc"),
                    united_states(),
                    &config,
                    now + Duration::from_secs(3)
                )
                .is_none(),
            "a seen country is not scored repeatedly"
        );
    }

    #[test]
    fn set_cookie_confirms_the_baseline_before_the_next_request() {
        let tracker = SessionTracker::new();
        let config = config();
        let now = Instant::now();
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("session=abc; Path=/; HttpOnly"),
        );
        tracker.observe_response_at("example.test", &headers, japan(), &config, now);
        let evidence = tracker
            .observe_request_at(
                "example.test",
                &cookies("abc"),
                united_states(),
                &config,
                now + Duration::from_secs(1),
            )
            .expect("set-cookie baseline");
        assert_eq!(evidence.from, japan());
        assert_eq!(evidence.to, united_states());
    }

    #[test]
    fn set_cookie_refresh_does_not_move_an_established_baseline() {
        let tracker = SessionTracker::new();
        let config = config();
        let now = Instant::now();
        let mut japan_headers = HeaderMap::new();
        japan_headers.append(SET_COOKIE, HeaderValue::from_static("session=abc; Path=/"));
        tracker.observe_response_at("example.test", &japan_headers, japan(), &config, now);
        let mut attacker_headers = HeaderMap::new();
        attacker_headers.append(SET_COOKIE, HeaderValue::from_static("session=abc; Path=/"));
        tracker.observe_response_at(
            "example.test",
            &attacker_headers,
            united_states(),
            &config,
            now + Duration::from_secs(1),
        );
        let evidence = tracker
            .observe_request_at(
                "example.test",
                &cookies("abc"),
                united_states(),
                &config,
                now + Duration::from_secs(2),
            )
            .expect("the refreshed cookie must not replace the JP baseline");
        assert_eq!(evidence.from, japan());
        assert_eq!(evidence.to, united_states());
    }

    #[test]
    fn deletion_removes_the_session() {
        let tracker = SessionTracker::new();
        let config = config();
        let now = Instant::now();
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("session=abc; Path=/"));
        tracker.observe_response_at("example.test", &headers, japan(), &config, now);
        let mut deletion = HeaderMap::new();
        deletion.append(
            SET_COOKIE,
            HeaderValue::from_static("session=; Max-Age=0; Path=/"),
        );
        tracker.observe_response_at(
            "example.test",
            &deletion,
            japan(),
            &config,
            now + Duration::from_secs(1),
        );
        assert!(
            tracker
                .observe_request_at(
                    "example.test",
                    &cookies("abc"),
                    united_states(),
                    &config,
                    now + Duration::from_secs(2)
                )
                .is_none()
        );
    }

    #[test]
    fn expiry_resets_an_unconfirmed_baseline() {
        let tracker = SessionTracker::new();
        let mut config = config();
        config.baseline_ttl = Duration::from_secs(10);
        let now = Instant::now();
        tracker.observe_request_at("example.test", &cookies("abc"), japan(), &config, now);
        tracker.observe_request_at(
            "example.test",
            &cookies("abc"),
            united_states(),
            &config,
            now + Duration::from_secs(11),
        );
        assert!(
            tracker
                .observe_request_at(
                    "example.test",
                    &cookies("abc"),
                    united_states(),
                    &config,
                    now + Duration::from_secs(12)
                )
                .is_none()
        );
    }

    #[test]
    fn max_tracked_is_bounded() {
        let tracker = SessionTracker::new();
        let mut config = config();
        config.max_tracked = 1;
        let now = Instant::now();
        tracker.observe_request_at("example.test", &cookies("a"), japan(), &config, now);
        tracker.observe_request_at(
            "example.test",
            &cookies("b"),
            japan(),
            &config,
            now + Duration::from_secs(1),
        );
        assert!(tracker.tracked.load(Ordering::Relaxed) <= 1);
    }
}
