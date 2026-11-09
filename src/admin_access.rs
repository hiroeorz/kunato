//! Time-limited opening and closing of administrative application functions.
//!
//! Home servers usually expose a small administrative surface to exactly one
//! owner. The configuration declares administrative functions (path groups)
//! and a default state for them. `open` and `close` commands create bounded,
//! in-memory overrides, optionally scoped to one client address or one
//! function, that revert to the configured default when they expire. Requests
//! that match a declared function are allowed or denied from that effective
//! state, and every allowed request is still evaluated by the rules and the
//! other inspection layers.
//!
//! Overrides are issued through the loopback admin listener, so the owner can
//! open or close access from an administrative channel such as SSH for the
//! time it takes to use it. The table resets when the process restarts.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;

/// Default lifetime of an override when the caller does not pass one.
pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
/// Longest lifetime an override may be set for.
pub const MAX_TTL: Duration = Duration::from_secs(60 * 60);
/// Default bound on the number of overrides held at once.
pub const DEFAULT_MAX_OVERRIDES: usize = 64;

/// Effective access state of a matching administrative function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessState {
    #[default]
    Open,
    Close,
}

impl AccessState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
        }
    }
}

/// A built-in administrative function preset. Presets are loaded when
/// `admin_access.enabled` is true and `admin_access.presets` is not disabled;
/// a `functions` entry with the same name replaces the preset.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdminFunctionPreset {
    pub name: &'static str,
    pub paths: &'static [&'static str],
    pub exclude: &'static [&'static str],
}

/// Built-in functions for administrative interfaces commonly found on home
/// servers and small deployments.
///
/// The patterns are deliberately conservative: role-like path segments are
/// root-anchored so public static directories such as `/static/admin/` stay
/// open, while product-specific names and WordPress paths also match a
/// subdirectory install. Spring Actuator keeps its health and info endpoints
/// public for monitoring; WordPress keeps `admin-ajax.php` and `admin-post.php`
/// public for logged-out themes and form handlers. Override a preset by name
/// to narrow or widen it, or set `admin_access.presets: false` to start from
/// only your own functions.
pub(crate) const DEFAULT_FUNCTIONS: &[AdminFunctionPreset] = &[
    AdminFunctionPreset {
        name: "wordpress-admin",
        paths: &[
            r"(?i)(?:^|/)wp-admin(?:/|$)",
            r"(?i)(?:^|/)wp-login\.php$",
            r"(?i)(?:^|/)xmlrpc\.php$",
        ],
        exclude: &[
            r"(?i)(?:^|/)wp-admin/admin-ajax\.php$",
            r"(?i)(?:^|/)wp-admin/admin-post\.php$",
        ],
    },
    AdminFunctionPreset {
        name: "rails-admin",
        paths: &[
            r"(?i)(?:^|/)rails/(?:info|mailers|conductor)(?:/|$)",
            r"(?i)(?:^|/)letter_opener(?:/|$)",
            r"(?i)(?:^|/)(?:sidekiq|pghero|flipper|blazer|delayed_job|good_job)(?:/|$)",
            r"(?i)(?:^|/)(?:active_admin|rails_admin|avo|administrate)(?:/|$)",
        ],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "laravel-admin",
        paths: &[
            r"(?i)(?:^|/)(?:horizon|telescope|nova|pulse|log-viewer|clockwork)(?:/|$)",
            r"(?i)(?:^|/)_debugbar(?:/|$)",
        ],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "generic-admin",
        paths: &[
            r"(?i)^/admin(?:\.php)?(?:/|$)",
            r"(?i)^/administrator(?:/|$)",
            r"(?i)^/adm(?:/|$)",
            r"(?i)^/api/(?:v\d+/)?admin(?:/|$)",
            r"(?i)^/-/admin(?:/|$)",
        ],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "phpmyadmin",
        paths: &[r"(?i)(?:^|/)(?:phpmyadmin|pma)(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "adminer",
        paths: &[r"(?i)(?:^|/)adminer(?:\.php)?(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "tomcat-manager",
        paths: &[r"(?i)^/manager(?:/|$)", r"(?i)^/host-manager(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "java-console",
        paths: &[
            r"(?i)(?:^|/)(?:jmx-console|web-console)(?:/|$)",
            r"(?i)(?:^|/)(?:axis2/)?axis2-admin(?:/|$)",
        ],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "solr-admin",
        paths: &[r"(?i)(?:^|/)solr(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "spring-actuator",
        paths: &[r"(?i)(?:^|/)actuator(?:/|$)"],
        exclude: &[r"(?i)(?:^|/)actuator/(?:health|info)(?:/|$)"],
    },
    AdminFunctionPreset {
        name: "nextcloud-admin",
        paths: &[r"(?i)(?:^|/)(?:index\.php/)?settings/admin(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "ghost-admin",
        paths: &[r"(?i)(?:^|/)ghost(?:/|$)"],
        exclude: &[],
    },
    AdminFunctionPreset {
        name: "typo3-admin",
        paths: &[r"(?i)(?:^|/)typo3(?:/|$)"],
        exclude: &[],
    },
];

/// One administrative function: a name used by overrides, the path patterns
/// that identify it, and optional path patterns that stay outside the gate.
#[derive(Debug)]
pub struct AdminFunction {
    pub name: String,
    paths: Vec<Regex>,
    exclude: Vec<Regex>,
}

impl AdminFunction {
    pub fn new(name: String, paths: Vec<Regex>, exclude: Vec<Regex>) -> Self {
        Self {
            name,
            paths,
            exclude,
        }
    }

    /// A request is gated when a decoded or normalized form of its path matches
    /// and that form is not excluded. An upstream that decodes differently from
    /// Kunato must not receive an administrative request through a form this
    /// function did not cover, so a single non-excluded matching form is enough
    /// to apply the effective open or close state. An exclusion only applies to
    /// the form that matches it, so a differently encoded form of a public path
    /// cannot hide an administrative one.
    pub fn matches(&self, path_forms: &[Cow<'_, str>]) -> bool {
        path_forms.iter().any(|form| {
            self.paths.iter().any(|path| path.is_match(form))
                && !self.exclude.iter().any(|exclude| exclude.is_match(form))
        })
    }
}

/// Compiled `admin_access` configuration. A disabled policy (or one without
/// functions) gates nothing.
#[derive(Debug)]
pub struct AdminAccess {
    pub enabled: bool,
    pub default: AccessState,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub max_overrides: usize,
    pub functions: Vec<AdminFunction>,
}

impl Default for AdminAccess {
    fn default() -> Self {
        Self {
            enabled: false,
            default: AccessState::Open,
            default_ttl: DEFAULT_TTL,
            max_ttl: MAX_TTL,
            max_overrides: DEFAULT_MAX_OVERRIDES,
            functions: Vec::new(),
        }
    }
}

impl AdminAccess {
    pub fn function(&self, name: &str) -> Option<&AdminFunction> {
        self.functions.iter().find(|function| function.name == name)
    }

    /// Resolve the effective state for every matching function. A path that
    /// matches several functions is open only when all of them are open, so a
    /// close override cannot be bypassed through an overlapping function.
    pub fn decide<'a>(
        &'a self,
        state: &AdminAccessState,
        client: IpAddr,
        path_forms: &[Cow<'_, str>],
        now: Instant,
    ) -> Decision<'a> {
        if !self.enabled {
            return Decision::NotGated;
        }
        let mut first = None;
        for function in &self.functions {
            if !function.matches(path_forms) {
                continue;
            }
            if first.is_none() {
                first = Some(function.name.as_str());
            }
            let effective = state
                .state_for(client, &function.name, now)
                .unwrap_or(self.default);
            if effective == AccessState::Close {
                return Decision::Denied(&function.name);
            }
        }
        match first {
            Some(function) => Decision::Allowed(function),
            None => Decision::NotGated,
        }
    }
}

/// Result of comparing a request path with the configured functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision<'a> {
    /// No administrative function covers this path.
    NotGated,
    /// Every matching function resolves to the open state.
    Allowed(&'a str),
    /// A matching function resolves to the closed state.
    Denied(&'a str),
}

/// One unexpired open or close override, as reported to the admin listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveOverride {
    pub client: Option<IpAddr>,
    pub function: Option<String>,
    pub state: AccessState,
    pub remaining: Duration,
}

/// Why an override was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideError {
    /// The bounded override table is full.
    Capacity,
    /// The lifetime does not fit in the monotonic clock.
    Overflow,
}

impl fmt::Display for OverrideError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity => formatter.write_str("override table is full"),
            Self::Overflow => formatter.write_str("override lifetime is too long"),
        }
    }
}

/// Process-wide override table. It is deliberately independent of the
/// hot-reloaded configuration: overrides keep their absolute expiry across a
/// reload, and the functions they name are resolved against the new
/// configuration on every request.
type OverrideKey = (Option<IpAddr>, Option<String>);
type OverrideMap = BTreeMap<OverrideKey, OverrideEntry>;

#[derive(Debug, Default)]
pub struct AdminAccessState {
    overrides: Mutex<OverrideMap>,
    sequence: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct OverrideEntry {
    state: AccessState,
    expires: Instant,
    sequence: u64,
}

impl AdminAccessState {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OverrideMap> {
        self.overrides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Return the active override for this client and function. The most
    /// recently issued matching override wins, so a broad `close` closes
    /// existing narrow opens and a later narrow `open` can reopen one device.
    pub fn state_for(&self, client: IpAddr, function: &str, now: Instant) -> Option<AccessState> {
        let overrides = self.lock();
        let mut best: Option<(u64, u8, AccessState)> = None;
        for ((override_client, override_function), entry) in overrides.iter() {
            if entry.expires <= now {
                continue;
            }
            if override_client.is_some_and(|value| value != client) {
                continue;
            }
            if let Some(name) = override_function
                && name.as_str() != function
            {
                continue;
            }
            let rank =
                u8::from(override_client.is_some()) * 2 + u8::from(override_function.is_some());
            let candidate = (entry.sequence, rank, entry.state);
            if best.is_none_or(|current| (candidate.0, candidate.1) > (current.0, current.1)) {
                best = Some(candidate);
            }
        }
        best.map(|(_, _, state)| state)
    }

    /// Add or replace an override and return its lifetime. Expired entries are
    /// pruned first, so they never prevent a new override.
    pub fn set(
        &self,
        client: Option<IpAddr>,
        function: Option<&str>,
        state: AccessState,
        ttl: Duration,
        max_overrides: usize,
        now: Instant,
    ) -> Result<Duration, OverrideError> {
        let expires = now.checked_add(ttl).ok_or(OverrideError::Overflow)?;
        let sequence = self
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut overrides = self.lock();
        overrides.retain(|_, entry| entry.expires > now);
        let key = (client, function.map(str::to_owned));
        let is_new = !overrides.contains_key(&key);
        if is_new && overrides.len() >= max_overrides {
            return Err(OverrideError::Capacity);
        }
        overrides.insert(
            key,
            OverrideEntry {
                state,
                expires,
                sequence,
            },
        );
        Ok(ttl)
    }

    /// List the unexpired overrides, pruning expired entries. Sorted by
    /// function, client, and state for a stable admin response.
    pub fn list(&self, now: Instant) -> Vec<ActiveOverride> {
        let mut overrides = self.lock();
        overrides.retain(|_, entry| entry.expires > now);
        let mut listed: Vec<ActiveOverride> = overrides
            .iter()
            .map(|((client, function), entry)| ActiveOverride {
                client: *client,
                function: function.clone(),
                state: entry.state,
                remaining: entry.expires.saturating_duration_since(now),
            })
            .collect();
        listed.sort_by(|left, right| {
            left.function
                .cmp(&right.function)
                .then_with(|| left.client.cmp(&right.client))
                .then_with(|| left.state.as_str().cmp(right.state.as_str()))
        });
        listed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::request_view::path_forms;

    fn function(name: &str, patterns: &[&str]) -> AdminFunction {
        AdminFunction::new(
            name.to_owned(),
            patterns
                .iter()
                .map(|pattern| Regex::new(pattern).expect("regex"))
                .collect(),
            Vec::new(),
        )
    }

    fn policy() -> AdminAccess {
        AdminAccess {
            enabled: true,
            functions: vec![
                function("wordpress-admin", &[r"^/wp-admin(?:/|$)"]),
                function("plugin-install", &[r"^/wp-admin/plugin-install\.php$"]),
            ],
            ..AdminAccess::default()
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    fn client() -> IpAddr {
        ip("192.0.2.10")
    }

    #[test]
    fn default_policy_gates_nothing() {
        let policy = AdminAccess::default();
        assert!(!policy.enabled);
        assert!(policy.functions.is_empty());
        assert_eq!(policy.default, AccessState::Open);
        assert_eq!(policy.default_ttl, DEFAULT_TTL);
        assert_eq!(policy.max_ttl, MAX_TTL);
        assert_eq!(policy.max_overrides, DEFAULT_MAX_OVERRIDES);
    }

    #[test]
    fn any_decoded_or_normalized_form_gates_the_request() {
        let policy = policy();
        let admin = policy.function("wordpress-admin").expect("function");
        for path in ["/wp-admin", "/wp-admin/options.php", "/%77p-admin"] {
            let forms = path_forms(path);
            assert!(admin.matches(&forms), "{path}: {forms:?}");
        }
        assert!(admin.matches(&path_forms("/wp-admin/../wp-admin/users.php")));
        assert!(!admin.matches(&path_forms("/public")));
        assert!(!admin.matches(&path_forms("/blog/wp-admin")));
    }

    #[test]
    fn requests_are_not_gated_without_an_enabled_policy() {
        let policy = AdminAccess::default();
        let state = AdminAccessState::new();
        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), Instant::now()),
            Decision::NotGated
        );
    }

    #[test]
    fn the_default_state_applies_until_an_override_matches() {
        let policy = policy();
        let state = AdminAccessState::new();
        let now = Instant::now();

        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Allowed("wordpress-admin")
        );

        state
            .set(
                None,
                None,
                AccessState::Close,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("close everything");
        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Denied("wordpress-admin")
        );

        state
            .set(
                Some(client()),
                None,
                AccessState::Open,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("open one client");
        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Allowed("wordpress-admin")
        );
        assert_eq!(
            policy.decide(&state, ip("192.0.2.11"), &path_forms("/wp-admin"), now),
            Decision::Denied("wordpress-admin")
        );
    }

    #[test]
    fn a_closed_default_is_opened_by_an_override() {
        let mut policy = policy();
        policy.default = AccessState::Close;
        let state = AdminAccessState::new();
        let now = Instant::now();

        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Denied("wordpress-admin")
        );

        state
            .set(
                None,
                None,
                AccessState::Open,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("open everything");
        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Allowed("wordpress-admin")
        );

        state
            .set(
                None,
                Some("wordpress-admin"),
                AccessState::Close,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("close one function");
        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Denied("wordpress-admin")
        );
    }

    #[test]
    fn an_overlapping_closed_function_denies_the_request() {
        let policy = policy();
        let state = AdminAccessState::new();
        let now = Instant::now();
        state
            .set(
                None,
                Some("wordpress-admin"),
                AccessState::Close,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("close the broad function");

        // The narrow plugin-install function is still open by default, but a
        // request matching both must not slip past the closed one.
        assert_eq!(
            policy.decide(
                &state,
                client(),
                &path_forms("/wp-admin/plugin-install.php"),
                now
            ),
            Decision::Denied("wordpress-admin")
        );
    }

    #[test]
    fn overrides_expire_automatically() {
        let policy = policy();
        let state = AdminAccessState::new();
        let now = Instant::now();
        state
            .set(
                None,
                None,
                AccessState::Close,
                Duration::from_secs(10),
                8,
                now,
            )
            .expect("close everything");

        assert_eq!(
            policy.decide(&state, client(), &path_forms("/wp-admin"), now),
            Decision::Denied("wordpress-admin")
        );
        assert_eq!(
            policy.decide(
                &state,
                client(),
                &path_forms("/wp-admin"),
                now + Duration::from_secs(10)
            ),
            Decision::Allowed("wordpress-admin")
        );
        assert!(state.list(now + Duration::from_secs(11)).is_empty());
    }

    #[test]
    fn the_newest_matching_override_wins() {
        let state = AdminAccessState::new();
        let now = Instant::now();
        let permanent = Duration::from_secs(60);
        state
            .set(None, None, AccessState::Close, permanent, 8, now)
            .expect("global close");
        state
            .set(None, Some("one"), AccessState::Close, permanent, 8, now)
            .expect("function close");
        state
            .set(Some(client()), None, AccessState::Open, permanent, 8, now)
            .expect("client open");
        state
            .set(
                Some(client()),
                Some("one"),
                AccessState::Close,
                permanent,
                8,
                now,
            )
            .expect("exact close");

        assert_eq!(
            state.state_for(client(), "one", now),
            Some(AccessState::Close)
        );
        assert_eq!(
            state.state_for(client(), "two", now),
            Some(AccessState::Open)
        );
        assert_eq!(
            state.state_for(ip("192.0.2.11"), "one", now),
            Some(AccessState::Close)
        );
        assert_eq!(
            state.state_for(ip("192.0.2.11"), "two", now),
            Some(AccessState::Close)
        );

        // A later broad command overrides an earlier narrow one, which is what
        // `kunato admin-access close` without arguments is expected to do.
        state
            .set(None, None, AccessState::Close, permanent, 8, now)
            .expect("close everything");
        assert_eq!(
            state.state_for(client(), "one", now),
            Some(AccessState::Close)
        );

        // A later narrow command can reopen one device while the rest stays
        // closed.
        state
            .set(Some(client()), None, AccessState::Open, permanent, 8, now)
            .expect("open one client");
        assert_eq!(
            state.state_for(client(), "one", now),
            Some(AccessState::Open)
        );
        assert_eq!(
            state.state_for(ip("192.0.2.11"), "one", now),
            Some(AccessState::Close)
        );
    }

    #[test]
    fn set_replaces_the_same_scope_and_bounds_the_table() {
        let state = AdminAccessState::new();
        let now = Instant::now();
        assert_eq!(
            state
                .set(
                    Some(client()),
                    Some("one"),
                    AccessState::Close,
                    Duration::from_secs(60),
                    1,
                    now
                )
                .expect("first"),
            Duration::from_secs(60)
        );
        assert_eq!(
            state
                .set(
                    Some(client()),
                    Some("one"),
                    AccessState::Open,
                    Duration::from_secs(120),
                    1,
                    now
                )
                .expect("replace"),
            Duration::from_secs(120)
        );
        assert_eq!(
            state.state_for(client(), "one", now),
            Some(AccessState::Open)
        );
        assert_eq!(
            state.set(
                Some(client()),
                Some("two"),
                AccessState::Close,
                Duration::from_secs(60),
                1,
                now
            ),
            Err(OverrideError::Capacity)
        );
        assert_eq!(
            state.set(None, None, AccessState::Close, Duration::MAX, 8, now),
            Err(OverrideError::Overflow)
        );

        // An expired override does not hold a slot.
        assert_eq!(
            state
                .set(
                    Some(client()),
                    Some("two"),
                    AccessState::Close,
                    Duration::from_secs(60),
                    1,
                    now + Duration::from_secs(121)
                )
                .expect("expired entries are pruned"),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn listing_is_sorted_and_reports_state() {
        let state = AdminAccessState::new();
        let now = Instant::now();
        state
            .set(
                Some(ip("192.0.2.12")),
                Some("beta"),
                AccessState::Close,
                Duration::from_secs(30),
                8,
                now,
            )
            .expect("set");
        state
            .set(
                None,
                Some("alpha"),
                AccessState::Open,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("set");
        state
            .set(
                Some(ip("192.0.2.10")),
                Some("alpha"),
                AccessState::Close,
                Duration::from_secs(60),
                8,
                now,
            )
            .expect("set");

        let listed = state.list(now + Duration::from_secs(10));
        let summary: Vec<(Option<String>, Option<IpAddr>, AccessState, u64)> = listed
            .into_iter()
            .map(|entry| {
                (
                    entry.function,
                    entry.client,
                    entry.state,
                    entry.remaining.as_secs(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (Some("alpha".to_owned()), None, AccessState::Open, 50),
                (
                    Some("alpha".to_owned()),
                    Some(ip("192.0.2.10")),
                    AccessState::Close,
                    50
                ),
                (
                    Some("beta".to_owned()),
                    Some(ip("192.0.2.12")),
                    AccessState::Close,
                    20
                ),
            ]
        );
    }

    fn preset(name: &str) -> AdminFunction {
        let preset = DEFAULT_FUNCTIONS
            .iter()
            .find(|preset| preset.name == name)
            .expect("known preset");
        AdminFunction::new(
            preset.name.to_owned(),
            preset
                .paths
                .iter()
                .map(|pattern| Regex::new(pattern).expect("preset path regex"))
                .collect(),
            preset
                .exclude
                .iter()
                .map(|pattern| Regex::new(pattern).expect("preset exclusion regex"))
                .collect(),
        )
    }

    #[test]
    fn default_presets_compile_and_have_unique_names() {
        let mut names = std::collections::BTreeSet::new();
        for preset in DEFAULT_FUNCTIONS {
            assert!(!preset.name.is_empty(), "a preset name is empty");
            assert!(
                names.insert(preset.name),
                "duplicate preset name `{}`",
                preset.name
            );
            assert!(!preset.paths.is_empty(), "`{}` has no paths", preset.name);
            for pattern in preset.paths.iter().chain(preset.exclude) {
                Regex::new(pattern).expect("preset regex");
            }
        }
    }

    #[test]
    fn default_presets_cover_common_administrative_paths() {
        for (name, path, expected) in [
            ("wordpress-admin", "/wp-admin/", true),
            ("wordpress-admin", "/blog/wp-admin/post.php", true),
            ("wordpress-admin", "/WP-ADMIN/", true),
            ("wordpress-admin", "/%77p-admin/", true),
            ("wordpress-admin", "/wp-login.php", true),
            ("wordpress-admin", "/blog/wp-login.php", true),
            ("wordpress-admin", "/xmlrpc.php", true),
            ("wordpress-admin", "/wp-admin/admin-ajax.php", false),
            ("wordpress-admin", "/blog/wp-admin/admin-ajax.php", false),
            ("wordpress-admin", "/wp-admin/admin-post.php", false),
            ("wordpress-admin", "/wp-content/themes/t/style.css", false),
            ("rails-admin", "/sidekiq/", true),
            ("rails-admin", "/blog/rails/info", true),
            ("rails-admin", "/active_admin", true),
            ("rails-admin", "/letter_opener", true),
            ("rails-admin", "/public", false),
            ("laravel-admin", "/horizon", true),
            ("laravel-admin", "/nova/", true),
            ("laravel-admin", "/login", false),
            ("generic-admin", "/admin", true),
            ("generic-admin", "/admin.php", true),
            ("generic-admin", "/administrator/", true),
            ("generic-admin", "/adm/", true),
            ("generic-admin", "/api/v1/admin", true),
            ("generic-admin", "/-/admin", true),
            ("generic-admin", "/api/v1/session", false),
            ("generic-admin", "/static/admin/css/base.css", false),
            ("phpmyadmin", "/phpmyadmin/", true),
            ("phpmyadmin", "/tools/pma", true),
            ("adminer", "/adminer.php", true),
            ("adminer", "/adminer", true),
            ("tomcat-manager", "/manager/html", true),
            ("tomcat-manager", "/host-manager/", true),
            ("java-console", "/jmx-console/", true),
            ("java-console", "/web-console", true),
            ("java-console", "/axis2-admin/login", true),
            ("solr-admin", "/solr/", true),
            ("spring-actuator", "/actuator", true),
            ("spring-actuator", "/actuator/env", true),
            ("spring-actuator", "/actuator/health", false),
            ("spring-actuator", "/actuator/health/liveness", false),
            ("spring-actuator", "/actuator/info", false),
            ("nextcloud-admin", "/settings/admin", true),
            (
                "nextcloud-admin",
                "/index.php/settings/admin/overview",
                true,
            ),
            ("nextcloud-admin", "/settings/user", false),
            ("ghost-admin", "/ghost/", true),
            ("typo3-admin", "/typo3/", true),
        ] {
            assert_eq!(
                preset(name).matches(&path_forms(path)),
                expected,
                "{name} {path}"
            );
        }
    }

    #[test]
    fn an_encoded_excluded_path_cannot_hide_an_administrative_form() {
        let wordpress = preset("wordpress-admin");
        // The raw form is not the literal admin-ajax path, so it must not be
        // excluded; the normalized form reaches an admin page.
        assert!(wordpress.matches(&path_forms("/wp-admin/admin-ajax.php%2f..%2fpost.php")));
        // The canonical public form is the only one that is excluded.
        assert!(!wordpress.matches(&path_forms("/wp-admin/admin-ajax.php")));
    }
}
