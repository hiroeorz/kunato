use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use http::Method;
use http::Uri;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};

pub mod watcher;

use crate::error::Error;
use crate::rules::matcher::{
    Matcher, PayloadMatcher, StatusRange, TARGET_BODY, TARGET_COOKIES, TARGET_HEADERS, TARGET_PATH,
    TARGET_QUERY, TARGET_RESPONSE_BODY,
};

const REGEX_SIZE_LIMIT: usize = 1 << 20;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_PATTERNS_PER_RULE: usize = 64;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_HEADER_ENTRIES: usize = 64;
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 1024;
const MAX_RULES_UPDATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RULES_UPDATE_JITTER_PERCENT: u8 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    Block,
    Allow,
    Log,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "BLOCK",
            Self::Allow => "ALLOW",
            Self::Log => "LOG",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    #[default]
    Request,
    Response,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSpec {
    #[serde(default = "default_block_status")]
    pub status: u16,
    #[serde(default)]
    pub body: Option<String>,
}

impl Default for ResponseSpec {
    fn default() -> Self {
        Self {
            status: default_block_status(),
            body: None,
        }
    }
}

fn default_block_status() -> u16 {
    403
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    #[serde(default, deserialize_with = "de_opt_string_or_seq")]
    pub path: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_opt_string_or_seq")]
    pub method: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_opt_string_or_seq")]
    pub source_ip: Option<Vec<String>>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, StringOrSeq>>,
    #[serde(default)]
    pub cookies: Option<BTreeMap<String, StringOrSeq>>,
    #[serde(default, rename = "in", deserialize_with = "de_opt_string_or_seq")]
    pub targets: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_opt_string_or_seq")]
    pub regex: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_opt_statuses")]
    pub status: Option<Vec<StatusItem>>,
    #[serde(default)]
    pub response_headers: Option<BTreeMap<String, StringOrSeq>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StatusItem {
    Code(u16),
    Text(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StatusItems {
    One(StatusItem),
    Many(Vec<StatusItem>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StringOrSeq {
    One(String),
    Many(Vec<String>),
}

impl StringOrSeq {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategorySpec {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub phase: Phase,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub response: Option<ResponseSpec>,
    /// Scoring mode: each matching rule adds one point and the category action
    /// applies once the score reaches the threshold.
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub response: Option<ResponseSpec>,
    #[serde(default)]
    pub limit: Option<LimitSpec>,
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
}

/// Per-source rate limit attached to a rule: while the source stays within
/// `requests` per `window` the rule is transparent; beyond it the rule fires.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSpec {
    pub requests: u32,
    #[serde(default = "secs60", deserialize_with = "de_duration")]
    pub window: Duration,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSpec {
    pub listen: SocketAddr,
    pub upstream: String,
    #[serde(default)]
    pub categories: Vec<CategorySpec>,
    #[serde(default)]
    pub rules_file: Option<PathBuf>,
    #[serde(default)]
    pub overrides_file: Option<PathBuf>,
    #[serde(default)]
    pub rules_update: RulesUpdateSpec,
    #[serde(default)]
    pub timeouts: TimeoutsSpec,
    #[serde(default)]
    pub limits: LimitsSpec,
    #[serde(default)]
    pub protection: ProtectionSpec,
    #[serde(default)]
    pub admin: AdminSpec,
    #[serde(default)]
    pub tls: Option<TlsSpec>,
    #[serde(default)]
    pub http3: Http3Spec,
    #[serde(default)]
    pub response_headers: ResponseHeadersSpec,
}

/// A categories-only YAML document, used for `rules_file` and `overrides_file`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesFileSpec {
    #[serde(default)]
    pub categories: Vec<CategorySpec>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesUpdateSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub checksum_url: Option<String>,
    #[serde(default = "hours24", deserialize_with = "de_duration")]
    pub interval: Duration,
    #[serde(default = "default_jitter_percent")]
    pub jitter_percent: u8,
    #[serde(default = "default_max_rules_bytes")]
    pub max_bytes: usize,
}

impl Default for RulesUpdateSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            checksum_url: None,
            interval: hours24(),
            jitter_percent: default_jitter_percent(),
            max_bytes: default_max_rules_bytes(),
        }
    }
}

fn hours24() -> Duration {
    Duration::from_secs(24 * 3600)
}

fn default_jitter_percent() -> u8 {
    10
}

fn default_max_rules_bytes() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsSpec {
    #[serde(default = "secs10", deserialize_with = "de_duration")]
    pub header_read: Duration,
    #[serde(default = "secs30", deserialize_with = "de_duration")]
    pub body_read: Duration,
    #[serde(default = "secs5", deserialize_with = "de_duration")]
    pub upstream_connect: Duration,
    #[serde(default = "secs30", deserialize_with = "de_duration")]
    pub upstream_response: Duration,
    #[serde(default = "secs10", deserialize_with = "de_duration")]
    pub shutdown_grace: Duration,
    #[serde(default = "minutes10", deserialize_with = "de_duration")]
    pub websocket_idle: Duration,
}

impl Default for TimeoutsSpec {
    fn default() -> Self {
        Self {
            header_read: secs10(),
            body_read: secs30(),
            upstream_connect: secs5(),
            upstream_response: secs30(),
            shutdown_grace: secs10(),
            websocket_idle: minutes10(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSpec {
    #[serde(default = "default_max_path_bytes")]
    pub max_path_bytes: usize,
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_max_body_bytes")]
    pub max_response_body_bytes: usize,
}

impl Default for LimitsSpec {
    fn default() -> Self {
        Self {
            max_path_bytes: default_max_path_bytes(),
            max_header_bytes: default_max_header_bytes(),
            max_headers: default_max_headers(),
            max_body_bytes: default_max_body_bytes(),
            max_response_body_bytes: default_max_body_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_admin_listen")]
    pub listen: SocketAddr,
}

impl Default for AdminSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_admin_listen(),
        }
    }
}

fn default_admin_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9090))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSpec {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http3Spec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeadersSpec {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, deserialize_with = "de_opt_string_or_seq")]
    pub allowlist: Option<Vec<String>>,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: f64,
    #[serde(default = "default_burst")]
    pub burst: f64,
    #[serde(default = "default_global_requests_per_second")]
    pub global_requests_per_second: f64,
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
    #[serde(default = "default_aggregate_ipv6_prefix")]
    pub aggregate_ipv6_prefix: u8,
    #[serde(default)]
    pub ban: BanSpec,
}

impl Default for ProtectionSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            allowlist: None,
            max_connections_per_ip: default_max_connections_per_ip(),
            max_connections: default_max_connections(),
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
            global_requests_per_second: default_global_requests_per_second(),
            max_tracked_ips: default_max_tracked_ips(),
            aggregate_ipv6_prefix: default_aggregate_ipv6_prefix(),
            ban: BanSpec::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanSpec {
    #[serde(default = "default_ban_violations")]
    pub violations: u32,
    #[serde(default = "secs10", deserialize_with = "de_duration")]
    pub window: Duration,
    #[serde(default = "secs60", deserialize_with = "de_duration")]
    pub duration: Duration,
    #[serde(default = "hours1", deserialize_with = "de_duration")]
    pub max_duration: Duration,
}

impl Default for BanSpec {
    fn default() -> Self {
        Self {
            violations: default_ban_violations(),
            window: secs10(),
            duration: secs60(),
            max_duration: hours1(),
        }
    }
}

fn default_max_connections_per_ip() -> u32 {
    32
}

fn default_max_connections() -> u32 {
    1024
}

fn default_requests_per_second() -> f64 {
    20.0
}

fn default_burst() -> f64 {
    60.0
}

fn default_global_requests_per_second() -> f64 {
    2000.0
}

fn default_max_tracked_ips() -> usize {
    100_000
}

fn default_aggregate_ipv6_prefix() -> u8 {
    64
}

fn default_ban_violations() -> u32 {
    5
}

fn secs5() -> Duration {
    Duration::from_secs(5)
}

fn secs60() -> Duration {
    Duration::from_secs(60)
}

fn hours1() -> Duration {
    Duration::from_secs(3600)
}

fn secs10() -> Duration {
    Duration::from_secs(10)
}

fn secs30() -> Duration {
    Duration::from_secs(30)
}

fn minutes10() -> Duration {
    Duration::from_secs(600)
}

fn default_max_path_bytes() -> usize {
    8 * 1024
}

fn default_max_header_bytes() -> usize {
    32 * 1024
}

fn default_max_headers() -> usize {
    100
}

fn default_max_body_bytes() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub header_read: Duration,
    pub body_read: Duration,
    pub upstream_connect: Duration,
    pub upstream_response: Duration,
    pub shutdown_grace: Duration,
    pub websocket_idle: Duration,
}

impl From<&TimeoutsSpec> for Timeouts {
    fn from(spec: &TimeoutsSpec) -> Self {
        Self {
            header_read: spec.header_read,
            body_read: spec.body_read,
            upstream_connect: spec.upstream_connect,
            upstream_response: spec.upstream_response,
            shutdown_grace: spec.shutdown_grace,
            websocket_idle: spec.websocket_idle,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_path_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub max_response_body_bytes: usize,
}

impl From<&LimitsSpec> for Limits {
    fn from(spec: &LimitsSpec) -> Self {
        Self {
            max_path_bytes: spec.max_path_bytes,
            max_header_bytes: spec.max_header_bytes,
            max_headers: spec.max_headers,
            max_body_bytes: spec.max_body_bytes,
            max_response_body_bytes: spec.max_response_body_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

impl From<&TlsSpec> for Tls {
    fn from(spec: &TlsSpec) -> Self {
        Self {
            cert_file: spec.cert_file.clone(),
            key_file: spec.key_file.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Http3 {
    pub enabled: bool,
    pub listen: Option<SocketAddr>,
}

impl From<&Http3Spec> for Http3 {
    fn from(spec: &Http3Spec) -> Self {
        Self {
            enabled: spec.enabled,
            listen: spec.listen,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RulesUpdate {
    pub enabled: bool,
    pub url: Option<Uri>,
    pub checksum_url: Option<Uri>,
    pub interval: Duration,
    pub jitter_percent: u8,
    pub max_bytes: usize,
}

impl Default for RulesUpdate {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            checksum_url: None,
            interval: hours24(),
            jitter_percent: default_jitter_percent(),
            max_bytes: default_max_rules_bytes(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResponseHeaders {
    remove: Vec<HeaderName>,
    set: Vec<(HeaderName, HeaderValue)>,
}

impl ResponseHeaders {
    /// Remove and replace configured response headers. Removal runs first, so a
    /// name that appears in both lists is replaced rather than deleted.
    pub fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.set {
            headers.insert(name, value.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct Admin {
    pub enabled: bool,
    pub listen: SocketAddr,
}

impl From<&AdminSpec> for Admin {
    fn from(spec: &AdminSpec) -> Self {
        Self {
            enabled: spec.enabled,
            listen: spec.listen,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Protection {
    pub enabled: bool,
    pub allowlist: Vec<IpNet>,
    pub max_connections_per_ip: u32,
    pub max_connections: u32,
    pub requests_per_second: f64,
    pub burst: f64,
    pub global_requests_per_second: f64,
    pub max_tracked_ips: usize,
    pub aggregate_ipv6_prefix: u8,
    pub ban: BanConfig,
}

impl From<&ProtectionSpec> for Protection {
    fn from(spec: &ProtectionSpec) -> Self {
        Self {
            enabled: spec.enabled,
            allowlist: spec
                .allowlist
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|value| parse_ip_net(value).ok())
                .collect(),
            max_connections_per_ip: spec.max_connections_per_ip,
            max_connections: spec.max_connections,
            requests_per_second: spec.requests_per_second,
            burst: spec.burst,
            global_requests_per_second: spec.global_requests_per_second,
            max_tracked_ips: spec.max_tracked_ips,
            aggregate_ipv6_prefix: spec.aggregate_ipv6_prefix,
            ban: BanConfig {
                violations: spec.ban.violations,
                window: spec.ban.window,
                duration: spec.ban.duration,
                max_duration: spec.ban.max_duration,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BanConfig {
    pub violations: u32,
    pub window: Duration,
    pub duration: Duration,
    pub max_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    scheme: String,
    authority: String,
}

impl Upstream {
    pub fn request_uri(&self, path_and_query: &str) -> Result<Uri, http::Error> {
        Uri::builder()
            .scheme(self.scheme.as_str())
            .authority(self.authority.as_str())
            .path_and_query(path_and_query)
            .build()
    }
}

#[derive(Debug)]
pub struct CompiledConfig {
    pub listen: SocketAddr,
    pub upstream: Upstream,
    pub categories: Vec<CompiledCategory>,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub protection: Protection,
    pub admin: Admin,
    pub tls: Option<Tls>,
    pub http3: Http3,
    pub response_headers: ResponseHeaders,
    pub rules_file: Option<PathBuf>,
    pub overrides_file: Option<PathBuf>,
    pub rules_update: RulesUpdate,
}

impl CompiledConfig {
    pub fn has_response_rules(&self) -> bool {
        self.categories
            .iter()
            .any(|category| category.phase == Phase::Response && !category.rules.is_empty())
    }

    pub fn has_body_target_rules(&self) -> bool {
        self.categories.iter().any(|category| {
            category
                .rules
                .iter()
                .any(|rule| targets(&rule.matcher, TARGET_BODY))
        })
    }

    pub fn has_response_body_rules(&self) -> bool {
        self.categories.iter().any(|category| {
            category.phase == Phase::Response
                && category
                    .rules
                    .iter()
                    .any(|rule| targets(&rule.matcher, TARGET_RESPONSE_BODY))
        })
    }
}

fn targets(matcher: &Matcher, target: u8) -> bool {
    matcher
        .payload
        .as_ref()
        .is_some_and(|payload| payload.targets & target != 0)
}

#[derive(Debug)]
pub struct CompiledCategory {
    pub name: String,
    pub phase: Phase,
    pub action: Option<Action>,
    pub response: Option<ResponseSpec>,
    pub threshold: Option<u32>,
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub action: Option<Action>,
    pub response: Option<ResponseSpec>,
    pub limit: Option<RuleLimit>,
    pub limit_key: u32,
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Copy)]
pub struct RuleLimit {
    pub requests: u32,
    pub window: Duration,
}

pub fn load(path: &Path) -> Result<CompiledConfig, Error> {
    let spec = read_spec(path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let rules_file = spec
        .rules_file
        .as_deref()
        .map(|rules| resolve_path(base, rules));
    let overrides_file = spec
        .overrides_file
        .as_deref()
        .map(|overrides| resolve_path(base, overrides));
    let rules = load_rules_spec(&rules_file)?;
    let overrides = load_rules_spec(&overrides_file)?;
    let sources = RulesSources {
        overrides,
        rules,
        rules_file,
        overrides_file,
    };
    compile(spec, sources).map_err(Error::ConfigInvalid)
}

/// Load the main configuration file without reading `rules_file` or
/// `overrides_file`. Used by `kunato update-rules`, which must work before the
/// managed rules file exists for the first time.
pub fn load_settings(path: &Path) -> Result<CompiledConfig, Error> {
    let spec = read_spec(path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let sources = RulesSources {
        rules_file: spec
            .rules_file
            .as_deref()
            .map(|rules| resolve_path(base, rules)),
        overrides_file: spec
            .overrides_file
            .as_deref()
            .map(|overrides| resolve_path(base, overrides)),
        ..RulesSources::default()
    };
    compile(spec, sources).map_err(Error::ConfigInvalid)
}

fn read_spec(path: &Path) -> Result<ConfigSpec, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_saphyr::from_str(&text)?)
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn load_rules_spec(path: &Option<PathBuf>) -> Result<RulesFileSpec, Error> {
    let Some(path) = path else {
        return Ok(RulesFileSpec::default());
    };
    let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
        path: path.clone(),
        source,
    })?;
    if text.trim().is_empty() {
        return Ok(RulesFileSpec::default());
    }
    serde_saphyr::from_str(&text).map_err(|source| Error::RulesParse {
        path: path.clone(),
        source: Box::new(source),
    })
}

pub fn parse(text: &str) -> Result<CompiledConfig, Error> {
    let spec: ConfigSpec = serde_saphyr::from_str(text)?;
    let sources = RulesSources {
        rules_file: spec.rules_file.clone(),
        overrides_file: spec.overrides_file.clone(),
        ..RulesSources::default()
    };
    compile(spec, sources).map_err(Error::ConfigInvalid)
}

/// A categories-only rule set compiled from a `rules_file` or `overrides_file`
/// document, used to validate downloaded rules before they replace the active file.
#[derive(Debug, Default)]
pub struct ParsedRules {
    pub categories: Vec<CompiledCategory>,
    pub disabled_rules: Vec<String>,
}

pub fn parse_rules(text: &str) -> Result<ParsedRules, Error> {
    if text.trim().is_empty() {
        return Ok(ParsedRules::default());
    }
    let spec: RulesFileSpec = serde_saphyr::from_str(text)?;
    let disabled = normalize_disabled_rules(&spec.disabled_rules);
    let mut issues = Vec::new();
    let categories = compile_categories(
        &[("rules file", spec.categories.as_slice())],
        &disabled,
        &mut issues,
    );
    if !issues.is_empty() {
        return Err(Error::ConfigInvalid(issues));
    }
    Ok(ParsedRules {
        categories,
        disabled_rules: spec.disabled_rules,
    })
}

fn normalize_disabled_rules(names: &[String]) -> BTreeSet<String> {
    names
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Default)]
struct RulesSources {
    overrides: RulesFileSpec,
    rules: RulesFileSpec,
    rules_file: Option<PathBuf>,
    overrides_file: Option<PathBuf>,
}

fn compile(spec: ConfigSpec, sources: RulesSources) -> Result<CompiledConfig, Vec<String>> {
    let mut issues = Vec::new();

    validate_limits(&spec.limits, &mut issues);
    validate_timeouts(&spec.timeouts, &mut issues);
    validate_protection(&spec.protection, &mut issues);
    validate_admin(&spec.admin, &mut issues);
    validate_tls(&spec.tls, &mut issues);
    validate_http3(&spec.http3, &spec.tls, &mut issues);
    let response_headers = compile_response_headers(&spec.response_headers, &mut issues);
    let upstream = compile_upstream(&spec.upstream, &mut issues);
    let rules_update = compile_rules_update(&spec.rules_update, &sources.rules_file, &mut issues);

    let mut disabled = normalize_disabled_rules(&sources.overrides.disabled_rules);
    if !sources.rules.disabled_rules.is_empty() {
        issues.push(
            "rules file: `disabled_rules` is only supported in the overrides file".to_owned(),
        );
    }
    disabled.extend(normalize_disabled_rules(&sources.rules.disabled_rules));

    let categories = compile_categories(
        &[
            ("overrides file", sources.overrides.categories.as_slice()),
            ("", spec.categories.as_slice()),
            ("rules file", sources.rules.categories.as_slice()),
        ],
        &disabled,
        &mut issues,
    );

    if !issues.is_empty() {
        return Err(issues);
    }

    let Some(upstream) = upstream else {
        return Err(vec!["invalid upstream configuration".to_owned()]);
    };

    Ok(CompiledConfig {
        listen: spec.listen,
        upstream,
        categories,
        timeouts: Timeouts::from(&spec.timeouts),
        limits: Limits::from(&spec.limits),
        protection: Protection::from(&spec.protection),
        admin: Admin::from(&spec.admin),
        tls: spec.tls.as_ref().map(Tls::from),
        http3: Http3::from(&spec.http3),
        response_headers,
        rules_file: sources.rules_file,
        overrides_file: sources.overrides_file,
        rules_update,
    })
}

fn compile_categories(
    sources: &[(&str, &[CategorySpec])],
    disabled: &BTreeSet<String>,
    issues: &mut Vec<String>,
) -> Vec<CompiledCategory> {
    let mut seen_categories: BTreeSet<String> = BTreeSet::new();
    let mut categories = Vec::new();

    for (source, specs) in sources {
        for category in *specs {
            let context = prefixed(source, &format!("category `{}`", category.name));

            if category.name.trim().is_empty() {
                issues.push(prefixed(source, "category name must not be empty"));
            } else if !seen_categories.insert(category.name.clone()) {
                issues.push(format!("{context}: duplicate category name"));
            }

            if let Some(response) = &category.response {
                validate_response(response, &context, issues);
            }

            if let Some(threshold) = category.threshold {
                if threshold == 0 {
                    issues.push(format!("{context}: threshold must be greater than zero"));
                }
                if category.enabled {
                    match category.action {
                        None => issues.push(format!(
                            "{context}: `threshold` requires `action` on the category"
                        )),
                        Some(Action::Allow) => issues.push(format!(
                            "{context}: a threshold category cannot use action ALLOW"
                        )),
                        Some(_) => {}
                    }
                }
            }
            let scoring = category.threshold.is_some();

            let mut seen_rules: BTreeSet<&str> = BTreeSet::new();
            let mut rules = Vec::new();

            for rule in &category.rules {
                let rule_context = prefixed(source, &format!("{context}: rule `{}`", rule.name));

                if rule.name.trim().is_empty() {
                    issues.push(format!("{context}: rule name must not be empty"));
                } else if !seen_rules.insert(rule.name.as_str()) {
                    issues.push(format!("{rule_context}: duplicate rule name"));
                }

                if let Some(response) = &rule.response {
                    validate_response(response, &rule_context, issues);
                }

                if scoring && category.enabled && rule.enabled {
                    if rule.action.is_some() {
                        issues.push(format!(
                            "{rule_context}: rules in a threshold category cannot set `action`"
                        ));
                    }
                    if rule.response.is_some() {
                        issues.push(format!(
                            "{rule_context}: rules in a threshold category cannot set `response`"
                        ));
                    }
                    if rule.limit.is_some() {
                        issues.push(format!(
                            "{rule_context}: rules in a threshold category cannot set `limit`"
                        ));
                    }
                }

                let matcher = compile_matcher(&rule.matcher, category.phase, &rule_context, issues);
                let effective_action = rule.action.or(category.action);
                if !scoring && category.enabled && rule.enabled && effective_action.is_none() {
                    issues.push(format!(
                        "{rule_context}: no effective action; set `action` on the rule or the category"
                    ));
                }

                let limit = compile_limit(
                    rule.limit.as_ref(),
                    category.phase,
                    effective_action,
                    &rule_context,
                    issues,
                );

                if !category.enabled || !rule.enabled || disabled.contains(rule.name.as_str()) {
                    continue;
                }

                rules.push(CompiledRule {
                    name: rule.name.clone(),
                    action: rule.action,
                    response: rule.response.clone(),
                    limit_key: limit
                        .map(|_| rule_limit_key(&category.name, &rule.name))
                        .unwrap_or(0),
                    limit,
                    matcher,
                });
            }

            if !category.enabled {
                continue;
            }

            categories.push(CompiledCategory {
                name: category.name.clone(),
                phase: category.phase,
                action: category.action,
                response: category.response.clone(),
                threshold: category.threshold,
                rules,
            });
        }
    }

    categories
}

fn prefixed(source: &str, message: &str) -> String {
    if source.is_empty() {
        message.to_owned()
    } else {
        format!("{source}: {message}")
    }
}

fn compile_limit(
    spec: Option<&LimitSpec>,
    phase: Phase,
    action: Option<Action>,
    context: &str,
    issues: &mut Vec<String>,
) -> Option<RuleLimit> {
    let spec = spec?;
    if phase != Phase::Request {
        issues.push(format!(
            "{context}: `limit` is only valid in request-phase categories"
        ));
    }
    if spec.requests == 0 {
        issues.push(format!(
            "{context}: limit.requests must be greater than zero"
        ));
    }
    if spec.window.is_zero() {
        issues.push(format!("{context}: limit.window must be greater than zero"));
    }
    if action == Some(Action::Allow) {
        issues.push(format!(
            "{context}: a rule with `limit` cannot resolve to ALLOW"
        ));
    }
    Some(RuleLimit {
        requests: spec.requests,
        window: spec.window,
    })
}

/// Stable identifier for a rule's limit bucket: survives hot reloads because
/// it hashes the category and rule names instead of compiled positions.
fn rule_limit_key(category: &str, rule: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in category
        .bytes()
        .chain(std::iter::once(0))
        .chain(rule.bytes())
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn validate_limits(limits: &LimitsSpec, issues: &mut Vec<String>) {
    for (name, value) in [
        ("max_path_bytes", limits.max_path_bytes),
        ("max_header_bytes", limits.max_header_bytes),
        ("max_headers", limits.max_headers),
        ("max_body_bytes", limits.max_body_bytes),
        ("max_response_body_bytes", limits.max_response_body_bytes),
    ] {
        if value == 0 {
            issues.push(format!("limits.{name} must be greater than zero"));
        }
    }
}

fn validate_timeouts(timeouts: &TimeoutsSpec, issues: &mut Vec<String>) {
    for (name, value) in [
        ("header_read", timeouts.header_read),
        ("body_read", timeouts.body_read),
        ("upstream_connect", timeouts.upstream_connect),
        ("upstream_response", timeouts.upstream_response),
        ("websocket_idle", timeouts.websocket_idle),
    ] {
        if value.is_zero() {
            issues.push(format!("timeouts.{name} must be greater than zero"));
        }
    }
}

fn validate_tls(spec: &Option<TlsSpec>, issues: &mut Vec<String>) {
    let Some(tls) = spec else {
        return;
    };
    if tls.cert_file.as_os_str().is_empty() {
        issues.push("tls.cert_file must not be empty".to_owned());
    }
    if tls.key_file.as_os_str().is_empty() {
        issues.push("tls.key_file must not be empty".to_owned());
    }
}

fn validate_http3(spec: &Http3Spec, tls: &Option<TlsSpec>, issues: &mut Vec<String>) {
    if spec.enabled && tls.is_none() {
        issues.push("http3 requires a tls block".to_owned());
    }
}

fn compile_rules_update(
    spec: &RulesUpdateSpec,
    rules_file: &Option<PathBuf>,
    issues: &mut Vec<String>,
) -> RulesUpdate {
    let url = spec
        .url
        .as_deref()
        .and_then(|raw| compile_update_uri(raw, "rules_update.url", issues));
    let checksum_url = spec
        .checksum_url
        .as_deref()
        .and_then(|raw| compile_update_uri(raw, "rules_update.checksum_url", issues));

    if spec.enabled {
        if url.is_none() {
            issues.push("rules_update.enabled requires `rules_update.url`".to_owned());
        }
        if checksum_url.is_none() {
            issues.push("rules_update.enabled requires `rules_update.checksum_url`".to_owned());
        }
        if rules_file.is_none() {
            issues.push("rules_update.enabled requires `rules_file`".to_owned());
        }
        if spec.interval.is_zero() {
            issues.push("rules_update.interval must be greater than zero".to_owned());
        }
        if spec.jitter_percent > MAX_RULES_UPDATE_JITTER_PERCENT {
            issues.push(format!(
                "rules_update.jitter_percent must be at most {MAX_RULES_UPDATE_JITTER_PERCENT}"
            ));
        }
        if spec.max_bytes == 0 || spec.max_bytes > MAX_RULES_UPDATE_BYTES {
            issues.push(format!(
                "rules_update.max_bytes must be between 1 and {MAX_RULES_UPDATE_BYTES}"
            ));
        }
    }

    RulesUpdate {
        enabled: spec.enabled,
        url,
        checksum_url,
        interval: spec.interval,
        jitter_percent: spec.jitter_percent,
        max_bytes: spec.max_bytes,
    }
}

fn compile_update_uri(raw: &str, field: &str, issues: &mut Vec<String>) -> Option<Uri> {
    let uri = match Uri::from_str(raw) {
        Ok(uri) => uri,
        Err(err) => {
            issues.push(format!("{field}: invalid URL `{raw}`: {err}"));
            return None;
        }
    };
    if uri.authority().is_none() {
        issues.push(format!("{field}: `{raw}` is missing a host"));
        return None;
    }
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "https" && !(scheme == "http" && uri_host_is_loopback(&uri)) {
        issues.push(format!(
            "{field}: `{raw}` must use https (http is only allowed for loopback hosts)"
        ));
        return None;
    }
    Some(uri)
}

fn uri_host_is_loopback(uri: &Uri) -> bool {
    match uri.host() {
        Some(host) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
        None => false,
    }
}

fn compile_response_headers(
    spec: &ResponseHeadersSpec,
    issues: &mut Vec<String>,
) -> ResponseHeaders {
    let mut remove = Vec::new();
    if spec.remove.len() > MAX_RESPONSE_HEADER_ENTRIES {
        issues.push(format!(
            "response_headers.remove: too many entries (max {MAX_RESPONSE_HEADER_ENTRIES})"
        ));
    }
    for raw in spec.remove.iter().take(MAX_RESPONSE_HEADER_ENTRIES) {
        match HeaderName::from_bytes(raw.as_bytes()) {
            Ok(name) if is_proxy_managed_header(&name) => issues.push(format!(
                "response_headers.remove: `{raw}` is managed by the proxy and cannot be removed"
            )),
            Ok(name) => remove.push(name),
            Err(_) => issues.push(format!(
                "response_headers.remove: invalid header name `{raw}`"
            )),
        }
    }

    let mut set = Vec::new();
    if spec.set.len() > MAX_RESPONSE_HEADER_ENTRIES {
        issues.push(format!(
            "response_headers.set: too many entries (max {MAX_RESPONSE_HEADER_ENTRIES})"
        ));
    }
    for (raw_name, raw_value) in spec.set.iter().take(MAX_RESPONSE_HEADER_ENTRIES) {
        let name = match HeaderName::from_bytes(raw_name.as_bytes()) {
            Ok(name) if is_proxy_managed_header(&name) => {
                issues.push(format!(
                    "response_headers.set: `{raw_name}` is managed by the proxy and cannot be set"
                ));
                continue;
            }
            Ok(name) => name,
            Err(_) => {
                issues.push(format!(
                    "response_headers.set: invalid header name `{raw_name}`"
                ));
                continue;
            }
        };
        if raw_value.is_empty() {
            issues.push(format!(
                "response_headers.set: `{raw_name}` must not be empty; use `remove` instead"
            ));
            continue;
        }
        if raw_value.len() > MAX_RESPONSE_HEADER_VALUE_BYTES {
            issues.push(format!(
                "response_headers.set: `{raw_name}` value exceeds {MAX_RESPONSE_HEADER_VALUE_BYTES} bytes"
            ));
            continue;
        }
        match HeaderValue::from_str(raw_value) {
            Ok(value) => set.push((name, value)),
            Err(_) => issues.push(format!(
                "response_headers.set: invalid value for `{raw_name}`"
            )),
        }
    }

    ResponseHeaders { remove, set }
}

fn is_proxy_managed_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "alt-svc"
    )
}

fn validate_admin(spec: &AdminSpec, issues: &mut Vec<String>) {
    if spec.enabled && !spec.listen.ip().is_loopback() {
        issues.push(format!(
            "admin.listen must be a loopback address, got `{}`",
            spec.listen
        ));
    }
}

fn validate_protection(spec: &ProtectionSpec, issues: &mut Vec<String>) {
    if spec.requests_per_second <= 0.0 {
        issues.push("protection.requests_per_second must be greater than zero".to_owned());
    }
    if spec.burst < 1.0 {
        issues.push("protection.burst must be at least 1".to_owned());
    }
    if spec.global_requests_per_second <= 0.0 {
        issues.push("protection.global_requests_per_second must be greater than zero".to_owned());
    }
    if spec.max_connections == 0 {
        issues.push("protection.max_connections must be greater than zero".to_owned());
    }
    if spec.max_connections_per_ip == 0 {
        issues.push("protection.max_connections_per_ip must be greater than zero".to_owned());
    }
    if spec.max_tracked_ips == 0 {
        issues.push("protection.max_tracked_ips must be greater than zero".to_owned());
    }
    if !(1..=128).contains(&spec.aggregate_ipv6_prefix) {
        issues.push("protection.aggregate_ipv6_prefix must be between 1 and 128".to_owned());
    }
    if spec.ban.violations == 0 {
        issues.push("protection.ban.violations must be greater than zero".to_owned());
    }
    if spec.ban.window.is_zero() {
        issues.push("protection.ban.window must be greater than zero".to_owned());
    }
    if spec.ban.duration.is_zero() {
        issues.push("protection.ban.duration must be greater than zero".to_owned());
    }
    if spec.ban.max_duration < spec.ban.duration {
        issues.push("protection.ban.max_duration must not be shorter than duration".to_owned());
    }
    if let Some(allowlist) = &spec.allowlist {
        for value in allowlist {
            if let Err(message) = parse_ip_net(value) {
                issues.push(format!("protection.allowlist: {message}"));
            }
        }
    }
}

fn validate_response(response: &ResponseSpec, context: &str, issues: &mut Vec<String>) {
    if !(100..=599).contains(&response.status) {
        issues.push(format!(
            "{context}: invalid response status {}",
            response.status
        ));
    }
    if let Some(body) = &response.body
        && body.len() > MAX_RESPONSE_BODY_BYTES
    {
        issues.push(format!(
            "{context}: response body exceeds {MAX_RESPONSE_BODY_BYTES} bytes"
        ));
    }
}

fn compile_upstream(raw: &str, issues: &mut Vec<String>) -> Option<Upstream> {
    let uri = match Uri::from_str(raw) {
        Ok(uri) => uri,
        Err(err) => {
            issues.push(format!("invalid upstream URL `{raw}`: {err}"));
            return None;
        }
    };

    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    if scheme != "http" {
        issues.push(format!(
            "upstream `{raw}`: only http upstreams are supported (https is planned)"
        ));
        return None;
    }

    let Some(authority) = uri.authority() else {
        issues.push(format!("upstream `{raw}`: missing host"));
        return None;
    };

    if let Some(path_and_query) = uri.path_and_query()
        && path_and_query.path() != "/"
    {
        issues.push(format!("upstream `{raw}`: base path is not supported"));
        return None;
    }

    Some(Upstream {
        scheme,
        authority: authority.as_str().to_owned(),
    })
}

fn compile_matcher(
    spec: &MatchSpec,
    phase: Phase,
    context: &str,
    issues: &mut Vec<String>,
) -> Matcher {
    let mut matcher = Matcher::default();
    let mut has_condition = false;

    if let Some(patterns) = &spec.path {
        has_condition = true;
        if patterns.is_empty() {
            issues.push(format!("{context}: `path` must not be empty"));
        }
        matcher.paths = compile_regexes(patterns, &format!("{context}: path"), issues);
    }

    if let Some(values) = &spec.method {
        has_condition = true;
        if values.is_empty() {
            issues.push(format!("{context}: `method` must not be empty"));
        }
        let methods = compile_methods(values, &format!("{context}: method"), issues);
        if !methods.is_empty() {
            matcher.methods = Some(methods);
        }
    }

    if let Some(values) = &spec.source_ip {
        has_condition = true;
        if values.is_empty() {
            issues.push(format!("{context}: `source_ip` must not be empty"));
        }
        let networks = compile_networks(values, &format!("{context}: source_ip"), issues);
        if !networks.is_empty() {
            matcher.source_ips = Some(networks);
        }
    }

    if let Some(map) = &spec.headers {
        has_condition = true;
        if map.is_empty() {
            issues.push(format!("{context}: `headers` must not be empty"));
        }
        matcher.headers = compile_header_matchers(map, context, issues);
    }

    if let Some(map) = &spec.cookies {
        has_condition = true;
        if map.is_empty() {
            issues.push(format!("{context}: `cookies` must not be empty"));
        }
        matcher.cookies = compile_cookie_matchers(map, context, issues);
    }

    if let Some(items) = &spec.status {
        has_condition = true;
        if phase != Phase::Response {
            issues.push(format!("{context}: `status` requires `phase: response`"));
        } else {
            matcher.statuses = compile_statuses(items, &format!("{context}: status"), issues);
        }
    }

    if let Some(map) = &spec.response_headers {
        has_condition = true;
        if phase != Phase::Response {
            issues.push(format!(
                "{context}: `response_headers` requires `phase: response`"
            ));
        } else {
            if map.is_empty() {
                issues.push(format!("{context}: `response_headers` must not be empty"));
            }
            matcher.response_headers =
                compile_header_matchers(map, &format!("{context}: response_headers"), issues);
        }
    }

    match &spec.regex {
        Some(patterns) => {
            has_condition = true;
            if patterns.is_empty() {
                issues.push(format!("{context}: `regex` must not be empty"));
            }
            matcher.payload =
                compile_payload(patterns, spec.targets.as_deref(), phase, context, issues);
        }
        None => {
            if spec.targets.is_some() {
                issues.push(format!("{context}: `in` requires `regex`"));
            }
        }
    }

    if !has_condition {
        issues.push(format!(
            "{context}: `match` must contain at least one condition"
        ));
    }

    matcher
}

fn compile_payload(
    patterns: &[String],
    targets: Option<&[String]>,
    phase: Phase,
    context: &str,
    issues: &mut Vec<String>,
) -> Option<PayloadMatcher> {
    let mut target_flags = 0u8;

    match targets {
        Some(targets) => {
            if targets.is_empty() {
                issues.push(format!("{context}: `in` must not be empty"));
            }
            for target in targets {
                match target.as_str() {
                    "path" => target_flags |= TARGET_PATH,
                    "query" => target_flags |= TARGET_QUERY,
                    "body" => target_flags |= TARGET_BODY,
                    "cookies" => target_flags |= TARGET_COOKIES,
                    "headers" => target_flags |= TARGET_HEADERS,
                    "response_body" => {
                        if phase == Phase::Response {
                            target_flags |= TARGET_RESPONSE_BODY;
                        } else {
                            issues.push(format!(
                                "{context}: `in` target `response_body` requires `phase: response`"
                            ));
                        }
                    }
                    other => issues.push(format!("{context}: unknown `in` target `{other}`")),
                }
            }
        }
        None if phase == Phase::Response => target_flags = TARGET_RESPONSE_BODY,
        None => target_flags = TARGET_QUERY | TARGET_BODY | TARGET_COOKIES,
    }

    let regexes = compile_regexes(patterns, &format!("{context}: regex"), issues);
    if target_flags == 0 || regexes.is_empty() {
        return None;
    }

    Some(PayloadMatcher {
        regexes,
        targets: target_flags,
    })
}

fn compile_regexes(patterns: &[String], context: &str, issues: &mut Vec<String>) -> Vec<Regex> {
    let mut regexes = Vec::new();

    if patterns.len() > MAX_PATTERNS_PER_RULE {
        issues.push(format!(
            "{context}: too many patterns (max {MAX_PATTERNS_PER_RULE})"
        ));
    }

    for pattern in patterns.iter().take(MAX_PATTERNS_PER_RULE) {
        if pattern.len() > MAX_PATTERN_BYTES {
            issues.push(format!(
                "{context}: pattern exceeds {MAX_PATTERN_BYTES} bytes"
            ));
            continue;
        }
        match RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            Ok(regex) => regexes.push(regex),
            Err(err) => issues.push(format!("{context}: invalid regex: {err}")),
        }
    }

    regexes
}

fn compile_methods(values: &[String], context: &str, issues: &mut Vec<String>) -> Vec<Method> {
    let mut methods = Vec::new();
    for value in values {
        match Method::from_bytes(value.as_bytes()) {
            Ok(method) => methods.push(method),
            Err(_) => issues.push(format!("{context}: invalid HTTP method `{value}`")),
        }
    }
    methods
}

fn compile_networks(values: &[String], context: &str, issues: &mut Vec<String>) -> Vec<IpNet> {
    let mut networks = Vec::new();
    for value in values {
        match parse_ip_net(value) {
            Ok(network) => networks.push(network),
            Err(message) => issues.push(format!("{context}: {message}")),
        }
    }
    networks
}

fn compile_statuses(
    items: &[StatusItem],
    context: &str,
    issues: &mut Vec<String>,
) -> Vec<StatusRange> {
    if items.is_empty() {
        issues.push(format!("{context}: `status` must not be empty"));
    }
    if items.len() > MAX_PATTERNS_PER_RULE {
        issues.push(format!(
            "{context}: too many status entries (max {MAX_PATTERNS_PER_RULE})"
        ));
    }

    let mut ranges = Vec::new();
    for item in items.iter().take(MAX_PATTERNS_PER_RULE) {
        match item {
            StatusItem::Code(code) => match status_code_range(*code) {
                Some(range) => ranges.push(range),
                None => issues.push(format!("{context}: invalid status code {code}")),
            },
            StatusItem::Text(text) => match parse_status_range(text) {
                Ok(range) => ranges.push(range),
                Err(message) => issues.push(format!("{context}: {message}")),
            },
        }
    }
    ranges
}

fn parse_status_range(text: &str) -> Result<StatusRange, String> {
    let trimmed = text.trim();

    if trimmed.len() == 3 {
        let bytes = trimmed.as_bytes();
        let is_class =
            (bytes[1] == b'x' || bytes[1] == b'X') && (bytes[2] == b'x' || bytes[2] == b'X');
        if is_class {
            if !(b'1'..=b'5').contains(&bytes[0]) {
                return Err(format!("invalid status class `{trimmed}`"));
            }
            let start = u16::from(bytes[0] - b'0') * 100;
            return Ok(StatusRange {
                start,
                end: start + 99,
            });
        }
    }

    if let Some((start, end)) = trimmed.split_once('-') {
        let start: u16 = start
            .trim()
            .parse()
            .map_err(|_| format!("invalid status range `{trimmed}`"))?;
        let end: u16 = end
            .trim()
            .parse()
            .map_err(|_| format!("invalid status range `{trimmed}`"))?;
        if !(100..=599).contains(&start) || !(100..=599).contains(&end) || start > end {
            return Err(format!("invalid status range `{trimmed}`"));
        }
        return Ok(StatusRange { start, end });
    }

    let code: u16 = trimmed
        .parse()
        .map_err(|_| format!("invalid status `{trimmed}`"))?;
    status_code_range(code).ok_or_else(|| format!("invalid status `{trimmed}`"))
}

fn status_code_range(code: u16) -> Option<StatusRange> {
    (100..=599).contains(&code).then_some(StatusRange {
        start: code,
        end: code,
    })
}

fn parse_ip_net(value: &str) -> Result<IpNet, String> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(network);
    }
    let address: IpAddr = value
        .parse()
        .map_err(|_| format!("invalid IP address or CIDR `{value}`"))?;
    Ok(IpNet::from(address))
}

fn compile_header_matchers(
    map: &BTreeMap<String, StringOrSeq>,
    context: &str,
    issues: &mut Vec<String>,
) -> Vec<(HeaderName, Vec<Regex>)> {
    let mut matchers = Vec::new();
    for (name, patterns) in map {
        let Ok(header) = HeaderName::from_bytes(name.as_bytes()) else {
            issues.push(format!("{context}: invalid header name `{name}`"));
            continue;
        };
        let regexes = compile_regexes(
            &patterns.clone().into_vec(),
            &format!("{context}: header `{name}`"),
            issues,
        );
        if !regexes.is_empty() {
            matchers.push((header, regexes));
        }
    }
    matchers
}

fn compile_cookie_matchers(
    map: &BTreeMap<String, StringOrSeq>,
    context: &str,
    issues: &mut Vec<String>,
) -> Vec<(String, Vec<Regex>)> {
    let mut matchers = Vec::new();
    for (name, patterns) in map {
        if name.trim().is_empty() {
            issues.push(format!("{context}: cookie name must not be empty"));
            continue;
        }
        let regexes = compile_regexes(
            &patterns.clone().into_vec(),
            &format!("{context}: cookie `{name}`"),
            issues,
        );
        if !regexes.is_empty() {
            matchers.push((name.clone(), regexes));
        }
    }
    matchers
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DurationValue {
    Seconds(u64),
    Text(String),
}

fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    match DurationValue::deserialize(deserializer)? {
        DurationValue::Seconds(seconds) => Ok(Duration::from_secs(seconds)),
        DurationValue::Text(text) => parse_duration(&text).map_err(DeError::custom),
    }
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("duration must not be empty".to_owned());
    }

    let (number, unit) = if let Some(value) = text.strip_suffix("ms") {
        (value, "ms")
    } else if let Some(value) = text.strip_suffix('s') {
        (value, "s")
    } else if let Some(value) = text.strip_suffix('m') {
        (value, "m")
    } else if let Some(value) = text.strip_suffix('h') {
        (value, "h")
    } else {
        (text, "s")
    };

    let value: u64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration `{text}`"))?;

    Ok(match unit {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        "h" => Duration::from_secs(value * 3600),
        _ => unreachable!("unit is one of the known suffixes"),
    })
}

fn de_opt_string_or_seq<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<StringOrSeq>::deserialize(deserializer)?;
    Ok(value.map(StringOrSeq::into_vec))
}

fn de_opt_statuses<'de, D>(deserializer: D) -> Result<Option<Vec<StatusItem>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<StatusItems>::deserialize(deserializer)?;
    Ok(value.map(|items| match items {
        StatusItems::One(item) => vec![item],
        StatusItems::Many(items) => items,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "listen: 127.0.0.1:8080\nupstream: http://127.0.0.1:3000\n";

    fn parse_with(base: &str, rest: &str) -> Result<CompiledConfig, Error> {
        parse(&format!("{base}{rest}"))
    }

    #[test]
    fn parses_minimal_config() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert!(config.categories.is_empty());
        assert_eq!(config.limits.max_body_bytes, 1024 * 1024);
        assert_eq!(config.timeouts.header_read, Duration::from_secs(10));
    }

    #[test]
    fn parses_compact_rule_style() {
        let config = parse_with(
            BASE,
            "categories:
  - name: sql-injection
    action: BLOCK
    response: { status: 403, body: Forbidden }
    rules:
      - name: union-select
        match: { regex: '(?i)\\bunion\\b.{0,40}\\bselect\\b', in: [query, body] }
",
        )
        .expect("valid config");
        let category = &config.categories[0];
        assert_eq!(category.action, Some(Action::Block));
        assert_eq!(category.response.as_ref().map(|r| r.status), Some(403));
        assert_eq!(category.rules.len(), 1);
        assert!(category.rules[0].matcher.payload.is_some());
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = parse_with(BASE, "categories: []\nbogus: true\n").expect_err("must fail");
        assert!(matches!(error, Error::ConfigParse(_)));
    }

    #[test]
    fn rejects_rule_without_effective_action() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    rules:
      - name: rule
        match: { path: / }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("no effective action"));
    }

    #[test]
    fn rule_action_overrides_category_default() {
        let config = parse_with(
            BASE,
            "categories:
  - name: scanners
    action: LOG
    rules:
      - name: block-sensitive
        action: BLOCK
        match: { path: /admin }
",
        )
        .expect("valid config");
        assert_eq!(config.categories[0].rules[0].action, Some(Action::Block));
    }

    #[test]
    fn rejects_invalid_regex() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: { path: '(' }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("invalid regex"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: { source_ip: not-an-ip }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("invalid IP address"));
    }

    #[test]
    fn rejects_empty_match() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: {}
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("at least one condition"));
    }

    #[test]
    fn rule_limits_are_compiled() {
        let config = parse_with(
            BASE,
            "categories:
  - name: brute-force
    action: BLOCK
    rules:
      - name: login
        limit: { requests: 5, window: 30s }
        match: { path: ^/login }
",
        )
        .expect("valid config");
        let rule = &config.categories[0].rules[0];
        let limit = rule.limit.expect("compiled limit");
        assert_eq!(limit.requests, 5);
        assert_eq!(limit.window, Duration::from_secs(30));
        assert_ne!(rule.limit_key, 0);
    }

    #[test]
    fn rule_limit_keys_are_stable_across_reloads() {
        let yaml = "categories:
  - name: brute-force
    action: BLOCK
    rules:
      - name: login
        limit: { requests: 5 }
        match: { path: ^/login }
";
        let first = parse_with(BASE, yaml).expect("valid config");
        let second = parse_with(BASE, yaml).expect("valid config");
        assert_eq!(
            first.categories[0].rules[0].limit_key,
            second.categories[0].rules[0].limit_key
        );
    }

    #[test]
    fn rejects_invalid_rule_limits() {
        let error = parse_with(
            BASE,
            "categories:
  - name: brute-force
    action: BLOCK
    rules:
      - name: login
        limit: { requests: 0 }
        match: { path: ^/login }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("limit.requests"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: brute-force
    action: BLOCK
    rules:
      - name: login
        limit: { requests: 5, window: 0s }
        match: { path: ^/login }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("limit.window"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: responses
    phase: response
    action: BLOCK
    rules:
      - name: leak
        limit: { requests: 5 }
        match: { regex: secret }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("request-phase"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: brute-force
    action: ALLOW
    rules:
      - name: login
        limit: { requests: 5 }
        match: { path: ^/login }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("ALLOW"), "{error}");
    }

    #[test]
    fn threshold_categories_are_compiled() {
        let config = parse_with(
            BASE,
            "categories:
  - name: anomaly
    action: BLOCK
    threshold: 2
    rules:
      - name: one
        match: { path: /a }
      - name: two
        match: { path: /b }
",
        )
        .expect("valid config");
        assert_eq!(config.categories[0].threshold, Some(2));
    }

    #[test]
    fn rejects_invalid_threshold_configurations() {
        let error = parse_with(
            BASE,
            "categories:
  - name: anomaly
    action: BLOCK
    threshold: 0
    rules:
      - name: one
        match: { path: /a }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("threshold"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: anomaly
    threshold: 2
    rules:
      - name: one
        match: { path: /a }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("requires `action`"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: anomaly
    action: ALLOW
    threshold: 2
    rules:
      - name: one
        match: { path: /a }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("ALLOW"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: anomaly
    action: BLOCK
    threshold: 2
    rules:
      - name: one
        action: LOG
        match: { path: /a }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("cannot set `action`"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: anomaly
    action: BLOCK
    threshold: 2
    rules:
      - name: one
        limit: { requests: 5 }
        match: { path: /a }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("cannot set `limit`"), "{error}");
    }

    #[test]
    fn rejects_duplicate_rule_names() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: same
        match: { path: /a }
      - name: same
        match: { path: /b }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("duplicate rule name"));
    }

    #[test]
    fn accepts_scalar_or_list_shorthand() {
        let config = parse_with(
            BASE,
            "categories:
  - name: methods
    action: LOG
    rules:
      - name: scalar
        match: { method: GET }
      - name: list
        match: { method: [GET, POST] }
      - name: ip-scalar
        match: { source_ip: 203.0.113.10 }
",
        )
        .expect("valid config");
        let methods = config.categories[0].rules[0]
            .matcher
            .methods
            .as_ref()
            .expect("methods");
        assert_eq!(methods.as_slice(), [Method::GET]);
    }

    #[test]
    fn skips_disabled_rules_and_categories() {
        let config = parse_with(
            BASE,
            "categories:
  - name: disabled-category
    enabled: false
    action: BLOCK
    rules:
      - name: rule
        match: { path: / }
  - name: live
    action: LOG
    rules:
      - name: disabled-rule
        enabled: false
        match: { path: /a }
",
        )
        .expect("valid config");
        assert_eq!(config.categories.len(), 1);
        assert!(config.categories[0].rules.is_empty());
    }

    #[test]
    fn parses_duration_units() {
        let config = parse_with(BASE, "timeouts: { header_read: 1500ms, body_read: 2m }\n")
            .expect("valid config");
        assert_eq!(config.timeouts.header_read, Duration::from_millis(1500));
        assert_eq!(config.timeouts.body_read, Duration::from_secs(120));
    }

    #[test]
    fn rejects_invalid_duration() {
        let error = parse_with(BASE, "timeouts: { header_read: soon }\n").expect_err("must fail");
        assert!(matches!(error, Error::ConfigParse(_)));
    }

    #[test]
    fn rejects_zero_limits() {
        let error = parse_with(BASE, "limits: { max_body_bytes: 0 }\n").expect_err("must fail");
        assert!(error.to_string().contains("max_body_bytes"));
    }

    #[test]
    fn parses_protection_block() {
        let config = parse_with(
            BASE,
            "protection:
  enabled: true
  allowlist: [10.0.0.0/8, 192.168.0.0/16]
  requests_per_second: 5
  burst: 10
  ban: { violations: 3, window: 20s, duration: 2m, max_duration: 30m }
",
        )
        .expect("valid config");
        assert!(config.protection.enabled);
        assert_eq!(config.protection.allowlist.len(), 2);
        assert_eq!(config.protection.requests_per_second, 5.0);
        assert_eq!(config.protection.burst, 10.0);
        assert_eq!(config.protection.aggregate_ipv6_prefix, 64);
        assert_eq!(config.protection.ban.violations, 3);
        assert_eq!(config.protection.ban.window, Duration::from_secs(20));
        assert_eq!(config.protection.ban.duration, Duration::from_secs(120));
        assert_eq!(
            config.protection.ban.max_duration,
            Duration::from_secs(1800)
        );
    }

    #[test]
    fn parses_admin_block() {
        let config = parse_with(BASE, "admin: { listen: 127.0.0.1:8000 }\n").expect("valid config");
        assert!(config.admin.enabled);
        assert_eq!(config.admin.listen.port(), 8000);
    }

    #[test]
    fn rejects_non_loopback_admin_listener() {
        let error = parse_with(BASE, "admin: { listen: 0.0.0.0:9090 }\n").expect_err("must fail");
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn parses_tls_block() {
        let config = parse_with(
            BASE,
            "tls: { cert_file: /etc/kunato/cert.pem, key_file: /etc/kunato/key.pem }\n",
        )
        .expect("valid config");
        let tls = config.tls.expect("tls block");
        assert_eq!(tls.cert_file, PathBuf::from("/etc/kunato/cert.pem"));
    }

    #[test]
    fn rejects_empty_tls_paths() {
        let error =
            parse_with(BASE, "tls: { cert_file: '', key_file: key.pem }\n").expect_err("must fail");
        assert!(error.to_string().contains("cert_file"));
    }

    #[test]
    fn parses_http3_block() {
        let config = parse_with(
            BASE,
            "tls: { cert_file: cert.pem, key_file: key.pem }
http3: { enabled: true, listen: 127.0.0.1:8443 }
",
        )
        .expect("valid config");
        assert!(config.http3.enabled);
        assert_eq!(config.http3.listen.map(|addr| addr.port()), Some(8443));
    }

    #[test]
    fn http3_is_disabled_by_default() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert!(!config.http3.enabled);
        assert!(config.http3.listen.is_none());
    }

    #[test]
    fn rejects_http3_without_tls() {
        let error = parse_with(BASE, "http3: { enabled: true }\n").expect_err("must fail");
        assert!(error.to_string().contains("http3 requires a tls block"));
    }

    #[test]
    fn parses_and_applies_response_header_policy() {
        let config = parse_with(
            BASE,
            "response_headers:
  remove: [Server, X-Powered-By]
  set: { X-Served-By: kunato }
",
        )
        .expect("valid config");

        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx/1.27"));
        headers.insert("x-powered-by", HeaderValue::from_static("php"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        config.response_headers.apply(&mut headers);

        assert!(!headers.contains_key("server"));
        assert!(!headers.contains_key("x-powered-by"));
        assert!(headers.contains_key("content-type"));
        assert_eq!(
            headers.get("x-served-by").map(|value| value.as_bytes()),
            Some(b"kunato".as_slice())
        );
    }

    #[test]
    fn response_header_set_wins_over_remove() {
        let config = parse_with(
            BASE,
            "response_headers: { remove: [server], set: { server: hidden } }\n",
        )
        .expect("valid config");

        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx"));
        config.response_headers.apply(&mut headers);

        assert_eq!(
            headers.get("server").map(|value| value.as_bytes()),
            Some(b"hidden".as_slice())
        );
    }

    #[test]
    fn rejects_invalid_response_header_policy() {
        let error = parse_with(BASE, "response_headers: { remove: ['bad header'] }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("invalid header name"));

        let error =
            parse_with(BASE, "response_headers: { set: { server: '' } }\n").expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"));

        let error = parse_with(BASE, "response_headers: { remove: [connection] }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("managed by the proxy"));
    }

    #[test]
    fn example_configuration_is_valid() {
        let config = parse(include_str!("../../rules.example.yaml"))
            .expect("example configuration must stay valid");
        assert!(!config.categories.is_empty());
        assert!(config.admin.enabled);
    }

    #[test]
    fn parses_response_phase_rules() {
        let config = parse_with(
            BASE,
            "categories:
  - name: response-leaks
    phase: response
    action: BLOCK
    rules:
      - name: server-errors
        match: { status: [500-599], response_headers: { Server: '(?i)apache' } }
      - name: leaked-secret
        match: { regex: 'BEGIN RSA PRIVATE KEY', in: [response_body] }
      - name: default-target
        match: { regex: 'stack trace' }
",
        )
        .expect("valid config");
        let category = &config.categories[0];
        assert_eq!(category.phase, Phase::Response);
        assert!(config.has_response_rules());
        assert_eq!(category.rules[0].matcher.statuses.len(), 1);
        assert!(category.rules[0].matcher.statuses[0].contains(503));
        assert_eq!(category.rules[0].matcher.response_headers.len(), 1);
        assert_eq!(
            category.rules[1]
                .matcher
                .payload
                .as_ref()
                .map(|p| p.targets),
            Some(TARGET_RESPONSE_BODY)
        );
        assert_eq!(
            category.rules[2]
                .matcher
                .payload
                .as_ref()
                .map(|p| p.targets),
            Some(TARGET_RESPONSE_BODY)
        );
    }

    #[test]
    fn request_only_config_has_no_response_rules() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert!(!config.has_response_rules());
    }

    #[test]
    fn rejects_response_conditions_in_request_phase() {
        for match_spec in [
            "status: [500]",
            "response_headers: { Server: nginx }",
            "regex: leak, in: [response_body]",
        ] {
            let error = parse_with(
                BASE,
                &format!(
                    "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: {{ {match_spec} }}
"
                ),
            )
            .expect_err("must fail");
            assert!(
                error.to_string().contains("phase: response"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn rejects_invalid_status_matchers() {
        for status in ["[99]", "[600]", "[500-400]", "[nope]", "[5xy]"] {
            let error = parse_with(
                BASE,
                &format!(
                    "categories:
  - name: broken
    phase: response
    action: BLOCK
    rules:
      - name: rule
        match: {{ status: {status} }}
"
                ),
            )
            .expect_err("must fail");
            assert!(
                error.to_string().contains("status"),
                "unexpected error for {status}: {error}"
            );
        }
    }

    #[test]
    fn parses_status_classes_and_scalars() {
        let config = parse_with(
            BASE,
            "categories:
  - name: errors
    phase: response
    action: LOG
    rules:
      - name: class
        match: { status: 5xx }
      - name: scalar
        match: { status: 404 }
",
        )
        .expect("valid config");
        let class = &config.categories[0].rules[0].matcher.statuses[0];
        assert_eq!((class.start, class.end), (500, 599));
        let scalar = &config.categories[0].rules[1].matcher.statuses[0];
        assert_eq!((scalar.start, scalar.end), (404, 404));
    }

    #[test]
    fn default_response_body_limit_matches_request_limit() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert_eq!(config.limits.max_response_body_bytes, 1024 * 1024);

        let error =
            parse_with(BASE, "limits: { max_response_body_bytes: 0 }\n").expect_err("must fail");
        assert!(error.to_string().contains("max_response_body_bytes"));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..2_000 {
            let length = (next_random(&mut state) % 512) as usize;
            let bytes: Vec<u8> = (0..length)
                .map(|_| (next_random(&mut state) & 0xff) as u8)
                .collect();
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse(&text);
        }
    }

    #[test]
    fn arbitrary_token_streams_never_panic() {
        const TOKENS: [&str; 24] = [
            "listen:",
            "127.0.0.1:8080",
            "upstream:",
            "http://127.0.0.1:3000",
            "categories:",
            "-",
            "name:",
            "action:",
            "BLOCK",
            "ALLOW",
            "LOG",
            "match:",
            "{",
            "}",
            "regex:",
            "path:",
            "in:",
            "[",
            "]",
            ",",
            "enabled:",
            "false",
            "response:",
            "timeouts:",
        ];

        let mut state = 0xDEAD_BEEF_CAFE_BABEu64;
        for _ in 0..500 {
            let count = (next_random(&mut state) % 40) as usize;
            let mut text = String::new();
            for _ in 0..count {
                text.push_str(TOKENS[(next_random(&mut state) % TOKENS.len() as u64) as usize]);
                text.push(if next_random(&mut state).is_multiple_of(5) {
                    '\n'
                } else {
                    ' '
                });
            }
            let _ = parse(&text);
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state ^ (*state >> 33)
    }

    #[test]
    fn rejects_invalid_protection_values() {
        let error =
            parse_with(BASE, "protection: { requests_per_second: 0 }\n").expect_err("must fail");
        assert!(error.to_string().contains("requests_per_second"));

        let error = parse_with(BASE, "protection: { allowlist: [nope] }\n").expect_err("must fail");
        assert!(error.to_string().contains("allowlist"));

        let error =
            parse_with(BASE, "protection: { aggregate_ipv6_prefix: 0 }\n").expect_err("must fail");
        assert!(error.to_string().contains("aggregate_ipv6_prefix"));

        let error = parse_with(BASE, "protection: { aggregate_ipv6_prefix: 129 }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("aggregate_ipv6_prefix"));
    }

    #[test]
    fn parses_aggregate_ipv6_prefix() {
        let config =
            parse_with(BASE, "protection: { aggregate_ipv6_prefix: 48 }\n").expect("valid config");
        assert_eq!(config.protection.aggregate_ipv6_prefix, 48);
    }

    #[test]
    fn body_rule_detection_reports_targets() {
        let config = parse_with(
            BASE,
            "categories:
  - name: sqli
    action: BLOCK
    rules:
      - name: union
        match: { regex: 'union select', in: [body] }
",
        )
        .expect("valid config");
        assert!(config.has_body_target_rules());
        assert!(!config.has_response_body_rules());

        let config = parse_with(
            BASE,
            "categories:
  - name: leaks
    phase: response
    action: BLOCK
    rules:
      - name: stack
        match: { regex: 'stack trace', in: [response_body] }
",
        )
        .expect("valid config");
        assert!(!config.has_body_target_rules());
        assert!(config.has_response_body_rules());
    }

    #[test]
    fn rejects_https_upstream() {
        let error = parse("listen: 127.0.0.1:8080\nupstream: https://example.com\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("only http"));
    }

    #[test]
    fn rejects_in_without_regex() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: { in: [query], path: / }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("`in` requires `regex`"));
    }

    #[test]
    fn rejects_oversized_response_body() {
        let body = "x".repeat(MAX_RESPONSE_BODY_BYTES + 1);
        let error = parse_with(
            BASE,
            &format!(
                "categories:
  - name: big
    action: BLOCK
    response: {{ status: 403, body: '{body}' }}
    rules:
      - name: rule
        match: {{ path: / }}
"
            ),
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("response body exceeds"));
    }

    #[test]
    fn rules_update_is_disabled_by_default() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert!(!config.rules_update.enabled);
        assert_eq!(config.rules_update.interval, Duration::from_secs(24 * 3600));
        assert_eq!(config.rules_update.jitter_percent, 10);
        assert!(config.rules_file.is_none());
        assert!(config.overrides_file.is_none());
    }

    fn update_block(url: &str, checksum_url: &str) -> String {
        format!(
            "rules_file: /var/lib/kunato/rules.yaml
rules_update:
  enabled: true
  url: {url}
  checksum_url: {checksum_url}
  interval: 24h
  jitter_percent: 10
  max_bytes: 1048576
"
        )
    }

    #[test]
    fn requires_rules_update_targets_when_enabled() {
        let error = parse_with(BASE, "rules_update: { enabled: true }\n").expect_err("must fail");
        let message = error.to_string();
        assert!(message.contains("requires `rules_update.url`"));
        assert!(message.contains("requires `rules_update.checksum_url`"));
        assert!(message.contains("requires `rules_file`"));
    }

    #[test]
    fn accepts_https_and_loopback_http_update_urls() {
        let config = parse_with(
            BASE,
            &update_block(
                "https://example.com/rules.yaml",
                "https://example.com/rules.yaml.sha256",
            ),
        )
        .expect("valid config");
        assert!(config.rules_update.enabled);
        assert_eq!(config.rules_update.max_bytes, 1048576);

        parse_with(
            BASE,
            &update_block(
                "http://127.0.0.1:8080/rules.yaml",
                "http://127.0.0.1:8080/rules.yaml.sha256",
            ),
        )
        .expect("loopback http is allowed for testing");
    }

    #[test]
    fn rejects_plain_http_update_urls_for_remote_hosts() {
        let error = parse_with(
            BASE,
            &update_block(
                "http://example.com/rules.yaml",
                "http://example.com/rules.yaml.sha256",
            ),
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("must use https"));
    }

    #[test]
    fn rejects_invalid_update_limits() {
        let error = parse_with(
            BASE,
            "rules_file: rules.yaml
rules_update:
  enabled: true
  url: https://example.com/rules.yaml
  checksum_url: https://example.com/rules.yaml.sha256
  interval: 0s
  jitter_percent: 60
  max_bytes: 0
",
        )
        .expect_err("must fail");
        let message = error.to_string();
        assert!(message.contains("interval must be greater than zero"));
        assert!(message.contains("jitter_percent must be at most 50"));
        assert!(message.contains("max_bytes must be between"));
    }

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).expect("write file");
    }

    #[test]
    fn load_merges_overrides_main_and_rules_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            &dir.path().join("overrides.yaml"),
            "categories:
  - name: overrides
    action: ALLOW
    rules:
      - name: trusted
        match: { source_ip: 127.0.0.1/32 }
disabled_rules: [auto-block]
",
        );
        write(
            &dir.path().join("rules.yaml"),
            "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: auto-block
        match: { path: ^/ }
      - name: other
        match: { path: ^/other }
",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
categories:
  - name: inline
    action: LOG
    rules:
      - name: inline-rule
        match: { path: ^/inline }
rules_file: rules.yaml
overrides_file: overrides.yaml
",
        );

        let config = load(&main).expect("valid config");
        let names: Vec<&str> = config
            .categories
            .iter()
            .map(|category| category.name.as_str())
            .collect();
        assert_eq!(names, ["overrides", "inline", "auto"]);

        let auto = config
            .categories
            .iter()
            .find(|category| category.name == "auto")
            .expect("auto category");
        assert_eq!(auto.rules.len(), 1);
        assert_eq!(auto.rules[0].name, "other");
        assert!(config.rules_file.is_some());
        assert!(config.overrides_file.is_some());
    }

    #[test]
    fn rules_file_rejects_disabled_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            &dir.path().join("rules.yaml"),
            "categories: []\ndisabled_rules: [something]\n",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: rules.yaml
",
        );
        let error = load(&main).expect_err("must fail");
        assert!(
            error
                .to_string()
                .contains("only supported in the overrides file")
        );
    }

    #[test]
    fn missing_rules_file_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: missing.yaml
",
        );
        let error = load(&main).expect_err("must fail");
        assert!(matches!(error, Error::ConfigRead { .. }));
    }

    #[test]
    fn parse_rules_validates_matchers() {
        let error = parse_rules(
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: { path: '(' }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("invalid regex"));

        let rules = parse_rules(
            "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: catch-all
        match: { path: ^/ }
",
        )
        .expect("valid rules");
        assert_eq!(rules.categories.len(), 1);
        assert_eq!(rules.categories[0].rules.len(), 1);
    }

    #[test]
    fn dist_rules_match_example_configuration() {
        let example = parse(include_str!("../../rules.example.yaml")).expect("example is valid");
        let dist = parse_rules(include_str!("../../dist/rules.yaml")).expect("dist is valid");
        assert_eq!(
            format!("{:?}", example.categories),
            format!("{:?}", dist.categories),
            "dist/rules.yaml has drifted from rules.example.yaml; run scripts/update-dist-rules.sh"
        );
    }

    #[test]
    fn dist_rules_checksum_matches() {
        let rules = include_bytes!("../../dist/rules.yaml");
        let expected = include_str!("../../dist/rules.yaml.sha256")
            .split_whitespace()
            .next()
            .expect("checksum file is not empty")
            .to_owned();
        assert_eq!(expected, crate::rules_update::sha256_hex(rules));
    }
}
