use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use http::Method;
use http::Uri;
use http::header::HeaderName;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};

pub mod watcher;

use crate::error::Error;
use crate::rules::matcher::{
    Matcher, PayloadMatcher, TARGET_BODY, TARGET_COOKIES, TARGET_HEADERS, TARGET_PATH, TARGET_QUERY,
};

const REGEX_SIZE_LIMIT: usize = 1 << 20;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_PATTERNS_PER_RULE: usize = 64;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024;

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
    pub action: Option<Action>,
    #[serde(default)]
    pub response: Option<ResponseSpec>,
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
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
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
}

impl Default for LimitsSpec {
    fn default() -> Self {
        Self {
            max_path_bytes: default_max_path_bytes(),
            max_header_bytes: default_max_header_bytes(),
            max_headers: default_max_headers(),
            max_body_bytes: default_max_body_bytes(),
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
}

impl From<&LimitsSpec> for Limits {
    fn from(spec: &LimitsSpec) -> Self {
        Self {
            max_path_bytes: spec.max_path_bytes,
            max_header_bytes: spec.max_header_bytes,
            max_headers: spec.max_headers,
            max_body_bytes: spec.max_body_bytes,
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
}

#[derive(Debug)]
pub struct CompiledCategory {
    pub name: String,
    pub action: Option<Action>,
    pub response: Option<ResponseSpec>,
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub action: Option<Action>,
    pub response: Option<ResponseSpec>,
    pub matcher: Matcher,
}

pub fn load(path: &Path) -> Result<CompiledConfig, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigRead {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<CompiledConfig, Error> {
    let spec: ConfigSpec = serde_saphyr::from_str(text)?;
    compile(spec).map_err(Error::ConfigInvalid)
}

fn compile(spec: ConfigSpec) -> Result<CompiledConfig, Vec<String>> {
    let mut issues = Vec::new();

    validate_limits(&spec.limits, &mut issues);
    validate_timeouts(&spec.timeouts, &mut issues);
    validate_protection(&spec.protection, &mut issues);
    validate_admin(&spec.admin, &mut issues);
    validate_tls(&spec.tls, &mut issues);
    validate_http3(&spec.http3, &spec.tls, &mut issues);
    let upstream = compile_upstream(&spec.upstream, &mut issues);

    let mut categories = Vec::new();
    let mut seen_categories: BTreeSet<&str> = BTreeSet::new();

    for category in &spec.categories {
        if category.name.trim().is_empty() {
            issues.push("category name must not be empty".to_owned());
        } else if !seen_categories.insert(category.name.as_str()) {
            issues.push(format!(
                "category `{}`: duplicate category name",
                category.name
            ));
        }

        let context = format!("category `{}`", category.name);
        if let Some(response) = &category.response {
            validate_response(response, &context, &mut issues);
        }

        let mut seen_rules: BTreeSet<&str> = BTreeSet::new();
        let mut rules = Vec::new();

        for rule in &category.rules {
            let rule_context = format!("{context}: rule `{}`", rule.name);

            if rule.name.trim().is_empty() {
                issues.push(format!("{context}: rule name must not be empty"));
            } else if !seen_rules.insert(rule.name.as_str()) {
                issues.push(format!("{rule_context}: duplicate rule name"));
            }

            if let Some(response) = &rule.response {
                validate_response(response, &rule_context, &mut issues);
            }

            let matcher = compile_matcher(&rule.matcher, &rule_context, &mut issues);
            let effective_action = rule.action.or(category.action);
            if category.enabled && rule.enabled && effective_action.is_none() {
                issues.push(format!(
                    "{rule_context}: no effective action; set `action` on the rule or the category"
                ));
            }

            if !category.enabled || !rule.enabled {
                continue;
            }

            rules.push(CompiledRule {
                name: rule.name.clone(),
                action: rule.action,
                response: rule.response.clone(),
                matcher,
            });
        }

        if !category.enabled {
            continue;
        }

        categories.push(CompiledCategory {
            name: category.name.clone(),
            action: category.action,
            response: category.response.clone(),
            rules,
        });
    }

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
    })
}

fn validate_limits(limits: &LimitsSpec, issues: &mut Vec<String>) {
    for (name, value) in [
        ("max_path_bytes", limits.max_path_bytes),
        ("max_header_bytes", limits.max_header_bytes),
        ("max_headers", limits.max_headers),
        ("max_body_bytes", limits.max_body_bytes),
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

fn compile_matcher(spec: &MatchSpec, context: &str, issues: &mut Vec<String>) -> Matcher {
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

    match &spec.regex {
        Some(patterns) => {
            has_condition = true;
            if patterns.is_empty() {
                issues.push(format!("{context}: `regex` must not be empty"));
            }
            matcher.payload = compile_payload(patterns, spec.targets.as_deref(), context, issues);
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
                    other => issues.push(format!("{context}: unknown `in` target `{other}`")),
                }
            }
        }
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
    fn example_configuration_is_valid() {
        let config = parse(include_str!("../../rules.example.yaml"))
            .expect("example configuration must stay valid");
        assert!(!config.categories.is_empty());
        assert!(config.admin.enabled);
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
}
