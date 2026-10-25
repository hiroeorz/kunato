use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http::Method;
use http::Uri;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use regex::{Regex, RegexBuilder, RegexSet};
use regex_syntax::hir::{Hir, HirKind, Look};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};

pub mod watcher;

use crate::allowed_hosts::AllowedHosts;
use crate::cidr::IpNet;
use crate::client_ip::ClientIp;
use crate::error::{Error, UNKNOWN_TARGET_ISSUE};
use crate::rules::matcher::{
    Matcher, PayloadMatcher, StatusRange, TARGET_BODY, TARGET_COOKIES, TARGET_HEADERS, TARGET_PATH,
    TARGET_QUERY, TARGET_RESPONSE_BODY,
};
use crate::yaml;

const REGEX_SIZE_LIMIT: usize = 1 << 20;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_PATTERNS_PER_RULE: usize = 64;
const MAX_CONTENT_ROUTES: usize = 64;
const MAX_PATH_BYTES_LIMIT: usize = 64 * 1024;
const MAX_HEADER_BYTES_LIMIT: usize = 1024 * 1024;
const MAX_HEADERS_LIMIT: usize = 1000;
const MAX_BODY_BYTES_LIMIT: usize = 8 * 1024 * 1024;
const MAX_GRAPHQL_DEPTH_LIMIT: usize = 1000;
const MAX_GRAPHQL_FIELDS_LIMIT: usize = 10_000;
const MAX_GRAPHQL_PATHS: usize = 16;
const MAX_GRAPHQL_PATH_BYTES: usize = 1024;
const DEFAULT_GRAPHQL_MAX_DEPTH: usize = 20;
const DEFAULT_GRAPHQL_MAX_FIELDS: usize = 1000;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_HEADER_ENTRIES: usize = 64;
const MAX_RESPONSE_HEADER_VALUE_BYTES: usize = 1024;
const MAX_RULES_UPDATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RULES_UPDATE_JITTER_PERCENT: u8 = 50;
const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DURATION: Duration = Duration::from_secs(365 * 24 * 60 * 60);
const MAX_BEHAVIOR_WINDOW: Duration = Duration::from_secs(60 * 60);
const MAX_BEHAVIOR_DISTINCT_PATHS: u32 = 256;
const DEFAULT_AUTH_PATHS: &[&str] = &[
    r"(?i)^/(wp-login\.php|xmlrpc\.php|login|logon|signin|sign_in|sign-in|session)(\.(php|do|jsp|aspx|html))?/?$",
    r"(?i)^/(users/sign_in|admin/login|api(/v[0-9]+)?/(auth|login|token|session|oauth|mfa|otp)|oauth|saml|auth|realms|openid-connect)(/|$)",
];

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

/// Policy for request bodies that exceed `limits.max_body_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyInspection {
    /// Reject the request with `413` when request-body rules (or a GraphQL
    /// endpoint) need to inspect a body that does not fit in the limit.
    #[default]
    Strict,
    /// Inspect the prefix and stream the remainder to the upstream.
    Stream,
}

/// Policy for inspecting `multipart/form-data` uploads against their declared
/// type and filename extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadInspection {
    /// Do not inspect upload contents.
    Off,
    /// Reject executable, script, or markup content behind an image, PDF,
    /// office, media, or font claim (or a safe filename extension).
    #[default]
    Mismatch,
    /// Also reject executable and script content behind an explicitly generic
    /// claim, and markup behind a generic claim.
    Strict,
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
pub struct ClientIpSpec {
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_client_ip_header")]
    pub header: String,
}

fn default_client_ip_header() -> String {
    "x-forwarded-for".to_owned()
}

/// A request route whose body is authored content (for example, a CMS article
/// editor) rather than request parameters. Body-targeting rules are skipped for
/// matching requests; every other target and every other protection stays
/// active.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRouteSpec {
    pub path: String,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSpec {
    pub listen: SocketAddr,
    pub upstream: String,
    /// Host names and IP literals clients may use to reach this server. When
    /// absent, host checking is disabled; an empty list or null value is
    /// rejected.
    #[serde(default, deserialize_with = "de_allowed_hosts")]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub client_ip: Option<ClientIpSpec>,
    #[serde(default)]
    pub content_routes: Vec<ContentRouteSpec>,
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
    #[serde(default)]
    pub php: PhpSpec,
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
    #[serde(default = "secs60", deserialize_with = "de_duration")]
    pub connection_idle: Duration,
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
            connection_idle: secs60(),
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
    #[serde(default = "default_websocket_message_bytes")]
    pub websocket_message_bytes: usize,
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    #[serde(default)]
    pub body_inspection: BodyInspection,
    #[serde(default)]
    pub upload_inspection: UploadInspection,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default)]
    pub graphql: GraphqlSpec,
    #[serde(default)]
    pub form: FormLimits,
}

impl Default for LimitsSpec {
    fn default() -> Self {
        Self {
            max_path_bytes: default_max_path_bytes(),
            max_header_bytes: default_max_header_bytes(),
            max_headers: default_max_headers(),
            max_body_bytes: default_max_body_bytes(),
            websocket_message_bytes: default_websocket_message_bytes(),
            max_response_body_bytes: default_max_response_body_bytes(),
            body_inspection: BodyInspection::default(),
            upload_inspection: UploadInspection::default(),
            max_concurrent_streams: default_max_concurrent_streams(),
            graphql: GraphqlSpec::default(),
            form: FormLimits::default(),
        }
    }
}

/// Origin-facing form resource limits, independent of rule actions.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FormLimits {
    pub enabled: bool,
    pub max_parts: usize,
    pub max_headers_per_part: usize,
    pub max_part_header_bytes: usize,
    pub max_field_name_bytes: usize,
    pub max_nesting_depth: usize,
    pub max_fields: usize,
    pub max_empty_files: usize,
    pub max_complexity: usize,
}

impl Default for FormLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_parts: 64,
            max_headers_per_part: 16,
            max_part_header_bytes: 8192,
            max_field_name_bytes: 1024,
            max_nesting_depth: 16,
            max_fields: 1000,
            max_empty_files: 16,
            max_complexity: 4096,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PhpSpec {
    pub enabled: bool,
    #[serde(deserialize_with = "de_allowed_hosts")]
    pub hosts: Option<Vec<String>>,
    pub paths: Vec<String>,
    pub block_multipart: bool,
    pub block_upload_progress: bool,
    pub upload_progress_names: Vec<String>,
    pub session_cookies: Vec<String>,
    pub max_session_id_bytes: usize,
    pub session_id_pattern: String,
}

impl Default for PhpSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: None,
            paths: Vec::new(),
            block_multipart: false,
            block_upload_progress: true,
            upload_progress_names: vec!["PHP_SESSION_UPLOAD_PROGRESS".to_owned()],
            session_cookies: vec!["PHPSESSID".to_owned()],
            max_session_id_bytes: 256,
            session_id_pattern: "^[A-Za-z0-9,-]+$".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct Php {
    pub enabled: bool,
    pub hosts: Option<AllowedHosts>,
    pub paths: Vec<String>,
    pub block_multipart: bool,
    pub block_upload_progress: bool,
    pub upload_progress_names: Vec<String>,
    pub session_cookies: Vec<String>,
    pub max_session_id_bytes: usize,
    pub session_id_pattern: Regex,
}

/// Limits for GraphQL documents. Requests routed to a GraphQL endpoint with a
/// query deeper than `max_depth` selection levels or with more than
/// `max_fields` expanded field selections are rejected before forwarding.
/// Fragment spreads are expanded for the count, so splitting a document across
/// fragments does not evade either limit.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Extra endpoint paths, matched exactly except for a trailing slash. The
    /// common `/graphql`, `/api/graphql`, and `/gql` shapes are recognized
    /// without configuration.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_graphql_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_graphql_max_fields")]
    pub max_fields: usize,
}

impl Default for GraphqlSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: Vec::new(),
            max_depth: DEFAULT_GRAPHQL_MAX_DEPTH,
            max_fields: DEFAULT_GRAPHQL_MAX_FIELDS,
        }
    }
}

fn default_graphql_max_depth() -> usize {
    DEFAULT_GRAPHQL_MAX_DEPTH
}

fn default_graphql_max_fields() -> usize {
    DEFAULT_GRAPHQL_MAX_FIELDS
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
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub acme: Option<AcmeSpec>,
}

/// Automatic certificate management through the ACME protocol (RFC 8555).
/// Challenges use TLS-ALPN-01 on the TLS listener, so the configured domains
/// must resolve to this server and TCP port 443 must be reachable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub contact: Option<String>,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub directory: Option<String>,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
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
    #[serde(default)]
    pub behavior: BehaviorSpec,
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
            behavior: BehaviorSpec::default(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BehaviorAction {
    #[default]
    Log,
    Block,
}

impl BehaviorAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "LOG",
            Self::Block => "BLOCK",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "secs60", deserialize_with = "de_duration")]
    pub window: Duration,
    #[serde(default = "default_behavior_min_requests")]
    pub min_requests: u32,
    #[serde(default)]
    pub enumeration: EnumerationSpec,
    #[serde(default)]
    pub auth: AuthSpec,
    #[serde(default)]
    pub global_auth: GlobalAuthSpec,
}

impl Default for BehaviorSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            window: secs60(),
            min_requests: default_behavior_min_requests(),
            enumeration: EnumerationSpec::default(),
            auth: AuthSpec::default(),
            global_auth: GlobalAuthSpec::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnumerationSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: BehaviorAction,
    #[serde(default = "default_not_found_ratio")]
    pub not_found_ratio: f64,
    #[serde(default = "default_distinct_paths")]
    pub distinct_paths: u32,
}

impl Default for EnumerationSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            action: BehaviorAction::Log,
            not_found_ratio: default_not_found_ratio(),
            distinct_paths: default_distinct_paths(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: BehaviorAction,
    #[serde(default = "default_auth_min_failures")]
    pub min_failures: u32,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

impl Default for AuthSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            action: BehaviorAction::Log,
            min_failures: default_auth_min_failures(),
            paths: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalAuthSpec {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "secs60", deserialize_with = "de_duration")]
    pub window: Duration,
    #[serde(default = "default_global_auth_min_failures")]
    pub min_failures: u32,
}

impl Default for GlobalAuthSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            window: secs60(),
            min_failures: default_global_auth_min_failures(),
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

fn default_behavior_min_requests() -> u32 {
    30
}

fn default_not_found_ratio() -> f64 {
    0.5
}

fn default_distinct_paths() -> u32 {
    40
}

fn default_auth_min_failures() -> u32 {
    20
}

fn default_global_auth_min_failures() -> u32 {
    100
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
    8 * 1024 * 1024
}

fn default_websocket_message_bytes() -> usize {
    1024 * 1024
}

fn default_max_response_body_bytes() -> usize {
    1024 * 1024
}

fn default_max_concurrent_streams() -> u32 {
    100
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub header_read: Duration,
    pub body_read: Duration,
    pub upstream_connect: Duration,
    pub upstream_response: Duration,
    pub shutdown_grace: Duration,
    pub connection_idle: Duration,
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
            connection_idle: spec.connection_idle,
            websocket_idle: spec.websocket_idle,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_path_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub websocket_message_bytes: usize,
    pub max_response_body_bytes: usize,
    pub body_inspection: BodyInspection,
    pub upload_inspection: UploadInspection,
    pub max_concurrent_streams: u32,
    pub graphql: Graphql,
    pub form: FormLimits,
}

impl From<&LimitsSpec> for Limits {
    fn from(spec: &LimitsSpec) -> Self {
        Self {
            max_path_bytes: spec.max_path_bytes,
            max_header_bytes: spec.max_header_bytes,
            max_headers: spec.max_headers,
            max_body_bytes: spec.max_body_bytes,
            websocket_message_bytes: spec.websocket_message_bytes,
            max_response_body_bytes: spec.max_response_body_bytes,
            body_inspection: spec.body_inspection,
            upload_inspection: spec.upload_inspection,
            max_concurrent_streams: spec.max_concurrent_streams,
            graphql: Graphql::from(&spec.graphql),
            form: spec.form.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Graphql {
    pub enabled: bool,
    pub paths: Vec<String>,
    pub max_depth: usize,
    pub max_fields: usize,
}

impl From<&GraphqlSpec> for Graphql {
    fn from(spec: &GraphqlSpec) -> Self {
        Self {
            enabled: spec.enabled,
            paths: spec.paths.clone(),
            max_depth: spec.max_depth,
            max_fields: spec.max_fields,
        }
    }
}

impl Graphql {
    /// True when `path` names a GraphQL endpoint. Every path segment is
    /// compared case-insensitively so `/api/graphql`, `/v1/graphql`, and
    /// `/gql` are recognized without configuration; `paths` adds endpoints
    /// whose path does not contain one of those names. Matrix parameters
    /// (`;jsessionid=...`) and trailing slashes are ignored for both forms,
    /// mirroring the servlet and Rack routing this guard defends.
    pub fn matches_path(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let path = trim_path(path);
        let plain = path_without_matrix_params(path);
        if self.paths.iter().any(|candidate| {
            path_without_matrix_params(trim_path(candidate)).eq_ignore_ascii_case(&plain)
        }) {
            return true;
        }
        plain.split('/').any(|segment| {
            segment.eq_ignore_ascii_case("graphql") || segment.eq_ignore_ascii_case("gql")
        })
    }
}

fn trim_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

fn path_without_matrix_params(path: &str) -> String {
    path.split('/')
        .map(|segment| segment.split(';').next().unwrap_or(segment))
        .collect::<Vec<_>>()
        .join("/")
}

/// Where automatically managed certificates are cached between restarts.
pub const DEFAULT_ACME_CACHE_DIR: &str = "/var/lib/kunato/acme";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub acme: Option<Acme>,
}

/// Resolved ACME settings: the directory URL and cache path defaults are
/// applied here so the runtime never deals with optional variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acme {
    pub domains: Vec<String>,
    pub contact: Option<String>,
    pub directory: String,
    pub cache_dir: PathBuf,
    pub allowed_origins: Vec<String>,
}

impl From<&TlsSpec> for Tls {
    fn from(spec: &TlsSpec) -> Self {
        Self {
            cert_file: spec.cert_file.clone(),
            key_file: spec.key_file.clone(),
            acme: spec
                .acme
                .as_ref()
                .filter(|acme| acme.enabled)
                .map(Acme::from),
        }
    }
}

impl From<&AcmeSpec> for Acme {
    fn from(spec: &AcmeSpec) -> Self {
        let directory = spec.directory.clone().unwrap_or_else(|| {
            match spec.staging {
                true => crate::acme::LETS_ENCRYPT_STAGING_DIRECTORY,
                false => crate::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            }
            .to_owned()
        });
        Self {
            domains: spec.domains.clone(),
            contact: spec.contact.clone(),
            directory,
            cache_dir: spec
                .cache_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ACME_CACHE_DIR)),
            allowed_origins: spec.allowed_origins.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub behavior: BehaviorConfig,
}

#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    pub enabled: bool,
    pub window: Duration,
    pub min_requests: u32,
    pub enumeration: EnumerationConfig,
    pub auth: AuthConfig,
    pub global_auth: GlobalAuthConfig,
}

impl BehaviorConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            window: secs60(),
            min_requests: default_behavior_min_requests(),
            enumeration: EnumerationConfig {
                enabled: false,
                action: BehaviorAction::Log,
                not_found_ratio: default_not_found_ratio(),
                distinct_paths: default_distinct_paths(),
            },
            auth: AuthConfig {
                enabled: false,
                action: BehaviorAction::Log,
                min_failures: default_auth_min_failures(),
                paths: RegexSet::empty(),
            },
            global_auth: GlobalAuthConfig {
                enabled: false,
                window: secs60(),
                min_failures: default_global_auth_min_failures(),
            },
        }
    }
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnumerationConfig {
    pub enabled: bool,
    pub action: BehaviorAction,
    pub not_found_ratio: f64,
    pub distinct_paths: u32,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub action: BehaviorAction,
    pub min_failures: u32,
    pub paths: RegexSet,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalAuthConfig {
    pub enabled: bool,
    pub window: Duration,
    pub min_failures: u32,
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

#[derive(Debug, Clone)]
pub struct ContentRoute {
    path: Regex,
    methods: Option<Vec<Method>>,
}

impl ContentRoute {
    /// Every path form must match so a request cannot be normalized by the
    /// upstream into a different endpoint after the body rules were skipped.
    fn matches(&self, method: &Method, path_forms: &[std::borrow::Cow<'_, str>]) -> bool {
        if let Some(methods) = &self.methods
            && !methods.contains(method)
        {
            return false;
        }
        !path_forms.is_empty() && path_forms.iter().all(|form| self.path.is_match(form))
    }
}

#[derive(Debug)]
pub struct CompiledConfig {
    pub listen: SocketAddr,
    pub upstream: Upstream,
    pub allowed_hosts: Option<AllowedHosts>,
    pub client_ip: ClientIp,
    pub content_routes: Vec<ContentRoute>,
    pub categories: Vec<CompiledCategory>,
    pub timeouts: Timeouts,
    pub limits: Limits,
    pub protection: Protection,
    pub admin: Admin,
    pub tls: Option<Tls>,
    pub http3: Http3,
    pub response_headers: ResponseHeaders,
    pub php: Php,
    pub rules_file: Option<PathBuf>,
    pub overrides_file: Option<PathBuf>,
    pub rules_update: RulesUpdate,
}

impl CompiledConfig {
    /// Route check for callers that only have the request head, so body
    /// inspection can be skipped before the body is collected.
    pub fn is_content_route(&self, method: &Method, uri: &Uri) -> bool {
        if self.content_routes.is_empty() {
            return false;
        }
        let forms = crate::request_view::path_forms(uri.path());
        self.content_routes
            .iter()
            .any(|route| route.matches(method, &forms))
    }

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

    /// Warning to log when body rules are configured in `stream` mode, where
    /// the uninspected remainder can carry a payload past every body rule.
    pub fn body_inspection_warning(&self) -> Option<String> {
        if self.limits.body_inspection != BodyInspection::Stream {
            return None;
        }
        let subject = match (
            self.has_body_target_rules(),
            self.limits.upload_inspection != UploadInspection::Off,
        ) {
            (true, true) => "body rules and multipart uploads",
            (true, false) => "body rules",
            (false, true) => "multipart uploads",
            (false, false) => return None,
        };
        Some(format!(
            "limits.body_inspection is `stream`: only the first {} bytes are inspected for \
             {subject} and larger request bodies may be forwarded uninspected; set `strict` to \
             reject them unless a rule allows the request. Enabled form limits and PHP profiles \
             still reject forms that cannot be inspected completely",
            self.limits.max_body_bytes
        ))
    }

    /// Warning to log when an enabled ACME domain is missing from
    /// `allowed_hosts`, which would reject every request for that name with a
    /// `421` even though a certificate was issued for it.
    pub fn allowed_hosts_warning(&self) -> Option<String> {
        let allowed = self.allowed_hosts.as_ref()?;
        let acme = self.tls.as_ref()?.acme.as_ref()?;
        let missing: Vec<&str> = acme
            .domains
            .iter()
            .map(String::as_str)
            .filter(|domain| !allowed.matches(domain))
            .collect();
        if missing.is_empty() {
            return None;
        }
        Some(format!(
            "allowed_hosts does not include the ACME domain(s) {}; requests for those names are \
             rejected with 421. Add them to allowed_hosts.",
            missing.join(", ")
        ))
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

    /// True when a response-phase rule inspects the *request* body. Only then
    /// does response evaluation need the request-body decoded forms.
    pub fn response_targets_request_body(&self) -> bool {
        self.categories.iter().any(|category| {
            category.phase == Phase::Response
                && category
                    .rules
                    .iter()
                    .any(|rule| targets(&rule.matcher, TARGET_BODY))
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
    pub limit_key: RuleLimitKey,
    pub matcher: Matcher,
}

pub type RuleLimitKey = Arc<(String, String)>;

#[derive(Debug, Clone, Copy)]
pub struct RuleLimit {
    pub requests: u32,
    pub window: Duration,
}

pub fn load(path: &Path) -> Result<CompiledConfig, Error> {
    load_candidate(path, None)
}

/// Validate a managed rules candidate against the main and overrides files
/// before it is installed, including on the first download.
pub fn load_with_rules_candidate(path: &Path, rules: &str) -> Result<CompiledConfig, Error> {
    load_candidate(path, Some(rules))
}

fn load_candidate(path: &Path, candidate: Option<&str>) -> Result<CompiledConfig, Error> {
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
    let rules = match candidate {
        Some(text) => yaml::from_str(text)?,
        None => load_rules_spec(&rules_file)?,
    };
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
    let text = read_config_text(path)?;
    Ok(yaml::from_str(&text)?)
}

pub(crate) fn read_config_text(path: &Path) -> Result<String, Error> {
    let read = || -> std::io::Result<String> {
        if !std::fs::metadata(path)?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration source must be a regular file",
            ));
        }
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "configuration source must be a regular file",
            ));
        }
        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "configuration source exceeds the 16 MiB limit",
            ));
        }
        Ok(text)
    };
    read().map_err(|source| Error::ConfigRead {
        path: path.to_path_buf(),
        source,
    })
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
    let text = read_config_text(path)?;
    if text.trim().is_empty() {
        return Ok(RulesFileSpec::default());
    }
    yaml::from_str(&text).map_err(|source| Error::RulesParse {
        path: path.clone(),
        source: Box::new(source),
    })
}

pub fn parse(text: &str) -> Result<CompiledConfig, Error> {
    let spec: ConfigSpec = yaml::from_str(text)?;
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
    let spec: RulesFileSpec = yaml::from_str(text)?;
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
    let protection = compile_protection(&spec.protection, &mut issues);
    validate_admin(&spec.admin, &mut issues);
    validate_tls(&spec.tls, &mut issues);
    validate_http3(&spec.http3, &spec.tls, &mut issues);
    let allowed_hosts = compile_allowed_hosts(&spec.allowed_hosts, &mut issues);
    let client_ip = compile_client_ip(spec.client_ip.as_ref(), &mut issues);
    let content_routes = compile_content_routes(&spec.content_routes, &mut issues);
    let response_headers = compile_response_headers(&spec.response_headers, &mut issues);
    let php = compile_php(&spec.php, &mut issues);
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
    let Some(php) = php else {
        return Err(vec!["invalid PHP profile".to_owned()]);
    };

    Ok(CompiledConfig {
        listen: spec.listen,
        upstream,
        allowed_hosts,
        client_ip,
        content_routes,
        categories,
        timeouts: Timeouts::from(&spec.timeouts),
        limits: Limits::from(&spec.limits),
        protection,
        admin: Admin::from(&spec.admin),
        tls: spec.tls.as_ref().map(Tls::from),
        http3: Http3::from(&spec.http3),
        response_headers,
        php,
        rules_file: sources.rules_file,
        overrides_file: sources.overrides_file,
        rules_update,
    })
}

fn compile_content_routes(
    routes: &[ContentRouteSpec],
    issues: &mut Vec<String>,
) -> Vec<ContentRoute> {
    if routes.len() > MAX_CONTENT_ROUTES {
        issues.push(format!(
            "content_routes: too many entries (max {MAX_CONTENT_ROUTES})"
        ));
    }

    let mut compiled = Vec::new();
    for (index, route) in routes.iter().take(MAX_CONTENT_ROUTES).enumerate() {
        let context = format!("content_routes[{index}]");
        if route.path.trim().is_empty() {
            issues.push(format!("{context}: `path` is required"));
            continue;
        }
        let mut regexes = compile_regexes(std::slice::from_ref(&route.path), &context, issues);
        let Some(path) = regexes.pop() else {
            continue;
        };
        let methods = match &route.methods {
            None => None,
            Some(values) if values.is_empty() => {
                issues.push(format!(
                    "{context}: `methods` must not be empty; omit it for every method"
                ));
                continue;
            }
            Some(values) => {
                let methods = compile_methods(values, &context, issues);
                if methods.is_empty() {
                    continue;
                }
                Some(methods)
            }
        };
        compiled.push(ContentRoute { path, methods });
    }
    compiled
}

fn compile_client_ip(spec: Option<&ClientIpSpec>, issues: &mut Vec<String>) -> ClientIp {
    let Some(spec) = spec else {
        return ClientIp::default();
    };
    if spec.trusted_proxies.is_empty() || spec.trusted_proxies.len() > 64 {
        issues.push(
            "client_ip.trusted_proxies must contain between 1 and 64 IPs or CIDRs".to_owned(),
        );
    }
    let mut networks = Vec::new();
    for value in spec.trusted_proxies.iter().take(64) {
        match parse_ip_net(value) {
            Ok(network) => {
                networks.push(network.to_ipv4_mapped().unwrap_or(network));
            }
            Err(error) => issues.push(format!("client_ip.trusted_proxies: {error}")),
        }
    }
    let header = HeaderName::from_bytes(spec.header.as_bytes())
        .ok()
        .filter(|name| {
            matches!(
                name.as_str(),
                "x-forwarded-for" | "x-real-ip" | "cf-connecting-ip" | "true-client-ip"
            )
        });
    let header = header.unwrap_or_else(|| {
        issues.push("client_ip.header must be x-forwarded-for, x-real-ip, cf-connecting-ip, or true-client-ip".to_owned());
        HeaderName::from_static("x-forwarded-for")
    });
    ClientIp::new(networks, header)
}

fn compile_allowed_hosts(
    spec: &Option<Vec<String>>,
    issues: &mut Vec<String>,
) -> Option<AllowedHosts> {
    let entries = spec.as_ref()?;
    AllowedHosts::validate(entries, issues)
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

                let effective_action = rule.action.or(category.action);
                let matcher = compile_matcher(
                    &rule.matcher,
                    category.phase,
                    effective_action,
                    &rule_context,
                    issues,
                );
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

                if !category.enabled
                    || !rule.enabled
                    || (*source != "overrides file" && disabled.contains(rule.name.as_str()))
                {
                    continue;
                }

                rules.push(CompiledRule {
                    name: rule.name.clone(),
                    action: rule.action,
                    response: rule.response.clone(),
                    limit_key: Arc::new((category.name.clone(), rule.name.clone())),
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

fn validate_limits(limits: &LimitsSpec, issues: &mut Vec<String>) {
    for (name, value, max) in [
        (
            "max_path_bytes",
            limits.max_path_bytes,
            MAX_PATH_BYTES_LIMIT,
        ),
        (
            "max_header_bytes",
            limits.max_header_bytes,
            MAX_HEADER_BYTES_LIMIT,
        ),
        ("max_headers", limits.max_headers, MAX_HEADERS_LIMIT),
        (
            "max_body_bytes",
            limits.max_body_bytes,
            MAX_BODY_BYTES_LIMIT,
        ),
        (
            "websocket_message_bytes",
            limits.websocket_message_bytes,
            MAX_BODY_BYTES_LIMIT,
        ),
        (
            "max_response_body_bytes",
            limits.max_response_body_bytes,
            MAX_BODY_BYTES_LIMIT,
        ),
    ] {
        if value == 0 {
            issues.push(format!("limits.{name} must be greater than zero"));
        } else if value > max {
            issues.push(format!("limits.{name} must not exceed {max}"));
        }
    }
    if !(1..=1000).contains(&limits.max_concurrent_streams) {
        issues.push("limits.max_concurrent_streams must be between 1 and 1000".to_owned());
    }
    validate_graphql(&limits.graphql, issues);
    for (name, value, max) in [
        ("max_parts", limits.form.max_parts, 64),
        (
            "max_headers_per_part",
            limits.form.max_headers_per_part,
            128,
        ),
        (
            "max_part_header_bytes",
            limits.form.max_part_header_bytes,
            64 * 1024,
        ),
        (
            "max_field_name_bytes",
            limits.form.max_field_name_bytes,
            4096,
        ),
        ("max_nesting_depth", limits.form.max_nesting_depth, 64),
        ("max_fields", limits.form.max_fields, 10_000),
        ("max_empty_files", limits.form.max_empty_files, 64),
        ("max_complexity", limits.form.max_complexity, 100_000),
    ] {
        if value == 0 || value > max {
            issues.push(format!("limits.form.{name} must be between 1 and {max}"));
        }
    }
}

fn compile_php(spec: &PhpSpec, issues: &mut Vec<String>) -> Option<Php> {
    if spec.enabled && spec.hosts.is_none() && spec.paths.is_empty() {
        issues.push(
            "php.enabled requires hosts or paths; use paths: [/] to explicitly cover every path"
                .to_owned(),
        );
    }
    let hosts = spec.hosts.as_ref().and_then(|entries| {
        let mut errors = Vec::new();
        let hosts = AllowedHosts::validate(entries, &mut errors);
        issues.extend(
            errors
                .into_iter()
                .map(|error| format!("php.hosts: {error}")),
        );
        hosts
    });
    if spec.paths.len() > 16 {
        issues.push("php.paths must contain at most 16 entries".to_owned());
    }
    for path in &spec.paths {
        if !path.starts_with('/')
            || path.len() > 1024
            || path.contains(['?', '#', '%'])
            || path.chars().any(char::is_whitespace)
            || crate::decoding::normalize_path(path).is_some_and(|normalized| normalized != *path)
        {
            issues.push(format!("php.paths entry `{path}` must be a normalized absolute path without query, fragment, encoding, or whitespace"));
        }
    }
    for (name, entries) in [
        ("upload_progress_names", &spec.upload_progress_names),
        ("session_cookies", &spec.session_cookies),
    ] {
        if entries.is_empty() || entries.len() > 16 {
            issues.push(format!("php.{name} must contain between 1 and 16 names"));
        }
        for entry in entries {
            if entry.len() > 128
                || entry.is_empty()
                || !entry
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            {
                issues.push(format!("php.{name} entries must be 1..128 ASCII letters, digits, underscores, hyphens, or dots"));
            }
        }
    }
    if !(1..=4096).contains(&spec.max_session_id_bytes) {
        issues.push("php.max_session_id_bytes must be between 1 and 4096".to_owned());
    }
    if spec.session_id_pattern.len() > MAX_PATTERN_BYTES
        || !is_fully_anchored(&spec.session_id_pattern)
    {
        issues.push(
            "php.session_id_pattern must be fully anchored and at most 4096 bytes".to_owned(),
        );
    }
    let session_id_pattern = match RegexBuilder::new(&spec.session_id_pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
    {
        Ok(regex) => regex,
        Err(error) => {
            issues.push(format!("php.session_id_pattern: {error}"));
            return None;
        }
    };
    Some(Php {
        enabled: spec.enabled,
        hosts,
        paths: spec
            .paths
            .iter()
            .map(|path| {
                if path == "/" {
                    path.clone()
                } else {
                    path.trim_end_matches('/').to_owned()
                }
            })
            .collect(),
        block_multipart: spec.block_multipart,
        block_upload_progress: spec.block_upload_progress,
        upload_progress_names: spec.upload_progress_names.clone(),
        session_cookies: spec.session_cookies.clone(),
        max_session_id_bytes: spec.max_session_id_bytes,
        session_id_pattern,
    })
}

fn validate_graphql(graphql: &GraphqlSpec, issues: &mut Vec<String>) {
    if graphql.max_depth == 0 || graphql.max_depth > MAX_GRAPHQL_DEPTH_LIMIT {
        issues.push(format!(
            "limits.graphql.max_depth must be between 1 and {MAX_GRAPHQL_DEPTH_LIMIT}"
        ));
    }
    if graphql.max_fields == 0 || graphql.max_fields > MAX_GRAPHQL_FIELDS_LIMIT {
        issues.push(format!(
            "limits.graphql.max_fields must be between 1 and {MAX_GRAPHQL_FIELDS_LIMIT}"
        ));
    }
    if graphql.paths.len() > MAX_GRAPHQL_PATHS {
        issues.push(format!(
            "limits.graphql.paths must contain at most {MAX_GRAPHQL_PATHS} entries"
        ));
    }
    for path in &graphql.paths {
        if !path.starts_with('/') {
            issues.push(format!(
                "limits.graphql.paths entry `{path}` must start with `/`"
            ));
        } else if path.len() > MAX_GRAPHQL_PATH_BYTES {
            issues.push(format!(
                "limits.graphql.paths entry is longer than {MAX_GRAPHQL_PATH_BYTES} bytes"
            ));
        } else if path.contains('?') || path.contains('#') {
            issues.push(format!(
                "limits.graphql.paths entry `{path}` must not contain a query or fragment"
            ));
        } else if path.chars().any(char::is_whitespace) {
            issues.push(format!(
                "limits.graphql.paths entry `{path}` must not contain whitespace"
            ));
        }
    }
}

fn validate_timeouts(timeouts: &TimeoutsSpec, issues: &mut Vec<String>) {
    for (name, value) in [
        ("header_read", timeouts.header_read),
        ("body_read", timeouts.body_read),
        ("upstream_connect", timeouts.upstream_connect),
        ("upstream_response", timeouts.upstream_response),
        ("shutdown_grace", timeouts.shutdown_grace),
        ("connection_idle", timeouts.connection_idle),
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
    let acme_enabled = tls.acme.as_ref().is_some_and(|acme| acme.enabled);
    match acme_enabled {
        true => {
            if tls.cert_file.is_some() || tls.key_file.is_some() {
                issues.push(
                    "tls.cert_file and tls.key_file cannot be combined with tls.acme".to_owned(),
                );
            }
            if let Some(acme) = &tls.acme {
                validate_acme(acme, issues);
            }
        }
        false => match (&tls.cert_file, &tls.key_file) {
            (Some(cert), Some(key)) => {
                if cert.as_os_str().is_empty() {
                    issues.push("tls.cert_file must not be empty".to_owned());
                }
                if key.as_os_str().is_empty() {
                    issues.push("tls.key_file must not be empty".to_owned());
                }
            }
            _ => issues.push(
                "tls.cert_file and tls.key_file are required unless tls.acme is enabled".to_owned(),
            ),
        },
    }
}

fn validate_acme(acme: &AcmeSpec, issues: &mut Vec<String>) {
    if acme.domains.is_empty() {
        issues.push("tls.acme.domains must contain at least one domain".to_owned());
    }
    let mut seen_domains = std::collections::HashSet::new();
    for domain in &acme.domains {
        if let Err(reason) = validate_acme_domain(domain) {
            issues.push(format!("tls.acme.domains: `{domain}` {reason}"));
        }
        if !seen_domains.insert(domain.to_ascii_lowercase()) {
            issues.push(format!(
                "tls.acme.domains: `{domain}` is a duplicate (domains are case-insensitive)"
            ));
        }
    }
    if acme.staging && acme.directory.is_some() {
        issues.push("tls.acme.staging cannot be combined with tls.acme.directory".to_owned());
    }
    if let Some(directory) = &acme.directory
        && let Err(reason) = validate_acme_url(directory)
    {
        issues.push(format!("tls.acme.directory {reason}"));
    }
    if let Some(contact) = &acme.contact
        && (contact.trim().is_empty() || !contact.contains('@'))
    {
        issues.push("tls.acme.contact must be an email address".to_owned());
    }
    if let Some(cache_dir) = &acme.cache_dir
        && cache_dir.as_os_str().is_empty()
    {
        issues.push("tls.acme.cache_dir must not be empty".to_owned());
    }
    for origin in &acme.allowed_origins {
        if let Err(reason) = validate_acme_origin(origin) {
            issues.push(format!("tls.acme.allowed_origins: `{origin}` {reason}"));
        }
    }
}

fn validate_acme_url(url: &str) -> Result<(), &'static str> {
    let uri: Uri = url.parse().map_err(|_| "must be a valid URL")?;
    if uri.scheme_str() != Some("https") {
        return Err("must use https://");
    }
    let Some(authority) = uri.authority() else {
        return Err("must include a host");
    };
    if authority.as_str().contains('@') {
        return Err("must not include user information");
    }
    if uri.host().is_none() {
        return Err("must include a host");
    }
    Ok(())
}

fn validate_acme_origin(origin: &str) -> Result<(), &'static str> {
    validate_acme_url(origin)?;
    let uri: Uri = origin.parse().map_err(|_| "must be a valid URL")?;
    if uri.path() != "/" || uri.query().is_some() {
        return Err("must be an origin without a path or query");
    }
    Ok(())
}

fn validate_acme_domain(domain: &str) -> Result<(), &'static str> {
    if domain.is_empty() {
        return Err("must not be empty");
    }
    if domain.len() > 253 {
        return Err("is longer than 253 bytes");
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err("must not start or end with a dot");
    }
    if domain.contains('*') {
        return Err("must not be a wildcard; TLS-ALPN-01 cannot validate wildcards");
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err("must be a DNS name, not an IP address");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err("contains an empty label");
        }
        if label.len() > 63 {
            return Err("contains a label longer than 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("contains a label starting or ending with a hyphen");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("contains characters other than ASCII letters, digits, and hyphens");
        }
    }
    Ok(())
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

fn compile_protection(spec: &ProtectionSpec, issues: &mut Vec<String>) -> Protection {
    validate_protection(spec, issues);
    let behavior = compile_behavior(&spec.behavior, issues);
    Protection {
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
        behavior,
    }
}

fn compile_behavior(spec: &BehaviorSpec, issues: &mut Vec<String>) -> BehaviorConfig {
    if spec.window.is_zero() || spec.window > MAX_BEHAVIOR_WINDOW {
        issues
            .push("protection.behavior.window must be greater than zero and at most 1h".to_owned());
    }
    if spec.min_requests == 0 {
        issues.push("protection.behavior.min_requests must be greater than zero".to_owned());
    }
    if !spec.enumeration.not_found_ratio.is_finite()
        || !(0.0..=1.0).contains(&spec.enumeration.not_found_ratio)
    {
        issues.push(
            "protection.behavior.enumeration.not_found_ratio must be finite and between 0 and 1"
                .to_owned(),
        );
    }
    if !(1..=MAX_BEHAVIOR_DISTINCT_PATHS).contains(&spec.enumeration.distinct_paths) {
        issues.push(format!(
            "protection.behavior.enumeration.distinct_paths must be between 1 and {MAX_BEHAVIOR_DISTINCT_PATHS}"
        ));
    }
    if spec.auth.min_failures == 0 {
        issues.push("protection.behavior.auth.min_failures must be greater than zero".to_owned());
    }
    if spec.global_auth.window.is_zero() || spec.global_auth.window > MAX_BEHAVIOR_WINDOW {
        issues.push(
            "protection.behavior.global_auth.window must be greater than zero and at most 1h"
                .to_owned(),
        );
    }
    if spec.global_auth.min_failures == 0 {
        issues.push(
            "protection.behavior.global_auth.min_failures must be greater than zero".to_owned(),
        );
    }

    let patterns: Vec<String> = match &spec.auth.paths {
        Some(paths) => paths.clone(),
        None => DEFAULT_AUTH_PATHS
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
    };
    let paths = compile_auth_paths(&patterns, issues);

    BehaviorConfig {
        enabled: spec.enabled,
        window: spec.window,
        min_requests: spec.min_requests,
        enumeration: EnumerationConfig {
            enabled: spec.enumeration.enabled,
            action: spec.enumeration.action,
            not_found_ratio: spec.enumeration.not_found_ratio,
            distinct_paths: spec.enumeration.distinct_paths,
        },
        auth: AuthConfig {
            enabled: spec.auth.enabled,
            action: spec.auth.action,
            min_failures: spec.auth.min_failures,
            paths,
        },
        global_auth: GlobalAuthConfig {
            enabled: spec.global_auth.enabled,
            window: spec.global_auth.window,
            min_failures: spec.global_auth.min_failures,
        },
    }
}

fn compile_auth_paths(patterns: &[String], issues: &mut Vec<String>) -> RegexSet {
    if patterns.len() > MAX_PATTERNS_PER_RULE {
        issues.push(format!(
            "protection.behavior.auth.paths: too many patterns (max {MAX_PATTERNS_PER_RULE})"
        ));
    }

    let mut valid = Vec::new();
    for pattern in patterns.iter().take(MAX_PATTERNS_PER_RULE) {
        if pattern.len() > MAX_PATTERN_BYTES {
            issues.push(format!(
                "protection.behavior.auth.paths: pattern exceeds {MAX_PATTERN_BYTES} bytes"
            ));
            continue;
        }
        match RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            Ok(_) => valid.push(pattern.as_str()),
            Err(err) => issues.push(format!(
                "protection.behavior.auth.paths: invalid regex: {err}"
            )),
        }
    }

    match RegexSet::new(valid.iter().copied()) {
        Ok(set) => set,
        Err(err) => {
            issues.push(format!(
                "protection.behavior.auth.paths: invalid regex set: {err}"
            ));
            RegexSet::empty()
        }
    }
}

fn validate_protection(spec: &ProtectionSpec, issues: &mut Vec<String>) {
    if !spec.requests_per_second.is_finite() || spec.requests_per_second <= 0.0 {
        issues
            .push("protection.requests_per_second must be finite and greater than zero".to_owned());
    }
    if !spec.burst.is_finite() || spec.burst < 1.0 {
        issues.push("protection.burst must be finite and at least 1".to_owned());
    }
    if !spec.global_requests_per_second.is_finite() || spec.global_requests_per_second <= 0.0 {
        issues.push(
            "protection.global_requests_per_second must be finite and greater than zero".to_owned(),
        );
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
    if !(200..=599).contains(&response.status) {
        issues.push(format!(
            "{context}: block and error responses must use a status from 200 to 599, got {}",
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
    action: Option<Action>,
    context: &str,
    issues: &mut Vec<String>,
) -> Matcher {
    let mut matcher = Matcher {
        allow_mode: action == Some(Action::Allow),
        ..Matcher::default()
    };
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
        matcher.headers =
            compile_header_matchers(map, context, action == Some(Action::Allow), issues);
    }

    if let Some(map) = &spec.cookies {
        has_condition = true;
        if map.is_empty() {
            issues.push(format!("{context}: `cookies` must not be empty"));
        }
        matcher.cookies =
            compile_cookie_matchers(map, context, action == Some(Action::Allow), issues);
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
            matcher.response_headers = compile_header_matchers(
                map,
                &format!("{context}: response_headers"),
                action == Some(Action::Allow),
                issues,
            );
        }
    }

    match &spec.regex {
        Some(patterns) => {
            has_condition = true;
            if patterns.is_empty() {
                issues.push(format!("{context}: `regex` must not be empty"));
            }
            matcher.payload = compile_payload(
                patterns,
                spec.targets.as_deref(),
                phase,
                action,
                context,
                issues,
            );
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
    action: Option<Action>,
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
                    other => issues.push(format!("{context}: {UNKNOWN_TARGET_ISSUE} `{other}`")),
                }
            }
        }
        None if phase == Phase::Response => target_flags = TARGET_RESPONSE_BODY,
        None => target_flags = TARGET_QUERY | TARGET_BODY | TARGET_COOKIES,
    }

    let regexes = compile_regexes(patterns, &format!("{context}: regex"), issues);
    if action == Some(Action::Allow) {
        require_anchored(patterns, &format!("{context}: regex"), issues);
    }
    if target_flags == 0 || regexes.is_empty() {
        return None;
    }

    Some(PayloadMatcher {
        regexes,
        targets: target_flags,
    })
}

/// ALLOW rules disable the WAF, so every pattern an ALLOW rule relies on must
/// cover the whole subject (entire header or cookie value, entire query/body
/// string). A pattern that matches anywhere inside a larger, attacker
/// controlled part lets the marker shadow later rules once it is appended.
fn require_anchored(patterns: &[String], context: &str, issues: &mut Vec<String>) {
    for pattern in patterns {
        if !is_fully_anchored(pattern) {
            issues.push(format!(
                "{context}: an ALLOW pattern must match the whole subject so an appended marker cannot trigger it; anchor the pattern at both ends, for example `^...$`"
            ));
        }
    }
}

/// A payload pattern is fully anchored when it can only match entire target
/// strings, leaving no position where an appended marker could satisfy it.
/// The regex is parsed so the check follows the engine's semantics instead of
/// the bytes written by the operator: a top-level `|` creates two anchors that
/// must each be checked, `\$` is a literal dollar sign rather than an anchor,
/// and `(?m)` turns `$` into an end-of-line assertion. Inline flags such as
/// `(?i)` are harmless, and a non-capturing group around anchored expressions
/// is accepted.
fn is_fully_anchored(pattern: &str) -> bool {
    regex_syntax::Parser::new()
        .parse(pattern)
        .is_ok_and(|hir| anchored_start(&hir) && anchored_end(&hir))
}

fn anchored_start(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Capture(capture) => anchored_start(&capture.sub),
        HirKind::Concat(parts) => parts.first().is_some_and(anchored_start),
        HirKind::Alternation(branches) => {
            !branches.is_empty() && branches.iter().all(anchored_start)
        }
        HirKind::Look(Look::Start) => true,
        _ => false,
    }
}

fn anchored_end(hir: &Hir) -> bool {
    match hir.kind() {
        HirKind::Capture(capture) => anchored_end(&capture.sub),
        HirKind::Concat(parts) => parts.last().is_some_and(anchored_end),
        HirKind::Alternation(branches) => !branches.is_empty() && branches.iter().all(anchored_end),
        HirKind::Look(Look::End) => true,
        _ => false,
    }
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
            Ok(method) => {
                if is_lowercase_standard_method(value) {
                    issues.push(format!(
                        "{context}: `{value}` is case-sensitive; write `{}`",
                        value.to_ascii_uppercase()
                    ));
                } else {
                    methods.push(method);
                }
            }
            Err(_) => issues.push(format!("{context}: invalid HTTP method `{value}`")),
        }
    }
    methods
}

/// HTTP methods are case-sensitive tokens, so `post` parses as a distinct
/// extension method that can never match a real `POST` request. Catch the
/// lowercase spelling of standard methods at load time instead of letting the
/// rule silently never fire.
fn is_lowercase_standard_method(value: &str) -> bool {
    const STANDARD: [&str; 9] = [
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ];
    let upper = value.to_ascii_uppercase();
    value != upper && STANDARD.contains(&upper.as_str())
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
    allow: bool,
    issues: &mut Vec<String>,
) -> Vec<(HeaderName, Vec<Regex>)> {
    let mut matchers = Vec::new();
    for (name, patterns) in map {
        if matches!(patterns, StringOrSeq::Many(values) if values.is_empty()) {
            issues.push(format!(
                "{context}: header `{name}` patterns must not be empty"
            ));
        }
        let Ok(header) = HeaderName::from_bytes(name.as_bytes()) else {
            issues.push(format!("{context}: invalid header name `{name}`"));
            continue;
        };
        let regexes = compile_regexes(
            &patterns.clone().into_vec(),
            &format!("{context}: header `{name}`"),
            issues,
        );
        if allow {
            require_anchored(
                &patterns.clone().into_vec(),
                &format!("{context}: header `{name}`"),
                issues,
            );
        }
        if !regexes.is_empty() {
            matchers.push((header, regexes));
        }
    }
    matchers
}

fn compile_cookie_matchers(
    map: &BTreeMap<String, StringOrSeq>,
    context: &str,
    allow: bool,
    issues: &mut Vec<String>,
) -> Vec<(String, Vec<Regex>)> {
    let mut matchers = Vec::new();
    for (name, patterns) in map {
        if matches!(patterns, StringOrSeq::Many(values) if values.is_empty()) {
            issues.push(format!(
                "{context}: cookie `{name}` patterns must not be empty"
            ));
        }
        if name.trim().is_empty() {
            issues.push(format!("{context}: cookie name must not be empty"));
            continue;
        }
        let regexes = compile_regexes(
            &patterns.clone().into_vec(),
            &format!("{context}: cookie `{name}`"),
            issues,
        );
        if allow {
            require_anchored(
                &patterns.clone().into_vec(),
                &format!("{context}: cookie `{name}`"),
                issues,
            );
        }
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
        DurationValue::Seconds(seconds) => {
            bounded_duration(Duration::from_secs(seconds)).map_err(DeError::custom)
        }
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

    let duration = match unit {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(
            value
                .checked_mul(60)
                .ok_or_else(|| format!("duration `{text}` overflows"))?,
        ),
        "h" => Duration::from_secs(
            value
                .checked_mul(3600)
                .ok_or_else(|| format!("duration `{text}` overflows"))?,
        ),
        _ => unreachable!("unit is one of the known suffixes"),
    };
    bounded_duration(duration)
}

fn bounded_duration(duration: Duration) -> Result<Duration, String> {
    if duration > MAX_DURATION {
        return Err("duration must not exceed 365 days".to_owned());
    }
    Ok(duration)
}

fn de_allowed_hosts<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<StringOrSeq>::deserialize(deserializer)?;
    match value {
        Some(value) => Ok(Some(value.into_vec())),
        None => Err(D::Error::custom(
            "allowed_hosts must not be empty; omit the field to disable host checking",
        )),
    }
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
        assert_eq!(config.limits.max_body_bytes, 8 * 1024 * 1024);
        assert_eq!(config.limits.body_inspection, BodyInspection::Strict);
        assert_eq!(config.limits.upload_inspection, UploadInspection::Mismatch);
        assert_eq!(config.timeouts.header_read, Duration::from_secs(10));
        assert_eq!(config.timeouts.connection_idle, Duration::from_secs(60));
    }

    #[test]
    fn content_routes_exempt_only_matching_methods_and_path_forms() {
        let config = parse_with(
            BASE,
            "content_routes:
  - path: ^/admin/posts(?:/|$)
    methods: [POST, PUT]
",
        )
        .expect("valid config");

        let uri: Uri = "/admin/posts/waf-in-rust".parse().expect("uri");
        assert!(config.is_content_route(&Method::POST, &uri));
        assert!(!config.is_content_route(&Method::GET, &uri));

        // The normalized form leaves the content route, so the exemption must
        // not apply even though the raw path has the prefix.
        let uri: Uri = "/admin/posts/../public".parse().expect("uri");
        assert!(!config.is_content_route(&Method::POST, &uri));
    }

    #[test]
    fn content_routes_without_methods_apply_to_every_method() {
        let config =
            parse_with(BASE, "content_routes:\n  - path: ^/editor(/|$)\n").expect("valid config");
        let uri: Uri = "/editor/draft".parse().expect("uri");
        for method in [Method::GET, Method::POST, Method::DELETE] {
            assert!(config.is_content_route(&method, &uri));
        }
    }

    #[test]
    fn rejects_invalid_content_routes() {
        for (rest, expected) in [
            ("content_routes:\n  - path: '('\n", "invalid regex"),
            (
                "content_routes:\n  - path: ^/admin\n    methods: [post]\n",
                "case-sensitive",
            ),
            ("content_routes:\n  - path: ''\n", "`path` is required"),
            (
                "content_routes:\n  - path: ^/admin\n    methods: []\n",
                "must not be empty",
            ),
        ] {
            let error = parse_with(BASE, rest).expect_err("must fail");
            assert!(
                error.to_string().contains(expected),
                "expected `{expected}` in {error}"
            );
        }
    }

    #[test]
    fn rejects_too_many_content_routes() {
        let routes: String = (0..=MAX_CONTENT_ROUTES)
            .map(|index| format!("  - path: ^/route{index}$\n"))
            .collect();
        let error = parse_with(BASE, &format!("content_routes:\n{routes}")).expect_err("must fail");
        assert!(error.to_string().contains("too many entries"));
    }

    #[test]
    fn client_ip_configuration_validates_trust_and_header_names() {
        let peer = "127.0.0.1:443".parse().expect("peer");
        let headers = HeaderMap::new();
        assert!(
            parse(BASE)
                .expect("default")
                .client_ip
                .resolve(peer, &headers)
                .is_ok()
        );
        for entry in ["127.0.0.1", "127.0.0.0/8", "::ffff:127.0.0.1/128"] {
            let config = parse_with(
                BASE,
                &format!("client_ip: {{ trusted_proxies: ['{entry}'] }}\n"),
            )
            .expect("config");
            assert!(config.client_ip.resolve(peer, &headers).is_err());
        }
        for value in [
            "client_ip: {}\n",
            "client_ip: { trusted_proxies: [] }\n",
            "client_ip: { trusted_proxies: [localhost] }\n",
            "client_ip: { trusted_proxies: ['127.0.0.1/33'] }\n",
            "client_ip: { trusted_proxies: [127.0.0.1], header: host }\n",
            "client_ip: { trusted_proxies: [127.0.0.1], unknown: true }\n",
        ] {
            assert!(parse_with(BASE, value).is_err(), "{value}");
        }
        let entries = vec!["127.0.0.1"; 65].join(", ");
        assert!(
            parse_with(
                BASE,
                &format!("client_ip: {{ trusted_proxies: [{entries}] }}\n")
            )
            .is_err()
        );
        for header in [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
        ] {
            let config = parse_with(
                BASE,
                &format!("client_ip: {{ trusted_proxies: [127.0.0.1], header: {header} }}\n"),
            )
            .expect("config");
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_bytes(header.as_bytes()).expect("name"),
                HeaderValue::from_static("203.0.113.7"),
            );
            assert_eq!(
                config
                    .client_ip
                    .resolve(peer, &headers)
                    .expect("client")
                    .client_ip,
                "203.0.113.7".parse::<IpAddr>().expect("IP")
            );
        }
    }

    #[test]
    fn parses_allowed_hosts() {
        let config = parse_with(
            BASE,
            "allowed_hosts:
  - example.com
  - '*.example.com'
  - 127.0.0.1
  - '[::1]'
  - 'example.com:8443'
categories: []
",
        )
        .expect("valid config");
        let allowed = config.allowed_hosts.expect("allowed hosts");
        assert!(allowed.matches("example.com"));
        assert!(allowed.matches("Example.COM."));
        assert!(allowed.matches("www.example.com"));
        assert!(!allowed.matches("example.com.evil"));
        assert!(allowed.matches("127.0.0.1:8080"));
        assert!(allowed.matches("[::1]"));
        assert!(allowed.matches("example.com:8443"));
        assert!(allowed.matches("example.com:443"));
    }

    #[test]
    fn allows_a_single_allowed_host_scalar() {
        let config = parse_with(BASE, "allowed_hosts: example.com\n").expect("valid config");
        let allowed = config.allowed_hosts.expect("allowed hosts");
        assert!(allowed.matches("example.com"));
    }

    #[test]
    fn rejects_a_null_allowed_hosts() {
        let error = parse_with(BASE, "allowed_hosts:\n").expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"));
        let error = parse_with(BASE, "allowed_hosts: null\n").expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_empty_and_invalid_allowed_hosts() {
        let error = parse_with(BASE, "allowed_hosts: []\n").expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"));

        let error = parse_with(BASE, "allowed_hosts: ['example.com:0']\n").expect_err("must fail");
        assert!(error.to_string().contains("allowed_hosts"));

        let error = parse_with(BASE, "allowed_hosts: ['foo bar']\n").expect_err("must fail");
        assert!(error.to_string().contains("allowed_hosts"));
    }

    #[test]
    fn warns_when_an_acme_domain_is_missing_from_allowed_hosts() {
        let config = parse_with(
            BASE,
            "allowed_hosts: [example.com]
tls: { acme: { enabled: true, domains: [example.com, www.example.com] } }
",
        )
        .expect("valid config");
        let warning = config.allowed_hosts_warning().expect("warning");
        assert!(warning.contains("www.example.com"));
        assert!(warning.contains("421"));
    }

    #[test]
    fn wildcard_allowed_hosts_cover_acme_domains() {
        let config = parse_with(
            BASE,
            "allowed_hosts: ['*.example.com', example.com]
tls: { acme: { enabled: true, domains: [example.com, www.example.com] } }
",
        )
        .expect("valid config");
        assert!(config.allowed_hosts_warning().is_none());
    }

    #[test]
    fn allowed_hosts_warning_is_absent_without_acme_or_a_list() {
        let config = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: [example.com] } }\n",
        )
        .expect("valid config");
        assert!(config.allowed_hosts_warning().is_none());

        let config = parse_with(BASE, "allowed_hosts: [example.com]\n").expect("valid config");
        assert!(config.allowed_hosts_warning().is_none());
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
        assert_eq!(
            *rule.limit_key,
            ("brute-force".to_owned(), "login".to_owned())
        );
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
    fn rejects_limits_above_the_hard_caps() {
        for (name, value) in [
            ("max_path_bytes", MAX_PATH_BYTES_LIMIT + 1),
            ("max_header_bytes", MAX_HEADER_BYTES_LIMIT + 1),
            ("max_headers", MAX_HEADERS_LIMIT + 1),
            ("max_body_bytes", MAX_BODY_BYTES_LIMIT + 1),
            ("max_response_body_bytes", MAX_BODY_BYTES_LIMIT + 1),
        ] {
            let error = parse_with(BASE, &format!("limits: {{ {name}: {value} }}\n"))
                .expect_err("limit above the hard cap must fail");
            assert!(error.to_string().contains(name), "{error}");
        }
    }

    #[test]
    fn rejects_zero_shutdown_grace_and_connection_idle() {
        for name in ["shutdown_grace", "connection_idle"] {
            let error =
                parse_with(BASE, &format!("timeouts: {{ {name}: 0s }}\n")).expect_err("must fail");
            assert!(error.to_string().contains(name), "{error}");
        }
    }

    #[test]
    fn parses_and_validates_max_concurrent_streams() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert_eq!(config.limits.max_concurrent_streams, 100);

        let config =
            parse_with(BASE, "limits: { max_concurrent_streams: 32 }\n").expect("valid config");
        assert_eq!(config.limits.max_concurrent_streams, 32);

        for value in [0, 1001] {
            let error = parse_with(
                BASE,
                &format!("limits: {{ max_concurrent_streams: {value} }}\n"),
            )
            .expect_err("must fail");
            assert!(
                error.to_string().contains("max_concurrent_streams"),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_lowercase_standard_methods() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    rules:
      - name: rule
        match: { method: post, path: / }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("POST"), "{error}");
    }

    #[test]
    fn rejects_informational_response_status() {
        let error = parse_with(
            BASE,
            "categories:
  - name: broken
    action: BLOCK
    response: { status: 101 }
    rules:
      - name: rule
        match: { path: / }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("200 to 599"), "{error}");
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
    fn behavior_defaults_are_observational() {
        let config = parse_with(BASE, "").expect("valid config");
        let behavior = &config.protection.behavior;
        assert!(behavior.enabled);
        assert_eq!(behavior.window, Duration::from_secs(60));
        assert_eq!(behavior.min_requests, 30);
        assert!(behavior.enumeration.enabled);
        assert_eq!(behavior.enumeration.action, BehaviorAction::Log);
        assert_eq!(behavior.enumeration.not_found_ratio, 0.5);
        assert_eq!(behavior.enumeration.distinct_paths, 40);
        assert!(behavior.auth.enabled);
        assert_eq!(behavior.auth.action, BehaviorAction::Log);
        assert_eq!(behavior.auth.min_failures, 20);
        assert!(behavior.auth.paths.is_match("/login"));
        assert!(behavior.auth.paths.is_match("/api/v1/token"));
        assert!(!behavior.auth.paths.is_match("/api/v1/users"));
        assert!(behavior.global_auth.enabled);
        assert_eq!(behavior.global_auth.window, Duration::from_secs(60));
        assert_eq!(behavior.global_auth.min_failures, 100);
    }

    #[test]
    fn parses_behavior_block() {
        let config = parse_with(
            BASE,
            "protection:
  behavior:
    enabled: false
    window: 30s
    min_requests: 5
    enumeration: { enabled: false, action: BLOCK, not_found_ratio: 0.25, distinct_paths: 10 }
    auth: { enabled: true, action: BLOCK, min_failures: 3, paths: ['^/custom$'] }
    global_auth: { enabled: false, window: 10s, min_failures: 50 }
",
        )
        .expect("valid config");
        let behavior = &config.protection.behavior;
        assert!(!behavior.enabled);
        assert_eq!(behavior.window, Duration::from_secs(30));
        assert_eq!(behavior.min_requests, 5);
        assert!(!behavior.enumeration.enabled);
        assert_eq!(behavior.enumeration.action, BehaviorAction::Block);
        assert_eq!(behavior.enumeration.not_found_ratio, 0.25);
        assert_eq!(behavior.enumeration.distinct_paths, 10);
        assert!(behavior.auth.enabled);
        assert_eq!(behavior.auth.action, BehaviorAction::Block);
        assert_eq!(behavior.auth.min_failures, 3);
        assert!(behavior.auth.paths.is_match("/custom"));
        assert!(!behavior.auth.paths.is_match("/login"));
        assert!(!behavior.global_auth.enabled);
        assert_eq!(behavior.global_auth.window, Duration::from_secs(10));
        assert_eq!(behavior.global_auth.min_failures, 50);
    }

    #[test]
    fn empty_auth_paths_match_nothing() {
        let config = parse_with(BASE, "protection:\n  behavior:\n    auth: { paths: [] }\n")
            .expect("valid config");
        assert!(!config.protection.behavior.auth.paths.is_match("/login"));
    }

    #[test]
    fn rejects_invalid_behavior_values() {
        for (yaml, expected) in [
            (
                "protection: { behavior: { window: 0s } }\n",
                "behavior.window",
            ),
            (
                "protection: { behavior: { window: 2h } }\n",
                "behavior.window",
            ),
            (
                "protection: { behavior: { min_requests: 0 } }\n",
                "behavior.min_requests",
            ),
            (
                "protection: { behavior: { enumeration: { not_found_ratio: 1.5 } } }\n",
                "not_found_ratio",
            ),
            (
                "protection: { behavior: { enumeration: { distinct_paths: 0 } } }\n",
                "distinct_paths",
            ),
            (
                "protection: { behavior: { enumeration: { distinct_paths: 257 } } }\n",
                "distinct_paths",
            ),
            (
                "protection: { behavior: { auth: { min_failures: 0 } } }\n",
                "auth.min_failures",
            ),
            (
                "protection: { behavior: { global_auth: { window: 0s } } }\n",
                "global_auth.window",
            ),
            (
                "protection: { behavior: { global_auth: { min_failures: 0 } } }\n",
                "global_auth.min_failures",
            ),
            (
                "protection: { behavior: { auth: { paths: ['('] } } }\n",
                "invalid regex",
            ),
        ] {
            let error = parse_with(BASE, yaml).expect_err("must fail");
            assert!(
                error.to_string().contains(expected),
                "{yaml}: {error} (expected {expected})"
            );
        }
    }

    #[test]
    fn rejects_unknown_behavior_fields_and_actions() {
        let error = parse_with(BASE, "protection: { behavior: { unknown: true } }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("unknown"), "{error}");

        let error = parse_with(
            BASE,
            "protection: { behavior: { enumeration: { action: DROP } } }\n",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("unknown"), "{error}");
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
        assert_eq!(
            tls.cert_file.as_deref(),
            Some(Path::new("/etc/kunato/cert.pem"))
        );
        assert_eq!(
            tls.key_file.as_deref(),
            Some(Path::new("/etc/kunato/key.pem"))
        );
        assert!(tls.acme.is_none());
    }

    #[test]
    fn rejects_empty_tls_paths() {
        let error =
            parse_with(BASE, "tls: { cert_file: '', key_file: key.pem }\n").expect_err("must fail");
        assert!(error.to_string().contains("cert_file"));
    }

    #[test]
    fn requires_cert_and_key_without_acme() {
        let error = parse_with(BASE, "tls: { cert_file: cert.pem }\n").expect_err("must fail");
        assert!(error.to_string().contains("tls.cert_file and tls.key_file"));
        let error = parse_with(BASE, "tls: {}\n").expect_err("must fail");
        assert!(error.to_string().contains("tls.cert_file and tls.key_file"));
    }

    #[test]
    fn parses_acme_block() {
        let config = parse_with(
            BASE,
            "tls:
  acme:
    enabled: true
    domains: [example.com, www.example.com]
    contact: admin@example.com
    allowed_origins: [https://cdn.example.com, https://acme.example.com:8443]
",
        )
        .expect("valid config");
        let tls = config.tls.expect("tls block");
        assert!(tls.cert_file.is_none());
        let acme = tls.acme.expect("acme settings");
        assert_eq!(acme.domains, vec!["example.com", "www.example.com"]);
        assert_eq!(acme.contact.as_deref(), Some("admin@example.com"));
        assert_eq!(
            acme.allowed_origins,
            vec![
                "https://cdn.example.com".to_owned(),
                "https://acme.example.com:8443".to_owned()
            ]
        );
        assert_eq!(
            acme.directory,
            crate::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
        );
        assert_eq!(acme.cache_dir, PathBuf::from(DEFAULT_ACME_CACHE_DIR));
    }

    #[test]
    fn acme_staging_directory_resolution() {
        let config = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: [example.com], staging: true } }\n",
        )
        .expect("valid config");
        let acme = config.tls.expect("tls block").acme.expect("acme settings");
        assert_eq!(acme.directory, crate::acme::LETS_ENCRYPT_STAGING_DIRECTORY);

        let config = parse_with(
            BASE,
            "tls:
  acme:
    enabled: true
    domains: [example.com]
    directory: https://acme.internal:14000/dir
    cache_dir: /srv/kunato/acme
",
        )
        .expect("valid config");
        let acme = config.tls.expect("tls block").acme.expect("acme settings");
        assert_eq!(acme.directory, "https://acme.internal:14000/dir");
        assert_eq!(acme.cache_dir, PathBuf::from("/srv/kunato/acme"));

        let error = parse_with(
            BASE,
            "tls:
  acme:
    enabled: true
    domains: [example.com]
    staging: true
    directory: https://acme.internal:14000/dir
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("staging cannot be combined"));

        let error = parse_with(
            BASE,
            "tls:
  acme:
    enabled: true
    domains: [example.com]
    directory: http://acme.internal:14000/dir
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn rejects_acme_without_domains() {
        let error = parse_with(BASE, "tls: { acme: { enabled: true } }\n").expect_err("must fail");
        assert!(error.to_string().contains("tls.acme.domains"));
    }

    #[test]
    fn rejects_invalid_acme_allowed_origins() {
        for origin in [
            "http://cdn.example.com",
            "https://cdn.example.com/path",
            "https://user@cdn.example.com",
            "https://cdn.example.com?query",
        ] {
            let yaml = format!(
                "tls: {{ acme: {{ enabled: true, domains: [example.com], allowed_origins: ['{origin}'] }} }}\n"
            );
            let error = parse_with(BASE, &yaml).expect_err("must fail");
            assert!(
                error.to_string().contains("allowed_origins"),
                "unexpected error for {origin}: {error}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_acme_domains_case_insensitively() {
        let error = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: [example.com, Example.com] } }\n",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_acme_wildcards_and_invalid_domains() {
        let error = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: ['*.example.com'] } }\n",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("wildcard"));

        let error = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: [192.0.2.1] } }\n",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("IP address"));

        let error = parse_with(
            BASE,
            "tls: { acme: { enabled: true, domains: ['exa mple.com'] } }\n",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("characters"));
    }

    #[test]
    fn rejects_acme_with_static_certificate() {
        let error = parse_with(
            BASE,
            "tls:
  cert_file: cert.pem
  key_file: key.pem
  acme: { enabled: true, domains: [example.com] }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn disabled_acme_falls_back_to_static_certificate() {
        let config = parse_with(
            BASE,
            "tls:
  cert_file: cert.pem
  key_file: key.pem
  acme: { enabled: false, domains: [example.com] }
",
        )
        .expect("valid config");
        let tls = config.tls.expect("tls block");
        assert!(tls.acme.is_none());
        assert_eq!(tls.cert_file.as_deref(), Some(Path::new("cert.pem")));
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
    fn defaults_keep_response_inspection_smaller_than_request_inspection() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert_eq!(config.limits.max_body_bytes, 8 * 1024 * 1024);
        assert_eq!(config.limits.websocket_message_bytes, 1024 * 1024);
        assert_eq!(config.limits.max_response_body_bytes, 1024 * 1024);

        let error =
            parse_with(BASE, "limits: { max_response_body_bytes: 0 }\n").expect_err("must fail");
        assert!(error.to_string().contains("max_response_body_bytes"));
    }

    #[test]
    fn rejects_invalid_websocket_message_limits() {
        for value in [0, MAX_BODY_BYTES_LIMIT + 1] {
            let error = parse_with(
                BASE,
                &format!("limits: {{ websocket_message_bytes: {value} }}\n"),
            )
            .expect_err("invalid WebSocket message limit must fail");
            assert!(error.to_string().contains("websocket_message_bytes"));
        }

        let config = parse_with(BASE, "limits: { websocket_message_bytes: 4096 }\n")
            .expect("valid WebSocket message limit");
        assert_eq!(config.limits.websocket_message_bytes, 4096);
    }

    #[test]
    fn parses_body_inspection_policy() {
        let config =
            parse_with(BASE, "limits: { body_inspection: stream }\n").expect("valid config");
        assert_eq!(config.limits.body_inspection, BodyInspection::Stream);

        let error = parse_with(BASE, "limits: { body_inspection: lenient }\n")
            .expect_err("unknown policy must fail");
        assert!(matches!(error, Error::ConfigParse(_)));

        let error = parse_with(BASE, "limits: { body_inspection: Strict }\n")
            .expect_err("policy names are lower case");
        assert!(matches!(error, Error::ConfigParse(_)));
    }

    #[test]
    fn parses_upload_inspection_policy() {
        let config = parse_with(BASE, "").expect("valid config");
        assert_eq!(config.limits.upload_inspection, UploadInspection::Mismatch);

        let config =
            parse_with(BASE, "limits: { upload_inspection: strict }\n").expect("valid config");
        assert_eq!(config.limits.upload_inspection, UploadInspection::Strict);

        let config =
            parse_with(BASE, "limits: { upload_inspection: off }\n").expect("valid config");
        assert_eq!(config.limits.upload_inspection, UploadInspection::Off);

        let error = parse_with(BASE, "limits: { upload_inspection: permissive }\n")
            .expect_err("unknown policy must fail");
        assert!(matches!(error, Error::ConfigParse(_)));
    }

    #[test]
    fn stream_mode_warns_for_body_rules_and_uploads() {
        let config =
            parse_with(BASE, "limits: { body_inspection: stream }\n").expect("valid config");
        let warning = config.body_inspection_warning().expect("warning");
        assert!(warning.contains("multipart uploads"), "{warning}");

        let config = parse_with(
            BASE,
            "limits: { body_inspection: stream, upload_inspection: off }\n",
        )
        .expect("valid config");
        assert!(config.body_inspection_warning().is_none());

        let config = parse_with(
            BASE,
            "limits: { body_inspection: stream, upload_inspection: off, max_body_bytes: 4096 }
categories:
  - name: sqli
    action: BLOCK
    rules:
      - name: union
        match: { regex: 'union select', in: [body] }
",
        )
        .expect("valid config");
        let warning = config.body_inspection_warning().expect("warning");
        assert!(warning.contains("stream"), "{warning}");
        assert!(warning.contains("4096"), "{warning}");
        assert!(!warning.contains("uploads"), "{warning}");

        let config = parse_with(
            BASE,
            "limits: { body_inspection: stream, max_body_bytes: 4096 }
categories:
  - name: sqli
    action: BLOCK
    rules:
      - name: union
        match: { regex: 'union select', in: [body] }
",
        )
        .expect("valid config");
        let warning = config.body_inspection_warning().expect("warning");
        assert!(
            warning.contains("body rules and multipart uploads"),
            "{warning}"
        );

        let config =
            parse_with(BASE, "limits: { upload_inspection: off }\n").expect("valid config");
        assert_eq!(config.limits.body_inspection, BodyInspection::Strict);
        assert!(config.body_inspection_warning().is_none());
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
        assert!(!config.response_targets_request_body());

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
        assert!(!config.response_targets_request_body());

        let config = parse_with(
            BASE,
            "categories:
  - name: response-body
    phase: response
    action: BLOCK
    rules:
      - name: marker
        match: { regex: marker, in: [body] }
",
        )
        .expect("valid config");
        assert!(config.response_targets_request_body());
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

    #[test]
    fn rejects_durations_that_overflow_their_unit() {
        let error = parse_with(BASE, "timeouts: { header_read: 18446744073709551615h }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("overflows"), "{error}");
        let error = parse_with(BASE, "timeouts: { body_read: 18446744073709551615m }\n")
            .expect_err("must fail");
        assert!(error.to_string().contains("overflows"), "{error}");
    }

    #[test]
    fn rejects_durations_beyond_the_cap() {
        for value in ["999999999999999s", "1000000000000s", "8761h"] {
            let error = parse_with(BASE, &format!("timeouts: {{ header_read: {value} }}\n"))
                .expect_err("must fail");
            assert!(
                error.to_string().contains("365 days"),
                "unexpected error for {value}: {error}"
            );
        }
        for value in [3600u64, 86400] {
            parse_with(BASE, &format!("timeouts: {{ header_read: {value} }}\n"))
                .expect("ordinary durations are accepted");
        }
        parse_with(BASE, "timeouts: { header_read: 364d }\n").expect_err("unknown unit suffix");
    }

    #[test]
    fn rejects_non_finite_protection_rates() {
        for field in ["requests_per_second", "global_requests_per_second", "burst"] {
            let yaml = format!("protection: {{ {field}: 1e400 }}\n");
            assert!(
                parse_with(BASE, &yaml).is_err(),
                "{field} must reject non-finite values"
            );
        }
    }

    #[test]
    fn tiny_finite_rates_are_accepted() {
        parse_with(
            BASE,
            "protection: { requests_per_second: 1e-300, burst: 1 }\n",
        )
        .expect("tiny finite rates are accepted");
    }

    #[test]
    fn rejects_empty_header_and_cookie_pattern_lists() {
        let error = parse_with(
            BASE,
            "categories:
  - name: c
    action: BLOCK
    rules:
      - name: r
        match: { headers: { x-required: [] } }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: c
    action: BLOCK
    rules:
      - name: r
        match: { cookies: { session: [] } }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"), "{error}");

        let error = parse_with(
            BASE,
            "categories:
  - name: c
    phase: response
    action: BLOCK
    rules:
      - name: r
        match: { response_headers: { server: [] } }
",
        )
        .expect_err("must fail");
        assert!(error.to_string().contains("must not be empty"), "{error}");
    }

    #[test]
    fn rule_limit_keys_use_full_identity() {
        let config = parse_with(
            BASE,
            "categories:
  - name: c
    action: BLOCK
    rules:
      - name: r95977
        limit: { requests: 1, window: 1h }
        match: { path: ^/a }
      - name: r353080
        limit: { requests: 1, window: 1h }
        match: { path: ^/b }
",
        )
        .expect("valid config");
        let first = &config.categories[0].rules[0];
        let second = &config.categories[0].rules[1];
        assert_ne!(first.limit_key, second.limit_key);
    }

    #[test]
    fn overrides_disabled_rules_do_not_drop_overrides_own_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            &dir.path().join("overrides.yaml"),
            "categories:
  - name: local
    action: ALLOW
    rules:
      - name: shared
        match: { path: ^/shared }
disabled_rules: [shared]
",
        );
        write(
            &dir.path().join("rules.yaml"),
            "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: shared
        match: { path: ^/shared }
      - name: other
        match: { path: ^/other }
",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: rules.yaml
overrides_file: overrides.yaml
",
        );

        let config = load(&main).expect("valid config");
        let local = config
            .categories
            .iter()
            .find(|category| category.name == "local")
            .expect("local category");
        assert_eq!(local.rules.len(), 1);
        assert_eq!(local.rules[0].name, "shared");
        let auto = config
            .categories
            .iter()
            .find(|category| category.name == "auto")
            .expect("auto category");
        assert_eq!(auto.rules.len(), 1);
        assert_eq!(auto.rules[0].name, "other");
    }

    #[test]
    fn candidate_rules_validate_against_inline_and_overrides_sources() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            &dir.path().join("overrides.yaml"),
            "categories:
  - name: local
    action: ALLOW
    rules:
      - name: trusted
        match: { source_ip: 127.0.0.1/32 }
",
        );
        let main = dir.path().join("kunato.yaml");
        write(
            &main,
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
rules_file: rules.yaml
overrides_file: overrides.yaml
categories:
  - name: inline
    action: LOG
    rules:
      - name: inline-rule
        match: { path: ^/inline }
",
        );

        let candidate = "categories:
  - name: auto
    action: BLOCK
    rules:
      - name: catch-all
        match: { path: ^/ }
";
        let compiled = load_with_rules_candidate(&main, candidate)
            .expect("candidate compiles without the file");
        assert_eq!(compiled.categories.len(), 3);

        let conflicting = "categories:
  - name: inline
    action: BLOCK
    rules:
      - name: duplicated
        match: { path: ^/dup }
";
        let error = load_with_rules_candidate(&main, conflicting)
            .expect_err("duplicate category must fail");
        assert!(error.to_string().contains("duplicate category"), "{error}");
    }

    #[test]
    fn allow_regex_must_be_anchored() {
        let unanchored = "categories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: marker\n        match: { regex: tokenfree, in: [query] }\n";
        let error = parse_with(BASE, unanchored).expect_err("unanchored ALLOW regex must fail");
        assert!(error.to_string().contains("anchor the pattern"), "{error}");

        let anchored = "categories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: marker\n        match: { regex: '^q=tokenfree$', in: [query] }\n";
        parse_with(BASE, anchored).expect("anchored ALLOW regex is valid");

        // A top-level alternation or an escaped dollar sign only looks
        // anchored: the first branch matches a prefix and `\$` is a literal.
        for unsafe_pattern in ["^q=tokenfree|q=abc$", r"^cost=\$"] {
            let yaml = format!(
                "categories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: marker\n        match: {{ regex: '{unsafe_pattern}', in: [query] }}\n"
            );
            parse_with(BASE, &yaml).expect_err("partially anchored ALLOW regex must fail");
        }

        // The same unanchored pattern is fine for a rule the operator wrote to
        // block or log.
        let blocking = "categories:\n  - name: scanners\n    action: BLOCK\n    rules:\n      - name: marker\n        match: { regex: tokenfree, in: [query] }\n";
        parse_with(BASE, blocking).expect("BLOCK keeps any-form regex semantics");
    }

    #[test]
    fn allow_header_and_cookie_patterns_must_be_anchored() {
        let unanchored = "categories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: marker\n        match: { headers: { x-marker: tokenfree } }\n";
        let error = parse_with(BASE, unanchored).expect_err("unanchored ALLOW header must fail");
        assert!(error.to_string().contains("header `x-marker`"), "{error}");

        let anchored = "categories:\n  - name: trusted\n    action: ALLOW\n    rules:\n      - name: marker\n        match: { headers: { x-marker: '^tokenfree$' }, cookies: { session: '^admin$' } }\n";
        parse_with(BASE, anchored).expect("anchored ALLOW header and cookie are valid");

        // BLOCK rules keep the any-substring semantics for their patterns.
        let blocking = "categories:\n  - name: scanners\n    action: BLOCK\n    rules:\n      - name: marker\n        match: { headers: { x-marker: tokenfree } }\n";
        parse_with(BASE, blocking).expect("BLOCK keeps any-form header semantics");
    }

    #[test]
    fn fully_anchored_patterns_are_recognized() {
        assert!(is_fully_anchored("^tokenfree$"));
        assert!(is_fully_anchored("(?i)^tokenfree$"));
        assert!(is_fully_anchored(r"\Atokenfree\z"));
        assert!(is_fully_anchored("^(?:a|b)$"));
        assert!(is_fully_anchored("(?:^tokenfree$)"));
        assert!(is_fully_anchored("^a$|^b$"));
        assert!(is_fully_anchored("^(?:a$|b$)"));
        assert!(!is_fully_anchored("^tokenfree"));
        assert!(!is_fully_anchored("tokenfree$"));
        assert!(!is_fully_anchored("tokenfree"));
        assert!(!is_fully_anchored("(?m)^tokenfree$"));
        assert!(!is_fully_anchored("(?i)^tokenfree"));
        assert!(!is_fully_anchored("^q=tokenfree|q=abc$"));
        assert!(!is_fully_anchored(r"^cost=\$"));
        assert!(!is_fully_anchored(r"^tokenfree\\z"));
        assert!(!is_fully_anchored("^a(?m)$"));
        assert!(!is_fully_anchored("^a$|b"));
    }

    #[test]
    fn graphql_limits_have_bounded_defaults() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        assert!(config.limits.graphql.enabled);
        assert_eq!(config.limits.graphql.max_depth, 20);
        assert_eq!(config.limits.graphql.max_fields, 1000);
        assert!(config.limits.graphql.paths.is_empty());
    }

    #[test]
    fn parses_graphql_limits_and_custom_paths() {
        let config = parse_with(
            BASE,
            "limits:\n  graphql:\n    paths: [/query, /v2/exec]\n    max_depth: 8\n    max_fields: 40\n",
        )
        .expect("valid config");
        assert_eq!(config.limits.graphql.max_depth, 8);
        assert_eq!(config.limits.graphql.max_fields, 40);
        assert!(config.limits.graphql.matches_path("/query"));
        assert!(config.limits.graphql.matches_path("/query;v=1"));
        assert!(config.limits.graphql.matches_path("/v2/exec/"));
        assert!(!config.limits.graphql.matches_path("/exec"));
    }

    #[test]
    fn recognizes_a_root_graphql_endpoint() {
        let config =
            parse_with(BASE, "limits:\n  graphql:\n    paths: [/]\n").expect("valid config");
        assert!(config.limits.graphql.matches_path("/"));
        assert!(!config.limits.graphql.matches_path("/other"));
    }

    #[test]
    fn recognizes_common_graphql_paths() {
        let config = parse_with(BASE, "categories: []\n").expect("valid config");
        let graphql = &config.limits.graphql;
        assert!(graphql.matches_path("/graphql"));
        assert!(graphql.matches_path("/graphql/"));
        assert!(graphql.matches_path("/api/graphql"));
        assert!(graphql.matches_path("/v1/GraphQL"));
        assert!(graphql.matches_path("/gql"));
        assert!(graphql.matches_path("/graphql;jsessionid=abc"));
        assert!(!graphql.matches_path("/graphqlql"));
        assert!(!graphql.matches_path("/graphql-assets"));
        assert!(!graphql.matches_path("/"));
    }

    #[test]
    fn rejects_invalid_graphql_limits() {
        for (body, expected) in [
            ("limits: { graphql: { max_depth: 0 } }\n", "max_depth"),
            ("limits: { graphql: { max_depth: 1001 } }\n", "max_depth"),
            ("limits: { graphql: { max_fields: 0 } }\n", "max_fields"),
            ("limits: { graphql: { max_fields: 10001 } }\n", "max_fields"),
            ("limits: { graphql: { paths: [query] } }\n", "must start"),
            ("limits: { graphql: { paths: [/graphql?x=1] } }\n", "query"),
        ] {
            let error = parse_with(BASE, body).expect_err("invalid graphql limit must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn form_limits_default_to_bounded_origin_facing_inspection() {
        let config = parse(BASE).expect("config");
        assert!(config.limits.form.enabled);
        assert_eq!(config.limits.form.max_parts, 64);
        assert_eq!(config.limits.form.max_headers_per_part, 16);
        assert_eq!(config.limits.form.max_part_header_bytes, 8192);
        assert_eq!(config.limits.form.max_nesting_depth, 16);
        assert!(!config.php.enabled);
        let config = parse_with(BASE, "limits: { form: { enabled: false, max_parts: 8 } }\n")
            .expect("config");
        assert!(!config.limits.form.enabled);
        assert_eq!(config.limits.form.max_parts, 8);
    }

    #[test]
    fn rejects_unbounded_form_resource_settings() {
        for (name, max) in [
            ("max_parts", 64),
            ("max_headers_per_part", 128),
            ("max_part_header_bytes", 65536),
            ("max_field_name_bytes", 4096),
            ("max_nesting_depth", 64),
            ("max_fields", 10000),
            ("max_empty_files", 64),
            ("max_complexity", 100000),
        ] {
            for value in [0, max + 1] {
                let error = parse_with(
                    BASE,
                    &format!("limits: {{ form: {{ {name}: {value} }} }}\n"),
                )
                .expect_err("invalid");
                assert!(
                    error.to_string().contains(&format!("limits.form.{name}")),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn php_profile_requires_an_explicit_scope_and_valid_session_policy() {
        for (body, expected) in [
            ("enabled: true", "requires hosts or paths"),
            ("hosts: []", "must not be empty"),
            ("hosts: [bad/host]", "php.hosts"),
            ("paths: [relative]", "absolute path"),
            ("paths: ['/x/../php']", "normalized"),
            ("paths: ['/%70hp']", "encoding"),
            ("session_cookies: []", "session_cookies"),
            (
                "upload_progress_names: ['bad name']",
                "upload_progress_names",
            ),
            ("max_session_id_bytes: 0", "max_session_id_bytes"),
            ("max_session_id_bytes: 4097", "max_session_id_bytes"),
            ("session_id_pattern: 'unanchored'", "fully anchored"),
            ("session_id_pattern: '^[$'", "session_id_pattern"),
        ] {
            let error = parse_with(BASE, &format!("php: {{ {body} }}\n")).expect_err("invalid");
            assert!(error.to_string().contains(expected), "{error}");
        }
        let config = parse_with(BASE, "php: { enabled: true, paths: [/], session_cookies: [SID], upload_progress_names: [PROGRESS] }\n").expect("valid");
        assert!(config.php.enabled);
        assert_eq!(config.php.session_cookies, ["SID"]);
        assert_eq!(config.php.upload_progress_names, ["PROGRESS"]);
    }
}
