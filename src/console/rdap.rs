//! Optional RDAP registry lookup for the console source drawer.
//!
//! This is the modern WHOIS replacement: a bounded HTTPS JSON query to the
//! authoritative regional internet registry selected by the embedded IANA
//! bootstrap. It is opt-in because it sends the queried address to an external
//! registry. Results are cached by network range in memory; the WAF request
//! path never calls this module. A registry that rejects the console's IPv6
//! address with HTTP 429 is retried once over IPv4, and that choice is
//! remembered for the registry host.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use flate2::read::GzDecoder;
use http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, LOCATION, RETRY_AFTER, USER_AGENT};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{HttpConnector, HttpInfo};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::cidr::IpNet;
use crate::config::ConsoleRdap;
use crate::console::asn::{canonical, is_global};
use crate::proxy::{BodyExt, Full};

static IPV4_BOOTSTRAP: &[u8] = include_bytes!("../../data/rdap-ipv4.json");
static IPV6_BOOTSTRAP: &[u8] = include_bytes!("../../data/rdap-ipv6.json");

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 2;
const MAX_TEXT_CHARS: usize = 160;
const MAX_REMARK_CHARS: usize = 300;
const MAX_REMARKS: usize = 2;
const MAX_CONTACTS: usize = 3;
const MAX_STATUS: usize = 8;
const MAX_CIDRS: usize = 8;
const MAX_ENTITY_DEPTH: usize = 2;
const MIN_HOST_INTERVAL: Duration = Duration::from_secs(1);
const NEGATIVE_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);
const USER_AGENT_VALUE: &str = "kunato-console";

/// The normalized RDAP outcome exposed to the console UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RdapState {
    Ok,
    Disabled,
    NotGlobal,
    NoBootstrap,
    NotFound,
    RateLimited,
    Timeout,
    Unavailable,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RdapContact {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RdapRecord {
    pub handle: Option<String>,
    pub name: Option<String>,
    pub network_type: Option<String>,
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub cidrs: Vec<String>,
    pub country: Option<String>,
    pub status: Vec<String>,
    pub registered_at: Option<String>,
    pub last_changed_at: Option<String>,
    pub registrant: Vec<RdapContact>,
    pub abuse: Vec<RdapContact>,
    pub remarks: Vec<String>,
    pub record_url: Option<String>,
    pub redacted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RdapLookup {
    pub state: RdapState,
    pub enabled: bool,
    pub cached: bool,
    pub fetched_at_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub retry_after_ms: Option<u64>,
    pub registry: Option<String>,
    pub record: Option<RdapRecord>,
}

impl RdapLookup {
    fn state(state: RdapState, enabled: bool) -> Self {
        Self {
            state,
            enabled,
            cached: false,
            fetched_at_ms: None,
            expires_at_ms: None,
            retry_after_ms: None,
            registry: None,
            record: None,
        }
    }

    fn cached(entry: &CacheEntry) -> Self {
        Self {
            state: entry.state(),
            enabled: true,
            cached: true,
            fetched_at_ms: Some(entry.fetched_at_ms),
            expires_at_ms: Some(entry.expires_at_ms),
            retry_after_ms: None,
            registry: (!entry.registry.is_empty()).then(|| entry.registry.clone()),
            record: entry.record.clone(),
        }
    }
}

type RdapClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Shared, bounded RDAP client and cache.
pub struct RdapService {
    enabled: bool,
    ready: bool,
    client: Option<RdapClient>,
    client_v4: Option<RdapClient>,
    bootstrap: Option<Bootstrap>,
    timeout: Duration,
    cache_ttl: Duration,
    cache: Mutex<Cache>,
    hosts: Mutex<HashMap<String, HostState>>,
    semaphore: Semaphore,
}

impl std::fmt::Debug for RdapService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RdapService")
            .field("enabled", &self.enabled)
            .field("ready", &self.ready)
            .field("has_bootstrap", &self.bootstrap.is_some())
            .field("has_ipv4_fallback", &self.client_v4.is_some())
            .finish()
    }
}

impl RdapService {
    pub fn new(config: ConsoleRdap) -> Self {
        if !config.enabled {
            return Self::disabled();
        }
        let bootstrap = match Bootstrap::embedded() {
            Ok(bootstrap) => Some(bootstrap),
            Err(error) => {
                warn!(error = %error, "cannot load the embedded RDAP bootstrap");
                None
            }
        };
        let client = match build_client(false) {
            Ok(client) => Some(client),
            Err(error) => {
                warn!(error = %error, "cannot initialize the RDAP HTTPS client");
                None
            }
        };
        let client_v4 = match build_client(true) {
            Ok(client) => Some(client),
            Err(error) => {
                warn!(error = %error, "cannot initialize the RDAP IPv4 fallback client");
                None
            }
        };
        let ready = bootstrap.is_some() && client.is_some();
        if ready {
            info!(
                cache_entries = config.cache_entries,
                timeout_ms = config.timeout.as_millis(),
                ipv4_fallback = client_v4.is_some(),
                "RDAP registry lookup enabled"
            );
        }
        Self {
            enabled: true,
            ready,
            client,
            client_v4,
            bootstrap,
            timeout: config.timeout,
            cache_ttl: config.cache_ttl,
            cache: Mutex::new(Cache::new(config.cache_entries)),
            hosts: Mutex::new(HashMap::new()),
            semaphore: Semaphore::new(1),
        }
    }

    fn disabled() -> Self {
        Self {
            enabled: false,
            ready: false,
            client: None,
            client_v4: None,
            bootstrap: None,
            timeout: Duration::from_secs(4),
            cache_ttl: Duration::from_secs(24 * 60 * 60),
            cache: Mutex::new(Cache::new(0)),
            hosts: Mutex::new(HashMap::new()),
            semaphore: Semaphore::new(1),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn lookup(&self, address: IpAddr) -> RdapLookup {
        if !self.enabled {
            return RdapLookup::state(RdapState::Disabled, false);
        }
        let address = canonical(address);
        if !is_global(address) {
            return RdapLookup::state(RdapState::NotGlobal, true);
        }
        if !self.ready {
            return RdapLookup::state(RdapState::Unavailable, true);
        }
        let Some(bootstrap) = self.bootstrap.as_ref() else {
            return RdapLookup::state(RdapState::NoBootstrap, true);
        };
        let Some(entry) = bootstrap.lookup(address).cloned() else {
            return RdapLookup::state(RdapState::NoBootstrap, true);
        };
        let now = now_ms();
        if let Some(entry) = cache_lock(&self.cache).lookup(address, now) {
            return RdapLookup::cached(&entry);
        }
        match tokio::time::timeout(self.timeout, self.query(address, entry, now)).await {
            Ok(Ok(Some(entry))) => entry,
            Ok(Ok(None)) => RdapLookup::state(RdapState::NotFound, true),
            Ok(Err(QueryError::RateLimited(retry_after_ms))) => {
                let mut lookup = RdapLookup::state(RdapState::RateLimited, true);
                lookup.retry_after_ms = Some(retry_after_ms);
                lookup
            }
            Ok(Err(QueryError::Invalid)) => RdapLookup::state(RdapState::Invalid, true),
            Ok(Err(QueryError::Unavailable)) => RdapLookup::state(RdapState::Unavailable, true),
            Err(_) => RdapLookup::state(RdapState::Timeout, true),
        }
    }

    async fn query(
        &self,
        address: IpAddr,
        entry: BootstrapEntry,
        requested_at_ms: u64,
    ) -> Result<Option<RdapLookup>, QueryError> {
        let _permit = match tokio::time::timeout(self.timeout, self.semaphore.acquire()).await {
            Ok(Ok(permit)) => permit,
            _ => return Err(QueryError::Unavailable),
        };
        if let Some(cached) = cache_lock(&self.cache).lookup(address, now_ms()) {
            return Ok(Some(RdapLookup::cached(&cached)));
        }
        let mut prefer_ipv4 = self.wait_for_host(&entry.host).await?;
        let mut current = format!("{}ip/{}", entry.base, address);
        for redirect in 0..=MAX_REDIRECTS {
            let Some(client) = self.client_for(prefer_ipv4) else {
                return Err(QueryError::Unavailable);
            };
            let mut response = match fetch_with_retry(client, &current).await {
                Ok(response) => response,
                Err(error) => {
                    debug!(error = %error, host = %entry.host, "RDAP request failed");
                    return Err(QueryError::Unavailable);
                }
            };
            if ipv4_fallback_applies(&response, prefer_ipv4, self.client_v4.is_some())
                && let Some(fallback) = self.client_v4.as_ref()
                && let Ok(retry) = fetch_with_retry(fallback, &current).await
                && retry.status != StatusCode::TOO_MANY_REQUESTS
            {
                info!(
                    host = %entry.host,
                    registry = %entry.registry,
                    "RDAP registry rejected the console's IPv6 address; using IPv4"
                );
                prefer_ipv4 = true;
                self.set_prefer_ipv4(&entry.host);
                response = retry;
            }
            if response.status.is_redirection() {
                if redirect == MAX_REDIRECTS {
                    return Err(QueryError::Unavailable);
                }
                let Some(location) = response.headers.get(LOCATION).and_then(|v| v.to_str().ok())
                else {
                    return Err(QueryError::Unavailable);
                };
                current = match follow(&current, location) {
                    Some(next) => next,
                    None => return Err(QueryError::Unavailable),
                };
                continue;
            }
            if response.status == StatusCode::NOT_FOUND {
                let expires = expires_at(requested_at_ms, NEGATIVE_TTL.min(self.cache_ttl));
                cache_lock(&self.cache).insert_negative(address, requested_at_ms, expires);
                return Ok(None);
            }
            if response.status == StatusCode::TOO_MANY_REQUESTS {
                let retry = retry_after(&response.headers);
                debug!(
                    host = %entry.host,
                    registry = %entry.registry,
                    retry_after_ms = retry.as_millis(),
                    "RDAP registry rate limited the console"
                );
                self.block_host(&entry.host, retry);
                return Err(QueryError::RateLimited(
                    retry.as_millis().min(u128::from(u64::MAX)) as u64,
                ));
            }
            if response.status != StatusCode::OK {
                return Err(QueryError::Unavailable);
            }
            let bytes = decode_body(&response.headers, response.body)?;
            let value: Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    debug!(error = %error, "RDAP response was not JSON");
                    return Err(QueryError::Invalid);
                }
            };
            let record = normalize(&value)?;
            let fetched_at_ms = now_ms();
            let expires_at_ms = expires_at(fetched_at_ms, self.cache_ttl);
            let (start, end) = record_range(&record, address);
            let record_url = record.record_url.clone();
            cache_lock(&self.cache).insert(
                start,
                end,
                record.clone(),
                entry.registry.clone(),
                fetched_at_ms,
                expires_at_ms,
            );
            return Ok(Some(RdapLookup {
                state: RdapState::Ok,
                enabled: true,
                cached: false,
                fetched_at_ms: Some(fetched_at_ms),
                expires_at_ms: Some(expires_at_ms),
                retry_after_ms: None,
                registry: Some(entry.registry),
                record: Some(RdapRecord {
                    record_url: record_url
                        .or_else(|| Some(format!("{}ip/{}", entry.base, address))),
                    ..record
                }),
            }));
        }
        Err(QueryError::Unavailable)
    }

    /// Wait for the per-host interval and report whether this host already
    /// required the IPv4 fallback.
    async fn wait_for_host(&self, host: &str) -> Result<bool, QueryError> {
        let (sleep_for, prefer_ipv4) = {
            let mut hosts = lock(&self.hosts);
            let now = Instant::now();
            let state = hosts.entry(host.to_owned()).or_default();
            if let Some(blocked) = state.blocked_until {
                if blocked > now {
                    return Err(QueryError::RateLimited(
                        blocked
                            .saturating_duration_since(now)
                            .as_millis()
                            .min(u128::from(u64::MAX)) as u64,
                    ));
                }
                state.blocked_until = None;
            }
            let sleep_for = if state.next_allowed > now {
                state.next_allowed.saturating_duration_since(now)
            } else {
                state.next_allowed = now + MIN_HOST_INTERVAL;
                Duration::ZERO
            };
            (sleep_for, state.prefer_ipv4)
        };
        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }
        Ok(prefer_ipv4)
    }

    fn client_for(&self, prefer_ipv4: bool) -> Option<&RdapClient> {
        if prefer_ipv4 {
            self.client_v4.as_ref().or(self.client.as_ref())
        } else {
            self.client.as_ref()
        }
    }

    fn set_prefer_ipv4(&self, host: &str) {
        let mut hosts = lock(&self.hosts);
        hosts.entry(host.to_owned()).or_default().prefer_ipv4 = true;
    }

    fn block_host(&self, host: &str, retry: Duration) {
        let mut hosts = lock(&self.hosts);
        let state = hosts.entry(host.to_owned()).or_default();
        state.blocked_until = Some(Instant::now() + retry.min(MAX_RETRY_AFTER));
    }
}

fn build_client(ipv4_only: bool) -> Result<RdapClient, String> {
    let mut http = HttpConnector::new();
    // `HttpsConnectorBuilder::build` does this for the default connector; a
    // wrapped connector must still allow the `https` scheme through.
    http.enforce_http(false);
    if ipv4_only {
        // Binding the local side to an unspecified IPv4 address also makes the
        // connector discard resolved IPv6 addresses, so the fallback client
        // cannot reach a registry that rate limits the console's IPv6 address.
        http.set_local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|error| format!("failed to load native TLS roots: {error}"))?
        .https_only()
        .enable_http1()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

#[derive(Clone, Debug)]
struct BootstrapEntry {
    network: IpNet,
    base: String,
    host: String,
    registry: String,
}

struct Bootstrap {
    entries: Vec<BootstrapEntry>,
}

impl Bootstrap {
    fn embedded() -> Result<Self, String> {
        let mut entries = Vec::new();
        for bytes in [IPV4_BOOTSTRAP, IPV6_BOOTSTRAP] {
            let file: BootstrapFile = serde_json::from_slice(bytes)
                .map_err(|error| format!("invalid IANA RDAP bootstrap JSON: {error}"))?;
            for (prefixes, urls) in file.services {
                let Some((base, host, registry)) = urls.iter().find_map(|url| parse_base(url))
                else {
                    continue;
                };
                for prefix in prefixes {
                    let Ok(network) = IpNet::from_str(&prefix) else {
                        continue;
                    };
                    entries.push(BootstrapEntry {
                        network,
                        base: base.clone(),
                        host: host.clone(),
                        registry: registry.clone(),
                    });
                }
            }
        }
        if entries.is_empty() {
            return Err("the IANA RDAP bootstrap contains no usable HTTPS service".to_owned());
        }
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.network.prefix_len()));
        Ok(Self { entries })
    }

    fn lookup(&self, address: IpAddr) -> Option<&BootstrapEntry> {
        self.entries
            .iter()
            .find(|entry| entry.network.contains(address))
    }
}

#[derive(Deserialize)]
struct BootstrapFile {
    services: Vec<(Vec<String>, Vec<String>)>,
}

fn parse_base(raw: &str) -> Option<(String, String, String)> {
    let uri: Uri = raw.parse().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let host = uri.host()?.to_ascii_lowercase();
    if uri.query().is_some() || uri.authority()?.as_str().contains('@') {
        return None;
    }
    if !host_is_plausible(&host) {
        return None;
    }
    let mut base = uri.to_string();
    if !base.ends_with('/') {
        base.push('/');
    }
    let registry = registry_label(&host);
    Some((base, host, registry))
}

fn host_is_plausible(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(address) => is_global(address),
        Err(_) => true,
    }
}

fn registry_label(host: &str) -> String {
    if host.ends_with("arin.net") {
        "ARIN".to_owned()
    } else if host.contains("ripe") {
        "RIPE NCC".to_owned()
    } else if host.ends_with("apnic.net") {
        "APNIC".to_owned()
    } else if host.ends_with("lacnic.net") || host.ends_with("registro.br") {
        "LACNIC".to_owned()
    } else if host.ends_with("afrinic.net") {
        "AFRINIC".to_owned()
    } else {
        host.to_owned()
    }
}

struct HostState {
    next_allowed: Instant,
    blocked_until: Option<Instant>,
    prefer_ipv4: bool,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            next_allowed: Instant::now(),
            blocked_until: None,
            prefer_ipv4: false,
        }
    }
}

struct Cache {
    entries: Vec<CacheEntry>,
    max: usize,
}

#[derive(Clone)]
struct CacheEntry {
    start: IpAddr,
    end: IpAddr,
    record: Option<RdapRecord>,
    registry: String,
    fetched_at_ms: u64,
    expires_at_ms: u64,
}

impl CacheEntry {
    fn state(&self) -> RdapState {
        if self.record.is_some() {
            RdapState::Ok
        } else {
            RdapState::NotFound
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.start, self.end, address) {
            (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(address)) => {
                u32::from(start) <= u32::from(address) && u32::from(address) <= u32::from(end)
            }
            (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(address)) => {
                u128::from(start) <= u128::from(address) && u128::from(address) <= u128::from(end)
            }
            _ => false,
        }
    }

    fn span(&self) -> u128 {
        match (self.start, self.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                u128::from(u32::from(end).saturating_sub(u32::from(start)))
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                u128::from(end).saturating_sub(u128::from(start))
            }
            _ => u128::MAX,
        }
    }
}

impl Cache {
    fn new(max: usize) -> Self {
        Self {
            entries: Vec::new(),
            max,
        }
    }

    fn lookup(&mut self, address: IpAddr, now_ms: u64) -> Option<CacheEntry> {
        self.entries.retain(|entry| entry.expires_at_ms > now_ms);
        self.entries
            .iter()
            .filter(|entry| entry.contains(address))
            .min_by_key(|entry| entry.span())
            .cloned()
    }

    fn insert(
        &mut self,
        start: IpAddr,
        end: IpAddr,
        record: RdapRecord,
        registry: String,
        fetched_at_ms: u64,
        expires_at_ms: u64,
    ) {
        if self.max == 0 {
            return;
        }
        self.entries
            .retain(|entry| !(entry.start == start && entry.end == end));
        while self.entries.len() >= self.max {
            self.entries.remove(0);
        }
        self.entries.push(CacheEntry {
            start,
            end,
            record: Some(record),
            registry,
            fetched_at_ms,
            expires_at_ms,
        });
    }

    fn insert_negative(&mut self, address: IpAddr, fetched_at_ms: u64, expires_at_ms: u64) {
        if self.max == 0 {
            return;
        }
        self.entries
            .retain(|entry| !(entry.start == address && entry.end == address));
        while self.entries.len() >= self.max {
            self.entries.remove(0);
        }
        self.entries.push(CacheEntry {
            start: address,
            end: address,
            record: None,
            registry: String::new(),
            fetched_at_ms,
            expires_at_ms,
        });
    }
}

fn expires_at(now_ms: u64, ttl: Duration) -> u64 {
    now_ms.saturating_add(ttl.as_millis().min(u128::from(u64::MAX)) as u64)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cache_lock(cache: &Mutex<Cache>) -> MutexGuard<'_, Cache> {
    lock(cache)
}

#[derive(Debug)]
enum QueryError {
    RateLimited(u64),
    Invalid,
    Unavailable,
}

struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    remote: Option<SocketAddr>,
}

async fn fetch(client: &RdapClient, url: &str) -> Result<HttpResponse, String> {
    let uri: Uri = url
        .parse()
        .map_err(|error| format!("invalid RDAP URL: {error}"))?;
    if uri.scheme_str() != Some("https") || !uri.host().is_some_and(host_is_plausible) {
        return Err("RDAP URL is not an allowed HTTPS endpoint".to_owned());
    }
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(ACCEPT, "application/rdap+json")
        .header(ACCEPT_ENCODING, "identity")
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(Full::new(Bytes::new()))
        .map_err(|error| format!("cannot build RDAP request: {error}"))?;
    let response = client
        .request(request)
        .await
        .map_err(|error| format!("RDAP request failed: {error}"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let remote = response
        .extensions()
        .get::<HttpInfo>()
        .map(HttpInfo::remote_addr);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| format!("RDAP body failed: {error}"))?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > MAX_BODY_BYTES {
                return Err("RDAP body exceeds the response limit".to_owned());
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: bytes,
        remote,
    })
}

async fn fetch_with_retry(client: &RdapClient, url: &str) -> Result<HttpResponse, String> {
    match fetch(client, url).await {
        Ok(response) if response.status.is_server_error() => {
            tokio::time::sleep(Duration::from_millis(150)).await;
            fetch(client, url).await
        }
        Ok(response) => Ok(response),
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(150)).await;
            fetch(client, url).await
        }
    }
}

fn follow(current: &str, location: &str) -> Option<String> {
    let location: Uri = location.parse().ok()?;
    let uri = if location.scheme_str().is_some() {
        location
    } else if location.path().starts_with('/') {
        let current: Uri = current.parse().ok()?;
        let authority = current.authority()?;
        format!("https://{authority}{location}").parse().ok()?
    } else {
        return None;
    };
    if uri.scheme_str() != Some("https") || !uri.host().is_some_and(host_is_plausible) {
        return None;
    }
    Some(uri.to_string())
}

fn decode_body(headers: &HeaderMap, body: Vec<u8>) -> Result<Vec<u8>, QueryError> {
    if headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("gzip"))
    {
        let decoder = GzDecoder::new(body.as_slice());
        let mut expanded = Vec::new();
        decoder
            .take(MAX_BODY_BYTES as u64 + 1)
            .read_to_end(&mut expanded)
            .map_err(|_| QueryError::Invalid)?;
        if expanded.len() > MAX_BODY_BYTES {
            return Err(QueryError::Invalid);
        }
        Ok(expanded)
    } else {
        Ok(body)
    }
}

fn retry_after(headers: &HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_RETRY_AFTER, |seconds| {
            Duration::from_secs(seconds.clamp(1, MAX_RETRY_AFTER.as_secs()))
        })
}

/// Whether a rate-limited answer should be retried over IPv4. Shared hosting
/// IPv6 prefixes are commonly throttled by registries even when the console's
/// IPv4 address is accepted, so only a 429 over IPv6 (or an unknown transport)
/// triggers the fallback.
fn ipv4_fallback_applies(
    response: &HttpResponse,
    prefer_ipv4: bool,
    has_ipv4_client: bool,
) -> bool {
    response.status == StatusCode::TOO_MANY_REQUESTS
        && !prefer_ipv4
        && has_ipv4_client
        && response.remote.is_none_or(|address| address.is_ipv6())
}

fn record_range(record: &RdapRecord, fallback: IpAddr) -> (IpAddr, IpAddr) {
    let start = record
        .start_address
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok());
    let end = record
        .end_address
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok());
    match (start, end) {
        (Some(start), Some(end)) if start.is_ipv4() == end.is_ipv4() => {
            if ip_value(start) <= ip_value(end) {
                (start, end)
            } else {
                (end, start)
            }
        }
        _ => (fallback, fallback),
    }
}

fn ip_value(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn normalize(value: &Value) -> Result<RdapRecord, QueryError> {
    if let Some(class) = value.get("objectClassName").and_then(Value::as_str)
        && class != "ip network"
    {
        return Err(QueryError::Invalid);
    }
    let handle = field(value, "handle");
    let name = field(value, "name");
    let start_address = field(value, "startAddress");
    let end_address = field(value, "endAddress");
    let cidrs = cidrs(value);
    if handle.is_none()
        && name.is_none()
        && start_address.is_none()
        && end_address.is_none()
        && cidrs.is_empty()
    {
        return Err(QueryError::Invalid);
    }
    Ok(RdapRecord {
        handle,
        name,
        network_type: field(value, "type"),
        start_address,
        end_address,
        cidrs,
        country: field(value, "country"),
        status: strings(value.get("status"), MAX_STATUS, 32),
        registered_at: event(value, "registration"),
        last_changed_at: event(value, "last changed"),
        registrant: contacts(value, "registrant"),
        abuse: contacts(value, "abuse"),
        remarks: remarks(value),
        record_url: record_url(value),
        redacted: value
            .get("redacted")
            .and_then(Value::as_array)
            .is_some_and(|entries| !entries.is_empty()),
    })
}

fn field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(|text| clean(text, MAX_TEXT_CHARS))
        .filter(|text| !text.is_empty())
}

fn strings(value: Option<&Value>, max: usize, max_chars: usize) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|text| clean(text, max_chars))
                .filter(|text| !text.is_empty())
                .take(max)
                .collect()
        })
        .unwrap_or_default()
}

fn event(value: &Value, action: &str) -> Option<String> {
    value
        .get("events")
        .and_then(Value::as_array)?
        .iter()
        .find(|event| {
            event
                .get("eventAction")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(action))
        })
        .and_then(|event| event.get("eventDate"))
        .and_then(Value::as_str)
        .map(|text| clean(text, 40))
}

fn cidrs(value: &Value) -> Vec<String> {
    let mut cidrs = Vec::new();
    let Some(values) = value.get("cidr0_cidrs").and_then(Value::as_array) else {
        return cidrs;
    };
    for item in values.iter().take(MAX_CIDRS) {
        let prefix = item
            .get("v4prefix")
            .or_else(|| item.get("v6prefix"))
            .and_then(Value::as_str);
        let length = item.get("length").and_then(Value::as_u64);
        let (Some(prefix), Some(length)) = (prefix, length) else {
            continue;
        };
        let cidr = format!("{}/{}", prefix.trim(), length);
        if cidr.parse::<IpNet>().is_ok() {
            cidrs.push(cidr);
        }
    }
    cidrs
}

fn contacts(value: &Value, role: &str) -> Vec<RdapContact> {
    let mut contacts = Vec::new();
    if let Some(entities) = value.get("entities").and_then(Value::as_array) {
        collect_entities(entities, role, 0, &mut contacts);
    }
    contacts
}

fn collect_entities(entities: &[Value], role: &str, depth: usize, contacts: &mut Vec<RdapContact>) {
    for entity in entities.iter().take(32) {
        if contacts.len() >= MAX_CONTACTS {
            return;
        }
        let roles = entity.get("roles").and_then(Value::as_array);
        let matches = roles.is_some_and(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .any(|value| value.eq_ignore_ascii_case(role))
        });
        if matches {
            let handle = field(entity, "handle");
            let (name, organization, email, phone) = vcard(entity);
            let contact = RdapContact {
                name: name.or_else(|| handle.clone()),
                organization,
                email,
                phone,
            };
            if (contact.name.is_some()
                || contact.organization.is_some()
                || contact.email.is_some()
                || contact.phone.is_some())
                && !contacts.iter().any(|existing| {
                    existing.email == contact.email
                        && existing.name == contact.name
                        && existing.organization == contact.organization
                })
            {
                contacts.push(contact);
            }
        }
        if depth < MAX_ENTITY_DEPTH
            && let Some(children) = entity.get("entities").and_then(Value::as_array)
        {
            collect_entities(children, role, depth + 1, contacts);
        }
    }
}

fn vcard(
    entity: &Value,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let Some(properties) = entity
        .get("vcardArray")
        .and_then(Value::as_array)
        .and_then(|array| array.get(1))
        .and_then(Value::as_array)
    else {
        return (None, None, None, None);
    };
    let mut name = None;
    let mut organization = None;
    let mut email = None;
    let mut phone = None;
    for property in properties {
        let Some(property) = property.as_array() else {
            continue;
        };
        let Some(key) = property.first().and_then(Value::as_str) else {
            continue;
        };
        let text = property.get(3).and_then(vcard_text);
        match key {
            "fn" => name = name.or(text),
            "org" => organization = organization.or(text),
            "email" => email = email.or(text),
            "tel" => phone = phone.or(text),
            _ => {}
        }
    }
    (name, organization, email, phone)
}

fn vcard_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(clean(text, MAX_TEXT_CHARS)).filter(|text| !text.is_empty());
    }
    let values = value.as_array()?;
    let text = values
        .iter()
        .filter_map(Value::as_str)
        .map(|text| clean(text, MAX_TEXT_CHARS))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!text.is_empty()).then_some(text)
}

fn remarks(value: &Value) -> Vec<String> {
    let Some(values) = value.get("remarks").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut remarks = Vec::new();
    for item in values {
        let Some(description) = item.get("description").and_then(Value::as_array) else {
            continue;
        };
        let text = description
            .iter()
            .filter_map(Value::as_str)
            .map(|text| clean(text, MAX_REMARK_CHARS))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !text.is_empty() {
            remarks.push(text);
        }
        if remarks.len() >= MAX_REMARKS {
            break;
        }
    }
    remarks
}

fn record_url(value: &Value) -> Option<String> {
    let links = value.get("links").and_then(Value::as_array)?;
    for link in links {
        let relation = link.get("rel").and_then(Value::as_str);
        if !relation.is_some_and(|value| value.eq_ignore_ascii_case("self")) {
            continue;
        }
        let href = link.get("href").and_then(Value::as_str)?;
        let uri: Uri = href.parse().ok()?;
        if uri.scheme_str() == Some("https") && uri.host().is_some_and(host_is_plausible) {
            return Some(uri.to_string());
        }
    }
    None
}

fn clean(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;
    use serde_json::json;

    fn config(enabled: bool) -> ConsoleRdap {
        ConsoleRdap {
            enabled,
            timeout: Duration::from_secs(4),
            cache_ttl: Duration::from_secs(24 * 60 * 60),
            cache_entries: 16,
        }
    }

    fn sample_record() -> RdapRecord {
        RdapRecord {
            handle: Some("8.8.8.0/24".to_owned()),
            name: Some("GOOGLE".to_owned()),
            network_type: Some("DIRECT ALLOCATION".to_owned()),
            start_address: Some("8.8.8.0".to_owned()),
            end_address: Some("8.8.8.255".to_owned()),
            cidrs: vec!["8.8.8.0/24".to_owned()],
            country: Some("US".to_owned()),
            status: vec!["active".to_owned()],
            registered_at: Some("2014-03-18T00:00:00Z".to_owned()),
            last_changed_at: Some("2024-01-01T00:00:00Z".to_owned()),
            registrant: vec![RdapContact {
                name: Some("Google LLC".to_owned()),
                organization: Some("Google LLC".to_owned()),
                email: None,
                phone: None,
            }],
            abuse: vec![RdapContact {
                name: Some("Abuse".to_owned()),
                organization: None,
                email: Some("network-abuse@google.com".to_owned()),
                phone: None,
            }],
            remarks: vec!["Google Public DNS".to_owned()],
            record_url: Some("https://rdap.arin.net/registry/ip/8.8.8.0/24".to_owned()),
            redacted: false,
        }
    }

    #[test]
    fn embedded_bootstrap_selects_the_authoritative_registry() {
        let bootstrap = Bootstrap::embedded().expect("bootstrap");
        for (address, registry) in [
            ("8.8.8.8", "ARIN"),
            ("193.0.6.139", "RIPE NCC"),
            ("1.1.1.1", "APNIC"),
            ("200.160.2.3", "LACNIC"),
            ("196.216.2.1", "AFRINIC"),
        ] {
            let address: IpAddr = address.parse().expect("IP");
            let entry = bootstrap.lookup(address).expect("bootstrap entry");
            assert_eq!(entry.registry, registry, "{address}");
            assert!(entry.base.starts_with("https://"), "{}", entry.base);
        }
    }

    #[test]
    fn normalize_extracts_registry_contacts_and_events() {
        let value = json!({
            "objectClassName": "ip network",
            "handle": "8.8.8.0 - 8.8.8.255",
            "name": "GOOGLE",
            "type": "DIRECT ALLOCATION",
            "startAddress": "8.8.8.0",
            "endAddress": "8.8.8.255",
            "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
            "country": "US",
            "status": ["active"],
            "events": [
                {"eventAction": "registration", "eventDate": "2014-03-18T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"}
            ],
            "entities": [
                {
                    "handle": "GOGL",
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Google LLC"],
                        ["org", {}, "text", "Google LLC"],
                        ["email", {}, "text", "registrant@example.net"]
                    ]]
                },
                {
                    "handle": "ABUSE",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Abuse"],
                        ["email", {}, "text", "network-abuse@google.com"]
                    ]]
                }
            ],
            "remarks": [{"description": ["Google Public DNS"]}],
            "links": [{"rel": "self", "href": "https://rdap.arin.net/registry/ip/8.8.8.0/24"}],
            "redacted": [{"name": "registrant", "method": "removal"}]
        });
        let record = normalize(&value).expect("record");
        assert_eq!(record.handle.as_deref(), Some("8.8.8.0 - 8.8.8.255"));
        assert_eq!(record.name.as_deref(), Some("GOOGLE"));
        assert_eq!(record.cidrs, ["8.8.8.0/24"]);
        assert_eq!(record.status, ["active"]);
        assert_eq!(
            record.registered_at.as_deref(),
            Some("2014-03-18T00:00:00Z")
        );
        assert_eq!(
            record.registrant[0].organization.as_deref(),
            Some("Google LLC")
        );
        assert_eq!(
            record.abuse[0].email.as_deref(),
            Some("network-abuse@google.com")
        );
        assert_eq!(record.remarks, ["Google Public DNS"]);
        assert!(record.redacted);
        assert_eq!(
            record.record_url.as_deref(),
            Some("https://rdap.arin.net/registry/ip/8.8.8.0/24")
        );
        let (start, end) = record_range(&record, "8.8.8.8".parse().expect("IP"));
        assert_eq!(start, "8.8.8.0".parse::<IpAddr>().expect("IP"));
        assert_eq!(end, "8.8.8.255".parse::<IpAddr>().expect("IP"));
    }

    #[test]
    fn normalize_rejects_a_non_network_object() {
        let value = json!({"objectClassName": "domain", "name": "example.test"});
        assert!(normalize(&value).is_err());
    }

    #[test]
    fn cache_reuses_ranges_and_negative_entries() {
        let mut cache = Cache::new(2);
        cache.insert(
            "8.8.8.0".parse().expect("IP"),
            "8.8.8.255".parse().expect("IP"),
            sample_record(),
            "ARIN".to_owned(),
            100,
            200,
        );
        let hit = cache
            .lookup("8.8.8.8".parse().expect("IP"), 150)
            .expect("hit");
        assert_eq!(hit.registry, "ARIN");
        assert_eq!(hit.state(), RdapState::Ok);
        assert!(cache.lookup("8.8.8.8".parse().expect("IP"), 250).is_none());

        cache.insert_negative("9.9.9.9".parse().expect("IP"), 100, 200);
        let miss = cache
            .lookup("9.9.9.9".parse().expect("IP"), 150)
            .expect("negative");
        assert_eq!(miss.state(), RdapState::NotFound);
    }

    #[test]
    fn retry_after_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(retry_after(&headers), Duration::from_secs(120));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("99999"));
        assert_eq!(retry_after(&headers), MAX_RETRY_AFTER);
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-number"));
        assert_eq!(retry_after(&headers), DEFAULT_RETRY_AFTER);
    }

    #[test]
    fn ipv4_fallback_only_applies_to_ipv6_rate_limits() {
        let response = |status, remote| HttpResponse {
            status,
            headers: HeaderMap::new(),
            body: Vec::new(),
            remote,
        };
        let v4: SocketAddr = "192.0.2.1:443".parse().expect("IPv4");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("IPv6");

        assert!(ipv4_fallback_applies(
            &response(StatusCode::TOO_MANY_REQUESTS, Some(v6)),
            false,
            true
        ));
        assert!(ipv4_fallback_applies(
            &response(StatusCode::TOO_MANY_REQUESTS, None),
            false,
            true
        ));
        assert!(!ipv4_fallback_applies(
            &response(StatusCode::TOO_MANY_REQUESTS, Some(v4)),
            false,
            true
        ));
        assert!(!ipv4_fallback_applies(
            &response(StatusCode::TOO_MANY_REQUESTS, Some(v6)),
            true,
            true
        ));
        assert!(!ipv4_fallback_applies(
            &response(StatusCode::TOO_MANY_REQUESTS, Some(v6)),
            false,
            false
        ));
        assert!(!ipv4_fallback_applies(
            &response(StatusCode::OK, Some(v6)),
            false,
            true
        ));
    }

    #[test]
    fn clean_bounds_and_flattens_control_characters() {
        assert_eq!(clean("  Google\nLLC  ", 160), "Google LLC");
        assert_eq!(clean(&"a".repeat(200), 20).len(), 20);
    }

    #[test]
    fn redirects_require_https_and_plausible_hosts() {
        let current = "https://rdap.apnic.net/ip/8.8.8.8";
        assert_eq!(
            follow(current, "https://rdap.arin.net/registry/ip/8.8.8.8").as_deref(),
            Some("https://rdap.arin.net/registry/ip/8.8.8.8")
        );
        assert!(follow(current, "http://rdap.arin.net/registry/ip/8.8.8.8").is_none());
        assert!(follow(current, "https://127.0.0.1/ip/8.8.8.8").is_none());
    }

    #[tokio::test]
    async fn disabled_lookup_is_explicit() {
        let service = RdapService::new(config(false));
        let lookup = service.lookup("8.8.8.8".parse().expect("IP")).await;
        assert_eq!(lookup.state, RdapState::Disabled);
        assert!(!lookup.enabled);
        assert!(lookup.record.is_none());
    }
}
