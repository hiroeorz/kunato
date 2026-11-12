use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::admin_access::{AccessState, AdminAccessState, OverrideError};
use crate::config::{Admin, CompiledConfig, valid_admin_function_name};
use crate::error::Error;
use crate::maintenance::MaintenanceState;
use crate::metrics::Metrics;
use crate::protection::{ProtectionState, normalize_ip};
use crate::proxy::server::drain_connections;
use crate::proxy::{ProxyBody, full_body};
use crate::snapshot::Snapshot;

const MAX_ADMIN_CONNECTIONS: usize = 64;
const ADMIN_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_CONNECTION_GRACE: Duration = Duration::from_secs(5);
const MAX_ADMIN_ACCESS_QUERY_BYTES: usize = 512;

pub struct AdminServer {
    listener: TcpListener,
    context: AdminContext,
}

#[derive(Clone)]
struct AdminContext {
    config: Arc<Snapshot<CompiledConfig>>,
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
    maintenance: Arc<MaintenanceState>,
    admin_access: Arc<AdminAccessState>,
}

impl AdminServer {
    pub async fn bind(
        spec: &Admin,
        config: Arc<Snapshot<CompiledConfig>>,
        metrics: Arc<Metrics>,
        protection: Arc<ProtectionState>,
        maintenance: Arc<MaintenanceState>,
        admin_access: Arc<AdminAccessState>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(spec.listen)
            .await
            .map_err(|source| Error::Bind {
                addr: spec.listen.to_string(),
                source,
            })?;
        Ok(Self {
            listener,
            context: AdminContext {
                config,
                metrics,
                protection,
                maintenance,
                admin_access,
            },
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let limit = Arc::new(Semaphore::new(MAX_ADMIN_CONNECTIONS));
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow_and_update() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let context = self.context.clone();
                            match Arc::clone(&limit).try_acquire_owned() {
                                Ok(permit) => {
                                    connections.spawn(serve_connection(stream, peer, context, permit));
                                }
                                Err(_) => {
                                    warn!(client = %peer, "admin connection limit exceeded");
                                    drop(stream);
                                }
                            }
                        }
                        Err(err) => warn!(error = %err, "failed to accept admin connection"),
                    }
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(err) = result {
                        debug!(error = %err, "admin connection task failed");
                    }
                }
            }
        }

        drop(self.listener);
        drain_connections(&mut connections, ADMIN_CONNECTION_GRACE).await;
        info!("admin listener stopped");
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    context: AdminContext,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let context = context.clone();
        async move { handle(request, context).await }
    });
    let result = http1::Builder::new()
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(ADMIN_HEADER_TIMEOUT)
        .serve_connection(io, service)
        .await;
    if let Err(err) = result {
        debug!(client = %peer, error = %err, "admin connection closed with error");
    }
}

async fn handle(
    request: Request<Incoming>,
    context: AdminContext,
) -> Result<Response<ProxyBody>, Infallible> {
    // The data plane always adds its forwarding markers. A request that
    // carries them did not come from a local administrative client, so the
    // loopback listener must not act as a confused deputy for a remote client
    // whose request was forwarded to this socket.
    if has_data_plane_markers(request.headers()) {
        let mut response = Response::new(full_body("proxy headers are not accepted"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(response);
    }
    if !admin_host_allowed(request.headers().get(http::header::HOST)) {
        let mut response = Response::new(full_body("misdirected request"));
        *response.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        return Ok(response);
    }
    let path = request.uri().path();
    if request.method() == Method::GET && path == "/metrics" {
        let body = context
            .metrics
            .render(context.protection.active_connections());
        let mut response = Response::new(full_body(body));
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        return Ok(response);
    }
    if request.method() == Method::GET && path == "/maintenance" {
        let body = if context.maintenance.enabled() {
            "on\n"
        } else {
            "off\n"
        };
        return Ok(text_response(StatusCode::OK, body));
    }
    if request.method() == Method::GET && path == "/admin-access" {
        if request.uri().query().is_some() {
            return Ok(bad_request("query parameters are not accepted"));
        }
        return Ok(admin_access_status(
            &context.config.load(),
            &context.admin_access,
        ));
    }
    if request.method() == Method::PUT {
        // `PUT` is not a simple cross-origin request, so a browser must pass a
        // CORS preflight that this listener never grants. That keeps a page on
        // another origin from toggling maintenance or an administrative
        // access state through the loopback listener.
        match path {
            "/maintenance/on" => {
                if !context.maintenance.set(true) {
                    info!("maintenance mode enabled");
                }
                return Ok(text_response(StatusCode::OK, "maintenance on\n"));
            }
            "/maintenance/off" => {
                if context.maintenance.set(false) {
                    info!("maintenance mode disabled");
                }
                return Ok(text_response(StatusCode::OK, "maintenance off\n"));
            }
            "/admin-access/open" => {
                return Ok(admin_access_set(
                    &context.config.load(),
                    &context.admin_access,
                    AccessState::Open,
                    request.uri().query(),
                ));
            }
            "/admin-access/close" => {
                return Ok(admin_access_set(
                    &context.config.load(),
                    &context.admin_access,
                    AccessState::Close,
                    request.uri().query(),
                ));
            }
            _ => {}
        }
    }

    let mut response = Response::new(full_body("not found"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    Ok(response)
}

fn admin_access_status(config: &CompiledConfig, state: &AdminAccessState) -> Response<ProxyBody> {
    let policy = &config.admin_access;
    let mut body = String::new();
    let _ = writeln!(body, "enabled: {}", policy.enabled);
    let _ = writeln!(body, "default: {}", policy.default.as_str());
    let _ = writeln!(
        body,
        "default_ttl_seconds: {}",
        whole_seconds(policy.default_ttl)
    );
    let _ = writeln!(body, "max_ttl_seconds: {}", whole_seconds(policy.max_ttl));
    let _ = writeln!(body, "max_overrides: {}", policy.max_overrides);
    for function in &policy.functions {
        let _ = writeln!(body, "function: {}", function.name);
    }
    for entry in state.list(Instant::now()) {
        let client = display_client(entry.client);
        let function = entry.function.as_deref().unwrap_or("*");
        let _ = writeln!(
            body,
            "override: state={} client={} function={} expires_in_seconds={}",
            entry.state.as_str(),
            client,
            function,
            whole_seconds(entry.remaining)
        );
    }
    text_response(StatusCode::OK, body)
}

fn admin_access_set(
    config: &CompiledConfig,
    state: &AdminAccessState,
    access: AccessState,
    query: Option<&str>,
) -> Response<ProxyBody> {
    let policy = &config.admin_access;
    if !policy.enabled {
        return text_response(StatusCode::NOT_FOUND, "admin access is not enabled\n");
    }
    let params = match parse_query(query, &["client", "function", "ttl"]) {
        Ok(params) => params,
        Err(message) => return bad_request(message),
    };
    let client = match params.get("client").copied() {
        None => None,
        Some(value) => match value.parse::<IpAddr>() {
            Ok(client) => Some(normalize_ip(client)),
            Err(_) => return bad_request("invalid `client` address"),
        },
    };
    let function = match params.get("function").copied() {
        None => None,
        Some(function) if valid_admin_function_name(function) => {
            if policy.function(function).is_none() {
                return bad_request(format!("unknown function `{function}`"));
            }
            Some(function)
        }
        Some(_) => return bad_request("invalid `function` name"),
    };
    let ttl = match params.get("ttl").copied() {
        None => policy.default_ttl,
        Some(value) => match crate::config::parse_duration(value) {
            Ok(ttl) => ttl,
            Err(message) => return bad_request(message),
        },
    };
    if ttl < Duration::from_secs(1) {
        return bad_request("`ttl` must be at least 1s");
    }
    if ttl > policy.max_ttl {
        return bad_request(format!(
            "`ttl` must not exceed max_ttl ({}s)",
            whole_seconds(policy.max_ttl)
        ));
    }
    match state.set(
        client,
        function,
        access,
        ttl,
        policy.max_overrides,
        Instant::now(),
    ) {
        Ok(ttl) => {
            let client = display_client(client);
            let function = function.unwrap_or("*");
            info!(
                state = access.as_str(),
                client = %client,
                function = %function,
                ttl_secs = whole_seconds(ttl),
                "administrative access override set"
            );
            text_response(
                StatusCode::OK,
                format!(
                    "{} client={client} function={function} expires_in_seconds={}\n",
                    access.as_str(),
                    whole_seconds(ttl)
                ),
            )
        }
        Err(OverrideError::Capacity) => {
            text_response(StatusCode::CONFLICT, "override table is full\n")
        }
        Err(error) => bad_request(error.to_string()),
    }
}

fn display_client(client: Option<IpAddr>) -> String {
    client
        .map(|value| value.to_string())
        .unwrap_or_else(|| "*".to_owned())
}

/// Parse the small query language of the administrative access endpoints.
/// Percent-encoding is deliberately unsupported: every accepted value (an IP
/// address, a function name, or a duration) is plain ASCII, so an encoded value
/// is a caller error rather than something to decode.
fn parse_query<'a>(
    query: Option<&'a str>,
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut params = BTreeMap::new();
    let Some(query) = query else {
        return Ok(params);
    };
    if query.len() > MAX_ADMIN_ACCESS_QUERY_BYTES {
        return Err("query string is too long".to_owned());
    }
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err("malformed query string".to_owned());
        };
        if key.is_empty() || value.is_empty() {
            return Err("query parameters must have a name and a value".to_owned());
        }
        if key.contains('%') || value.contains('%') {
            return Err("percent-encoding is not supported".to_owned());
        }
        if !allowed.contains(&key) {
            return Err(format!("unknown query parameter `{key}`"));
        }
        if params.insert(key, value).is_some() {
            return Err(format!("duplicate query parameter `{key}`"));
        }
    }
    Ok(params)
}

fn bad_request(message: impl Into<String>) -> Response<ProxyBody> {
    text_response(StatusCode::BAD_REQUEST, format!("{}\n", message.into()))
}

/// Report a duration in whole seconds, rounding any sub-second remainder up so
/// a still-active override never shows `expires_in_seconds=0`.
fn whole_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn text_response(status: StatusCode, body: impl Into<Bytes>) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn has_data_plane_markers(headers: &http::HeaderMap) -> bool {
    ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"]
        .iter()
        .any(|name| headers.contains_key(*name))
}

/// Reject DNS-rebinding requests: the admin listener only accepts loopback
/// names, so a browser resolving an attacker-controlled name to 127.0.0.1
/// still sends that name in `Host`. A missing Host is also rejected: every
/// supported admin client is HTTP/1.1 or newer and sends one.
fn admin_host_allowed(host: Option<&HeaderValue>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let Ok(host) = host.to_str() else {
        return false;
    };
    let host = host.trim();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(name, _)| name).unwrap_or(host)
    } else {
        host.rsplit_once(':')
            .filter(|(name, port)| {
                !name.contains(':') && port.chars().all(|ch| ch.is_ascii_digit())
            })
            .map(|(name, _)| name)
            .unwrap_or(host)
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_loopback_admin_hosts() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:9090",
            "localhost",
            "LOCALHOST:9090",
            "[::1]",
            "[::1]:9090",
        ] {
            assert!(
                admin_host_allowed(Some(&HeaderValue::from_str(host).expect("host"))),
                "{host}"
            );
        }
        assert!(
            !admin_host_allowed(None),
            "a missing Host must not reach the admin listener"
        );
    }

    #[test]
    fn rejects_dns_rebinding_hosts() {
        for host in ["evil.example", "evil.example:9090", "10.0.0.1", "0.0.0.0"] {
            assert!(
                !admin_host_allowed(Some(&HeaderValue::from_str(host).expect("host"))),
                "{host}"
            );
        }
    }

    #[test]
    fn rejects_data_plane_forwarding_markers() {
        let headers = http::HeaderMap::new();
        assert!(!has_data_plane_markers(&headers));
        for name in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"] {
            let mut headers = http::HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("203.0.113.1"));
            assert!(has_data_plane_markers(&headers), "{name}");
        }
    }

    use crate::proxy::BodyExt;

    fn compiled(admin_access: &str) -> CompiledConfig {
        crate::config::parse(&format!(
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
admin: {{ listen: 127.0.0.1:0 }}
{admin_access}"
        ))
        .expect("valid config")
    }

    async fn response_parts(response: Response<ProxyBody>) -> (StatusCode, String) {
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn admin_access_query_parsing_is_strict_and_bounded() {
        let parsed = parse_query(
            Some("client=192.0.2.10&function=admin"),
            &["client", "function"],
        )
        .expect("query");
        assert_eq!(parsed.get("client").copied(), Some("192.0.2.10"));
        assert_eq!(parsed.get("function").copied(), Some("admin"));

        for (query, expected) in [
            ("client", "malformed query string"),
            ("client=&function=admin", "must have a name and a value"),
            ("client=192.0.2.10&client=192.0.2.11", "duplicate"),
            ("client=192.0.2.10&unknown=1", "unknown query parameter"),
            ("client=192.0.2.%31%30", "percent-encoding"),
        ] {
            let error = parse_query(Some(query), &["client", "function"]).expect_err("invalid");
            assert!(error.contains(expected), "{query}: {error}");
        }
        let long = format!("client={}", "1".repeat(MAX_ADMIN_ACCESS_QUERY_BYTES));
        let error = parse_query(Some(&long), &["client"]).expect_err("too long");
        assert!(error.contains("too long"), "{error}");
    }

    #[test]
    fn whole_seconds_rounds_sub_second_remainders_up() {
        assert_eq!(whole_seconds(Duration::from_secs(600)), 600);
        assert_eq!(whole_seconds(Duration::from_millis(1_500)), 2);
        assert_eq!(whole_seconds(Duration::from_millis(1)), 1);
    }

    #[tokio::test]
    async fn set_requires_an_enabled_policy_and_a_known_function() {
        let disabled = compiled("admin_access: { enabled: false }\n");
        let state = AdminAccessState::new();
        let (status, body) = response_parts(admin_access_set(
            &disabled,
            &state,
            AccessState::Open,
            Some("client=192.0.2.10&function=admin"),
        ))
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("not enabled"), "{body}");

        let config = compiled(
            "admin_access:
  enabled: true
  default: close
  presets: false
  functions:
    - name: admin
      paths: ['^/admin(?:/|$)']
",
        );
        let (status, body) = response_parts(admin_access_set(
            &config,
            &state,
            AccessState::Open,
            Some("client=192.0.2.10&function=nope"),
        ))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unknown function `nope`"), "{body}");

        let (status, body) = response_parts(admin_access_set(
            &config,
            &state,
            AccessState::Open,
            Some("client=bad&function=admin"),
        ))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid `client`"), "{body}");
    }

    #[tokio::test]
    async fn open_close_and_status_share_the_override_table() {
        let config = compiled(
            "admin_access:
  enabled: true
  default: close
  presets: false
  default_ttl: 10m
  max_ttl: 1h
  functions:
    - name: admin
      paths: ['^/admin(?:/|$)']
",
        );
        let state = AdminAccessState::new();
        let client = "192.0.2.10".parse().expect("ip");

        let (status, body) = response_parts(admin_access_set(
            &config,
            &state,
            AccessState::Open,
            Some("client=192.0.2.10&function=admin&ttl=2m"),
        ))
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("open client=192.0.2.10 function=admin expires_in_seconds=120"),
            "{body}"
        );
        assert_eq!(
            state.state_for(client, "admin", Instant::now()),
            Some(AccessState::Open)
        );

        let (status, body) = response_parts(admin_access_status(&config, &state)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("enabled: true"), "{body}");
        assert!(body.contains("default: close"), "{body}");
        assert!(body.contains("function: admin"), "{body}");
        assert!(
            body.contains("override: state=open client=192.0.2.10 function=admin"),
            "{body}"
        );

        let (status, body) =
            response_parts(admin_access_set(&config, &state, AccessState::Close, None)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("close client=* function=*"), "{body}");
        assert_eq!(
            state.state_for(client, "admin", Instant::now()),
            Some(AccessState::Close)
        );
    }

    #[tokio::test]
    async fn default_open_is_reported_by_status() {
        let config = compiled(
            "admin_access:
  enabled: true
  presets: false
  functions:
    - name: admin
      paths: ['^/admin(?:/|$)']
",
        );
        let state = AdminAccessState::new();
        let (status, body) = response_parts(admin_access_status(&config, &state)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("default: open"), "{body}");
        assert!(body.contains("max_overrides: 64"), "{body}");
    }

    #[tokio::test]
    async fn set_rejects_ttls_outside_the_policy() {
        let config = compiled(
            "admin_access:
  enabled: true
  default: close
  presets: false
  max_ttl: 10m
  max_overrides: 1
  functions:
    - name: admin
      paths: ['^/admin(?:/|$)']
",
        );
        let state = AdminAccessState::new();
        for (ttl, expected) in [
            ("0", "at least 1s"),
            ("0.5s", "invalid duration"),
            ("11m", "must not exceed max_ttl"),
        ] {
            let (status, body) = response_parts(admin_access_set(
                &config,
                &state,
                AccessState::Open,
                Some(&format!("client=192.0.2.10&function=admin&ttl={ttl}")),
            ))
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{ttl}");
            assert!(body.contains(expected), "{ttl}: {body}");
        }

        let (status, _) = response_parts(admin_access_set(
            &config,
            &state,
            AccessState::Open,
            Some("client=192.0.2.10&function=admin"),
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = response_parts(admin_access_set(
            &config,
            &state,
            AccessState::Open,
            Some("client=192.0.2.11&function=admin"),
        ))
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("override table is full"), "{body}");
    }
}
