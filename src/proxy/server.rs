use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderValue, UPGRADE};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::CompiledConfig;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::{ConnectionGuard, Decision, ProtectionState};
use crate::proxy::client::UpstreamClient;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::websocket::{self, Upgrade};
use crate::proxy::{BoxError, PrefixBody, ProxyBody, full_body};
use crate::proxy::{http3, tls};
use crate::request_view::RequestView;
use crate::rules::eval;

const RAW_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Http1,
    Http2,
}

#[derive(Clone)]
pub struct Context {
    config: Arc<ArcSwap<CompiledConfig>>,
    client: UpstreamClient,
    protection: Arc<ProtectionState>,
    metrics: Arc<Metrics>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    scheme: &'static str,
    alt_svc: Option<HeaderValue>,
}

impl Context {
    pub fn config(&self) -> Arc<CompiledConfig> {
        self.config.load_full()
    }

    pub(crate) fn try_acquire_connection(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        let config = self.config();
        self.protection
            .try_acquire_connection(ip, &config.protection)
    }
}

pub struct Server {
    listener: TcpListener,
    context: Context,
    http3: Option<quinn::Endpoint>,
}

impl Server {
    pub async fn bind(
        addr: SocketAddr,
        config: Arc<ArcSwap<CompiledConfig>>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind {
                addr: addr.to_string(),
                source,
            })?;
        let local_addr = listener.local_addr()?;
        let client = UpstreamClient::new(config.load().timeouts.upstream_connect);
        let (tls_acceptor, scheme) = match config.load().tls.as_ref() {
            Some(tls) => {
                let server_config = tls::load_server_config(&tls.cert_file, &tls.key_file)?;
                (
                    Some(tokio_rustls::TlsAcceptor::from(server_config)),
                    "https",
                )
            }
            None => (None, "http"),
        };
        let (http3, alt_svc) = match http3::bind(&config.load(), local_addr) {
            Ok(Some(listener)) => {
                info!(addr = %listener.local_addr, "HTTP/3 listening");
                (Some(listener.endpoint), listener.alt_svc)
            }
            Ok(None) => (None, None),
            Err(err) => {
                warn!(error = %err, "failed to start HTTP/3 listener; continuing without it");
                (None, None)
            }
        };
        Ok(Self {
            listener,
            context: Context {
                config,
                client,
                protection: Arc::new(ProtectionState::new()),
                metrics,
                tls_acceptor,
                scheme,
                alt_svc,
            },
            http3,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn protection(&self) -> Arc<ProtectionState> {
        Arc::clone(&self.context.protection)
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let Server {
            listener,
            context,
            http3,
        } = self;
        let http3_task = http3.map(|endpoint| {
            let context = context.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(http3::serve(endpoint, context, shutdown))
        });
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow_and_update() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let context = context.clone();
                            let connection_shutdown = shutdown.clone();
                            let config = context.config();
                            match context.try_acquire_connection(peer.ip()) {
                                Some(guard) => {
                                    let header_read_timeout = config.timeouts.header_read;
                                    connections.spawn(serve_connection(
                                        stream,
                                        peer,
                                        context,
                                        header_read_timeout,
                                        connection_shutdown,
                                        guard,
                                    ));
                                }
                                None => {
                                    warn!(client = %peer.ip(), "connection limit exceeded");
                                    connections.spawn(reject_connection(stream));
                                }
                            }
                        }
                        Err(err) => warn!(error = %err, "failed to accept connection"),
                    }
                }
            }
        }

        drop(listener);
        let grace = context.config().timeouts.shutdown_grace;
        info!(?grace, "listener stopped, draining connections");
        drain_connections(&mut connections, grace).await;
        if let Some(task) = http3_task {
            let _ = task.await;
        }
    }
}

pub(crate) async fn drain_connections(connections: &mut JoinSet<()>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match tokio::time::timeout_at(deadline, connections.join_next()).await {
            Ok(Some(Ok(()))) => continue,
            Ok(Some(Err(err))) => {
                debug!(error = %err, "connection task failed");
            }
            Ok(None) => break,
            Err(_) => {
                warn!("shutdown grace elapsed, aborting remaining connections");
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                break;
            }
        }
    }
}

async fn reject_connection(mut stream: tokio::net::TcpStream) {
    let _ = stream.write_all(RAW_503).await;
    let _ = stream.shutdown().await;
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    context: Context,
    header_read_timeout: Duration,
    shutdown: watch::Receiver<bool>,
    guard: ConnectionGuard,
) {
    match context.tls_acceptor.clone() {
        Some(acceptor) => {
            let tls = match tokio::time::timeout(header_read_timeout, acceptor.accept(stream)).await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(err)) => {
                    debug!(client = %peer, error = %err, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    debug!(client = %peer, "TLS handshake timed out");
                    return;
                }
            };
            let protocol = if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                Protocol::Http2
            } else {
                Protocol::Http1
            };
            serve_io(
                TokioIo::new(tls),
                protocol,
                peer,
                context,
                header_read_timeout,
                shutdown,
                guard,
            )
            .await;
        }
        None => {
            let Some(protocol) = detect_protocol(&stream, header_read_timeout).await else {
                debug!(client = %peer, "connection ended before HTTP version detection");
                return;
            };
            serve_io(
                TokioIo::new(stream),
                protocol,
                peer,
                context,
                header_read_timeout,
                shutdown,
                guard,
            )
            .await;
        }
    }
}

async fn detect_protocol(stream: &tokio::net::TcpStream, timeout: Duration) -> Option<Protocol> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; H2_PREFACE.len()];

    loop {
        let filled = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(filled)) if filled > 0 => filled,
            _ => return None,
        };

        let available = &buf[..filled.min(H2_PREFACE.len())];
        if !H2_PREFACE.starts_with(available) {
            return Some(Protocol::Http1);
        }
        if filled >= H2_PREFACE.len() {
            return Some(Protocol::Http2);
        }

        match tokio::time::timeout_at(deadline, stream.readable()).await {
            Ok(Ok(())) => {}
            _ => return None,
        }
    }
}

async fn serve_io<I>(
    io: I,
    protocol: Protocol,
    peer: SocketAddr,
    context: Context,
    header_read_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
    guard: ConnectionGuard,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let max_header_list_size =
        u32::try_from(context.config().limits.max_header_bytes).unwrap_or(u32::MAX);
    let guard_slot = Arc::new(std::sync::Mutex::new(Some(guard)));
    let service_shutdown = shutdown.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let context = context.clone();
        let shutdown = service_shutdown.clone();
        let guard_slot = Arc::clone(&guard_slot);
        async move { handle_request(request, peer, context, shutdown, guard_slot).await }
    });

    match protocol {
        Protocol::Http1 => {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(true)
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);
            let connection = builder.serve_connection(io, service).with_upgrades();
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                result = connection.as_mut() => {
                    if let Err(err) = result {
                        debug!(client = %peer, error = %err, "connection closed with error");
                    }
                }
                _ = shutdown.changed() => {
                    connection.as_mut().graceful_shutdown();
                    if let Err(err) = connection.as_mut().await {
                        debug!(client = %peer, error = %err, "connection closed during shutdown");
                    }
                }
            }
        }
        Protocol::Http2 => {
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            builder
                .timer(TokioTimer::new())
                .max_header_list_size(max_header_list_size);
            let connection = builder.serve_connection(io, service);
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                result = connection.as_mut() => {
                    if let Err(err) = result {
                        debug!(client = %peer, error = %err, "connection closed with error");
                    }
                }
                _ = shutdown.changed() => {
                    connection.as_mut().graceful_shutdown();
                    if let Err(err) = connection.as_mut().await {
                        debug!(client = %peer, error = %err, "connection closed during shutdown");
                    }
                }
            }
        }
    }
}

async fn handle_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    context: Context,
    shutdown: watch::Receiver<bool>,
    guard_slot: Arc<std::sync::Mutex<Option<ConnectionGuard>>>,
) -> Result<Response<ProxyBody>, Infallible> {
    let upgrade = if is_websocket_upgrade(&request) {
        let guard = guard_slot.lock().ok().and_then(|mut slot| slot.take());
        Some(Upgrade {
            on_upgrade: hyper::upgrade::on(&mut request),
            shutdown,
            guard,
        })
    } else {
        None
    };

    let config = context.config();
    let (parts, body) = request.into_parts();
    let result = match read_body(body, &config).await {
        Ok(body) => process(parts, body, peer, &config, &context, upgrade).await,
        Err(err) => Err(err),
    };
    let mut response = match result {
        Ok(response) => response,
        Err(err) => rejected(peer, &err),
    };
    config.response_headers.apply(response.headers_mut());
    if let Some(alt_svc) = &context.alt_svc {
        response.headers_mut().insert("alt-svc", alt_svc.clone());
    }
    Ok(response)
}

/// A request body read for inspection: a bounded prefix plus, when the body is
/// larger, the untaken remainder stream that is forwarded after evaluation.
struct RequestPayload {
    prefix: Bytes,
    pending: Vec<Frame<Bytes>>,
    rest: Option<Incoming>,
    truncated: bool,
}

async fn read_body(
    mut body: Incoming,
    config: &CompiledConfig,
) -> Result<RequestPayload, HttpError> {
    let limit = config.limits.max_body_bytes;
    let deadline = tokio::time::Instant::now() + config.timeouts.body_read;
    let mut prefix: Vec<u8> = Vec::new();
    let mut pending: Vec<Frame<Bytes>> = Vec::new();
    let mut truncated = false;

    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                return Err(HttpError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body read timed out",
                ));
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                return Err(HttpError::new(
                    StatusCode::BAD_REQUEST,
                    "malformed request body",
                ));
            }
            Ok(Some(Ok(frame))) => frame,
        };

        match frame.into_data() {
            Ok(data) => {
                if prefix.len() + data.len() > limit {
                    let take = limit.saturating_sub(prefix.len());
                    prefix.extend_from_slice(&data[..take]);
                    let remainder = data.slice(take..);
                    if !remainder.is_empty() {
                        pending.push(Frame::data(remainder));
                    }
                    truncated = true;
                    break;
                }
                prefix.extend_from_slice(&data);
            }
            Err(frame) => pending.push(frame),
        }
    }

    Ok(RequestPayload {
        prefix: Bytes::from(prefix),
        pending,
        rest: if truncated { Some(body) } else { None },
        truncated,
    })
}

pub(crate) fn rejected(peer: SocketAddr, err: &HttpError) -> Response<ProxyBody> {
    warn!(
        client = %peer.ip(),
        status = err.status.as_u16(),
        reason = err.message,
        "request rejected"
    );
    forward::error_response_for(err)
}

pub(crate) async fn process_request(
    parts: http::request::Parts,
    body: Bytes,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
) -> Response<ProxyBody> {
    let payload = RequestPayload {
        prefix: body,
        pending: Vec::new(),
        rest: None,
        truncated: false,
    };
    match process(parts, payload, peer, config, context, None).await {
        Ok(response) => response,
        Err(err) => rejected(peer, &err),
    }
}

fn is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    request.version() == http::Version::HTTP_11
        && request.method() == http::Method::GET
        && header_has_token(request.headers(), CONNECTION, "upgrade")
        && request
            .headers()
            .get(UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
}

fn header_has_token(headers: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

fn record_upstream_error(context: &Context, result: &Result<Response<ProxyBody>, HttpError>) {
    if let Err(err) = result {
        match err.status {
            StatusCode::GATEWAY_TIMEOUT => {
                context
                    .metrics
                    .upstream_timeouts
                    .fetch_add(1, Ordering::Relaxed);
            }
            StatusCode::BAD_GATEWAY => {
                context
                    .metrics
                    .upstream_connect_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

async fn process(
    parts: http::request::Parts,
    payload: RequestPayload,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
    upgrade: Option<Upgrade>,
) -> Result<Response<ProxyBody>, HttpError> {
    context.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let body = &payload.prefix;
    if payload.truncated {
        context
            .metrics
            .request_truncated
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            client = %peer.ip(),
            limit = config.limits.max_body_bytes,
            path = %parts.uri.path(),
            "request body truncated for inspection; streaming the remainder"
        );
    }

    match context
        .protection
        .check_request(peer.ip(), &config.protection)
    {
        Decision::Allow => {}
        Decision::RateLimited { retry_after } => {
            context.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::with_retry_after(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
                retry_after,
            ));
        }
        Decision::Banned { retry_after } => {
            context.metrics.banned.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::with_retry_after(
                StatusCode::TOO_MANY_REQUESTS,
                "client temporarily banned",
                retry_after,
            ));
        }
        Decision::Overloaded { retry_after } => {
            context.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
            return Err(HttpError::with_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "server overloaded",
                retry_after,
            ));
        }
    }

    if parts.uri.path().len() > config.limits.max_path_bytes {
        return Err(HttpError::new(StatusCode::URI_TOO_LONG, "URI too long"));
    }

    let header_bytes: usize = parts
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum();
    if parts.headers.len() > config.limits.max_headers
        || header_bytes > config.limits.max_header_bytes
    {
        return Err(HttpError::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request headers too large",
        ));
    }

    let inspected_body = if config.has_body_target_rules() {
        crate::decoding::decode_content_encoding(body, &parts.headers, config.limits.max_body_bytes)
    } else {
        None
    };
    let inspected_body = inspected_body.as_deref().unwrap_or(body);
    let view = RequestView::with_body_decoding(
        &parts.method,
        &parts.uri,
        &parts.headers,
        inspected_body,
        peer.ip(),
        config.has_body_target_rules(),
    );
    let outcome = eval::evaluate(config, &view, Some(context.protection.as_ref()));

    if !outcome.logs.is_empty() {
        context.metrics.logged.fetch_add(1, Ordering::Relaxed);
    }

    for record in &outcome.logs {
        info!(
            category = %record.category,
            rule = %record.rule,
            action = record.action.as_str(),
            client = %peer.ip(),
            method = %parts.method,
            path = %parts.uri.path(),
            "rule matched"
        );
    }

    if let Some(blocked) = &outcome.blocked {
        context.metrics.blocked.fetch_add(1, Ordering::Relaxed);
        if blocked.rate_limited {
            context.metrics.rule_limited.fetch_add(1, Ordering::Relaxed);
        }
        info!(
            category = %blocked.category,
            rule = %blocked.rule,
            action = "BLOCK",
            rate_limited = blocked.rate_limited,
            client = %peer.ip(),
            method = %parts.method,
            path = %parts.uri.path(),
            "request blocked"
        );
        return Ok(forward::block_response(&blocked.response));
    }

    drop(view);

    if let Some(upgrade) = upgrade {
        if payload.rest.is_some() {
            return Err(HttpError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upgrade request body too large",
            ));
        }
        let result = websocket::forward_handshake(
            config,
            parts,
            payload.prefix,
            context.scheme,
            peer,
            upgrade,
        )
        .await;
        record_upstream_error(context, &result);
        return result;
    }

    let (outbound_body, exchange_timeout) = match payload.rest {
        Some(rest) => {
            let rest = rest.map_err(|err| Box::new(err) as BoxError).boxed();
            let body = PrefixBody::new(payload.prefix.clone(), payload.pending, rest).boxed();
            (body, config.timeouts.body_read)
        }
        None => (
            full_body(payload.prefix.clone()),
            config.timeouts.upstream_response,
        ),
    };

    let result = forward::forward_request(
        &context.client,
        config,
        &parts,
        outbound_body,
        peer,
        context.scheme,
        exchange_timeout,
    )
    .await;
    record_upstream_error(context, &result);
    let response = result?;

    if !config.has_response_rules() {
        return Ok(response);
    }

    crate::proxy::response::inspect(
        config,
        &context.metrics,
        &parts,
        inspected_body,
        peer,
        response,
    )
    .await
}
