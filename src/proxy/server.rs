use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderValue, UPGRADE};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls_acme::AcmeAcceptor;
use tracing::{debug, info, warn};

use crate::acme::AcmeService;
use crate::config::CompiledConfig;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::{ConnectionGuard, Decision, ProtectionState, normalize_ip};
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

/// HTTP/2 connections are pinged after this much idle time and closed when the
/// pings go unanswered, so idle clients cannot hold connection slots forever.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Http1,
    Http2,
}

#[derive(Clone)]
enum TlsMode {
    Plain,
    Static(tokio_rustls::TlsAcceptor),
    Acme {
        acceptor: AcmeAcceptor,
        config: Arc<rustls::ServerConfig>,
    },
}

#[derive(Clone)]
pub struct Context {
    config: Arc<ArcSwap<CompiledConfig>>,
    client: Arc<ArcSwap<UpstreamClient>>,
    protection: Arc<ProtectionState>,
    metrics: Arc<Metrics>,
    tls: TlsMode,
    scheme: &'static str,
    alt_svc: Option<HeaderValue>,
}

impl Context {
    pub fn config(&self) -> Arc<CompiledConfig> {
        self.config.load_full()
    }

    /// Return an upstream client built for the snapshot's connect timeout,
    /// rebuilding it after a hot reload changed the timeout.
    pub(crate) fn client_for(&self, config: &CompiledConfig) -> Arc<UpstreamClient> {
        let current = self.client.load();
        if current.connect_timeout() == config.timeouts.upstream_connect {
            return Arc::clone(&current);
        }
        drop(current);
        let replacement = Arc::new(UpstreamClient::new(config.timeouts.upstream_connect));
        self.client.store(Arc::clone(&replacement));
        replacement
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
        acme: Option<&AcmeService>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| Error::Bind {
                addr: addr.to_string(),
                source,
            })?;
        let local_addr = listener.local_addr()?;
        let snapshot = config.load();
        let connect_timeout = snapshot.timeouts.upstream_connect;
        let (tls, scheme) = match acme {
            Some(service) => (
                TlsMode::Acme {
                    acceptor: service.acceptor(),
                    config: service.tls_config(),
                },
                "https",
            ),
            None => match snapshot.tls.as_ref() {
                Some(tls) => {
                    let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) else {
                        return Err(Error::Tls(
                            "tls.cert_file and tls.key_file are required unless tls.acme is enabled"
                                .to_owned(),
                        ));
                    };
                    let server_config = tls::load_server_config(cert_file, key_file)?;
                    (
                        TlsMode::Static(tokio_rustls::TlsAcceptor::from(server_config)),
                        "https",
                    )
                }
                None => (TlsMode::Plain, "http"),
            },
        };
        let (http3, alt_svc) = match http3::bind(&snapshot, local_addr, acme) {
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
        drop(snapshot);
        Ok(Self {
            listener,
            context: Context {
                config,
                client: Arc::new(ArcSwap::from_pointee(UpstreamClient::new(connect_timeout))),
                protection: Arc::new(ProtectionState::new()),
                metrics,
                tls,
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
                            let peer = normalize_peer(peer);
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
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(err) = result {
                        debug!(error = %err, "connection task failed");
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

pub(crate) fn normalize_peer(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalize_ip(peer.ip()), peer.port())
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
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    context: Context,
    header_read_timeout: Duration,
    shutdown: watch::Receiver<bool>,
    guard: ConnectionGuard,
) {
    match context.tls.clone() {
        TlsMode::Static(acceptor) => {
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
            serve_tls_connection(tls, peer, context, header_read_timeout, shutdown, guard).await;
        }
        TlsMode::Acme { acceptor, config } => {
            let handshake =
                match tokio::time::timeout(header_read_timeout, acceptor.accept(stream)).await {
                    Ok(Ok(Some(handshake))) => handshake,
                    Ok(Ok(None)) => {
                        debug!(client = %peer, "TLS-ALPN-01 challenge completed");
                        return;
                    }
                    Ok(Err(err)) => {
                        debug!(client = %peer, error = %err, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        debug!(client = %peer, "TLS handshake timed out");
                        return;
                    }
                };
            let tls = match tokio::time::timeout(header_read_timeout, handshake.into_stream(config))
                .await
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
            serve_tls_connection(tls, peer, context, header_read_timeout, shutdown, guard).await;
        }
        TlsMode::Plain => {
            let Some((protocol, prefix)) = detect_protocol(&mut stream, header_read_timeout).await
            else {
                debug!(client = %peer, "connection ended before HTTP version detection");
                return;
            };
            serve_io(
                TokioIo::new(PrefixedIo::new(stream, prefix)),
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

async fn serve_tls_connection(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: SocketAddr,
    context: Context,
    header_read_timeout: Duration,
    shutdown: watch::Receiver<bool>,
    guard: ConnectionGuard,
) {
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

/// Classify a plaintext connection as HTTP/1 or HTTP/2 by reading just enough
/// of the HTTP/2 preface, returning the consumed bytes so they can be replayed
/// to the protocol parser. Reads are bounded by the deadline and never busy-loop
/// on unread data.
async fn detect_protocol(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Option<(Protocol, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = Vec::with_capacity(H2_PREFACE.len());

    loop {
        if buf.len() >= H2_PREFACE.len() {
            return Some((Protocol::Http2, buf));
        }
        let mut chunk = [0u8; 32];
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => return None,
        };
        buf.extend_from_slice(&chunk[..read]);
        let seen = &buf[..buf.len().min(H2_PREFACE.len())];
        if !H2_PREFACE.starts_with(seen) {
            return Some((Protocol::Http1, buf));
        }
    }

    if buf.is_empty() {
        None
    } else {
        Some((Protocol::Http1, buf))
    }
}

/// Replays bytes that were consumed during protocol detection before the
/// wrapped stream, then delegates every operation to it.
struct PrefixedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let remaining = &this.prefix[this.offset..];
        if !remaining.is_empty() {
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            this.offset += take;
            if this.offset == this.prefix.len() {
                this.prefix.clear();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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
    let limits = context.config();
    let max_header_list_size = u32::try_from(limits.limits.max_header_bytes).unwrap_or(u32::MAX);
    let max_headers = limits.limits.max_headers;
    let max_concurrent_streams = limits.limits.max_concurrent_streams;
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
                .max_headers(max_headers)
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
                .max_header_list_size(max_header_list_size)
                .max_concurrent_streams(max_concurrent_streams)
                .keep_alive_interval(Some(H2_KEEP_ALIVE_INTERVAL))
                .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT);
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
        Some(Upgrade {
            on_upgrade: hyper::upgrade::on(&mut request),
            shutdown,
            guard_slot,
        })
    } else {
        None
    };

    let config = context.config();
    let (parts, body) = request.into_parts();
    let result = match early_protection_error(&context, peer, &config) {
        Some(err) => Err(err),
        None => match read_body(body, &config).await {
            Ok(body) => process(parts, body, peer, &config, &context, upgrade).await,
            Err(err) => Err(err),
        },
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

/// Ban pre-check that runs before a request body is ingested. A hit is counted
/// like a regular rejection so the request totals stay consistent.
pub(crate) fn early_protection_error(
    context: &Context,
    peer: SocketAddr,
    config: &CompiledConfig,
) -> Option<HttpError> {
    context
        .protection
        .check_banned(peer.ip(), &config.protection)
        .and_then(|decision| {
            context.metrics.requests.fetch_add(1, Ordering::Relaxed);
            protection_error(context, decision)
        })
}

/// Map a protection decision to the error response Kunato returns, recording
/// the matching metric. `Decision::Allow` maps to `None`.
pub(crate) fn protection_error(context: &Context, decision: Decision) -> Option<HttpError> {
    match decision {
        Decision::Allow => None,
        Decision::RateLimited { retry_after } => {
            context.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            Some(HttpError::with_retry_after(
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
                retry_after,
            ))
        }
        Decision::Banned { retry_after } => {
            context.metrics.banned.fetch_add(1, Ordering::Relaxed);
            Some(HttpError::with_retry_after(
                StatusCode::TOO_MANY_REQUESTS,
                "client temporarily banned",
                retry_after,
            ))
        }
        Decision::Overloaded { retry_after } => {
            context.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
            Some(HttpError::with_retry_after(
                StatusCode::SERVICE_UNAVAILABLE,
                "server overloaded",
                retry_after,
            ))
        }
    }
}

/// A request body read for inspection: a bounded prefix plus, when the body is
/// larger, the untaken remainder stream that is forwarded after evaluation.
pub(crate) struct RequestPayload {
    pub(crate) prefix: Bytes,
    pub(crate) pending: Vec<Frame<Bytes>>,
    pub(crate) rest: Option<ProxyBody>,
    pub(crate) truncated: bool,
}

async fn read_body(
    mut body: Incoming,
    config: &CompiledConfig,
) -> Result<RequestPayload, HttpError> {
    let limit = config.limits.max_body_bytes;
    let deadline = tokio::time::Instant::now() + config.timeouts.body_read;
    let mut prefix: Vec<u8> = Vec::new();
    let mut pending: Vec<Frame<Bytes>> = Vec::new();
    let mut overflowed = false;
    let mut hit_limit = false;

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
                let room = limit.saturating_sub(prefix.len());
                if data.len() >= room {
                    let take = room.min(data.len());
                    prefix.extend_from_slice(&data[..take]);
                    let remainder = data.slice(take..);
                    if !remainder.is_empty() {
                        pending.push(Frame::data(remainder));
                        overflowed = true;
                    }
                    hit_limit = true;
                    break;
                }
                prefix.extend_from_slice(&data);
            }
            Err(frame) => pending.push(frame),
        }
    }

    let truncated = overflowed
        || (hit_limit
            && body
                .size_hint()
                .exact()
                .is_none_or(|remaining| remaining > 0));
    Ok(RequestPayload {
        prefix: Bytes::from(prefix),
        pending,
        rest: if hit_limit {
            Some(body.map_err(|err| Box::new(err) as BoxError).boxed())
        } else {
            None
        },
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

pub(crate) async fn process_payload(
    parts: http::request::Parts,
    payload: RequestPayload,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
) -> Response<ProxyBody> {
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

fn record_upstream_error(context: &Context, err: &HttpError) {
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

async fn process(
    mut parts: http::request::Parts,
    payload: RequestPayload,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
    upgrade: Option<Upgrade>,
) -> Result<Response<ProxyBody>, HttpError> {
    forward::normalize_host_header(&mut parts);
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

    let decision = context
        .protection
        .check_request(peer.ip(), &config.protection);
    if let Some(err) = protection_error(context, decision) {
        return Err(err);
    }

    let request_target = parts
        .uri
        .path_and_query()
        .map_or(0, |target| target.as_str().len());
    if request_target > config.limits.max_path_bytes {
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

    let decoded_body = if config.has_body_target_rules() {
        crate::decoding::decode_content_encoding(body, &parts.headers, config.limits.max_body_bytes)
    } else {
        None
    };
    if config.has_body_target_rules()
        && !body.is_empty()
        && crate::decoding::encoding_is_uninspectable(&parts.headers)
    {
        context
            .metrics
            .request_decode_skipped
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            client = %peer.ip(),
            path = %parts.uri.path(),
            "request body encoding cannot be decoded for inspection"
        );
    }
    if decoded_body
        .as_ref()
        .is_some_and(|decoded| decoded.truncated)
    {
        context
            .metrics
            .request_decode_truncated
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            client = %peer.ip(),
            limit = config.limits.max_body_bytes,
            path = %parts.uri.path(),
            "decompressed request body truncated for inspection"
        );
    }
    let inspected_body = decoded_body.map(|decoded| decoded.body);
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
            &parts,
            payload.prefix.clone(),
            context.scheme,
            peer,
            upgrade,
        )
        .await;
        if let Err(err) = &result {
            record_upstream_error(context, err);
        }
        return match result? {
            websocket::Handshake::Upgraded(response) => Ok(response),
            websocket::Handshake::Response(response) => {
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
        };
    }

    let (outbound_body, exchange_timeout) = match payload.rest {
        Some(rest) => {
            let body = PrefixBody::new(payload.prefix.clone(), payload.pending, rest).boxed();
            (body, config.timeouts.body_read)
        }
        None if !payload.pending.is_empty() => (
            PrefixBody::new(
                payload.prefix.clone(),
                payload.pending,
                full_body(Bytes::new()),
            )
            .boxed(),
            config.timeouts.upstream_response,
        ),
        None => (
            full_body(payload.prefix.clone()),
            config.timeouts.upstream_response,
        ),
    };

    let client = context.client_for(config);
    let result = forward::forward_request(
        &client,
        config,
        &parts,
        outbound_body,
        peer,
        context.scheme,
        exchange_timeout,
    )
    .await;
    if let Err(err) = &result {
        record_upstream_error(context, err);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn connected_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect client");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    #[tokio::test]
    async fn detects_a_split_http2_preface_and_returns_its_bytes() {
        let (mut client, mut server) = connected_pair().await;
        let (first, rest) = H2_PREFACE.split_at(3);
        client.write_all(first).await.expect("write first half");
        let detect =
            tokio::spawn(async move { detect_protocol(&mut server, Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.write_all(rest).await.expect("write second half");

        let (protocol, prefix) = detect.await.expect("detect task").expect("detected");
        assert_eq!(protocol, Protocol::Http2);
        assert_eq!(prefix, H2_PREFACE);
    }

    #[tokio::test]
    async fn a_partial_preface_stops_at_the_deadline_without_spinning() {
        let (mut client, mut server) = connected_pair().await;
        client.write_all(b"P").await.expect("write partial preface");

        let start = std::time::Instant::now();
        let detected = detect_protocol(&mut server, Duration::from_millis(100)).await;
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "detection must be bounded by the deadline"
        );
        assert!(matches!(detected, Some((Protocol::Http1, _))));
    }

    #[tokio::test]
    async fn an_http1_request_is_classified_immediately() {
        let (mut client, mut server) = connected_pair().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n")
            .await
            .expect("write request");
        let (protocol, prefix) = detect_protocol(&mut server, Duration::from_secs(5))
            .await
            .expect("detected");
        assert_eq!(protocol, Protocol::Http1);
        assert!(prefix.starts_with(b"GET /"));
    }
}
