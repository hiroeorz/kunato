use std::borrow::Cow;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_ENCODING, HeaderMap, HeaderValue, UPGRADE};
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
use crate::config::{BodyInspection, CompiledConfig, UploadInspection};
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::{BehaviorSignal, ConnectionGuard, Decision, ProtectionState, normalize_ip};
use crate::proxy::client::UpstreamClient;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::websocket::{self, Upgrade};
use crate::proxy::{BoxError, PrefixBody, ProxyBody, full_body, settle_body_end};
use crate::proxy::{http3, tls};
use crate::request_view::RequestView;
use crate::rules::eval;

const RAW_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Process-wide budget for buffers held by body inspection. A request or
/// response reserves a worst-case share before it starts buffering, so a burst
/// of concurrent bodies cannot grow the process without bound.
const INSPECTION_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const REQUEST_INSPECTION_FACTOR: usize = 8;
const RESPONSE_INSPECTION_FACTOR: usize = 3;
/// Requests start with this small baseline; the raw prefix grows it as body
/// bytes arrive, and the decoded-form worst case is reserved only immediately
/// before decoding and rule evaluation. A stalled body therefore holds its
/// actual buffered bytes, not the whole decoding budget.
const MIN_INSPECTION_RESERVATION: usize = 64 * 1024;

struct InspectionBudget {
    reserved: AtomicUsize,
}

impl InspectionBudget {
    fn new() -> Self {
        Self {
            reserved: AtomicUsize::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<InspectionGuard> {
        self.add(bytes).then(|| InspectionGuard {
            budget: Arc::clone(self),
            bytes,
        })
    }

    fn add(&self, bytes: usize) -> bool {
        let mut current = self.reserved.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > INSPECTION_BUDGET_BYTES {
                return false;
            }
            match self.reserved.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}

pub(crate) struct InspectionGuard {
    budget: Arc<InspectionBudget>,
    bytes: usize,
}

impl InspectionGuard {
    fn bytes(&self) -> usize {
        self.bytes
    }

    fn grow(&mut self, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }
        if !self.budget.add(additional) {
            return false;
        }
        self.bytes += additional;
        true
    }
}

impl Drop for InspectionGuard {
    fn drop(&mut self) {
        self.budget.reserved.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn request_inspection_bytes(config: &CompiledConfig, raw_bytes: usize) -> usize {
    raw_bytes
        .min(config.limits.max_body_bytes)
        .saturating_mul(REQUEST_INSPECTION_FACTOR)
        .max(MIN_INSPECTION_RESERVATION)
}

fn grow_inspection_to(inspection: &mut InspectionGuard, target: usize) -> bool {
    if target <= inspection.bytes() {
        return true;
    }
    inspection.grow(target - inspection.bytes())
}

/// Reserve the raw bytes buffered so far. This is deliberately unmultiplied:
/// the decoded forms may not be materialized at all (for a streamed body or a
/// request with no body rules), and reserving their worst case here would let
/// a few slow bodies exhaust the process-wide budget.
pub(crate) fn grow_request_inspection_raw(
    inspection: &mut InspectionGuard,
    config: &CompiledConfig,
    observed_bytes: usize,
) -> bool {
    let target = observed_bytes
        .min(config.limits.max_body_bytes)
        .max(MIN_INSPECTION_RESERVATION);
    grow_inspection_to(inspection, target)
}

/// Request activity for one HTTP/2 connection. The idle watchdog observes it
/// so a client that completes the handshake (or answers keep-alive pings)
/// without ever sending a request cannot hold a connection slot forever.
struct ConnectionActivity {
    active: AtomicUsize,
    requests: AtomicU64,
    changed: watch::Sender<u64>,
}

impl ConnectionActivity {
    fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            active: AtomicUsize::new(0),
            requests: AtomicU64::new(0),
            changed,
        }
    }

    fn start(self: &Arc<Self>) -> ActiveRequest {
        self.active.fetch_add(1, Ordering::AcqRel);
        let requests = self.requests.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.changed.send(requests);
        ActiveRequest {
            activity: Arc::clone(self),
        }
    }
}

struct ActiveRequest {
    activity: Arc<ConnectionActivity>,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.activity.active.fetch_sub(1, Ordering::AcqRel);
        let requests = self.activity.requests.load(Ordering::Acquire);
        let _ = self.activity.changed.send(requests);
    }
}

/// Keeps a request active until its response body has been streamed, so an
/// HTTP/2 response that outlives the service future is not mistaken for an idle
/// connection.
struct ActivityBody {
    inner: ProxyBody,
    _active: ActiveRequest,
}

impl Body for ActivityBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Resolves when an HTTP/2 connection has no request in flight and has been
/// idle for the configured duration. The first request gets the stricter
/// header timeout, so a TLS/ALPN client that never sends a preface is closed
/// quickly.
async fn connection_is_idle(
    activity: Arc<ConnectionActivity>,
    first_request: Duration,
    idle: Duration,
) {
    let mut changed = activity.changed.subscribe();
    loop {
        if activity.active.load(Ordering::Acquire) == 0 {
            let seen = *changed.borrow_and_update();
            let timeout = if activity.requests.load(Ordering::Acquire) == 0 {
                first_request
            } else {
                idle
            };
            tokio::select! {
                _ = tokio::time::sleep(timeout) => {
                    if activity.active.load(Ordering::Acquire) == 0
                        && *changed.borrow() == seen {
                        return;
                    }
                }
                result = changed.changed() => {
                    if result.is_err() {
                        return;
                    }
                }
            }
        } else if changed.changed().await.is_err() {
            return;
        }
    }
}

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
    inspection: Arc<InspectionBudget>,
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

    /// Reserve the small baseline share of memory for inspecting one request
    /// body. The raw prefix and decoded forms grow it as needed.
    pub(crate) fn reserve_request_inspection(&self) -> Option<InspectionGuard> {
        self.inspection.reserve(MIN_INSPECTION_RESERVATION)
    }

    /// Reserve the worst-case memory for inspecting one upstream response.
    pub(crate) fn reserve_response_inspection(
        &self,
        config: &CompiledConfig,
    ) -> Option<InspectionGuard> {
        let bytes = config
            .limits
            .max_response_body_bytes
            .saturating_mul(RESPONSE_INSPECTION_FACTOR)
            .max(64 * 1024);
        self.inspection.reserve(bytes)
    }

    pub(crate) fn record_overloaded(&self) {
        self.metrics.overloaded.fetch_add(1, Ordering::Relaxed);
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
                inspection: Arc::new(InspectionBudget::new()),
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

/// A connection-level rejection before any request was parsed. Deliberately
/// not counted in `kunato_requests_total`, which tracks requests Kunato kept
/// and evaluated (or answered) as requests.
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
    let activity = (protocol == Protocol::Http2).then(|| Arc::new(ConnectionActivity::new()));
    let watchdog_activity = activity.clone();
    let service_shutdown = shutdown.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let context = context.clone();
        let shutdown = service_shutdown.clone();
        let guard_slot = Arc::clone(&guard_slot);
        let activity = activity.clone();
        async move {
            let active = activity.as_ref().map(ConnectionActivity::start);
            handle_request(request, peer, context, shutdown, guard_slot, active).await
        }
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
            let Some(watchdog_activity) = watchdog_activity else {
                debug!(client = %peer, "HTTP/2 connection has no activity tracker");
                return;
            };
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
                _ = connection_is_idle(
                    watchdog_activity,
                    header_read_timeout,
                    limits.timeouts.connection_idle,
                ) => {
                    debug!(client = %peer, "closing idle HTTP/2 connection");
                    connection.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(Duration::from_secs(1), connection.as_mut()).await;
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
    active: Option<ActiveRequest>,
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
    let (mut parts, body) = request.into_parts();
    let result = if let Some(err) = admission_error(&context, peer, &config) {
        Err(err)
    } else if let Some(err) = host_policy_error(&context, &config, &mut parts, peer) {
        Err(err)
    } else if let Some(inspection) = context.reserve_request_inspection() {
        match read_body(body, &config, inspection, &context).await {
            Ok((body, inspection)) => {
                process(parts, body, peer, &config, &context, upgrade, inspection).await
            }
            Err(err) => Err(err),
        }
    } else {
        context.record_overloaded();
        Err(inspection_capacity_error())
    };
    let mut response = match result {
        Ok(response) => response,
        Err(err) => rejected(peer, &err),
    };
    config.response_headers.apply(response.headers_mut());
    if let Some(alt_svc) = &context.alt_svc {
        response.headers_mut().insert("alt-svc", alt_svc.clone());
    }
    let (parts, body) = response.into_parts();
    let body = match active {
        Some(active) => ActivityBody {
            inner: body,
            _active: active,
        }
        .boxed(),
        None => body,
    };
    Ok(Response::from_parts(parts, body))
}

/// Admission check that runs before a request body is ingested. It consumes
/// the source's rate budget and counts the request, so a rate-limited client
/// never causes a body buffer allocation.
pub(crate) fn admission_error(
    context: &Context,
    peer: SocketAddr,
    config: &CompiledConfig,
) -> Option<HttpError> {
    context.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let decision = context
        .protection
        .check_request(peer.ip(), &config.protection);
    protection_error(context, decision)
}

/// Enforce the optional Host/authority allowlist before the request body is
/// ingested. The helper also promotes `:authority` to `Host`, so callers get a
/// normalized request head for rule evaluation and forwarding.
pub(crate) fn host_policy_error(
    context: &Context,
    config: &CompiledConfig,
    parts: &mut http::request::Parts,
    peer: SocketAddr,
) -> Option<HttpError> {
    forward::normalize_host_header(parts);
    let allowed = config.allowed_hosts.as_ref()?;
    let Err(violation) = allowed.check(parts) else {
        return None;
    };
    context
        .metrics
        .host_rejected
        .fetch_add(1, Ordering::Relaxed);
    if let Some(host) = violation.host() {
        debug!(
            client = %peer.ip(),
            host = %host,
            "request Host is not in allowed_hosts"
        );
    }
    Some(HttpError::new(violation.status(), violation.message()))
}

/// Stable error for requests that could not reserve inspection memory. The
/// client should retry after the current inspections release their budget.
pub(crate) fn inspection_capacity_error() -> HttpError {
    HttpError::with_retry_after(
        StatusCode::SERVICE_UNAVAILABLE,
        "inspection capacity exhausted",
        Duration::from_secs(1),
    )
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
    mut inspection: InspectionGuard,
    context: &Context,
) -> Result<(RequestPayload, InspectionGuard), HttpError> {
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
                let observed = prefix.len().saturating_add(data.len());
                if !grow_request_inspection_raw(&mut inspection, config, observed) {
                    context.record_overloaded();
                    return Err(inspection_capacity_error());
                }
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

    let mut truncated = overflowed;
    if hit_limit && !truncated {
        truncated = match body.size_hint().exact() {
            // An exact remaining size settles the boundary without reading on.
            Some(remaining) => remaining > 0,
            // Chunked and HTTP/2 bodies report no exact size, so a body that
            // ends exactly at the limit needs a one-frame look-ahead to avoid
            // being mislabeled as truncated.
            None => settle_body_end(&mut body, Some(deadline), &mut pending).await,
        };
    }
    let payload = RequestPayload {
        prefix: Bytes::from(prefix),
        pending,
        rest: if hit_limit {
            Some(body.map_err(|err| Box::new(err) as BoxError).boxed())
        } else {
            None
        },
        truncated,
    };
    Ok((payload, inspection))
}

fn graphql_error(violation: crate::graphql::Violation) -> HttpError {
    match violation {
        crate::graphql::Violation::Incomplete => HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "graphql request body too large to inspect",
        ),
        crate::graphql::Violation::TooDeep { .. }
        | crate::graphql::Violation::TooManyFields { .. }
        | crate::graphql::Violation::TooComplex => {
            HttpError::new(StatusCode::BAD_REQUEST, "graphql query too complex")
        }
        crate::graphql::Violation::Uninspectable
        | crate::graphql::Violation::Cyclic
        | crate::graphql::Violation::Ambiguous => {
            HttpError::new(StatusCode::BAD_REQUEST, "graphql request rejected")
        }
    }
}

pub(crate) fn rejected(peer: SocketAddr, err: &HttpError) -> Response<ProxyBody> {
    // Rate limits and load shedding are expected under attack; logging every
    // one at warning level turns a flood into a disk-I/O amplifier. Metrics
    // still count them.
    if matches!(
        err.status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        debug!(
            client = %peer.ip(),
            status = err.status.as_u16(),
            reason = err.message,
            "request rejected"
        );
    } else {
        warn!(
            client = %peer.ip(),
            status = err.status.as_u16(),
            reason = err.message,
            "request rejected"
        );
    }
    forward::error_response_for(err)
}

pub(crate) async fn process_payload(
    parts: http::request::Parts,
    payload: RequestPayload,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
    inspection: InspectionGuard,
) -> Response<ProxyBody> {
    match process(parts, payload, peer, config, context, None, inspection).await {
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

/// Standard method names are upper case on the wire. A token that differs only
/// in case (`get`, `pOsT`) is a valid extension method to HTTP parsers, so
/// servers and frameworks that compare methods case-sensitively can be
/// bypassed by it (CVE-2026-111235, OpenNMS REST filters). Such tokens have no
/// practical legitimate use, so they are rejected before rule evaluation.
/// Custom methods that are not case variants of a standard one still pass.
fn non_canonical_method(method: &http::Method) -> bool {
    const STANDARD_METHODS: &[&str] = &[
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "CONNECT",
        "OPTIONS",
        "TRACE",
        "PATCH",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "REPORT",
        "SEARCH",
        "MKCALENDAR",
        "ACL",
        "PURGE",
        "M-SEARCH",
        "NOTIFY",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
    ];

    let name = method.as_str();
    let upper = name.to_ascii_uppercase();
    name != upper && STANDARD_METHODS.contains(&upper.as_str())
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

fn record_behavior(
    context: &Context,
    peer: SocketAddr,
    parts: &http::request::Parts,
    status: StatusCode,
    config: &CompiledConfig,
) {
    let outcome = context.protection.observe_response(
        peer.ip(),
        parts.uri.path(),
        status,
        &config.protection,
    );

    if outcome.observed_not_found {
        context
            .metrics
            .behavior_not_found
            .fetch_add(1, Ordering::Relaxed);
    }
    if outcome.observed_auth_failure {
        context
            .metrics
            .behavior_auth_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    if let Some(flag) = outcome.source {
        let blocked = flag.ban.is_some();
        let ban_seconds = flag.ban.map(|duration| duration.as_secs()).unwrap_or(0);
        match flag.signal {
            BehaviorSignal::Enumeration => {
                context
                    .metrics
                    .behavior_enumeration_flags
                    .fetch_add(1, Ordering::Relaxed);
                let ratio = if flag.requests == 0 {
                    0.0
                } else {
                    f64::from(flag.not_found) / f64::from(flag.requests)
                };
                warn!(
                    client = %peer.ip(),
                    signal = flag.signal.as_str(),
                    path = %parts.uri.path(),
                    requests = flag.requests,
                    not_found = flag.not_found,
                    ratio,
                    distinct_paths = flag.distinct_paths,
                    threshold = config.protection.behavior.enumeration.distinct_paths,
                    action = flag.action.as_str(),
                    blocked,
                    ban_seconds,
                    "behavior threshold reached"
                );
            }
            BehaviorSignal::AuthAbuse => {
                context
                    .metrics
                    .behavior_auth_flags
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    client = %peer.ip(),
                    signal = flag.signal.as_str(),
                    path = %parts.uri.path(),
                    auth_failures = flag.auth_failures,
                    threshold = config.protection.behavior.auth.min_failures,
                    action = flag.action.as_str(),
                    blocked,
                    ban_seconds,
                    "behavior threshold reached"
                );
            }
        }
        if blocked {
            context
                .metrics
                .behavior_blocked
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    if let Some(flag) = outcome.global {
        context
            .metrics
            .behavior_global_auth_flags
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            failures = flag.failures,
            window_secs = flag.window.as_secs(),
            threshold = config.protection.behavior.global_auth.min_failures,
            "behavioral global authentication abuse detected"
        );
    }
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
    mut inspection: InspectionGuard,
) -> Result<Response<ProxyBody>, HttpError> {
    // The request entry points enforce this before buffering the body. Repeat
    // it here so a direct `process_payload` caller cannot skip the policy.
    if let Some(err) = host_policy_error(context, config, &mut parts, peer) {
        return Err(err);
    }
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
            "request body truncated for inspection"
        );
    }

    if non_canonical_method(&parts.method) {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "non-canonical HTTP method",
        ));
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

    let graphql_path = config.limits.graphql.enabled && {
        let forms = crate::decoding::percent_decode_forms(parts.uri.path());
        forms
            .iter()
            .any(|form| config.limits.graphql.matches_path(form))
            || forms
                .last()
                .and_then(|form| crate::decoding::normalize_path(form))
                .is_some_and(|normalized| config.limits.graphql.matches_path(&normalized))
    };
    let body_rules = config.has_body_target_rules();
    let inspect_body = body_rules || graphql_path;
    let inspect_uploads = config.limits.upload_inspection != UploadInspection::Off
        && crate::upload::is_multipart(&parts.headers)
        && !body.is_empty();
    let encoded = parts.headers.contains_key(CONTENT_ENCODING);
    let decode_body = inspect_body || (inspect_uploads && encoded);
    if (decode_body || inspect_uploads) && !body.is_empty() {
        // The read path reserved only the raw prefix. Reserve the decoded-form
        // worst case (or the bounded multipart-parse worst case) now,
        // immediately before decoding and rule evaluation: a stalled body must
        // not be able to hold this share of the budget.
        let raw_bytes = if encoded {
            config.limits.max_body_bytes
        } else {
            body.len()
        };
        if !grow_inspection_to(&mut inspection, request_inspection_bytes(config, raw_bytes)) {
            context.record_overloaded();
            return Err(inspection_capacity_error());
        }
    }
    let body_truncated;
    let inspected_body: Cow<'_, [u8]> = match if decode_body {
        crate::decoding::decode_body_for_inspection(
            body,
            &parts.headers,
            config.limits.max_body_bytes,
        )
    } else {
        crate::decoding::DecodeOutcome::NotEncoded
    } {
        crate::decoding::DecodeOutcome::NotEncoded => {
            body_truncated = payload.truncated;
            Cow::Borrowed(body)
        }
        crate::decoding::DecodeOutcome::Decoded {
            body: decoded,
            complete,
        } => {
            let strict = config.limits.body_inspection == BodyInspection::Strict;
            if !complete || (payload.truncated && !strict) {
                context
                    .metrics
                    .request_decode_truncated
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    client = %peer.ip(),
                    limit = config.limits.max_body_bytes,
                    path = %parts.uri.path(),
                    decoded_complete = complete,
                    raw_truncated = payload.truncated,
                    "request body could not be fully decoded for inspection; rejecting"
                );
                return Err(HttpError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large to inspect",
                ));
            }
            body_truncated = payload.truncated;
            Cow::Owned(decoded)
        }
        crate::decoding::DecodeOutcome::Unsupported => {
            context
                .metrics
                .request_decode_skipped
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                client = %peer.ip(),
                path = %parts.uri.path(),
                "request body encoding cannot be inspected; rejecting"
            );
            return Err(HttpError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported request body encoding",
            ));
        }
        crate::decoding::DecodeOutcome::Malformed => {
            context
                .metrics
                .request_decode_skipped
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                client = %peer.ip(),
                path = %parts.uri.path(),
                "request body encoding is malformed; rejecting"
            );
            return Err(HttpError::new(
                StatusCode::BAD_REQUEST,
                "malformed request body encoding",
            ));
        }
    };
    if decode_body {
        let decision = context.protection.charge_inspection(
            peer.ip(),
            &config.protection,
            inspected_body.len(),
        );
        if let Some(err) = protection_error(context, decision) {
            return Err(err);
        }
    }
    if inspect_uploads
        && let Some(rejection) = crate::upload::inspect(
            &parts.headers,
            inspected_body.as_ref(),
            config.limits.upload_inspection,
        )
    {
        context
            .metrics
            .upload_rejected
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            client = %peer.ip(),
            path = %parts.uri.path(),
            filename = %rejection.filename,
            declared = rejection.declared.as_deref().unwrap_or("-"),
            kind = rejection.kind.as_str(),
            "upload content rejected"
        );
        return Err(HttpError::new(
            StatusCode::FORBIDDEN,
            "upload content does not match its declared type",
        ));
    }
    if graphql_path
        && let Some(violation) = crate::graphql::inspect(
            parts.uri.query(),
            &parts.headers,
            inspected_body.as_ref(),
            body_truncated,
            crate::graphql::Limits {
                max_depth: config.limits.graphql.max_depth,
                max_fields: config.limits.graphql.max_fields,
            },
        )
    {
        context
            .metrics
            .graphql_rejected
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            client = %peer.ip(),
            path = %parts.uri.path(),
            ?violation,
            "graphql request rejected"
        );
        return Err(graphql_error(violation));
    }
    let view = RequestView::with_body_decoding(
        &parts.method,
        &parts.uri,
        &parts.headers,
        inspected_body.as_ref(),
        peer.ip(),
        body_rules,
    )
    .with_body_truncated(body_truncated);
    let outcome = eval::evaluate(config, &view, Some(context.protection.as_ref()));
    // The rule scan is done; release the budget before waiting on the upstream.
    // The body prefix it covered is still needed for response-phase rules, but
    // it is a single bounded buffer.
    drop(inspection);

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

    // A matching ALLOW rule explicitly trusts the request, including a body
    // that was too large for complete inspection. Without one, an oversized
    // body is rejected rather than forwarded with an uninspected remainder.
    if config.limits.body_inspection == BodyInspection::Strict
        && (inspect_body || inspect_uploads)
        && body_truncated
        && outcome.allowed.is_none()
    {
        context
            .metrics
            .request_body_rejected
            .fetch_add(1, Ordering::Relaxed);
        debug!(
            client = %peer.ip(),
            limit = config.limits.max_body_bytes,
            path = %parts.uri.path(),
            "request body exceeds the inspection limit; rejecting"
        );
        return Err(HttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the inspection limit",
        ));
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
                record_behavior(context, peer, &parts, response.status(), config);
                if !config.has_response_rules() {
                    return Ok(response);
                }
                let Some(response_inspection) = context.reserve_response_inspection(config) else {
                    context.record_overloaded();
                    return Err(inspection_capacity_error());
                };
                crate::proxy::response::inspect(
                    config,
                    &context.metrics,
                    &parts,
                    crate::proxy::response::InspectedRequest {
                        body: inspected_body.as_ref(),
                        truncated: body_truncated,
                    },
                    peer,
                    response,
                    response_inspection,
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
    record_behavior(context, peer, &parts, response.status(), config);

    if !config.has_response_rules() {
        return Ok(response);
    }

    let Some(response_inspection) = context.reserve_response_inspection(config) else {
        context.record_overloaded();
        return Err(inspection_capacity_error());
    };
    crate::proxy::response::inspect(
        config,
        &context.metrics,
        &parts,
        crate::proxy::response::InspectedRequest {
            body: inspected_body.as_ref(),
            truncated: body_truncated,
        },
        peer,
        response,
        response_inspection,
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

    #[test]
    fn inspection_budget_reserves_and_releases_capacity() {
        let budget = Arc::new(InspectionBudget::new());
        let half = INSPECTION_BUDGET_BYTES / 2;
        let first = budget.reserve(half).expect("first half fits");
        let second = budget.reserve(half).expect("second half fits");
        assert!(budget.reserve(1).is_none(), "budget must be exhausted");

        drop(first);
        let extra = budget.reserve(1).expect("space freed");
        assert_eq!(budget.reserved.load(Ordering::Relaxed), half + 1);
        drop(extra);
        drop(second);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inspection_guard_grows_and_releases_its_reservation() {
        let budget = Arc::new(InspectionBudget::new());
        let mut guard = budget.reserve(64 * 1024).expect("baseline fits");
        let half = INSPECTION_BUDGET_BYTES / 2;
        assert!(guard.grow(half - 64 * 1024));
        assert_eq!(budget.reserved.load(Ordering::Relaxed), half);
        assert!(
            !guard.grow(INSPECTION_BUDGET_BYTES),
            "growth must not exceed the budget"
        );
        assert_eq!(budget.reserved.load(Ordering::Relaxed), half);
        drop(guard);
        assert_eq!(budget.reserved.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watchdog_closes_a_connection_without_a_request() {
        let activity = Arc::new(ConnectionActivity::new());
        let watchdog = tokio::spawn(connection_is_idle(
            Arc::clone(&activity),
            Duration::from_secs(10),
            Duration::from_secs(20),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!watchdog.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        watchdog.await.expect("watchdog task");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watchdog_waits_for_an_active_request() {
        let activity = Arc::new(ConnectionActivity::new());
        let active = activity.start();
        let watchdog = tokio::spawn(connection_is_idle(
            Arc::clone(&activity),
            Duration::from_secs(10),
            Duration::from_secs(20),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(
            !watchdog.is_finished(),
            "active requests must not be closed"
        );
        drop(active);
        tokio::time::advance(Duration::from_secs(20)).await;
        watchdog.await.expect("watchdog task");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watchdog_uses_the_idle_timeout_after_a_request() {
        let activity = Arc::new(ConnectionActivity::new());
        drop(activity.start());
        let watchdog = tokio::spawn(connection_is_idle(
            Arc::clone(&activity),
            Duration::from_secs(10),
            Duration::from_secs(20),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(19)).await;
        assert!(!watchdog.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        watchdog.await.expect("watchdog task");
    }
}
