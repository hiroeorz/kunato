use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::CompiledConfig;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::{ConnectionGuard, Decision, ProtectionState};
use crate::proxy::ProxyBody;
use crate::proxy::client::UpstreamClient;
use crate::proxy::forward::{self, HttpError};
use crate::request_view::RequestView;
use crate::rules::eval;

const RAW_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

#[derive(Clone)]
pub struct Context {
    config: Arc<ArcSwap<CompiledConfig>>,
    client: UpstreamClient,
    protection: Arc<ProtectionState>,
    metrics: Arc<Metrics>,
}

impl Context {
    pub fn config(&self) -> Arc<CompiledConfig> {
        self.config.load_full()
    }
}

pub struct Server {
    listener: TcpListener,
    context: Context,
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
        let client = UpstreamClient::new(config.load().timeouts.upstream_connect);
        Ok(Self {
            listener,
            context: Context {
                config,
                client,
                protection: Arc::new(ProtectionState::new()),
                metrics,
            },
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn protection(&self) -> Arc<ProtectionState> {
        Arc::clone(&self.context.protection)
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
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
                            let connection_shutdown = shutdown.clone();
                            let config = context.config();
                            match context.protection.try_acquire_connection(peer.ip(), &config.protection) {
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

        drop(self.listener);
        let grace = self.context.config().timeouts.shutdown_grace;
        info!(?grace, "listener stopped, draining connections");
        drain_connections(&mut connections, grace).await;
    }
}

async fn drain_connections(connections: &mut JoinSet<()>, grace: Duration) {
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
    mut shutdown: watch::Receiver<bool>,
    _guard: ConnectionGuard,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let context = context.clone();
        async move { handle_request(request, peer, context).await }
    });

    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);

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

async fn handle_request(
    request: Request<Incoming>,
    peer: SocketAddr,
    context: Context,
) -> Result<Response<ProxyBody>, Infallible> {
    let config = context.config();
    match process(request, peer, &config, &context).await {
        Ok(response) => Ok(response),
        Err(err) => {
            warn!(
                client = %peer.ip(),
                status = err.status.as_u16(),
                reason = err.message,
                "request rejected"
            );
            Ok(forward::error_response_for(&err))
        }
    }
}

async fn process(
    request: Request<Incoming>,
    peer: SocketAddr,
    config: &CompiledConfig,
    context: &Context,
) -> Result<Response<ProxyBody>, HttpError> {
    context.metrics.requests.fetch_add(1, Ordering::Relaxed);

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

    let (parts, body) = request.into_parts();

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

    let body = match tokio::time::timeout(
        config.timeouts.body_read,
        Limited::new(body, config.limits.max_body_bytes).collect(),
    )
    .await
    {
        Err(_) => {
            return Err(HttpError::new(
                StatusCode::REQUEST_TIMEOUT,
                "request body read timed out",
            ));
        }
        Ok(Err(_)) => {
            return Err(HttpError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        Ok(Ok(collected)) => collected.to_bytes(),
    };

    let view = RequestView::new(&parts.method, &parts.uri, &parts.headers, &body, peer.ip());
    let outcome = eval::evaluate(config, &view);

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
        info!(
            category = %blocked.category,
            rule = %blocked.rule,
            action = "BLOCK",
            client = %peer.ip(),
            method = %parts.method,
            path = %parts.uri.path(),
            "request blocked"
        );
        return Ok(forward::block_response(&blocked.response));
    }

    drop(view);

    let result = forward::forward_request(&context.client, config, parts, body, peer).await;
    if let Err(err) = &result {
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
    result
}
