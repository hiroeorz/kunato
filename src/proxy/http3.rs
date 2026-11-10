use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use h3::server::{RequestResolver, RequestStream};
use http::header::HeaderValue;
use http::{Method, Response, StatusCode};
use hyper::body::{Body, Frame};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::acme::AcmeService;
use crate::client_ip::ClientSource;
use crate::config::CompiledConfig;
use crate::error::Error;
use crate::protection::ConnectionGuard;
use crate::proxy::BodyExt;
use crate::proxy::forward::HttpError;
use crate::proxy::server::{self, Context, InspectionGuard, RequestPayload};
use crate::proxy::tls;
use crate::proxy::{ProxyBody, settle_body_end};

pub struct Listener {
    pub endpoint: quinn::Endpoint,
    pub alt_svc: Option<HeaderValue>,
    pub local_addr: SocketAddr,
}

pub fn bind(
    config: &CompiledConfig,
    fallback: SocketAddr,
    acme: Option<&AcmeService>,
) -> Result<Option<Listener>, Error> {
    if !config.http3.enabled {
        return Ok(None);
    }

    let listen = config.http3.listen.unwrap_or(fallback);
    let server_config = match acme {
        Some(service) => service.quic_config(),
        None => {
            let Some(tls) = &config.tls else {
                return Err(Error::Tls("http3 requires a tls block".to_owned()));
            };
            let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) else {
                return Err(Error::Tls(
                    "tls.cert_file and tls.key_file are required unless tls.acme is enabled"
                        .to_owned(),
                ));
            };
            tls::load_quic_server_config(cert_file, key_file)?
        }
    };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .map_err(|err| Error::Tls(format!("failed to initialize QUIC: {err}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from(config.limits.max_concurrent_streams));
    if let Ok(idle) = quinn::IdleTimeout::try_from(config.timeouts.connection_idle) {
        transport.max_idle_timeout(Some(idle));
    }
    server_config.transport_config(Arc::new(transport));
    let endpoint =
        quinn::Endpoint::server(server_config, listen).map_err(|source| Error::Bind {
            addr: listen.to_string(),
            source,
        })?;
    let local_addr = endpoint.local_addr().unwrap_or(listen);
    let alt_svc = HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", local_addr.port())).ok();

    Ok(Some(Listener {
        endpoint,
        alt_svc,
        local_addr,
    }))
}

pub async fn serve(
    endpoint: quinn::Endpoint,
    context: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            incoming = endpoint.accept() => {
                match incoming {
                    Some(incoming) => {
                        // A spoofed Initial must not take a shared TCP/UDP
                        // connection slot: require address validation first and
                        // make the client prove reachability with a Retry.
                        if !incoming.remote_address_validated() {
                            if let Err(err) = incoming.retry() {
                                debug!(error = %err, "HTTP/3 address validation failed");
                            }
                            continue;
                        }
                        let peer = server::normalize_peer(incoming.remote_address());
                        match context.try_acquire_connection(peer.ip()) {
                            Some(guard) => {
                                let context = context.clone();
                                let connection_shutdown = shutdown.clone();
                                connections.spawn(serve_connection(
                                    incoming,
                                    peer,
                                    context,
                                    connection_shutdown,
                                    guard,
                                ));
                            }
                            None => {
                                warn!(client = %peer.ip(), "HTTP/3 connection limit exceeded");
                                incoming.refuse();
                            }
                        }
                    }
                    None => break,
                }
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = result {
                    debug!(error = %err, "HTTP/3 connection task failed");
                }
            }
        }
    }

    let grace = context.config().timeouts.shutdown_grace;
    info!(?grace, "HTTP/3 listener stopped, draining connections");
    server::drain_connections(&mut connections, grace).await;
    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    endpoint.wait_idle().await;
}

async fn serve_connection(
    incoming: quinn::Incoming,
    peer: SocketAddr,
    context: Context,
    shutdown: watch::Receiver<bool>,
    _guard: ConnectionGuard,
) {
    let handshake_timeout = context.config().timeouts.header_read;
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(err) => {
            debug!(client = %peer, error = %err, "HTTP/3 handshake rejected");
            return;
        }
    };
    let connection = match tokio::time::timeout(handshake_timeout, connecting).await {
        Err(_) => {
            debug!(client = %peer, "HTTP/3 handshake timed out");
            return;
        }
        Ok(Err(err)) => {
            debug!(client = %peer, error = %err, "HTTP/3 handshake failed");
            return;
        }
        Ok(Ok(connection)) => connection,
    };
    serve_h3(connection, peer, context, shutdown).await;
}

async fn serve_h3(
    connection: quinn::Connection,
    peer: SocketAddr,
    context: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    let handshake_timeout = context.config().timeouts.header_read;
    let max_field_section_size =
        u64::try_from(context.config().limits.max_header_bytes).unwrap_or(u64::MAX);
    let mut builder = h3::server::builder();
    builder.max_field_section_size(max_field_section_size);
    let mut connection = match tokio::time::timeout(
        handshake_timeout,
        builder.build(h3_quinn::Connection::new(connection)),
    )
    .await
    {
        Err(_) => {
            debug!(client = %peer, "HTTP/3 setup timed out");
            return;
        }
        Ok(Err(err)) => {
            debug!(client = %peer, error = %err, "HTTP/3 setup failed");
            return;
        }
        Ok(Ok(connection)) => connection,
    };

    let activity = Arc::new(server::ConnectionActivity::new());
    let limits = context.config();
    let header_read = limits.timeouts.header_read;
    let idle = limits.timeouts.connection_idle;
    let mut requests = JoinSet::new();
    let mut closing = false;
    loop {
        tokio::select! {
            changed = shutdown.changed(), if !closing => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    let _ = connection.shutdown(0).await;
                    closing = true;
                }
            }
            _ = server::connection_is_idle(
                Arc::clone(&activity),
                header_read,
                idle,
            ) => {
                debug!(client = %peer, "closing idle HTTP/3 connection");
                let _ = connection.shutdown(0).await;
                break;
            }
            accepted = connection.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let context = context.clone();
                        let active = activity.start();
                        requests.spawn(handle_request(resolver, peer, context, active));
                    }
                    Ok(None) => break,
                    Err(err) => {
                        debug!(client = %peer, error = %err, "HTTP/3 connection failed");
                        break;
                    }
                }
            }
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
        }
    }

    while requests.join_next().await.is_some() {}
}

async fn handle_request(
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
    peer: SocketAddr,
    context: Context,
    active: server::ActiveRequest,
) {
    let header_read = context.config().timeouts.header_read;
    let (request, stream) =
        match tokio::time::timeout(header_read, resolver.resolve_request()).await {
            Err(_) => {
                debug!(client = %peer, "HTTP/3 request head timed out");
                return;
            }
            Ok(Err(err)) => {
                debug!(client = %peer, error = %err, "malformed HTTP/3 request");
                return;
            }
            Ok(Ok(value)) => value,
        };

    let config = context.config();
    let head_request = request.method() == Method::HEAD;
    let (mut parts, _) = request.into_parts();
    let (mut send, mut recv) = stream.split();
    let resolved = server::resolve_source(&context, peer, &config, &parts);
    let source = resolved
        .as_ref()
        .copied()
        .unwrap_or_else(|_| ClientSource::direct(peer));
    let mut response = if let Err(err) = resolved {
        server::rejected(source, &err)
    } else if let Some(err) = server::admission_error(&context, source, &parts, &config) {
        server::rejected(source, &err)
    } else if let Some(err) = server::host_policy_error(&context, &config, &mut parts, source) {
        server::rejected(source, &err)
    } else if let Some(err) = server::request_head_error(&config, &parts) {
        server::rejected(source, &err)
    } else if let Some(response) = server::maintenance_response(&context, &parts) {
        response
    } else if let Some(response) = server::admin_access_response(&context, &config, source, &parts)
    {
        response
    } else if let Some(response) = server::decoy_head(&context, &config, source, &mut parts) {
        recv.stop_sending(Code::H3_NO_ERROR);
        response
    } else if let Some(inspection) = server::request_inspection(&context, source, &parts) {
        match read_prefix(recv, &config, source, inspection, &context).await {
            Ok((payload, inspection)) => {
                server::process_payload(parts, payload, source, &config, &context, inspection).await
            }
            Err(err) => server::rejected(source, &err),
        }
    } else {
        context.record_overloaded();
        server::rejected(source, &server::inspection_capacity_error())
    };
    config.response_headers.apply(response.headers_mut());
    crate::decoy::finalize(&mut response);
    let active = active.into_streaming();
    if let Err(err) = send_response(
        &mut send,
        response,
        head_request,
        config.timeouts.connection_idle,
        &active,
    )
    .await
    {
        debug!(client = %peer, error = %err, "failed to send HTTP/3 response");
    }
}

/// A streaming body over the receive half of an HTTP/3 request stream, used
/// when only a prefix of the request body was buffered for inspection.
struct RequestBody {
    recv: RequestStream<h3_quinn::RecvStream, Bytes>,
    done: bool,
}

impl RequestBody {
    fn new(recv: RequestStream<h3_quinn::RecvStream, Bytes>) -> Self {
        Self { recv, done: false }
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = crate::proxy::BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match this.recv.poll_recv_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(mut chunk))) => {
                let data = chunk.copy_to_bytes(chunk.remaining());
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Ok(None)) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(err)) => {
                this.done = true;
                Poll::Ready(Some(Err(Box::new(err))))
            }
        }
    }
}

/// Buffer a bounded prefix of the request body and keep the receive half for
/// the remainder, mirroring the TCP path's body policy: bodies larger than
/// `limits.max_body_bytes` are rejected by strict mode or streamed by `stream`
/// mode after the prefix is inspected.
async fn read_prefix(
    mut recv: RequestStream<h3_quinn::RecvStream, Bytes>,
    config: &CompiledConfig,
    source: crate::client_ip::ClientSource,
    mut inspection: InspectionGuard,
    context: &Context,
) -> Result<(RequestPayload, InspectionGuard), HttpError> {
    let limit = config.limits.max_body_bytes;
    let deadline = tokio::time::Instant::now() + config.timeouts.body_read;
    let mut prefix: Vec<u8> = Vec::new();
    let mut pending: Vec<Frame<Bytes>> = Vec::new();
    let mut hit_limit = false;

    loop {
        let mut chunk = match tokio::time::timeout_at(deadline, recv.recv_data()).await {
            Err(_) => {
                return Err(HttpError::new(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body read timed out",
                ));
            }
            Ok(Err(_)) => {
                return Err(HttpError::new(
                    StatusCode::BAD_REQUEST,
                    "malformed request body",
                ));
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => chunk,
        };

        let chunk = chunk.copy_to_bytes(chunk.remaining());
        if let Some(err) = server::charge_body_bytes(context, source, config, chunk.len()) {
            return Err(err);
        }
        let observed = prefix.len().saturating_add(chunk.len());
        if !server::grow_request_inspection_raw(&mut inspection, config, observed) {
            context.record_overloaded();
            return Err(server::inspection_capacity_error());
        }
        let room = limit.saturating_sub(prefix.len());
        if chunk.len() >= room {
            let take = room.min(chunk.len());
            prefix.extend_from_slice(&chunk[..take]);
            let remainder = chunk.slice(take..);
            if !remainder.is_empty() {
                pending.push(Frame::data(remainder));
            }
            hit_limit = true;
            break;
        }
        prefix.extend_from_slice(&chunk);
    }

    let mut rest = None;
    let mut truncated = hit_limit;
    if hit_limit {
        let mut tail = RequestBody::new(recv);
        if pending.is_empty() {
            // HTTP/3 reports no size hint, so settle the boundary at the
            // limit with a one-frame look-ahead, mirroring the TCP path.
            truncated = settle_body_end(&mut tail, Some(deadline), &mut pending).await;
        }
        rest = Some(tail.boxed());
    }
    let payload = RequestPayload {
        prefix: Bytes::from(prefix),
        pending,
        rest,
        truncated,
    };
    Ok((payload, inspection))
}

async fn send_response(
    stream: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    response: Response<ProxyBody>,
    head_request: bool,
    idle: std::time::Duration,
    active: &server::ActiveRequest,
) -> Result<(), StreamError> {
    let (parts, mut body) = response.into_parts();
    let mut head = Response::new(());
    *head.status_mut() = parts.status;
    *head.headers_mut() = parts.headers;
    let Ok(sent) = tokio::time::timeout(idle, stream.send_response(head)).await else {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        return Ok(());
    };
    sent?;
    active.record_progress();

    if head_request {
        if let Ok(finished) = tokio::time::timeout(idle, stream.finish()).await {
            finished?;
        }
        return Ok(());
    }

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                // Drop trailer fields: they are not inspected, so they must
                // not reach the client.
                if let Ok(data) = frame.into_data() {
                    let Ok(sent) = tokio::time::timeout(idle, stream.send_data(data)).await else {
                        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
                        return Ok(());
                    };
                    sent?;
                    active.record_progress();
                }
            }
            Err(_) => {
                stream.stop_stream(Code::H3_INTERNAL_ERROR);
                return Ok(());
            }
        }
    }

    if let Ok(finished) = tokio::time::timeout(idle, stream.finish()).await {
        finished?;
    }
    Ok(())
}
