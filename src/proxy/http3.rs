use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use h3::error::{Code, StreamError};
use h3::server::{RequestResolver, RequestStream};
use h3_quinn::BidiStream;
use http::header::HeaderValue;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::CompiledConfig;
use crate::error::Error;
use crate::protection::ConnectionGuard;
use crate::proxy::ProxyBody;
use crate::proxy::forward::HttpError;
use crate::proxy::server::{self, Context};
use crate::proxy::tls;

pub struct Listener {
    pub endpoint: quinn::Endpoint,
    pub alt_svc: Option<HeaderValue>,
    pub local_addr: SocketAddr,
}

pub fn bind(config: &CompiledConfig, fallback: SocketAddr) -> Result<Option<Listener>, Error> {
    if !config.http3.enabled {
        return Ok(None);
    }
    let Some(tls) = &config.tls else {
        return Err(Error::Tls("http3 requires a tls block".to_owned()));
    };

    let listen = config.http3.listen.unwrap_or(fallback);
    let server_config = tls::load_quic_server_config(&tls.cert_file, &tls.key_file)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .map_err(|err| Error::Tls(format!("failed to initialize QUIC: {err}")))?;
    let endpoint =
        quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), listen)
            .map_err(|source| Error::Bind {
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
                        let peer = incoming.remote_address();
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
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(err) => {
            debug!(client = %peer, error = %err, "HTTP/3 handshake rejected");
            return;
        }
    };
    let connection = match connecting.await {
        Ok(connection) => connection,
        Err(err) => {
            debug!(client = %peer, error = %err, "HTTP/3 handshake failed");
            return;
        }
    };
    serve_h3(connection, peer, context, shutdown).await;
}

async fn serve_h3(
    connection: quinn::Connection,
    peer: SocketAddr,
    context: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    let max_field_section_size =
        u64::try_from(context.config().limits.max_header_bytes).unwrap_or(u64::MAX);
    let mut builder = h3::server::builder();
    builder.max_field_section_size(max_field_section_size);
    let mut connection = match builder.build(h3_quinn::Connection::new(connection)).await {
        Ok(connection) => connection,
        Err(err) => {
            debug!(client = %peer, error = %err, "HTTP/3 setup failed");
            return;
        }
    };

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
            accepted = connection.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let context = context.clone();
                        requests.spawn(handle_request(resolver, peer, context));
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
) {
    let (request, mut stream) = match resolver.resolve_request().await {
        Ok(value) => value,
        Err(err) => {
            debug!(client = %peer, error = %err, "malformed HTTP/3 request");
            return;
        }
    };

    let config = context.config();
    let (parts, _) = request.into_parts();
    let mut response = match read_body(&mut stream, &config).await {
        Ok(body) => server::process_request(parts, body, peer, &config, &context).await,
        Err(err) => server::rejected(peer, &err),
    };
    config.response_headers.apply(response.headers_mut());
    if let Err(err) = send_response(&mut stream, response).await {
        debug!(client = %peer, error = %err, "failed to send HTTP/3 response");
    }
}

async fn read_body(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    config: &CompiledConfig,
) -> Result<Bytes, HttpError> {
    let deadline = tokio::time::Instant::now() + config.timeouts.body_read;
    let mut body = BytesMut::new();

    loop {
        let mut chunk = match tokio::time::timeout_at(deadline, stream.recv_data()).await {
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

        if body.len() + chunk.remaining() > config.limits.max_body_bytes {
            return Err(HttpError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        let chunk = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

async fn send_response(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    response: Response<ProxyBody>,
) -> Result<(), StreamError> {
    let (parts, mut body) = response.into_parts();
    let mut head = Response::new(());
    *head.status_mut() = parts.status;
    *head.headers_mut() = parts.headers;
    stream.send_response(head).await?;

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    stream.send_data(data).await?;
                }
            }
            Err(_) => {
                stream.stop_stream(Code::H3_INTERNAL_ERROR);
                return Ok(());
            }
        }
    }

    stream.finish().await
}
