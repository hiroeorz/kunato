use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderValue, UPGRADE};
use http::{Request, Response, StatusCode, Uri};
use hyper::client::conn::http1;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::debug;

use crate::config::CompiledConfig;
use crate::protection::ConnectionGuard;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::{ProxyBody, full_body};

pub(crate) struct Upgrade {
    pub on_upgrade: OnUpgrade,
    pub shutdown: watch::Receiver<bool>,
    pub guard_slot: Arc<Mutex<Option<ConnectionGuard>>>,
}

pub(crate) enum Handshake {
    /// The upstream accepted the upgrade; the response is the opaque `101`.
    Upgraded(Response<ProxyBody>),
    /// The upstream answered with a regular response that still needs the
    /// response phase.
    Response(Response<ProxyBody>),
}

pub(crate) async fn forward_handshake(
    config: &CompiledConfig,
    parts: &http::request::Parts,
    body: ProxyBody,
    scheme: &'static str,
    peer: SocketAddr,
    upgrade: Upgrade,
) -> Result<Handshake, HttpError> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let base = config.upstream.request_uri("/").map_err(|err| {
        debug!(error = %err, "failed to build upstream URI");
        HttpError::new(StatusCode::BAD_GATEWAY, "invalid upstream URI")
    })?;
    let host = base
        .host()
        .ok_or_else(|| HttpError::new(StatusCode::BAD_GATEWAY, "invalid upstream host"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    let port = base.port_u16().unwrap_or(80);

    let stream = match tokio::time::timeout(
        config.timeouts.upstream_connect,
        TcpStream::connect((host, port)),
    )
    .await
    {
        Err(_) => {
            return Err(HttpError::new(
                StatusCode::BAD_GATEWAY,
                "upstream connect timed out",
            ));
        }
        Ok(Err(err)) => {
            debug!(error = %err, "upstream connect failed");
            return Err(HttpError::new(
                StatusCode::BAD_GATEWAY,
                "upstream connect failed",
            ));
        }
        Ok(Ok(stream)) => stream,
    };

    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| {
            debug!(error = %err, "upstream handshake failed");
            HttpError::new(StatusCode::BAD_GATEWAY, "upstream handshake failed")
        })?;
    tokio::spawn(async move {
        if let Err(err) = connection.with_upgrades().await {
            debug!(error = %err, "upstream connection closed");
        }
    });

    let uri: Uri = path_and_query.parse().map_err(|err| {
        debug!(error = %err, "invalid request target");
        HttpError::new(StatusCode::BAD_GATEWAY, "invalid upstream URI")
    })?;
    let mut request = Request::new(body);
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = uri;
    copy_handshake_headers(&parts.headers, request.headers_mut());
    forward::coalesce_cookie_headers(request.headers_mut())?;
    forward::set_forwarded_headers(
        request.headers_mut(),
        &parts.headers,
        &parts.uri,
        peer,
        scheme,
    );

    let mut response = match tokio::time::timeout(
        config.timeouts.upstream_response,
        sender.send_request(request),
    )
    .await
    {
        Err(_) => {
            return Err(HttpError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream timed out",
            ));
        }
        Ok(Err(err)) => {
            debug!(error = %err, "upstream request failed");
            return Err(HttpError::new(
                StatusCode::BAD_GATEWAY,
                "upstream request failed",
            ));
        }
        Ok(Ok(response)) => response,
    };

    if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || (config.php.matches(parts) && config.php.rejects_response(response.headers()))
    {
        return Ok(Handshake::Response(forward::convert_response(response)));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut response);
    let mut handshake = Response::new(full_body(Bytes::new()));
    *handshake.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    copy_handshake_headers(response.headers(), handshake.headers_mut());

    let guard = upgrade
        .guard_slot
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    tokio::spawn(tunnel(
        upgrade.on_upgrade,
        upstream_upgrade,
        config.timeouts.websocket_idle,
        upgrade.shutdown,
        guard,
        peer,
    ));
    Ok(Handshake::Upgraded(handshake))
}

fn copy_handshake_headers(source: &HeaderMap, target: &mut HeaderMap) {
    forward::copy_forward_headers(source, target);
    target.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    target.insert(UPGRADE, HeaderValue::from_static("websocket"));
}

async fn tunnel(
    downstream: OnUpgrade,
    upstream: OnUpgrade,
    idle: Duration,
    mut shutdown: watch::Receiver<bool>,
    guard: Option<ConnectionGuard>,
    peer: SocketAddr,
) {
    let _guard = guard;

    let downstream = match downstream.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            debug!(client = %peer, error = %err, "client upgrade failed");
            return;
        }
    };
    let upstream = match upstream.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            debug!(client = %peer, error = %err, "upstream upgrade failed");
            return;
        }
    };

    debug!(client = %peer, "WebSocket tunnel established");
    let activity = Arc::new(Mutex::new(Instant::now()));
    let mut downstream = ActivityIo::new(TokioIo::new(downstream), Arc::clone(&activity));
    let mut upstream = ActivityIo::new(TokioIo::new(upstream), Arc::clone(&activity));

    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {}
        _ = idle_watchdog(activity, idle) => {
            debug!(client = %peer, "WebSocket tunnel idle timeout");
        }
        _ = shutdown.changed() => {
            debug!(client = %peer, "WebSocket tunnel closed for shutdown");
        }
    }
}

async fn idle_watchdog(last: Arc<Mutex<Instant>>, idle: Duration) {
    loop {
        let idle_for = match last.lock() {
            Ok(last) => last.elapsed(),
            Err(_) => idle,
        };
        let remaining = idle.saturating_sub(idle_for);
        if remaining.is_zero() {
            return;
        }
        tokio::time::sleep(remaining).await;
    }
}

struct ActivityIo<T> {
    inner: T,
    last: Arc<Mutex<Instant>>,
}

impl<T> ActivityIo<T> {
    fn new(inner: T, last: Arc<Mutex<Instant>>) -> Self {
        Self { inner, last }
    }

    fn touch(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ActivityIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.touch();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ActivityIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(_))) {
            this.touch();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
