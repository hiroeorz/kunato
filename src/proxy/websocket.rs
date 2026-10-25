use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONNECTION, HeaderMap, HeaderValue, UPGRADE};
use http::{Method, Request, Response, StatusCode, Uri};
use hyper::client::conn::http1;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, warn};

use crate::client_ip::ClientSource;
use crate::config::CompiledConfig;
use crate::protection::ConnectionGuard;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::{ProxyBody, full_body};
use crate::request_view::RequestView;
use crate::rules::eval::evaluate_websocket;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;
/// A fragmented message cannot spend unbounded memory on frame headers.
const MAX_FRAGMENTS: usize = 256;

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

struct OwnedRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
}

pub(crate) async fn forward_handshake(
    config: &CompiledConfig,
    snapshot: Arc<CompiledConfig>,
    parts: &http::request::Parts,
    body: ProxyBody,
    scheme: &'static str,
    source: ClientSource,
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
        source.client_ip,
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

    // Application payloads can only be inspected when frames are not
    // compressed. Requesting the extension is removed above; an upstream that
    // negotiates it anyway cannot be inspected, so reject the tunnel.
    if response.headers().contains_key("sec-websocket-extensions") {
        return Err(HttpError::new(
            StatusCode::BAD_GATEWAY,
            "WebSocket extensions are not supported",
        ));
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
    let owned = OwnedRequest {
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        headers: parts.headers.clone(),
    };
    let body_rules_exempt = snapshot.is_content_route(&parts.method, &parts.uri);
    tokio::spawn(tunnel(
        upgrade.on_upgrade,
        upstream_upgrade,
        snapshot.timeouts.websocket_idle,
        upgrade.shutdown,
        guard,
        source,
        snapshot,
        owned,
        body_rules_exempt,
    ));
    Ok(Handshake::Upgraded(handshake))
}

fn copy_handshake_headers(source: &HeaderMap, target: &mut HeaderMap) {
    forward::copy_forward_headers(source, target);
    target.remove("sec-websocket-extensions");
    target.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    target.insert(UPGRADE, HeaderValue::from_static("websocket"));
}

#[allow(clippy::too_many_arguments)]
async fn tunnel(
    downstream: OnUpgrade,
    upstream: OnUpgrade,
    idle: Duration,
    mut shutdown: watch::Receiver<bool>,
    guard: Option<ConnectionGuard>,
    source: ClientSource,
    config: Arc<CompiledConfig>,
    request: OwnedRequest,
    body_rules_exempt: bool,
) {
    let _guard = guard;

    let downstream = match downstream.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            debug!(client = %source.client_ip, peer = %source.peer, error = %err, "client upgrade failed");
            return;
        }
    };
    let upstream = match upstream.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            debug!(client = %source.client_ip, peer = %source.peer, error = %err, "upstream upgrade failed");
            return;
        }
    };

    debug!(client = %source.client_ip, peer = %source.peer, "WebSocket tunnel established");
    let activity = Arc::new(Mutex::new(Instant::now()));
    let downstream = ActivityIo::new(TokioIo::new(downstream), Arc::clone(&activity));
    let upstream = ActivityIo::new(TokioIo::new(upstream), Arc::clone(&activity));
    let (down_read, down_write) = tokio::io::split(downstream);
    let (up_read, up_write) = tokio::io::split(upstream);
    let (close_tx, close_rx) = mpsc::channel(1);
    let message_limit = config.limits.websocket_message_bytes;
    let to_client = pump_upstream_to_client(up_read, down_write, close_rx, message_limit);
    let to_upstream = pump_client_to_upstream(
        down_read,
        up_write,
        close_tx,
        config,
        request,
        source.client_ip,
        body_rules_exempt,
        message_limit,
    );

    tokio::select! {
        _ = to_client => {}
        _ = to_upstream => {}
        _ = idle_watchdog(activity, idle) => {
            debug!(client = %source.client_ip, peer = %source.peer, "WebSocket tunnel idle timeout");
        }
        _ = shutdown.changed() => {
            debug!(client = %source.client_ip, peer = %source.peer, "WebSocket tunnel closed for shutdown");
        }
    }
}

struct CloseCommand {
    code: u16,
    reason: String,
    ack: oneshot::Sender<()>,
}

async fn pump_upstream_to_client<R, W>(
    mut reader: R,
    mut writer: W,
    mut close: mpsc::Receiver<CloseCommand>,
    message_limit: usize,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            frame = read_frame(&mut reader, message_limit, false) => {
                match frame {
                    Ok(frame) => {
                        if writer.write_all(&frame.raw).await.is_err() {
                            return;
                        }
                        if frame.opcode == OP_CLOSE {
                            return;
                        }
                    }
                    Err(WsError::TooLarge) => {
                        let _ = writer.write_all(&close_frame(1009, "message too large")).await;
                        let _ = writer.flush().await;
                        return;
                    }
                    Err(_) => return,
                }
            }
            command = close.recv() => {
                if let Some(command) = command {
                    let _ = writer.write_all(&close_frame(command.code, &command.reason)).await;
                    let _ = writer.flush().await;
                    let _ = command.ack.send(());
                }
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_client_to_upstream<R, W>(
    mut reader: R,
    mut writer: W,
    close: mpsc::Sender<CloseCommand>,
    config: Arc<CompiledConfig>,
    request: OwnedRequest,
    source_ip: IpAddr,
    body_rules_exempt: bool,
    message_limit: usize,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut message = Message::default();
    loop {
        let frame = match read_frame(&mut reader, message_limit, true).await {
            Ok(frame) => frame,
            Err(WsError::TooLarge) => {
                send_close(&close, 1009, "message too large").await;
                return;
            }
            Err(WsError::Protocol(reason)) => {
                send_close(&close, 1002, reason).await;
                return;
            }
            Err(WsError::Io) => return,
        };
        match frame.opcode {
            OP_CLOSE | OP_PING | OP_PONG => {
                if writer.write_all(&frame.raw).await.is_err() {
                    return;
                }
                if frame.opcode == OP_CLOSE {
                    return;
                }
                continue;
            }
            _ => {}
        }
        let fin = frame.fin;
        match message.push(frame, message_limit) {
            Ok(()) => {}
            Err(PushError::TooLarge) => {
                send_close(&close, 1009, "message too large").await;
                return;
            }
            Err(PushError::Protocol(reason)) => {
                send_close(&close, 1002, reason).await;
                return;
            }
        }
        if !fin {
            continue;
        }
        let (opcode, payload, raw) = message.finish();
        if opcode == OP_TEXT && std::str::from_utf8(&payload).is_err() {
            send_close(&close, 1007, "invalid UTF-8").await;
            return;
        }
        let view = RequestView::with_body_decoding(
            &request.method,
            &request.uri,
            &request.headers,
            &payload,
            source_ip,
            false,
        )
        .with_body_rules_exempt(body_rules_exempt);
        let outcome = evaluate_websocket(&config, &view);
        if let Some(blocked) = outcome.blocked {
            warn!(
                client = %source_ip,
                category = %blocked.category,
                rule = %blocked.rule,
                "WebSocket application payload blocked"
            );
            let reason = format!("{}/{}", blocked.category, blocked.rule);
            send_close(&close, 1008, &reason).await;
            return;
        }
        for record in outcome.logs {
            warn!(
                client = %source_ip,
                category = %record.category,
                rule = %record.rule,
                "WebSocket application payload logged"
            );
        }
        for part in raw {
            if writer.write_all(&part).await.is_err() {
                return;
            }
        }
        if writer.flush().await.is_err() {
            return;
        }
    }
}

async fn send_close(close: &mpsc::Sender<CloseCommand>, code: u16, reason: &str) {
    let (ack, wait) = oneshot::channel();
    let command = CloseCommand {
        code,
        reason: reason.to_owned(),
        ack,
    };
    if close.send(command).await.is_ok() {
        let _ = wait.await;
    }
}

fn close_frame(code: u16, reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(123);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let reason = &reason.as_bytes()[..end];
    let payload_len = 2 + reason.len();
    let mut frame = Vec::with_capacity(2 + payload_len);
    frame.push(0x80 | OP_CLOSE);
    frame.push(payload_len as u8);
    frame.extend_from_slice(&code.to_be_bytes());
    frame.extend_from_slice(reason);
    frame
}

#[derive(Default)]
struct Message {
    opcode: Option<u8>,
    payload: Vec<u8>,
    raw: Vec<Vec<u8>>,
}

enum PushError {
    Protocol(&'static str),
    TooLarge,
}

impl Message {
    fn push(&mut self, frame: Frame, limit: usize) -> Result<(), PushError> {
        match frame.opcode {
            OP_TEXT | OP_BINARY => {
                if self.opcode.is_some() {
                    return Err(PushError::Protocol("new message before fragment end"));
                }
                self.opcode = Some(frame.opcode);
            }
            OP_CONTINUATION => {
                if self.opcode.is_none() {
                    return Err(PushError::Protocol("unexpected continuation"));
                }
            }
            _ => return Err(PushError::Protocol("unexpected data opcode")),
        }
        if self.raw.len() >= MAX_FRAGMENTS {
            return Err(PushError::TooLarge);
        }
        if self.payload.len().saturating_add(frame.payload.len()) > limit {
            return Err(PushError::TooLarge);
        }
        self.payload.extend_from_slice(&frame.payload);
        self.raw.push(frame.raw);
        Ok(())
    }

    fn finish(&mut self) -> (u8, Vec<u8>, Vec<Vec<u8>>) {
        (
            self.opcode.take().unwrap_or(OP_TEXT),
            std::mem::take(&mut self.payload),
            std::mem::take(&mut self.raw),
        )
    }
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    raw: Vec<u8>,
}

enum WsError {
    Io,
    Protocol(&'static str),
    TooLarge,
}

async fn read_frame<R>(reader: &mut R, max: usize, require_mask: bool) -> Result<Frame, WsError>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    reader
        .read_exact(&mut head)
        .await
        .map_err(|_| WsError::Io)?;
    let fin = head[0] & 0x80 != 0;
    if head[0] & 0x70 != 0 {
        return Err(WsError::Protocol("reserved bits are set"));
    }
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    if masked != require_mask {
        return Err(WsError::Protocol("invalid masking"));
    }
    let mut raw = head.to_vec();
    let mut len = u64::from(head[1] & 0x7f);
    if head[1] & 0x7f == 126 {
        let mut extended = [0u8; 2];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|_| WsError::Io)?;
        len = u64::from(u16::from_be_bytes(extended));
        raw.extend_from_slice(&extended);
    } else if head[1] & 0x7f == 127 {
        let mut extended = [0u8; 8];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|_| WsError::Io)?;
        len = u64::from_be_bytes(extended);
        raw.extend_from_slice(&extended);
    }

    let control = opcode & 0x08 != 0;
    if !matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return Err(WsError::Protocol("invalid opcode"));
    }
    if control && (!fin || len > 125) {
        return Err(WsError::Protocol("invalid control frame"));
    }
    if len > max as u64 {
        return Err(WsError::TooLarge);
    }

    let mut mask = [0u8; 4];
    if masked {
        reader
            .read_exact(&mut mask)
            .await
            .map_err(|_| WsError::Io)?;
        raw.extend_from_slice(&mask);
    }
    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| WsError::Io)?;
    raw.extend_from_slice(&payload);
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Frame {
        fin,
        opcode,
        payload,
        raw,
    })
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
