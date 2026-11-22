//! Read-only console HTTP and SSE delivery.

mod assets;
mod auth;
mod dto;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::{Console, ConsoleTls};
use crate::console::HistoryQuery;
use crate::console::collector::HistoryReader;
use crate::error::Error;
use crate::proxy::server::drain_connections;
use crate::proxy::{BodyExt, BoxError, ProxyBody, full_body};

use super::runtime::LiveState;
use auth::{Auth, Login, session_cookie_name};

const MAX_CONNECTIONS: usize = 128;
const MAX_LIVE_STREAMS: usize = 16;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_GRACE: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT: Duration = Duration::from_secs(15);
const MAX_LOGIN_BODY: usize = 4 * 1024;
const MAX_QUERY_BYTES: usize = 1024;
const MAX_HISTORY_LIMIT: usize = 128;
const MAX_CORRELATION_LIMIT: usize = 128;
const STREAM_CHANNEL: usize = 8;
/// A subscriber whose bounded channel stays full this long is disconnected.
const SLOW_STREAM_TIMEOUT: Duration = Duration::from_secs(120);
const CSP: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// A bound console listener.
pub struct ConsoleServer {
    listener: TcpListener,
    context: Arc<Context>,
}

struct Context {
    console: Console,
    live: watch::Receiver<Option<Arc<LiveState>>>,
    reader: HistoryReader,
    auth: Option<Arc<Auth>>,
    tls: Option<TlsState>,
    live_slots: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
}

#[derive(Clone)]
struct Connection {
    context: Arc<Context>,
    peer: SocketAddr,
    tls: bool,
}

/// The server-side session bound to one live stream. Bearer-token clients and
/// an authentication-disabled console have no session, so all fields are
/// `None` and the stream is bounded only by shutdown.
struct SessionGuard {
    auth: Option<Arc<Auth>>,
    session: Option<String>,
    expiry: Option<Instant>,
}

impl ConsoleServer {
    pub async fn bind(
        console: &Console,
        live: watch::Receiver<Option<Arc<LiveState>>>,
        reader: HistoryReader,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(console.listen)
            .await
            .map_err(|source| Error::Bind {
                addr: console.listen.to_string(),
                source,
            })?;
        let auth = match &console.auth {
            Some(auth) => Some(Arc::new(Auth::load(&auth.token_file)?)),
            None => None,
        };
        let tls = match &console.tls {
            Some(tls) => Some(TlsState::load(tls).await?),
            None => None,
        };
        Ok(Self {
            listener,
            context: Arc::new(Context {
                console: console.clone(),
                live,
                reader,
                auth,
                tls,
                live_slots: Arc::new(Semaphore::new(MAX_LIVE_STREAMS)),
                shutdown,
            }),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
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
                            if !peer_allowed(&self.context.console, peer.ip()) {
                                warn!(client = %peer, "console client denied by the source allowlist");
                                tokio::spawn(async move {
                                    let mut stream = stream;
                                    // Drain part of the request first: closing
                                    // with unread input would reset the
                                    // connection before the client sees 403.
                                    let mut buffer = [0u8; 1024];
                                    let _ = tokio::time::timeout(
                                        Duration::from_millis(250),
                                        stream.read(&mut buffer),
                                    )
                                    .await;
                                    let _ = stream
                                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        .await;
                                    let _ = stream.shutdown().await;
                                });
                                continue;
                            }
                            let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                                warn!(client = %peer, "console connection limit exceeded");
                                continue;
                            };
                            let connection = Connection {
                                context: self.context.clone(),
                                peer,
                                tls: self.context.tls.is_some(),
                            };
                            connections.spawn(serve_connection(stream, permit, connection));
                        }
                        Err(error) => warn!(error = %error, "failed to accept console connection"),
                    }
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        debug!(error = %error, "console connection task failed");
                    }
                }
            }
        }
        drop(self.listener);
        drain_connections(&mut connections, CONNECTION_GRACE).await;
        info!("console listener stopped");
    }
}

async fn serve_connection(
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    connection: Connection,
) {
    if let Some(tls) = &connection.context.tls {
        let config = tls.config().await;
        let acceptor = TlsAcceptor::from(config);
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => serve_http1(TokioIo::new(stream), connection).await,
            Ok(Err(error)) => {
                debug!(client = %connection.peer, error = %error, "console TLS handshake failed");
            }
            Err(_) => debug!(client = %connection.peer, "console TLS handshake timed out"),
        }
    } else {
        serve_http1(TokioIo::new(stream), connection).await;
    }
}

async fn serve_http1<I>(io: I, connection: Connection)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let connection = connection.clone();
        async move { handle(request, connection).await }
    });
    let result = http1::Builder::new()
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(io, service)
        .await;
    if let Err(error) = result {
        debug!(error = %error, "console connection closed with error");
    }
}

async fn handle(
    request: Request<Incoming>,
    connection: Connection,
) -> Result<Response<ProxyBody>, Infallible> {
    Ok(secure(route(request, connection).await))
}

async fn route(request: Request<Incoming>, connection: Connection) -> Response<ProxyBody> {
    if has_forwarding_markers(request.headers()) {
        return text(
            StatusCode::BAD_REQUEST,
            "proxy forwarding headers are not accepted\n",
        );
    }
    if let Err(status) = host_allowed(&connection.context.console, request.headers()) {
        return text(status, status.canonical_reason().unwrap_or("rejected"));
    }

    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if let Some(allow) = allowed_methods(&path)
        && !allow
            .split(", ")
            .any(|candidate| candidate == method.as_str())
    {
        let mut response = text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static(allow));
        return response;
    }

    let accepts_body = method == Method::POST && path == "/api/v1/session";
    if !accepts_body && has_request_body(request.headers()) {
        return text(
            StatusCode::BAD_REQUEST,
            "request bodies are not accepted on this route\n",
        );
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/login") => html(assets::LOGIN),
        ("GET", "/login.js") => script(assets::LOGIN_JS),
        ("GET", "/styles.css") => css(assets::STYLES),
        ("GET", "/favicon.svg") => svg(assets::FAVICON),
        ("GET" | "POST" | "DELETE", "/api/v1/session") => {
            session_route(method, request, &connection).await
        }
        _ => {
            if !authenticated(&connection, request.headers()) {
                if path == "/" {
                    return redirect("/login");
                }
                return error_json(StatusCode::UNAUTHORIZED, "authentication required");
            }
            match (method.as_str(), path.as_str()) {
                ("GET", "/") => html(assets::INDEX),
                ("GET", "/app.js") => script(assets::APP_JS),
                ("GET", "/world-map.js") => script(assets::WORLD_MAP_JS),
                ("GET", "/api/v1/health") => health(&connection),
                ("GET", "/api/v1/history") => history(request, &connection).await,
                ("GET", "/api/v1/correlations") => correlations(request, &connection).await,
                ("GET", "/api/v1/live") => live(request, &connection),
                _ => text(StatusCode::NOT_FOUND, "not found\n"),
            }
        }
    }
}

fn allowed_methods(path: &str) -> Option<&'static str> {
    match path {
        "/" | "/app.js" | "/world-map.js" | "/login" | "/login.js" | "/styles.css"
        | "/favicon.svg" => Some("GET"),
        "/api/v1/health" | "/api/v1/history" | "/api/v1/correlations" | "/api/v1/live" => {
            Some("GET")
        }
        "/api/v1/session" => Some("GET, POST, DELETE"),
        _ => None,
    }
}

fn health(connection: &Connection) -> Response<ProxyBody> {
    let state = connection.context.live.borrow().clone();
    match dto::health(&connection.context.console, state.as_deref(), now_ms()) {
        Ok(json) => json_response(json),
        Err(_) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to encode health"),
    }
}

async fn history(request: Request<Incoming>, connection: &Connection) -> Response<ProxyBody> {
    let params = match query_params(
        request.uri().query(),
        &["from_ms", "until_ms", "limit", "site", "revision"],
    ) {
        Ok(params) => params,
        Err(message) => return bad_request(message),
    };
    let from_ms = match required_u64(&params, "from_ms") {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let until_ms = match required_u64(&params, "until_ms") {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let limit = match optional_usize(&params, "limit", 24) {
        Ok(value) if (1..=MAX_HISTORY_LIMIT).contains(&value) => value,
        Ok(_) => return bad_request("`limit` must be between 1 and 128"),
        Err(message) => return bad_request(message),
    };
    let revision = match optional_u64(&params, "revision") {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let site = params.get("site").map(|value| (*value).to_owned());
    let query = HistoryQuery {
        instance: connection.context.console.instance.clone(),
        site,
        from_ms,
        until_ms,
        limit,
        revision,
    };
    match connection.context.reader.history(query).await {
        Ok(page) => match dto::history(
            &page,
            &connection.context.console.instance,
            from_ms,
            until_ms,
        ) {
            Ok((json, _, _)) => json_response(json),
            Err(_) => error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode history",
            ),
        },
        Err(crate::console::Error::HistoryChanged) => {
            error_json(StatusCode::CONFLICT, "history changed; restart the read")
        }
        Err(crate::console::Error::Busy | crate::console::Error::OperationTimeout) => {
            let mut response = error_json(StatusCode::SERVICE_UNAVAILABLE, "history is busy");
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
        Err(crate::console::Error::Invalid(message)) => bad_request(message),
        Err(error) => {
            warn!(error = %error, "console history read failed");
            error_json(StatusCode::INTERNAL_SERVER_ERROR, "history is unavailable")
        }
    }
}

async fn correlations(request: Request<Incoming>, connection: &Connection) -> Response<ProxyBody> {
    let params = match query_params(
        request.uri().query(),
        &["from_ms", "until_ms", "limit", "credential_id"],
    ) {
        Ok(params) => params,
        Err(message) => return bad_request(message),
    };
    let from_ms = match required_u64(&params, "from_ms") {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let until_ms = match required_u64(&params, "until_ms") {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let limit = match optional_usize(&params, "limit", 24) {
        Ok(value) if (1..=MAX_CORRELATION_LIMIT).contains(&value) => value,
        Ok(_) => return bad_request("`limit` must be between 1 and 128"),
        Err(message) => return bad_request(message),
    };
    let credential_id = params.get("credential_id").map(|value| (*value).to_owned());
    if credential_id
        .as_ref()
        .is_some_and(|id| id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return bad_request("`credential_id` must be 32 hexadecimal digits");
    }
    let query = crate::console::correlations::CorrelationQuery {
        source: connection.context.console.instance.clone(),
        credential_id,
        from_ms,
        until_ms,
        limit,
    };
    match connection.context.reader.correlations(query).await {
        Ok(page) => match dto::correlations(&page) {
            Ok(json) if json.len() <= dto::MAX_CORRELATION_BYTES => json_response(json),
            Ok(_) => error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "correlation page exceeds the response bound",
            ),
            Err(_) => error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode correlation evidence",
            ),
        },
        Err(crate::console::Error::Busy | crate::console::Error::OperationTimeout) => {
            let mut response = error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "correlation reads are busy",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
        Err(crate::console::Error::Invalid(message)) => bad_request(message),
        Err(error) => {
            warn!(error = %error, "console correlation read failed");
            error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "correlation evidence is unavailable",
            )
        }
    }
}

async fn session_route(
    method: Method,
    request: Request<Incoming>,
    connection: &Connection,
) -> Response<ProxyBody> {
    let authenticated = authenticated(connection, request.headers());
    let Some(auth) = &connection.context.auth else {
        if method == Method::GET {
            return json_response(
                serde_json::to_vec(&serde_json::json!({
                    "enabled": false,
                    "authenticated": true,
                    "tls": connection.tls,
                }))
                .unwrap_or_default(),
            );
        }
        return error_json(StatusCode::CONFLICT, "authentication is not enabled");
    };
    if method == Method::GET {
        return json_response(
            serde_json::to_vec(&serde_json::json!({
                "enabled": true,
                "authenticated": authenticated,
                "tls": connection.tls,
            }))
            .unwrap_or_default(),
        );
    }
    if method == Method::DELETE {
        let name = session_cookie_name(connection.tls);
        if let Some(session) = session_cookie(request.headers(), name) {
            auth.revoke_session(session);
        }
        let mut response = json_response(br#"{"authenticated":false}"#.to_vec());
        response.headers_mut().insert(
            header::SET_COOKIE,
            cookie_header(name, "", connection.tls, Some(0)),
        );
        return response;
    }
    if method == Method::POST {
        return login(request, connection, auth).await;
    }
    text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n")
}

async fn login(
    request: Request<Incoming>,
    connection: &Connection,
    auth: &Auth,
) -> Response<ProxyBody> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("application/json") {
        return error_json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/json",
        );
    }
    let body = match tokio::time::timeout(
        HEADER_TIMEOUT,
        read_body(request.into_body(), MAX_LOGIN_BODY),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(status)) => {
            return error_json(status, "login body is not acceptable");
        }
        Err(_) => {
            return error_json(StatusCode::REQUEST_TIMEOUT, "login body timed out");
        }
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LoginBody {
        token: String,
    }
    let Ok(LoginBody { token }) = serde_json::from_slice::<LoginBody>(&body) else {
        return bad_request("invalid login body");
    };
    match auth.login(connection.peer.ip(), &token, Instant::now()) {
        Login::Accepted(session) => {
            info!(client = %connection.peer, "console login succeeded");
            let name = session_cookie_name(connection.tls);
            let mut response = json_response(br#"{"authenticated":true}"#.to_vec());
            response.headers_mut().insert(
                header::SET_COOKIE,
                cookie_header(name, &session, connection.tls, None),
            );
            response
        }
        Login::Rejected => {
            warn!(client = %connection.peer, "console login failed");
            error_json(StatusCode::UNAUTHORIZED, "authentication failed")
        }
        Login::TooMany { retry_after_secs } => {
            let mut response =
                error_json(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts");
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    }
}

fn live(request: Request<Incoming>, connection: &Connection) -> Response<ProxyBody> {
    if request.uri().query().is_some() {
        return bad_request("query parameters are not accepted");
    }
    let last_event_id = request
        .headers()
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .map(str::to_owned);
    let (session_guard, revocations) = match &connection.context.auth {
        Some(auth) => {
            let bearer_ok =
                bearer(request.headers()).is_some_and(|token| auth.token_matches(token.as_bytes()));
            let name = session_cookie_name(connection.tls);
            let session = if bearer_ok {
                None
            } else {
                session_cookie(request.headers(), name)
            };
            match session {
                Some(session) => {
                    let Some(expiry) = auth.session_expiry(session, Instant::now()) else {
                        return error_json(StatusCode::UNAUTHORIZED, "authentication required");
                    };
                    (
                        SessionGuard {
                            auth: Some(Arc::clone(auth)),
                            session: Some(session.to_owned()),
                            expiry: Some(expiry),
                        },
                        Some(auth.subscribe_revocations()),
                    )
                }
                // The operator token authenticates without a session. It has
                // no server-side expiry to enforce.
                None => (
                    SessionGuard {
                        auth: None,
                        session: None,
                        expiry: None,
                    },
                    None,
                ),
            }
        }
        None => (
            SessionGuard {
                auth: None,
                session: None,
                expiry: None,
            },
            None,
        ),
    };
    let Ok(permit) = Arc::clone(&connection.context.live_slots).try_acquire_owned() else {
        return error_json(StatusCode::SERVICE_UNAVAILABLE, "too many live streams");
    };
    let (tx, rx) = mpsc::channel::<Frame<Bytes>>(STREAM_CHANNEL);
    let live = connection.context.live.clone();
    let shutdown = connection.context.shutdown.clone();
    let console = connection.context.console.clone();
    tokio::spawn(async move {
        let _permit = permit;
        stream_state(
            console,
            live,
            shutdown,
            tx,
            last_event_id,
            session_guard,
            revocations,
        )
        .await;
    });
    let mut response = Response::new(ChannelBody { receiver: rx }.boxed());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

async fn stream_state(
    console: Console,
    mut live: watch::Receiver<Option<Arc<LiveState>>>,
    mut shutdown: watch::Receiver<bool>,
    tx: mpsc::Sender<Frame<Bytes>>,
    resume_id: Option<String>,
    session_guard: SessionGuard,
    mut revocations: Option<watch::Receiver<u64>>,
) {
    if !session_allowed(&session_guard) {
        return;
    }
    if tx
        .try_send(Frame::data(Bytes::from_static(b"retry: 3000\n\n")))
        .is_err()
    {
        return;
    }
    let mut last_generation: Option<String> = None;
    let mut blocked_since: Option<tokio::time::Instant> = None;
    let mut first = true;
    if !send_state(
        &tx,
        &console,
        &mut live,
        &resume_id,
        first,
        &mut last_generation,
        &mut blocked_since,
    ) {
        return;
    }
    first = false;
    let mut heartbeat =
        tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
    loop {
        if *shutdown.borrow() || !session_allowed(&session_guard) {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow_and_update() {
                    break;
                }
            }
            _ = session_revoked(&mut revocations) => {
                if !session_allowed(&session_guard) {
                    debug!("console live stream closed: session revoked or expired");
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if !session_allowed(&session_guard) {
                    debug!("console live stream closed: session expired");
                    break;
                }
                if blocked_since.is_some_and(|since| since.elapsed() >= SLOW_STREAM_TIMEOUT) {
                    debug!("console live stream closed: subscriber is not reading");
                    break;
                }
                match tx.try_send(Frame::data(Bytes::from_static(b": keepalive\n\n"))) {
                    Ok(()) => blocked_since = None,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        blocked_since.get_or_insert_with(tokio::time::Instant::now);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            changed = live.changed() => {
                if changed.is_err() {
                    break;
                }
                if !session_allowed(&session_guard) {
                    debug!("console live stream closed: session revoked or expired");
                    break;
                }
                if !send_state(
                    &tx,
                    &console,
                    &mut live,
                    &resume_id,
                    first,
                    &mut last_generation,
                    &mut blocked_since,
                ) {
                    break;
                }
            }
        }
    }
}

fn session_allowed(session_guard: &SessionGuard) -> bool {
    let (Some(auth), Some(session)) = (&session_guard.auth, &session_guard.session) else {
        // Authentication is disabled, or the request presented the operator
        // token instead of a session.
        return true;
    };
    let now = Instant::now();
    if session_guard.expiry.is_none_or(|expiry| expiry <= now) {
        return false;
    }
    auth.validate_session(session, now)
}

/// Wait until any session is revoked. The stream revalidates its own session
/// after every wake-up, so a logout closes exactly the affected streams.
async fn session_revoked(revocations: &mut Option<watch::Receiver<u64>>) {
    match revocations {
        Some(receiver) => {
            let _ = receiver.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Send the current state. Returns false when the subscriber is gone.
fn send_state(
    tx: &mpsc::Sender<Frame<Bytes>>,
    console: &Console,
    live: &mut watch::Receiver<Option<Arc<LiveState>>>,
    resume_id: &Option<String>,
    first: bool,
    last_generation: &mut Option<String>,
    blocked_since: &mut Option<tokio::time::Instant>,
) -> bool {
    let Some(state) = live.borrow_and_update().clone() else {
        if first {
            let payload = dto::health(console, None, now_ms()).unwrap_or_default();
            let mut frame = Vec::with_capacity(payload.len() + 32);
            frame.extend_from_slice(b"event: pending\ndata: ");
            frame.extend_from_slice(&payload);
            frame.extend_from_slice(b"\n\n");
            return admit(tx, Frame::data(Bytes::from(frame)), blocked_since);
        }
        return true;
    };
    let Some(snapshot) = &state.snapshot else {
        return true;
    };
    let id = format!("{}:{}", snapshot.source.generation, snapshot.sequence);
    let generation = snapshot.source.generation.clone();
    let generation_changed = last_generation
        .as_deref()
        .is_some_and(|previous| previous != generation);
    let replayed = if first {
        resume_id.as_deref().is_none_or(|value| value == id)
    } else {
        !generation_changed
    };
    let Ok(payload) = dto::state(console, &state, replayed, generation_changed) else {
        return true;
    };
    let mut frame = Vec::with_capacity(payload.len() + 64);
    frame.extend_from_slice(b"event: state\nid: ");
    frame.extend_from_slice(id.as_bytes());
    frame.extend_from_slice(b"\ndata: ");
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(b"\n\n");
    *last_generation = Some(generation);
    admit(tx, Frame::data(Bytes::from(frame)), blocked_since)
}

/// Try to queue one frame. A full channel drops this frame instead of growing
/// memory or blocking collection; the next state carries absolute values.
fn admit(
    tx: &mpsc::Sender<Frame<Bytes>>,
    frame: Frame<Bytes>,
    blocked_since: &mut Option<tokio::time::Instant>,
) -> bool {
    match tx.try_send(frame) {
        Ok(()) => {
            *blocked_since = None;
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            blocked_since.get_or_insert_with(tokio::time::Instant::now);
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

struct ChannelBody {
    receiver: mpsc::Receiver<Frame<Bytes>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.receiver.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}

fn authenticated(connection: &Connection, headers: &HeaderMap) -> bool {
    let Some(auth) = &connection.context.auth else {
        return true;
    };
    if let Some(token) = bearer(headers)
        && auth.token_matches(token.as_bytes())
    {
        return true;
    }
    let name = session_cookie_name(connection.tls);
    session_cookie(headers, name)
        .is_some_and(|session| auth.validate_session(session, Instant::now()))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

fn session_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && !value.is_empty()).then_some(value)
        })
}

fn cookie_header(name: &str, value: &str, tls: bool, max_age: Option<u64>) -> HeaderValue {
    let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Strict");
    if tls {
        cookie.push_str("; Secure");
    }
    if let Some(age) = max_age {
        cookie.push_str(&format!("; Max-Age={age}"));
    }
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

fn peer_allowed(console: &Console, peer: IpAddr) -> bool {
    let peer = crate::protection::normalize_ip(peer);
    if console.allowed_clients.is_empty() {
        return peer.is_loopback();
    }
    console.allowed_clients.iter().any(|network| {
        network.contains(peer)
            || network
                .to_ipv4_mapped()
                .is_some_and(|network| network.contains(peer))
    })
}

fn host_allowed(console: &Console, headers: &HeaderMap) -> Result<(), StatusCode> {
    let mut values = headers.get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Ok(value) = value.to_str() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let value = value.trim();
    if crate::allowed_hosts::normalized_authority(value).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    match &console.allowed_hosts {
        Some(hosts) if !hosts.matches(value) => Err(StatusCode::MISDIRECTED_REQUEST),
        Some(_) => Ok(()),
        None if loopback_host(value) => Ok(()),
        None => Err(StatusCode::MISDIRECTED_REQUEST),
    }
}

fn loopback_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(name, _)| name).unwrap_or(host)
    } else {
        host.rsplit_once(':')
            .filter(|(name, port)| {
                !name.contains(':')
                    && !port.is_empty()
                    && port.chars().all(|ch| ch.is_ascii_digit())
            })
            .map(|(name, _)| name)
            .unwrap_or(host)
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn has_request_body(headers: &HeaderMap) -> bool {
    headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > 0)
}

fn has_forwarding_markers(headers: &HeaderMap) -> bool {
    ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"]
        .iter()
        .any(|name| headers.contains_key(*name))
}

fn query_params<'a>(
    query: Option<&'a str>,
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut params = BTreeMap::new();
    let Some(query) = query else {
        return Ok(params);
    };
    if query.len() > MAX_QUERY_BYTES {
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

fn required_u64(params: &BTreeMap<&str, &str>, name: &str) -> Result<u64, String> {
    match params.get(name) {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| format!("`{name}` must be a non-negative integer")),
        None => Err(format!("missing query parameter `{name}`")),
    }
}

fn optional_u64(params: &BTreeMap<&str, &str>, name: &str) -> Result<Option<u64>, String> {
    match params.get(name) {
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("`{name}` must be a non-negative integer")),
        None => Ok(None),
    }
}

fn optional_usize(
    params: &BTreeMap<&str, &str>,
    name: &str,
    default: usize,
) -> Result<usize, String> {
    match params.get(name) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("`{name}` must be a non-negative integer")),
        None => Ok(default),
    }
}

async fn read_body(mut body: Incoming, limit: usize) -> Result<Vec<u8>, StatusCode> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > limit {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn secure(mut response: Response<ProxyBody>) -> Response<ProxyBody> {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

fn json_response(json: Vec<u8>) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(json));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error_json(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::to_vec(&serde_json::json!({"error": message})).unwrap_or_default();
    let mut response = json_response(body);
    *response.status_mut() = status;
    response
}

fn bad_request(message: impl Into<String>) -> Response<ProxyBody> {
    error_json(StatusCode::BAD_REQUEST, &message.into())
}

fn text(status: StatusCode, body: impl Into<Bytes>) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn redirect(location: &'static str) -> Response<ProxyBody> {
    let mut response = text(StatusCode::FOUND, "");
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    response
}

fn html(body: &'static str) -> Response<ProxyBody> {
    asset(body, "text/html; charset=utf-8")
}

fn css(body: &'static str) -> Response<ProxyBody> {
    asset(body, "text/css; charset=utf-8")
}

fn script(body: &'static str) -> Response<ProxyBody> {
    asset(body, "text/javascript; charset=utf-8")
}

fn svg(body: &'static str) -> Response<ProxyBody> {
    asset(body, "image/svg+xml")
}

fn asset(body: &'static str, content_type: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

struct TlsState {
    cert_file: PathBuf,
    key_file: Option<PathBuf>,
    inner: tokio::sync::Mutex<TlsInner>,
}

struct TlsInner {
    config: Arc<rustls::ServerConfig>,
    stamp: Stamp,
    attempted: Instant,
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    cert: FileStamp,
    key: Option<FileStamp>,
}

#[derive(Clone, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl TlsState {
    async fn load(tls: &ConsoleTls) -> Result<Self, Error> {
        let config =
            crate::proxy::tls::load_console_server_config(&tls.cert_file, tls.key_file.as_deref())?;
        let stamp = stamp(&tls.cert_file, tls.key_file.as_deref()).await;
        Ok(Self {
            cert_file: tls.cert_file.clone(),
            key_file: tls.key_file.clone(),
            inner: tokio::sync::Mutex::new(TlsInner {
                config,
                stamp,
                attempted: Instant::now(),
            }),
        })
    }

    async fn config(&self) -> Arc<rustls::ServerConfig> {
        let stamp = stamp(&self.cert_file, self.key_file.as_deref()).await;
        let mut inner = self.inner.lock().await;
        if stamp != inner.stamp && inner.attempted.elapsed() >= TLS_RELOAD_INTERVAL {
            inner.attempted = Instant::now();
            match crate::proxy::tls::load_console_server_config(
                &self.cert_file,
                self.key_file.as_deref(),
            ) {
                Ok(config) => {
                    info!(path = %self.cert_file.display(), "console certificate reloaded");
                    inner.config = config;
                    inner.stamp = stamp;
                }
                Err(error) => {
                    warn!(error = %error, "console certificate reload failed; keeping previous material");
                }
            }
        }
        inner.config.clone()
    }
}

async fn stamp(cert_file: &Path, key_file: Option<&Path>) -> Stamp {
    Stamp {
        cert: file_stamp(cert_file).await,
        key: match key_file {
            Some(key_file) => Some(file_stamp(key_file).await),
            None => None,
        },
    }
}

async fn file_stamp(path: &Path) -> FileStamp {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => FileStamp {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        },
        Err(_) => FileStamp {
            len: 0,
            modified: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn parse_console(yaml: &str) -> Console {
        config::parse(&format!(
            "listen: 127.0.0.1:8080
upstream: http://127.0.0.1:3000
{yaml}"
        ))
        .expect("valid config")
        .console
    }

    fn headers(host: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(host) = host {
            headers.insert(header::HOST, HeaderValue::from_static(host));
        }
        headers
    }

    #[test]
    fn peer_allowlist_normalizes_ipv4_mapped_peers() {
        let console =
            parse_console("console: { enabled: true, allowed_clients: ['127.0.0.1/32'] }\n");
        assert!(peer_allowed(&console, "127.0.0.1".parse().unwrap()));
        assert!(peer_allowed(&console, "::ffff:127.0.0.1".parse().unwrap()));
        assert!(!peer_allowed(&console, "::1".parse().unwrap()));

        let console = parse_console("console: { enabled: true, allowed_clients: ['::1/128'] }\n");
        assert!(peer_allowed(&console, "::1".parse().unwrap()));
        assert!(!peer_allowed(&console, "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn an_empty_allowlist_means_loopback_only() {
        let console = parse_console("console: { enabled: true }\n");
        assert!(peer_allowed(&console, "127.0.0.1".parse().unwrap()));
        assert!(peer_allowed(&console, "::1".parse().unwrap()));
        assert!(!peer_allowed(&console, "192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn host_validation_uses_loopback_names_or_the_configured_list() {
        let console = parse_console("console: { enabled: true }\n");
        assert_eq!(
            host_allowed(&console, &headers(Some("127.0.0.1:9091"))),
            Ok(())
        );
        assert_eq!(host_allowed(&console, &headers(Some("localhost"))), Ok(()));
        assert_eq!(host_allowed(&console, &headers(Some("[::1]:9091"))), Ok(()));
        assert_eq!(
            host_allowed(&console, &headers(Some("console.example.com"))),
            Err(StatusCode::MISDIRECTED_REQUEST)
        );
        assert_eq!(
            host_allowed(&console, &headers(None)),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            host_allowed(&console, &headers(Some("bad host"))),
            Err(StatusCode::BAD_REQUEST)
        );

        let console =
            parse_console("console: { enabled: true, allowed_hosts: ['console.example.com'] }\n");
        assert_eq!(
            host_allowed(&console, &headers(Some("console.example.com:9091"))),
            Ok(())
        );
        assert_eq!(
            host_allowed(&console, &headers(Some("evil.example"))),
            Err(StatusCode::MISDIRECTED_REQUEST)
        );
    }

    #[test]
    fn query_parsing_is_strict_and_bounded() {
        let parsed = query_params(
            Some("from_ms=1&until_ms=2&limit=3"),
            &["from_ms", "until_ms", "limit"],
        )
        .expect("valid query");
        assert_eq!(parsed.get("from_ms").copied(), Some("1"));

        for (query, expected) in [
            ("from_ms=1&from_ms=2", "duplicate"),
            ("from_ms=1&unknown=2", "unknown"),
            ("from_ms=%31", "percent-encoding"),
            ("from_ms", "malformed"),
            ("from_ms=", "name and a value"),
        ] {
            let error = query_params(Some(query), &["from_ms", "until_ms", "limit"])
                .expect_err("invalid query");
            assert!(error.contains(expected), "{query}: {error}");
        }
    }

    #[test]
    fn unexpected_request_bodies_are_detected() {
        let mut headers = HeaderMap::new();
        assert!(!has_request_body(&headers));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert!(!has_request_body(&headers));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        assert!(has_request_body(&headers));
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        assert!(has_request_body(&headers));
    }
}
