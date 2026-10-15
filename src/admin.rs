use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

use crate::config::Admin;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::ProtectionState;
use crate::proxy::server::drain_connections;
use crate::proxy::{ProxyBody, full_body};

const MAX_ADMIN_CONNECTIONS: usize = 64;
const ADMIN_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_CONNECTION_GRACE: Duration = Duration::from_secs(5);

pub struct AdminServer {
    listener: TcpListener,
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
}

impl AdminServer {
    pub async fn bind(
        spec: &Admin,
        metrics: Arc<Metrics>,
        protection: Arc<ProtectionState>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(spec.listen)
            .await
            .map_err(|source| Error::Bind {
                addr: spec.listen.to_string(),
                source,
            })?;
        Ok(Self {
            listener,
            metrics,
            protection,
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
                            let metrics = self.metrics.clone();
                            let protection = self.protection.clone();
                            match Arc::clone(&limit).try_acquire_owned() {
                                Ok(permit) => {
                                    connections.spawn(serve_connection(stream, peer, metrics, protection, permit));
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
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let metrics = metrics.clone();
        let protection = protection.clone();
        async move { handle(request, metrics, protection).await }
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
    metrics: Arc<Metrics>,
    protection: Arc<ProtectionState>,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() == Method::GET && request.uri().path() == "/metrics" {
        let body = metrics.render(protection.active_connections());
        let mut response = Response::new(full_body(body));
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        return Ok(response);
    }

    let mut response = Response::new(full_body("not found"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    Ok(response)
}
