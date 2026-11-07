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
use crate::maintenance::MaintenanceState;
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
    maintenance: Arc<MaintenanceState>,
}

impl AdminServer {
    pub async fn bind(
        spec: &Admin,
        metrics: Arc<Metrics>,
        protection: Arc<ProtectionState>,
        maintenance: Arc<MaintenanceState>,
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
            maintenance,
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
                            let maintenance = self.maintenance.clone();
                            match Arc::clone(&limit).try_acquire_owned() {
                                Ok(permit) => {
                                    connections.spawn(serve_connection(stream, peer, metrics, protection, maintenance, permit));
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
    maintenance: Arc<MaintenanceState>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        let metrics = metrics.clone();
        let protection = protection.clone();
        let maintenance = maintenance.clone();
        async move { handle(request, metrics, protection, maintenance).await }
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
    maintenance: Arc<MaintenanceState>,
) -> Result<Response<ProxyBody>, Infallible> {
    if !admin_host_allowed(request.headers().get(http::header::HOST)) {
        let mut response = Response::new(full_body("misdirected request"));
        *response.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        return Ok(response);
    }
    if request.method() == Method::GET && request.uri().path() == "/metrics" {
        let body = metrics.render(protection.active_connections());
        let mut response = Response::new(full_body(body));
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        return Ok(response);
    }
    if request.method() == Method::GET && request.uri().path() == "/maintenance" {
        let body = if maintenance.enabled() {
            "on\n"
        } else {
            "off\n"
        };
        return Ok(text_response(StatusCode::OK, body));
    }
    if request.method() == Method::PUT {
        // `PUT` is not a simple cross-origin request, so a browser must pass a
        // CORS preflight that this listener never grants. That keeps a page on
        // another origin from toggling maintenance through the loopback
        // listener.
        match request.uri().path() {
            "/maintenance/on" => {
                if !maintenance.set(true) {
                    info!("maintenance mode enabled");
                }
                return Ok(text_response(StatusCode::OK, "maintenance on\n"));
            }
            "/maintenance/off" => {
                if maintenance.set(false) {
                    info!("maintenance mode disabled");
                }
                return Ok(text_response(StatusCode::OK, "maintenance off\n"));
            }
            _ => {}
        }
    }

    let mut response = Response::new(full_body("not found"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    Ok(response)
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Reject DNS-rebinding requests: the admin listener only accepts loopback
/// names, so a browser resolving an attacker-controlled name to 127.0.0.1
/// still sends that name in `Host`.
fn admin_host_allowed(host: Option<&HeaderValue>) -> bool {
    let Some(host) = host else {
        // HTTP/1.0 clients may omit Host; they cannot be driven by a browser
        // rebinding attack.
        return true;
    };
    let Ok(host) = host.to_str() else {
        return false;
    };
    let host = host.trim();
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map(|(name, _)| name).unwrap_or(host)
    } else {
        host.rsplit_once(':')
            .filter(|(name, port)| {
                !name.contains(':') && port.chars().all(|ch| ch.is_ascii_digit())
            })
            .map(|(name, _)| name)
            .unwrap_or(host)
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_loopback_admin_hosts() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:9090",
            "localhost",
            "LOCALHOST:9090",
            "[::1]",
            "[::1]:9090",
        ] {
            assert!(
                admin_host_allowed(Some(&HeaderValue::from_str(host).expect("host"))),
                "{host}"
            );
        }
        assert!(admin_host_allowed(None));
    }

    #[test]
    fn rejects_dns_rebinding_hosts() {
        for host in ["evil.example", "evil.example:9090", "10.0.0.1", "0.0.0.0"] {
            assert!(
                !admin_host_allowed(Some(&HeaderValue::from_str(host).expect("host"))),
                "{host}"
            );
        }
    }
}
