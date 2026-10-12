use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::Admin;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::protection::ProtectionState;
use crate::proxy::{ProxyBody, full_body};

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
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |request: Request<Incoming>| {
                                    let metrics = metrics.clone();
                                    let protection = protection.clone();
                                    async move { handle(request, metrics, protection).await }
                                });
                                if let Err(err) = http1::Builder::new()
                                    .keep_alive(true)
                                    .serve_connection(io, service)
                                    .await
                                {
                                    debug!(client = %peer, error = %err, "admin connection closed with error");
                                }
                            });
                        }
                        Err(err) => warn!(error = %err, "failed to accept admin connection"),
                    }
                }
            }
        }

        info!("admin listener stopped");
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
