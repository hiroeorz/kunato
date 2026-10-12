use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_BODY_DISPLAY: usize = 4096;

#[derive(Debug, Parser)]
#[command(about = "Example upstream server for testing Kunato with a browser or curl")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;
    info!(addr = %listener.local_addr()?, "example upstream listening");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |request: Request<Incoming>| handle(request, peer));
                    if let Err(err) = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, service)
                        .await
                    {
                        error!(client = %peer, error = %err, "connection error");
                    }
                });
            }
        }
    }

    info!("example upstream stopped");
    Ok(())
}

async fn handle(
    request: Request<Incoming>,
    peer: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let started = Instant::now();
    let is_head = request.method() == Method::HEAD;
    let method = request.method().clone();
    let target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let headers = request.headers().clone();

    let body = match Limited::new(request.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            let status = StatusCode::PAYLOAD_TOO_LARGE;
            log_request(peer, &method, &target, status, 0, started);
            return Ok(build_response(
                status,
                "payload too large".to_owned(),
                is_head,
            ));
        }
    };

    let report = format_report(peer, &method, &target, &headers, &body);
    let status = StatusCode::OK;
    log_request(peer, &method, &target, status, report.len(), started);
    Ok(build_response(status, report, is_head))
}

fn build_response(status: StatusCode, body: String, is_head: bool) -> Response<Full<Bytes>> {
    let payload = if is_head { String::new() } else { body };
    let mut response = Response::new(Full::new(Bytes::from(payload)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn format_report(
    peer: SocketAddr,
    method: &Method,
    target: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> String {
    let mut report = String::new();
    report.push_str("kunato example upstream\n");
    report.push_str(&format!("client: {peer}\n"));
    report.push_str(&format!("method: {method}\n"));
    report.push_str(&format!("target: {target}\n"));

    report.push_str("headers:\n");
    for (name, value) in headers {
        match value.to_str() {
            Ok(value) => report.push_str(&format!("  {name}: {value}\n")),
            Err(_) => report.push_str(&format!("  {name}: <non-utf8 value>\n")),
        }
    }

    report.push_str(&format!("body: {} bytes\n", body.len()));
    if !body.is_empty() {
        let text = String::from_utf8_lossy(body);
        let truncated: String = text.chars().take(MAX_BODY_DISPLAY).collect();
        report.push_str(&truncated);
        if truncated.chars().count() < text.chars().count() {
            report.push_str("\n...<truncated>");
        }
        report.push('\n');
    }

    report
}

fn log_request(
    peer: SocketAddr,
    method: &Method,
    target: &str,
    status: StatusCode,
    body_bytes: usize,
    started: Instant,
) {
    info!(
        client = %peer,
        method = %method,
        target = %target,
        status = status.as_u16(),
        body_bytes,
        duration_ms = started.elapsed().as_millis() as u64,
        "access"
    );
}
