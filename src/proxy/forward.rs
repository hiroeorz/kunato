use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use tracing::debug;

use crate::config::{CompiledConfig, ResponseSpec};
use crate::proxy::client::UpstreamClient;
use crate::proxy::{BoxError, ProxyBody, full_body};

#[derive(Debug)]
pub struct HttpError {
    pub status: StatusCode,
    pub message: &'static str,
    pub retry_after: Option<Duration>,
}

impl HttpError {
    pub fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            retry_after: None,
        }
    }

    pub fn with_retry_after(
        status: StatusCode,
        message: &'static str,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message,
            retry_after: Some(retry_after),
        }
    }
}

pub fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

pub fn error_response_for(error: &HttpError) -> Response<ProxyBody> {
    let mut response = error_response(error.status, error.message);
    if let Some(retry_after) = error.retry_after
        && let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
    {
        response.headers_mut().insert("retry-after", value);
    }
    response
}

pub fn block_response(spec: &ResponseSpec) -> Response<ProxyBody> {
    let status = StatusCode::from_u16(spec.status).unwrap_or(StatusCode::FORBIDDEN);
    let body = spec.body.clone().unwrap_or_else(|| "Forbidden".to_owned());
    error_response(status, &body)
}

pub async fn forward_request(
    client: &UpstreamClient,
    config: &CompiledConfig,
    parts: http::request::Parts,
    body: Bytes,
    peer: SocketAddr,
    scheme: &'static str,
) -> Result<Response<ProxyBody>, HttpError> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let uri = config.upstream.request_uri(path_and_query).map_err(|err| {
        debug!(error = %err, "failed to build upstream URI");
        HttpError::new(StatusCode::BAD_GATEWAY, "invalid upstream URI")
    })?;

    let mut request = Request::new(Full::new(body));
    *request.method_mut() = parts.method;
    *request.uri_mut() = uri;
    *request.version_mut() = parts.version;
    copy_forward_headers(&parts.headers, request.headers_mut());

    if let Ok(forwarded_for) = HeaderValue::from_str(&peer.ip().to_string()) {
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded_for);
    }
    let forwarded_proto = if scheme == "https" {
        HeaderValue::from_static("https")
    } else {
        HeaderValue::from_static("http")
    };
    request
        .headers_mut()
        .insert("x-forwarded-proto", forwarded_proto);
    if let Some(host) = parts.headers.get(HOST) {
        request
            .headers_mut()
            .insert("x-forwarded-host", host.clone());
    }

    let result =
        tokio::time::timeout(config.timeouts.upstream_response, client.request(request)).await;

    let response = match result {
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

    Ok(convert_response(response))
}

fn convert_response(response: Response<Incoming>) -> Response<ProxyBody> {
    let (parts, incoming) = response.into_parts();
    let body = incoming.map_err(|err| Box::new(err) as BoxError).boxed();

    let mut response = Response::new(body);
    *response.status_mut() = parts.status;
    *response.version_mut() = parts.version;

    let connection_tokens = connection_tokens(&parts.headers);
    for (name, value) in &parts.headers {
        if is_hop_by_hop(name) || connection_tokens.contains(name) {
            continue;
        }
        response.headers_mut().append(name, value.clone());
    }

    response
}

fn copy_forward_headers(source: &HeaderMap, target: &mut HeaderMap) {
    let connection_tokens = connection_tokens(source);
    for (name, value) in source {
        if is_hop_by_hop(name) || connection_tokens.contains(name) {
            continue;
        }
        target.append(name, value.clone());
    }
}

fn connection_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut tokens = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            if let Ok(name) = HeaderName::from_bytes(token.trim().as_bytes()) {
                tokens.push(name);
            }
        }
    }
    tokens
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
