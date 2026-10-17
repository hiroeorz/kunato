use std::net::SocketAddr;
use std::time::Duration;

use http::header::{CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tracing::debug;

use crate::config::{CompiledConfig, ResponseSpec};
use crate::protection::normalize_ip;
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
    parts: &http::request::Parts,
    body: ProxyBody,
    peer: SocketAddr,
    scheme: &'static str,
    exchange_timeout: Duration,
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

    let mut request = Request::new(body);
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    copy_forward_headers(&parts.headers, request.headers_mut());
    if let Some(host) = parts.headers.get(HOST).cloned() {
        request.headers_mut().insert(HOST, host);
    }
    set_forwarded_headers(
        request.headers_mut(),
        &parts.headers,
        &parts.uri,
        peer,
        scheme,
    );

    let result = tokio::time::timeout(exchange_timeout, client.request(request)).await;

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

/// Legacy identity headers that attestation proxies up the chain may have
/// added. Clients can forge all of them, so applications behind Kunato must
/// rely on the canonical `X-Forwarded-*` trio (rewritten below) instead; the
/// forged copies are removed from every forwarded request.
const LEGACY_IDENTITY_HEADERS: [&str; 4] =
    ["forwarded", "x-real-ip", "x-client-ip", "x-forwarded-port"];

pub(crate) fn set_forwarded_headers(
    target: &mut HeaderMap,
    source: &HeaderMap,
    source_uri: &http::Uri,
    peer: SocketAddr,
    scheme: &'static str,
) {
    for name in LEGACY_IDENTITY_HEADERS {
        target.remove(name);
    }
    if let Ok(forwarded_for) = HeaderValue::from_str(&normalize_ip(peer.ip()).to_string()) {
        target.insert("x-forwarded-for", forwarded_for);
    }
    let forwarded_proto = if scheme == "https" {
        HeaderValue::from_static("https")
    } else {
        HeaderValue::from_static("http")
    };
    target.insert("x-forwarded-proto", forwarded_proto);

    let forwarded_host = source.get(HOST).cloned().or_else(|| {
        source_uri
            .authority()
            .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
    });
    if let Some(host) = forwarded_host {
        target.insert("x-forwarded-host", host);
    }
}

/// Give an HTTP/2 or HTTP/3 request an explicit `Host` header derived from the
/// `:authority` pseudo-header, so header rules and the forwarded request see the
/// same host the client addressed on every protocol version.
pub(crate) fn normalize_host_header(parts: &mut http::request::Parts) {
    if parts.headers.contains_key(HOST) {
        return;
    }
    let Some(authority) = parts.uri.authority() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
        parts.headers.insert(HOST, value);
    }
}

pub(crate) fn convert_response(response: Response<Incoming>) -> Response<ProxyBody> {
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

pub(crate) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_mapped_peers_are_normalized_in_forwarded_headers() {
        let mut target = HeaderMap::new();
        let source = HeaderMap::new();
        let uri: http::Uri = "/".parse().expect("valid URI");
        let peer: SocketAddr = "[::ffff:10.0.0.1]:1234".parse().expect("valid peer");

        set_forwarded_headers(&mut target, &source, &uri, peer, "http");

        assert_eq!(
            target
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn forged_legacy_identity_headers_are_removed() {
        let mut target = HeaderMap::new();
        target.insert("forwarded", HeaderValue::from_static("for=6.6.6.6"));
        target.append("x-real-ip", HeaderValue::from_static("7.7.7.7"));
        target.append("x-real-ip", HeaderValue::from_static("8.8.8.8"));
        target.insert("x-client-ip", HeaderValue::from_static("9.9.9.9"));
        target.insert("x-forwarded-port", HeaderValue::from_static("1234"));
        let mut source = HeaderMap::new();
        source.insert("x-real-ip", HeaderValue::from_static("10.10.10.10"));
        let uri: http::Uri = "/".parse().expect("valid URI");
        let peer: SocketAddr = "203.0.113.7:4444".parse().expect("valid peer");

        set_forwarded_headers(&mut target, &source, &uri, peer, "http");

        for name in LEGACY_IDENTITY_HEADERS {
            assert!(
                target.get(name).is_none(),
                "{name} must not survive forwarding"
            );
        }
        assert_eq!(
            target
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn proxy_connection_is_hop_by_hop() {
        assert!(is_hop_by_hop(&HeaderName::from_static("proxy-connection")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("x-real-ip")));
    }

    #[test]
    fn authority_becomes_host_for_http2_requests() {
        let request = Request::builder()
            .uri("http://public.example:8080/path")
            .body(())
            .expect("valid request");
        let (mut parts, ()) = request.into_parts();
        normalize_host_header(&mut parts);
        assert_eq!(
            parts
                .headers
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("public.example:8080")
        );
    }

    #[test]
    fn explicit_host_is_not_overwritten() {
        let request = Request::builder()
            .uri("http://public.example/path")
            .header(HOST, "origin.example")
            .body(())
            .expect("valid request");
        let (mut parts, ()) = request.into_parts();
        normalize_host_header(&mut parts);
        assert_eq!(
            parts
                .headers
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("origin.example")
        );
    }
}
