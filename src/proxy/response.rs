use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use tracing::{debug, info, warn};

use crate::config::CompiledConfig;
use crate::metrics::Metrics;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::{BoxError, PrefixBody, ProxyBody, settle_body_end};
use crate::request_view::{RequestView, ResponseView};
use crate::rules::eval;

pub struct Buffered {
    pub parts: http::response::Parts,
    pub prefix: Bytes,
    pub truncated: bool,
    pub body: ProxyBody,
}

pub async fn buffer_prefix(
    response: Response<ProxyBody>,
    limit: usize,
) -> Result<Buffered, BoxError> {
    let (parts, mut body) = response.into_parts();
    let mut prefix: Vec<u8> = Vec::new();
    let mut pending: Vec<Frame<Bytes>> = Vec::new();
    let mut overflowed = false;
    let mut hit_limit = false;

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                let room = limit.saturating_sub(prefix.len());
                if data.len() >= room {
                    let take = room.min(data.len());
                    prefix.extend_from_slice(&data[..take]);
                    let remainder = data.slice(take..);
                    if !remainder.is_empty() {
                        pending.push(Frame::data(remainder));
                        overflowed = true;
                    }
                    hit_limit = true;
                    break;
                }
                prefix.extend_from_slice(&data);
            }
            Err(frame) => pending.push(frame),
        }
    }

    // `size_hint` cannot classify chunked bodies, so a body that ends exactly
    // at the limit needs a look-ahead; the outer `upstream_response` timeout in
    // `inspect` bounds any stall the look-ahead may observe.
    let mut truncated = overflowed;
    if hit_limit && !truncated {
        truncated = match body.size_hint().exact() {
            Some(remaining) => remaining > 0,
            None => settle_body_end(&mut body, None, &mut pending).await,
        };
    }

    let prefix = Bytes::from(prefix);
    let body = PrefixBody::new(prefix.clone(), pending, body).boxed();

    Ok(Buffered {
        parts,
        prefix,
        truncated,
        body,
    })
}

pub async fn inspect(
    config: &CompiledConfig,
    metrics: &Metrics,
    request: &http::request::Parts,
    request_body: &[u8],
    peer: SocketAddr,
    response: Response<ProxyBody>,
) -> Result<Response<ProxyBody>, HttpError> {
    let buffered = match tokio::time::timeout(
        config.timeouts.upstream_response,
        buffer_prefix(response, config.limits.max_response_body_bytes),
    )
    .await
    {
        Err(_) => {
            metrics.upstream_timeouts.fetch_add(1, Ordering::Relaxed);
            debug!(
                timeout = ?config.timeouts.upstream_response,
                "timed out buffering upstream response for inspection"
            );
            return Err(HttpError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream response timed out",
            ));
        }
        Ok(Err(err)) => {
            debug!(error = %err, "failed to buffer upstream response for inspection");
            return Err(HttpError::new(
                StatusCode::BAD_GATEWAY,
                "upstream response failed",
            ));
        }
        Ok(Ok(buffered)) => buffered,
    };

    let decoded_prefix = if config.has_response_body_rules() {
        crate::decoding::decode_content_encoding(
            &buffered.prefix,
            &buffered.parts.headers,
            config.limits.max_response_body_bytes,
        )
    } else {
        None
    };
    if config.has_response_body_rules()
        && !buffered.prefix.is_empty()
        && crate::decoding::encoding_is_uninspectable(&buffered.parts.headers)
    {
        metrics
            .response_decode_skipped
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            status = buffered.parts.status.as_u16(),
            "response body encoding cannot be decoded for inspection"
        );
    }
    let decode_truncated = decoded_prefix
        .as_ref()
        .is_some_and(|decoded| decoded.truncated);
    if decode_truncated {
        metrics
            .response_decode_truncated
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            limit = config.limits.max_response_body_bytes,
            status = buffered.parts.status.as_u16(),
            "decompressed response body truncated for inspection"
        );
    }
    let inspected_prefix = decoded_prefix
        .as_ref()
        .map(|decoded| decoded.body.as_slice())
        .unwrap_or(&buffered.prefix);

    let view = RequestView::with_body_decoding(
        &request.method,
        &request.uri,
        &request.headers,
        request_body,
        peer.ip(),
        config.has_body_target_rules(),
    );
    let response_view = ResponseView::new(
        buffered.parts.status,
        &buffered.parts.headers,
        inspected_prefix,
        buffered.truncated || decode_truncated,
    );
    let outcome = eval::evaluate_response(config, &view, &response_view);

    if !outcome.logs.is_empty() {
        metrics.response_logged.fetch_add(1, Ordering::Relaxed);
    }
    for record in &outcome.logs {
        info!(
            phase = record.phase.as_str(),
            category = %record.category,
            rule = %record.rule,
            action = record.action.as_str(),
            client = %peer.ip(),
            status = buffered.parts.status.as_u16(),
            "response rule matched"
        );
    }

    if let Some(blocked) = &outcome.blocked {
        metrics.response_blocked.fetch_add(1, Ordering::Relaxed);
        info!(
            phase = blocked.phase.as_str(),
            category = %blocked.category,
            rule = %blocked.rule,
            action = "BLOCK",
            client = %peer.ip(),
            status = buffered.parts.status.as_u16(),
            "response blocked"
        );
        return Ok(forward::block_response(&blocked.response));
    }

    if buffered.truncated {
        metrics.response_truncated.fetch_add(1, Ordering::Relaxed);
        debug!(
            limit = config.limits.max_response_body_bytes,
            status = buffered.parts.status.as_u16(),
            "response body truncated for inspection"
        );
    }

    Ok(Response::from_parts(buffered.parts, buffered.body))
}
