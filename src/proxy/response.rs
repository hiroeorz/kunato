use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use tracing::{debug, info, warn};

use crate::config::CompiledConfig;
use crate::metrics::Metrics;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::server::InspectionGuard;
use crate::proxy::{BoxError, PrefixBody, ProxyBody, settle_body_end};
use crate::request_view::{RequestView, ResponseView};
use crate::rules::eval;

pub struct Buffered {
    pub parts: http::response::Parts,
    pub prefix: Bytes,
    pub truncated: bool,
    pub body: PrefixBody,
}

/// The request body as it was evaluated, plus whether it was only a prefix.
pub(crate) struct InspectedRequest<'a> {
    pub body: &'a [u8],
    pub truncated: bool,
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
    let body = PrefixBody::new(prefix.clone(), pending, body);

    Ok(Buffered {
        parts,
        prefix,
        truncated,
        body,
    })
}

pub(crate) async fn inspect(
    config: &CompiledConfig,
    metrics: &Metrics,
    request: &http::request::Parts,
    inspected_request: InspectedRequest<'_>,
    peer: SocketAddr,
    response: Response<ProxyBody>,
    inspection: InspectionGuard,
) -> Result<Response<ProxyBody>, HttpError> {
    if config.php.matches(request) && config.php.rejects_response(response.headers()) {
        metrics
            .php_response_rejected
            .fetch_add(1, Ordering::Relaxed);
        warn!(client = %peer.ip(), path = %request.uri.path(), "PHP profile rejected an anomalous session cookie");
        return Ok(forward::error_response(
            StatusCode::FORBIDDEN,
            "invalid PHP session response",
        ));
    }
    let buffered = if !config.has_response_body_rules() {
        let (parts, body) = response.into_parts();
        Buffered {
            parts,
            prefix: Bytes::new(),
            truncated: false,
            body: PrefixBody::new(Bytes::new(), Vec::new(), body),
        }
    } else {
        match tokio::time::timeout(
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
        }
    };

    let decoded_prefix = if config.has_response_body_rules() {
        crate::decoding::decode_body_for_inspection(
            &buffered.prefix,
            &buffered.parts.headers,
            config.limits.max_response_body_bytes,
        )
    } else {
        crate::decoding::DecodeOutcome::NotEncoded
    };
    let mut body_truncated = buffered.truncated;
    let inspected_prefix: Cow<'_, [u8]> = match decoded_prefix {
        crate::decoding::DecodeOutcome::NotEncoded => Cow::Borrowed(&buffered.prefix),
        crate::decoding::DecodeOutcome::Decoded { body, complete } => {
            if !complete {
                metrics
                    .response_decode_truncated
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    limit = config.limits.max_response_body_bytes,
                    status = buffered.parts.status.as_u16(),
                    "decompressed response body truncated for inspection"
                );
                body_truncated = true;
            }
            Cow::Owned(body)
        }
        crate::decoding::DecodeOutcome::Unsupported | crate::decoding::DecodeOutcome::Malformed => {
            metrics
                .response_decode_skipped
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                status = buffered.parts.status.as_u16(),
                "response body encoding cannot be inspected; inspecting the raw prefix"
            );
            body_truncated = true;
            Cow::Borrowed(&buffered.prefix)
        }
    };

    let view = RequestView::with_body_decoding(
        &request.method,
        &request.uri,
        &request.headers,
        inspected_request.body,
        peer.ip(),
        config.response_targets_request_body(),
    )
    .with_body_truncated(inspected_request.truncated);
    let response_view = ResponseView::new(
        buffered.parts.status,
        &buffered.parts.headers,
        inspected_prefix.as_ref(),
        body_truncated,
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

    Ok(Response::from_parts(
        buffered.parts,
        buffered.body.with_guard(Arc::new(inspection)).boxed(),
    ))
}
