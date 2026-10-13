use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tracing::{debug, info};

use crate::config::CompiledConfig;
use crate::metrics::Metrics;
use crate::proxy::forward::{self, HttpError};
use crate::proxy::{BoxError, ProxyBody};
use crate::request_view::{RequestView, ResponseView};
use crate::rules::eval;

pub struct PrefixBody {
    prefix: Bytes,
    pending: Vec<Frame<Bytes>>,
    rest: ProxyBody,
}

impl Body for PrefixBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let data = std::mem::take(&mut this.prefix);
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if !this.pending.is_empty() {
            return Poll::Ready(Some(Ok(this.pending.remove(0))));
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_empty() && self.pending.is_empty() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let pending: u64 = self
            .pending
            .iter()
            .filter_map(|frame| frame.data_ref())
            .map(|data| data.len() as u64)
            .sum();
        let buffered = self.prefix.len() as u64 + pending;
        let rest = self.rest.size_hint();

        let mut hint = SizeHint::new();
        hint.set_lower(buffered + rest.lower());
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + buffered);
        }
        hint
    }
}

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
    let mut truncated = false;

    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                if prefix.len() + data.len() > limit {
                    let take = limit.saturating_sub(prefix.len());
                    prefix.extend_from_slice(&data[..take]);
                    let remainder = data.slice(take..);
                    if !remainder.is_empty() {
                        pending.push(Frame::data(remainder));
                    }
                    truncated = true;
                    break;
                }
                prefix.extend_from_slice(&data);
            }
            Err(frame) => pending.push(frame),
        }
    }

    let prefix = Bytes::from(prefix);
    let body = PrefixBody {
        prefix: prefix.clone(),
        pending,
        rest: body,
    }
    .boxed();

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
    request_body: &Bytes,
    peer: SocketAddr,
    response: Response<ProxyBody>,
) -> Result<Response<ProxyBody>, HttpError> {
    let buffered = buffer_prefix(response, config.limits.max_response_body_bytes)
        .await
        .map_err(|err| {
            debug!(error = %err, "failed to buffer upstream response for inspection");
            HttpError::new(StatusCode::BAD_GATEWAY, "upstream response failed")
        })?;

    let view = RequestView::new(
        &request.method,
        &request.uri,
        &request.headers,
        request_body,
        peer.ip(),
    );
    let response_view = ResponseView::new(
        buffered.parts.status,
        &buffered.parts.headers,
        &buffered.prefix,
        buffered.truncated,
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
