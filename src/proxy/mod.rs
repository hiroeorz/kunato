pub mod client;
pub mod forward;
pub mod http3;
pub mod response;
pub mod server;
pub mod tls;
pub mod websocket;

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

pub fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A body that emits a buffered prefix, then any pending frames, then streams
/// the remainder. Used on both the request and response paths when only a
/// bounded prefix was consumed for inspection.
pub struct PrefixBody {
    prefix: Bytes,
    pending: Vec<Frame<Bytes>>,
    rest: ProxyBody,
}

impl PrefixBody {
    pub fn new(prefix: Bytes, pending: Vec<Frame<Bytes>>, rest: ProxyBody) -> Self {
        Self {
            prefix,
            pending,
            rest,
        }
    }
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
