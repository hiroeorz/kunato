pub mod body;
pub mod client;
pub mod forward;
pub mod http3;
pub mod response;
pub mod server;
pub mod tls;
pub mod websocket;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};

pub use body::{BodyExt, BoxBody, Collected, Full};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// A body whose prefix filled the inspection limit exactly may end right
/// there, but `size_hint` reports "unknown" for chunked and HTTP/2 bodies, so
/// the boundary is settled with a one-frame look-ahead: no further data
/// (besides optional trailers) means the whole body fit in the prefix and the
/// body is *not* truncated; another data frame means the remainder was never
/// inspected and the body is truncated. The polled frame is recorded in
/// `pending` so the replay stream (prefix, pending frames, rest) stays intact.
/// A deadline that expires or a read failure leaves completeness unknown,
/// which is labeled truncated.
pub(crate) async fn settle_body_end<B>(
    body: &mut B,
    deadline: Option<tokio::time::Instant>,
    pending: &mut Vec<Frame<Bytes>>,
) -> bool
where
    B: Body<Data = Bytes> + Unpin + Send,
{
    let frame = match deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(frame) => frame,
            Err(_) => return true,
        },
        None => body.frame().await,
    };
    match frame {
        None => false,
        Some(Err(_)) => true,
        Some(Ok(frame)) => match frame.into_data() {
            Ok(data) => {
                pending.push(Frame::data(data));
                true
            }
            Err(frame) => {
                // Trailers carry no inspected data; the body ends here.
                pending.push(frame);
                false
            }
        },
    }
}

pub fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into()).boxed()
}

/// Follow a buffered allocation through body frames, clones, and slices.
pub(crate) fn with_bytes_guard<G>(bytes: Bytes, guard: Arc<G>) -> Bytes
where
    G: Send + Sync + 'static,
{
    if bytes.is_empty() {
        return bytes;
    }
    Bytes::from_owner(GuardedBytes {
        bytes,
        _guard: guard,
    })
}

struct GuardedBytes<G> {
    bytes: Bytes,
    _guard: Arc<G>,
}

impl<G> AsRef<[u8]> for GuardedBytes<G> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
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

    pub(crate) fn with_guard<G: Send + Sync + 'static>(mut self, guard: Arc<G>) -> Self {
        self.prefix = with_bytes_guard(self.prefix, Arc::clone(&guard));
        self.pending = self
            .pending
            .into_iter()
            .map(|frame| frame.map_data(|bytes| with_bytes_guard(bytes, Arc::clone(&guard))))
            .collect();
        self
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
