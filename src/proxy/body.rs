//! Minimal HTTP body utilities used by the proxy, clients, and tests.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};

use super::BoxError;

pub trait BodyExt: Body + Sized {
    /// Poll the next body frame without pinning the caller.
    fn frame(&mut self) -> FrameFuture<'_, Self>
    where
        Self: Unpin,
    {
        FrameFuture { body: self }
    }

    /// Collect the whole body. The caller is responsible for bounding the body
    /// size; use `frame()` when a read must be limited.
    fn collect(self) -> Collect<Self>
    where
        Self: Unpin,
    {
        Collect {
            body: self,
            data: Vec::new(),
            trailers: None,
        }
    }

    fn boxed(self) -> BoxBody<Self::Data, Self::Error>
    where
        Self: Send + Sync + 'static,
        Self::Data: 'static,
        Self::Error: 'static,
    {
        let inner: Pin<
            Box<dyn Body<Data = Self::Data, Error = Self::Error> + Send + Sync + 'static>,
        > = Box::pin(self);
        BoxBody { inner }
    }

    fn map_err<F, E>(self, map: F) -> MapErr<Self, F>
    where
        F: FnMut(Self::Error) -> E,
    {
        MapErr { body: self, map }
    }
}

impl<B: Body> BodyExt for B {}

pub struct FrameFuture<'a, B: Body> {
    body: &'a mut B,
}

impl<B> Future for FrameFuture<'_, B>
where
    B: Body + Unpin,
{
    type Output = Option<Result<Frame<B::Data>, B::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.get_mut().body).poll_frame(cx)
    }
}

pub struct Full<T> {
    data: Option<T>,
}

impl<T: Buf> Full<T> {
    pub fn new(data: T) -> Self {
        let data = if data.has_remaining() {
            Some(data)
        } else {
            None
        };
        Self { data }
    }
}

impl<T: Buf + Unpin + 'static> Body for Full<T> {
    type Data = T;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        Poll::Ready(this.data.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        hint.set_exact(
            self.data
                .as_ref()
                .map(|data| data.remaining() as u64)
                .unwrap_or(0),
        );
        hint
    }
}

pub struct BoxBody<D, E> {
    inner: Pin<Box<dyn Body<Data = D, Error = E> + Send + Sync + 'static>>,
}

impl<D: Buf, E> Body for BoxBody<D, E> {
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub struct MapErr<B, F> {
    body: B,
    map: F,
}

impl<B, F, E> Body for MapErr<B, F>
where
    B: Body + Unpin,
    F: FnMut(B::Error) -> E + Unpin,
{
    type Data = B::Data;
    type Error = E;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err((this.map)(error)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

pub struct Collect<B: Body> {
    body: B,
    data: Vec<B::Data>,
    trailers: Option<HeaderMap>,
}

impl<B> Future for Collect<B>
where
    B: Body + Unpin,
    B::Data: Unpin,
{
    type Output = Result<Collected<B::Data>, B::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(Collected {
                        data: std::mem::take(&mut this.data),
                        trailers: this.trailers.take(),
                    }));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.data.push(data),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            this.trailers = Some(trailers);
                        }
                    }
                },
            }
        }
    }
}

pub struct Collected<D> {
    data: Vec<D>,
    trailers: Option<HeaderMap>,
}

impl<D> Collected<D> {
    pub fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }
}

impl<D: Buf> Collected<D> {
    pub fn to_bytes(self) -> Bytes {
        let mut buffer = BytesMut::new();
        for chunk in self.data {
            buffer.put(chunk);
        }
        buffer.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::{BodyExt, BoxBody, Full};
    use crate::proxy::BoxError;
    use bytes::Bytes;
    use hyper::body::Body;

    #[tokio::test]
    async fn empty_full_is_end_stream_and_has_no_frames() {
        let mut body = Full::new(Bytes::new());
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn boxed_full_collects_all_data() {
        let body: BoxBody<Bytes, BoxError> = Full::new(Bytes::from_static(b"abc")).boxed();
        let collected = body.collect().await.expect("collect");
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"abc"));
    }

    #[tokio::test]
    async fn full_size_hint_is_exact() {
        let body = Full::new(Bytes::from_static(b"abcd"));
        assert_eq!(body.size_hint().exact(), Some(4));
        let empty = Full::new(Bytes::new());
        assert_eq!(empty.size_hint().exact(), Some(0));
    }
}
