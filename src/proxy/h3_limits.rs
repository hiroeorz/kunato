//! Bounded QUIC transport for the HTTP/3 server.
//!
//! h3 0.0.8 applies `max_field_section_size` only after it has buffered a
//! complete HEADERS frame, so a client can declare a header block far above the
//! configured limit and make the WAF retain every delivered byte until
//! `header_read` expires. The wrapper in this module parses request-stream frame
//! headers as they pass through and fails the stream as soon as a HEADERS frame
//! declares more than the configured field-section limit, before the payload is
//! read. DATA and unknown frames are skipped by their declared length, so the
//! parser adds no buffer of its own beyond a nine-byte frame header.

use std::sync::{Mutex, PoisonError};

use bytes::Bytes;
use h3::error::Code;
use h3::quic::{
    self, BidiStream, ConnectionErrorIncoming, OpenStreams, StreamErrorIncoming, WriteBuf,
};

/// Largest frame header this parser needs: one type byte plus an eight-byte
/// QUIC varint length.
const MAX_FRAME_HEADER_BYTES: usize = 9;

/// Frame type of an HTTP/3 HEADERS frame (RFC 9114 section 6.2).
const HEADERS_FRAME_TYPE: u8 = 0x01;

/// QPACK encoding can make a header-block payload slightly larger than the
/// decoded field section it carries (literal prefixes, name references and
/// per-field overhead), so the declared frame length is allowed this much above
/// the configured field-section limit. The bound stays fixed, which is what
/// keeps the pre-parse buffer bounded.
const HEAD_FRAME_OVERHEAD_BYTES: u64 = 8 * 1024;

/// A request-stream frame header parser. It only needs the declared length of
/// each frame: a HEADERS frame above the limit is rejected, and every other
/// frame is skipped without retaining its payload.
#[derive(Default)]
struct FrameParser {
    header: Vec<u8>,
    skip: u64,
}

impl FrameParser {
    /// Consume bytes read from the request stream and fail when a HEADERS frame
    /// declares more than `limit` bytes.
    fn inspect(&mut self, data: &[u8], limit: u64) -> Result<(), String> {
        let mut index = 0;
        while index < data.len() {
            if self.skip > 0 {
                let available = (data.len() - index) as u64;
                let consumed = self.skip.min(available) as usize;
                index += consumed;
                self.skip -= consumed as u64;
                continue;
            }
            self.header.push(data[index]);
            index += 1;
            match frame_header(&self.header)? {
                Some((kind, length)) => {
                    if kind == HEADERS_FRAME_TYPE && length > limit {
                        return Err(format!(
                            "HEADERS frame declares {length} bytes, over the {limit}-byte limit"
                        ));
                    }
                    self.header.clear();
                    self.skip = length;
                }
                None if self.header.len() > MAX_FRAME_HEADER_BYTES => {
                    return Err("malformed frame header".to_owned());
                }
                None => {}
            }
        }
        Ok(())
    }
}

/// Parse one frame header. `Ok(None)` means the accumulated bytes are not enough
/// yet; `Err` means the bytes cannot be a valid header.
fn frame_header(header: &[u8]) -> Result<Option<(u8, u64)>, String> {
    let Some(&kind) = header.first() else {
        return Ok(None);
    };
    let Some(&first) = header.get(1) else {
        return Ok(None);
    };
    let size = 1usize << (first >> 6);
    if header.len() < 1 + size {
        return Ok(None);
    }
    let mut length = u64::from(first & 0x3f);
    for &byte in &header[2..1 + size] {
        length = (length << 8) | u64::from(byte);
    }
    Ok(Some((kind, length)))
}

/// Shared frame-limit state for the two halves of one request stream.
struct StreamLimit {
    max_field_section_bytes: u64,
    parser: Mutex<FrameParser>,
}

impl StreamLimit {
    fn new(max_field_section_bytes: u64) -> Self {
        Self {
            max_field_section_bytes: max_field_section_bytes
                .saturating_add(HEAD_FRAME_OVERHEAD_BYTES),
            parser: Mutex::new(FrameParser::default()),
        }
    }

    fn inspect(&self, data: &[u8]) -> Result<(), StreamErrorIncoming> {
        self.parser
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .inspect(data, self.max_field_section_bytes)
            .map_err(|message| {
                StreamErrorIncoming::Unknown(Box::new(std::io::Error::other(message)))
            })
    }
}

/// An `h3_quinn` connection that bounds the request-stream frames it delivers
/// to h3 by their declared length.
pub(crate) struct BoundedConnection {
    inner: h3_quinn::Connection,
    max_field_section_bytes: u64,
}

impl BoundedConnection {
    pub(crate) fn new(inner: h3_quinn::Connection, max_field_section_bytes: u64) -> Self {
        Self {
            inner,
            max_field_section_bytes,
        }
    }

    fn bidi(&self, inner: h3_quinn::BidiStream<Bytes>) -> BoundedBidi {
        BoundedBidi {
            inner,
            limit: std::sync::Arc::new(StreamLimit::new(self.max_field_section_bytes)),
        }
    }
}

/// The outgoing-stream handle of a [`BoundedConnection`].
pub(crate) struct BoundedOpen {
    inner: h3_quinn::OpenStreams,
    max_field_section_bytes: u64,
}

impl OpenStreams<Bytes> for BoundedOpen {
    type BidiStream = BoundedBidi;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx) {
            core::task::Poll::Ready(Ok(inner)) => core::task::Poll::Ready(Ok(BoundedBidi {
                inner,
                limit: std::sync::Arc::new(StreamLimit::new(self.max_field_section_bytes)),
            })),
            core::task::Poll::Ready(Err(err)) => core::task::Poll::Ready(Err(err)),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl OpenStreams<Bytes> for BoundedConnection {
    type BidiStream = BoundedBidi;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx) {
            core::task::Poll::Ready(Ok(inner)) => core::task::Poll::Ready(Ok(self.bidi(inner))),
            core::task::Poll::Ready(Err(err)) => core::task::Poll::Ready(Err(err)),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl quic::Connection<Bytes> for BoundedConnection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = BoundedOpen;

    fn poll_accept_recv(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx) {
            core::task::Poll::Ready(Ok(inner)) => core::task::Poll::Ready(Ok(self.bidi(inner))),
            core::task::Poll::Ready(Err(err)) => core::task::Poll::Ready(Err(err)),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        BoundedOpen {
            inner: quic::Connection::<Bytes>::opener(&self.inner),
            max_field_section_bytes: self.max_field_section_bytes,
        }
    }
}

/// A bidirectional request stream that enforces the frame limit on its
/// received bytes.
pub(crate) struct BoundedBidi {
    inner: h3_quinn::BidiStream<Bytes>,
    limit: std::sync::Arc<StreamLimit>,
}

impl quic::RecvStream for BoundedBidi {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match quic::RecvStream::poll_data(&mut self.inner, cx) {
            core::task::Poll::Ready(Ok(Some(data))) => match self.limit.inspect(&data) {
                Ok(()) => core::task::Poll::Ready(Ok(Some(data))),
                Err(err) => core::task::Poll::Ready(Err(err)),
            },
            other => other,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        quic::RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> quic::StreamId {
        quic::RecvStream::recv_id(&self.inner)
    }
}

impl quic::SendStream<Bytes> for BoundedBidi {
    fn poll_ready(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_ready(&mut self.inner, cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        quic::SendStream::<Bytes>::send_data(&mut self.inner, data)
    }

    fn poll_finish(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_finish(&mut self.inner, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        quic::SendStream::<Bytes>::reset(&mut self.inner, reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        quic::SendStream::<Bytes>::send_id(&self.inner)
    }
}

impl BidiStream<Bytes> for BoundedBidi {
    type SendStream = BoundedSend;
    type RecvStream = BoundedRecv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = BidiStream::<Bytes>::split(self.inner);
        (
            BoundedSend { inner: send },
            BoundedRecv {
                inner: recv,
                limit: self.limit,
            },
        )
    }
}

/// The sending half of a [`BoundedBidi`].
pub(crate) struct BoundedSend {
    inner: h3_quinn::SendStream<Bytes>,
}

impl quic::SendStream<Bytes> for BoundedSend {
    fn poll_ready(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_ready(&mut self.inner, cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        quic::SendStream::<Bytes>::send_data(&mut self.inner, data)
    }

    fn poll_finish(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), StreamErrorIncoming>> {
        quic::SendStream::<Bytes>::poll_finish(&mut self.inner, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        quic::SendStream::<Bytes>::reset(&mut self.inner, reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        quic::SendStream::<Bytes>::send_id(&self.inner)
    }
}

/// The receiving half of a [`BoundedBidi`].
pub(crate) struct BoundedRecv {
    inner: h3_quinn::RecvStream,
    limit: std::sync::Arc<StreamLimit>,
}

impl quic::RecvStream for BoundedRecv {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match quic::RecvStream::poll_data(&mut self.inner, cx) {
            core::task::Poll::Ready(Ok(Some(data))) => match self.limit.inspect(&data) {
                Ok(()) => core::task::Poll::Ready(Ok(Some(data))),
                Err(err) => core::task::Poll::Ready(Err(err)),
            },
            other => other,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        quic::RecvStream::stop_sending(&mut self.inner, error_code);
    }

    fn recv_id(&self) -> quic::StreamId {
        quic::RecvStream::recv_id(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_block_over_the_limit_is_rejected_from_its_declared_length() {
        // Type 0x01 (HEADERS) with a one-byte varint length of 40.
        let mut parser = FrameParser::default();
        assert!(parser.inspect(&[0x01, 40], 32).is_err());
    }

    #[test]
    fn a_head_block_at_the_limit_is_accepted() {
        let mut parser = FrameParser::default();
        assert!(parser.inspect(&[0x01, 32], 32).is_ok());
        assert!(parser.inspect(&[0u8; 32], 32).is_ok());
    }

    #[test]
    fn data_frames_are_skipped_without_a_size_limit() {
        // DATA (0x00) declaring four bytes, then a HEADERS frame under the limit.
        let mut parser = FrameParser::default();
        assert!(parser.inspect(&[0x00, 4, 1, 2, 3, 4], 32).is_ok());
        assert!(parser.inspect(&[0x01, 10], 32).is_ok());
        assert!(parser.inspect(&[0u8; 10], 32).is_ok());
    }

    #[test]
    fn a_huge_declared_headers_length_is_rejected_from_the_first_bytes() {
        // HEADERS with a four-byte varint length of 268435456 (256 MiB); the
        // rejection must happen as soon as the five header bytes are present,
        // before any payload byte is delivered.
        let mut parser = FrameParser::default();
        assert!(parser.inspect(&[0x01, 0x90], 32 * 1024).is_ok());
        assert!(parser.inspect(&[0x00, 0x00], 32 * 1024).is_ok());
        assert!(parser.inspect(&[0x00], 32 * 1024).is_err());
    }

    #[test]
    fn a_headers_frame_after_a_skipped_body_is_still_checked() {
        // HEADERS (10, under limit), DATA (40), then an over-limit trailer.
        let mut parser = FrameParser::default();
        assert!(parser.inspect(&[0x01, 10], 32).is_ok());
        assert!(parser.inspect(&[0u8; 10], 32).is_ok());
        assert!(parser.inspect(&[0x00, 40], 32).is_ok());
        assert!(parser.inspect(&[0u8; 40], 32).is_ok());
        assert!(parser.inspect(&[0x01, 33], 32).is_err());
    }
}
