//! Minimal HTTP/2 cleartext (h2c, prior knowledge) client.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::hpack;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

const MAX_FRAME_SIZE: usize = 16384;
const MAX_FRAME_READ: usize = 1024 * 1024;
const BOMB_FIELD_SIZE: usize = 1000;
const BOMB_FIELD_NAME: &str = "x-bomb";
const FIRST_DYNAMIC_INDEX: usize = 62;

pub struct H2Request<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub authority: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub hpack_bomb: Option<usize>,
    pub pad_header: Option<usize>,
}

pub fn send(stream: &mut TcpStream, request: &H2Request<'_>) -> Result<String, String> {
    stream
        .write_all(PREFACE)
        .map_err(|err| format!("write: {err}"))?;
    write_frame(stream, FRAME_SETTINGS, 0, 0, &[])?;

    let block = encode_headers(request);
    write_header_block(stream, &block, request.body.is_empty())?;
    write_body(stream, request.body)?;
    stream.flush().map_err(|err| format!("flush: {err}"))?;

    read_status(stream)
}

fn write_header_block(
    stream: &mut TcpStream,
    block: &[u8],
    end_stream: bool,
) -> Result<(), String> {
    let chunks: Vec<&[u8]> = block.chunks(MAX_FRAME_SIZE).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let mut flags = 0u8;
        if index + 1 == chunks.len() {
            flags |= FLAG_END_HEADERS;
        }
        if index == 0 {
            if end_stream {
                flags |= FLAG_END_STREAM;
            }
            write_frame(stream, FRAME_HEADERS, flags, 1, chunk)?;
        } else {
            write_frame(stream, FRAME_CONTINUATION, flags, 1, chunk)?;
        }
    }
    Ok(())
}

fn write_body(stream: &mut TcpStream, body: &[u8]) -> Result<(), String> {
    if body.is_empty() {
        return Ok(());
    }
    let chunks: Vec<&[u8]> = body.chunks(MAX_FRAME_SIZE).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let flags = if index + 1 == chunks.len() {
            FLAG_END_STREAM
        } else {
            0
        };
        write_frame(stream, FRAME_DATA, flags, 1, chunk)?;
    }
    Ok(())
}

fn read_status(stream: &mut TcpStream) -> Result<String, String> {
    loop {
        let frame = read_frame(stream)?;
        match frame.kind {
            FRAME_SETTINGS if frame.flags & FLAG_ACK == 0 => {
                write_frame(stream, FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
            }
            FRAME_PING if frame.flags & FLAG_ACK == 0 && frame.payload.len() == 8 => {
                write_frame(stream, FRAME_PING, FLAG_ACK, 0, &frame.payload)?;
            }
            FRAME_HEADERS if frame.stream_id == 1 => {
                let mut block = frame.payload;
                let mut end_headers = frame.flags & FLAG_END_HEADERS != 0;
                while !end_headers {
                    let continuation = read_frame(stream)?;
                    if continuation.kind != FRAME_CONTINUATION || continuation.stream_id != 1 {
                        return Err("unexpected frame between header fragments".to_owned());
                    }
                    end_headers = continuation.flags & FLAG_END_HEADERS != 0;
                    block.extend_from_slice(&continuation.payload);
                }
                let status = hpack::decode_status(&block)?;
                if (100..200).contains(&status) {
                    continue;
                }
                return Ok(status.to_string());
            }
            FRAME_RST_STREAM if frame.stream_id == 1 => {
                return Ok(format!(
                    "RST_STREAM({})",
                    error_name(frame_code(&frame.payload))
                ));
            }
            FRAME_GOAWAY => {
                let code = frame
                    .payload
                    .get(4..8)
                    .map(|bytes| u32::from_be_bytes(bytes.try_into().expect("four bytes")))
                    .unwrap_or(0);
                return Ok(format!("GOAWAY({})", error_name(code)));
            }
            _ => {}
        }
    }
}

struct Frame {
    kind: u8,
    flags: u8,
    stream_id: usize,
    payload: Vec<u8>,
}

fn read_frame(stream: &mut TcpStream) -> Result<Frame, String> {
    let mut head = [0u8; 9];
    stream
        .read_exact(&mut head)
        .map_err(|err| format!("read: {err}"))?;
    let length = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    if length > MAX_FRAME_READ {
        return Err(format!("frame too large: {length} bytes"));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|err| format!("read: {err}"))?;
    Ok(Frame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]) as usize,
        payload,
    })
}

fn write_frame(
    stream: &mut TcpStream,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), String> {
    let length = payload.len();
    if length > 0xff_ff_ff {
        return Err(format!("frame too large: {length} bytes"));
    }
    let mut head = [0u8; 9];
    head[0] = (length >> 16) as u8;
    head[1] = (length >> 8) as u8;
    head[2] = length as u8;
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&stream_id.to_be_bytes());
    stream
        .write_all(&head)
        .map_err(|err| format!("write: {err}"))?;
    stream
        .write_all(payload)
        .map_err(|err| format!("write: {err}"))
}

fn frame_code(payload: &[u8]) -> u32 {
    payload
        .get(0..4)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().expect("four bytes")))
        .unwrap_or(0)
}

fn error_name(code: u32) -> String {
    let name = match code {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x4 => "SETTINGS_TIMEOUT",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xa => "CONNECT_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => return format!("0x{code:x}"),
    };
    name.to_owned()
}

fn encode_headers(request: &H2Request<'_>) -> Vec<u8> {
    let mut block = Vec::new();

    match request.method {
        "GET" => block.push(0x82),
        "POST" => block.push(0x83),
        method => encode_literal_value(&mut block, 2, method.as_bytes()),
    }
    block.push(0x86);
    if request.target == "/" {
        block.push(0x84);
    } else {
        encode_literal_value(&mut block, 4, request.target.as_bytes());
    }
    encode_literal_value(&mut block, 1, request.authority.as_bytes());

    for (name, value) in request.headers {
        let name = name.to_ascii_lowercase();
        encode_literal_name(&mut block, &name, value.as_bytes());
    }

    if let Some(length) = request.pad_header {
        let value = vec![b'a'; length];
        encode_literal_name(&mut block, "x-pad", &value);
    }

    if let Some(repeats) = request.hpack_bomb {
        let value = vec![b'a'; BOMB_FIELD_SIZE];
        encode_indexed_literal(&mut block, BOMB_FIELD_NAME, &value);
        for _ in 0..repeats {
            block.push(0x80 | FIRST_DYNAMIC_INDEX as u8);
        }
    }

    block
}

fn encode_literal_name(block: &mut Vec<u8>, name: &str, value: &[u8]) {
    block.push(0x00);
    encode_string(block, name.as_bytes());
    encode_string(block, value);
}

fn encode_literal_value(block: &mut Vec<u8>, name_index: usize, value: &[u8]) {
    encode_int(block, 4, 0x00, name_index);
    encode_string(block, value);
}

fn encode_indexed_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
    block.push(0x40);
    encode_string(block, name.as_bytes());
    encode_string(block, value);
}

fn encode_string(block: &mut Vec<u8>, bytes: &[u8]) {
    encode_int(block, 7, 0x00, bytes.len());
    block.extend_from_slice(bytes);
}

fn encode_int(block: &mut Vec<u8>, prefix_bits: u8, pattern: u8, value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        block.push(pattern | value as u8);
        return;
    }
    block.push(pattern | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        block.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    block.push(rest as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(hpack_bomb: Option<usize>, pad_header: Option<usize>) -> H2Request<'a> {
        H2Request {
            method: "GET",
            target: "/check",
            authority: "127.0.0.1:8080",
            headers: &[],
            body: &[],
            hpack_bomb,
            pad_header,
        }
    }

    #[test]
    fn encodes_static_pseudo_headers() {
        let block = encode_headers(&request(None, None));
        assert_eq!(block[0], 0x82);
        assert_eq!(block[1], 0x86);
        assert_eq!(block[2], 0x04);
    }

    #[test]
    fn bomb_block_expands_to_many_fields() {
        let block = encode_headers(&request(Some(50), None));
        let fields = hpack::decode(&block).expect("decodes");
        let bombs = fields.iter().filter(|(name, _)| name == "x-bomb").count();
        assert_eq!(bombs, 51);
        let total: usize = fields
            .iter()
            .map(|(name, value)| name.len() + value.len() + 32)
            .sum();
        assert!(total > 50 * BOMB_FIELD_SIZE);
    }

    #[test]
    fn bomb_block_stays_compressed() {
        let block = encode_headers(&request(Some(400), None));
        assert!(
            block.len() < 2 * BOMB_FIELD_SIZE,
            "bomb block is {} bytes",
            block.len()
        );
    }

    #[test]
    fn pad_header_uses_continuation_frames() {
        let block = encode_headers(&request(None, Some(20000)));
        assert!(block.len() > MAX_FRAME_SIZE);
        let fields = hpack::decode(&block).expect("decodes");
        let pad = fields
            .iter()
            .find(|(name, _)| name == "x-pad")
            .expect("x-pad field");
        assert_eq!(pad.1.len(), 20000);
    }

    #[test]
    fn encodes_long_integers() {
        let mut block = Vec::new();
        encode_int(&mut block, 7, 0x00, 1000);
        assert_eq!(block, vec![0x7f, 0xe9, 0x06]);
    }
}
