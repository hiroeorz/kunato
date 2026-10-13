use std::io::Read;

use brotli_decompressor::Decompressor as BrotliDecoder;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue};

const DECODE_BUFFER_BYTES: usize = 8 * 1024;

pub fn decode_content_encoding(body: &[u8], headers: &HeaderMap, limit: usize) -> Option<Vec<u8>> {
    if body.is_empty() || limit == 0 {
        return None;
    }
    let encoding = single_encoding(headers.get(CONTENT_ENCODING)?)?;
    let decoded = match encoding.as_str() {
        "gzip" | "x-gzip" => read_bounded(GzDecoder::new(body), limit),
        "deflate" => decode_deflate(body, limit),
        "br" => read_bounded(BrotliDecoder::new(body, DECODE_BUFFER_BYTES), limit),
        _ => return None,
    };
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

pub fn decode_body_format(body: &[u8], headers: &HeaderMap) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let media_type = headers
        .get(CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();

    if media_type == "application/x-www-form-urlencoded" {
        Some(form_decode(body))
    } else if media_type == "application/json" || media_type.ends_with("+json") {
        Some(json_unescape(body))
    } else {
        None
    }
}

fn single_encoding(value: &HeaderValue) -> Option<String> {
    let mut encoding: Option<String> = None;
    for token in value.to_str().ok()?.split(',') {
        let token = token.trim();
        if token.is_empty() || token.eq_ignore_ascii_case("identity") {
            continue;
        }
        if encoding.is_some() {
            return None;
        }
        encoding = Some(token.to_ascii_lowercase());
    }
    encoding
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0u8; DECODE_BUFFER_BYTES];
    while output.len() < limit {
        let want = (limit - output.len()).min(buffer.len());
        match reader.read(&mut buffer[..want]) {
            Ok(0) | Err(_) => break,
            Ok(read) => output.extend_from_slice(&buffer[..read]),
        }
    }
    output
}

fn decode_deflate(input: &[u8], limit: usize) -> Vec<u8> {
    let decoded = read_bounded(ZlibDecoder::new(input), limit);
    if decoded.is_empty() {
        read_bounded(DeflateDecoder::new(input), limit)
    } else {
        decoded
    }
}

fn form_decode(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        match body[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < body.len() => {
                match (hex_value(body[index + 1]), hex_value(body[index + 2])) {
                    (Some(high), Some(low)) => {
                        output.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        output.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

fn json_unescape(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        let byte = body[index];
        if byte != b'\\' {
            output.push(byte);
            index += 1;
            continue;
        }

        let Some(&escape) = body.get(index + 1) else {
            output.push(byte);
            break;
        };

        match escape {
            b'u' => {
                let Some(high) = body.get(index + 2..index + 6).and_then(hex4) else {
                    output.push(byte);
                    index += 1;
                    continue;
                };
                if (0xd800..=0xdbff).contains(&high)
                    && body.get(index + 6) == Some(&b'\\')
                    && body.get(index + 7) == Some(&b'u')
                    && let Some(low) = body.get(index + 8..index + 12).and_then(hex4)
                    && (0xdc00..=0xdfff).contains(&low)
                {
                    let code =
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                    push_char(&mut output, code);
                    index += 12;
                    continue;
                }
                push_char(&mut output, u32::from(high));
                index += 6;
            }
            b'"' | b'\\' | b'/' => {
                output.push(escape);
                index += 2;
            }
            b'b' => {
                output.push(0x08);
                index += 2;
            }
            b'f' => {
                output.push(0x0c);
                index += 2;
            }
            b'n' => {
                output.push(b'\n');
                index += 2;
            }
            b'r' => {
                output.push(b'\r');
                index += 2;
            }
            b't' => {
                output.push(b'\t');
                index += 2;
            }
            _ => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let mut value = 0u16;
    for &byte in bytes {
        value = value.checked_mul(16)? + u16::from(hex_value(byte)?);
    }
    Some(value)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn push_char(output: &mut Vec<u8>, code: u32) {
    if let Some(character) = char::from_u32(code) {
        let mut buffer = [0u8; 4];
        output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
    } else {
        output.extend_from_slice("\u{FFFD}".as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName};

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("zlib write");
        encoder.finish().expect("zlib finish")
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(&mut &data[..], &mut output, &params).expect("brotli compress");
        output
    }

    fn headers(name: HeaderName, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name, HeaderValue::from_str(value).expect("valid header"));
        map
    }

    #[test]
    fn gzip_body_is_decoded() {
        let payload = b"q=1 union select password";
        let decoded = decode_content_encoding(
            &gzip(payload),
            &headers(CONTENT_ENCODING, "gzip"),
            payload.len(),
        );
        assert_eq!(decoded.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn zlib_and_raw_deflate_bodies_are_decoded() {
        let payload = b"q=1 union select password";
        for encoded in [zlib(payload), raw_deflate(payload)] {
            let decoded = decode_content_encoding(
                &encoded,
                &headers(CONTENT_ENCODING, "deflate"),
                payload.len(),
            );
            assert_eq!(decoded.as_deref(), Some(&payload[..]));
        }
    }

    #[test]
    fn brotli_body_is_decoded() {
        let payload = b"q=1 union select password";
        let decoded = decode_content_encoding(
            &brotli(payload),
            &headers(CONTENT_ENCODING, "br"),
            payload.len(),
        );
        assert_eq!(decoded.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn stacked_encodings_are_left_uninspected() {
        let payload = b"q=1 union select password";
        let stacked = zlib(&gzip(payload));
        assert!(
            decode_content_encoding(
                &stacked,
                &headers(CONTENT_ENCODING, "gzip, deflate"),
                payload.len()
            )
            .is_none()
        );
    }

    #[test]
    fn decoded_output_is_bounded() {
        let encoded = gzip(&vec![b'a'; 64 * 1024]);
        let decoded = decode_content_encoding(&encoded, &headers(CONTENT_ENCODING, "gzip"), 128);
        assert_eq!(decoded.map(|body| body.len()), Some(128));
    }

    #[test]
    fn unknown_or_invalid_encodings_fall_back() {
        let payload = b"payload";
        assert!(
            decode_content_encoding(payload, &headers(CONTENT_ENCODING, "zstd"), 1024).is_none()
        );
        assert!(
            decode_content_encoding(payload, &headers(CONTENT_ENCODING, "gzip"), 1024).is_none()
        );
        assert!(decode_content_encoding(payload, &HeaderMap::new(), 1024).is_none());
        assert!(
            decode_content_encoding(
                payload,
                &headers(CONTENT_ENCODING, "gzip, deflate, br, zstd"),
                1024
            )
            .is_none()
        );
    }

    #[test]
    fn form_bodies_are_decoded() {
        let decoded = decode_body_format(
            b"q=%27+union%2Fselect+&x=1",
            &headers(CONTENT_TYPE, "application/x-www-form-urlencoded"),
        );
        assert_eq!(decoded.as_deref(), Some(&b"q=' union/select &x=1"[..]));
    }

    #[test]
    fn json_string_escapes_are_decoded() {
        let body = br#"{"q":"\u0075nion\u0020select","path":"a\/b","note":"say \"hi\"","emoji":"\uD83D\uDE00"}"#;
        let decoded = decode_body_format(
            body,
            &headers(CONTENT_TYPE, "application/json; charset=utf-8"),
        )
        .expect("json decoded");
        let text = String::from_utf8(decoded).expect("valid utf8");
        assert!(text.contains("union select"));
        assert!(text.contains("a/b"));
        assert!(text.contains("say \"hi\""));
        assert!(text.contains('\u{1F600}'));
    }

    #[test]
    fn json_suffix_content_types_are_decoded() {
        let decoded = decode_body_format(
            br#"{"q":"\u0075nion"}"#,
            &headers(CONTENT_TYPE, "application/problem+json"),
        );
        assert_eq!(decoded.as_deref(), Some(&br#"{"q":"union"}"#[..]));
    }

    #[test]
    fn other_content_types_are_left_alone() {
        assert!(decode_body_format(b"<script>", &headers(CONTENT_TYPE, "text/html")).is_none());
        assert!(decode_body_format(b"plain", &HeaderMap::new()).is_none());
        assert!(decode_body_format(b"", &headers(CONTENT_TYPE, "application/json")).is_none());
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..5_000 {
            let length = (next_random(&mut state) % 48) as usize;
            let body: Vec<u8> = (0..length)
                .map(|_| (next_random(&mut state) & 0xff) as u8)
                .collect();
            let _ = decode_body_format(
                &body,
                &headers(CONTENT_TYPE, "application/x-www-form-urlencoded"),
            );
            let _ = decode_body_format(&body, &headers(CONTENT_TYPE, "application/json"));
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "gzip"), 1024);
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "deflate"), 1024);
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "br"), 1024);
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state ^ (*state >> 33)
    }
}
