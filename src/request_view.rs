use std::borrow::Cow;
use std::net::IpAddr;

use http::header::{COOKIE, HeaderMap};
use http::{Method, StatusCode, Uri};

use crate::decoding::decode_body_format;

pub struct RequestView<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub decoded_path: Cow<'a, str>,
    pub query: Option<&'a str>,
    pub decoded_query: Option<Cow<'a, str>>,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub decoded_body: Option<Vec<u8>>,
    pub source_ip: IpAddr,
}

impl<'a> RequestView<'a> {
    pub fn new(
        method: &'a Method,
        uri: &'a Uri,
        headers: &'a HeaderMap,
        body: &'a [u8],
        source_ip: IpAddr,
    ) -> Self {
        Self::with_body_decoding(method, uri, headers, body, source_ip, true)
    }

    pub fn with_body_decoding(
        method: &'a Method,
        uri: &'a Uri,
        headers: &'a HeaderMap,
        body: &'a [u8],
        source_ip: IpAddr,
        decode_body: bool,
    ) -> Self {
        let path = uri.path();
        let query = uri.query();
        Self {
            method,
            path,
            decoded_path: percent_decode(path),
            query,
            decoded_query: query.map(percent_decode),
            headers,
            body,
            decoded_body: if decode_body {
                decode_body_format(body, headers)
            } else {
                None
            },
            source_ip,
        }
    }
}

pub struct ResponseView<'a> {
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub body_truncated: bool,
}

impl<'a> ResponseView<'a> {
    pub fn new(
        status: StatusCode,
        headers: &'a HeaderMap,
        body: &'a [u8],
        body_truncated: bool,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            body_truncated,
        }
    }
}

pub fn percent_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('%') {
        return Cow::Borrowed(input);
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }

    Cow::Owned(String::from_utf8_lossy(&decoded).into_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn cookie_pairs(headers: &HeaderMap) -> Vec<(&str, &str)> {
    let mut pairs = Vec::new();
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(';') {
            let part = part.trim();
            if let Some((name, value)) = part.split_once('=') {
                pairs.push((name.trim(), value.trim()));
            }
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_plain_text_borrowed() {
        assert!(matches!(percent_decode("/plain/path"), Cow::Borrowed(_)));
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("%2e%2e%2f"), "../");
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn keeps_invalid_escapes() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn decodes_lossy_utf8() {
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..5_000 {
            let length = (next_random(&mut state) % 64) as usize;
            let text: String = (0..length)
                .map(|_| {
                    let byte = (next_random(&mut state) & 0x7f) as u8;
                    char::from(byte)
                })
                .collect();
            let _ = percent_decode(&text);
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state ^ (*state >> 33)
    }
}
