use std::borrow::Cow;
use std::net::IpAddr;

use http::header::{COOKIE, HeaderMap};
use http::{Method, StatusCode, Uri};

use crate::decoding::{decoded_body_forms, percent_decode_forms};

pub struct RequestView<'a> {
    pub method: &'a Method,
    pub path_forms: Vec<Cow<'a, str>>,
    pub query_forms: Vec<Cow<'a, str>>,
    pub headers: &'a HeaderMap,
    pub body: &'a [u8],
    pub body_forms: Vec<Vec<u8>>,
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
        Self {
            method,
            path_forms: percent_decode_forms(uri.path()),
            query_forms: uri.query().map(percent_decode_forms).unwrap_or_default(),
            headers,
            body,
            body_forms: if decode_body && !body.is_empty() {
                decoded_body_forms(body, headers)
            } else {
                Vec::new()
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
    use http::{HeaderMap, HeaderValue, Method, Uri};

    use super::*;

    fn view<'a>(uri: &'a Uri, headers: &'a HeaderMap, body: &'a [u8]) -> RequestView<'a> {
        RequestView::new(
            &Method::GET,
            uri,
            headers,
            body,
            "127.0.0.1".parse().expect("valid IP"),
        )
    }

    #[test]
    fn plain_path_keeps_a_single_borrowed_form() {
        let headers = HeaderMap::new();
        let uri: Uri = "/plain/path".parse().expect("valid URI");
        let view = view(&uri, &headers, b"");
        assert_eq!(view.path_forms.len(), 1);
        assert!(matches!(view.path_forms[0], Cow::Borrowed("/plain/path")));
        assert!(view.query_forms.is_empty());
    }

    #[test]
    fn path_forms_decode_twice() {
        let headers = HeaderMap::new();
        let uri: Uri = "/files/%252e%252e%252fetc".parse().expect("valid URI");
        let view = view(&uri, &headers, b"");
        let forms: Vec<&str> = view.path_forms.iter().map(|form| form.as_ref()).collect();
        assert_eq!(
            forms,
            vec![
                "/files/%252e%252e%252fetc",
                "/files/%2e%2e%2fetc",
                "/files/../etc"
            ]
        );
    }

    #[test]
    fn query_forms_stop_when_decoding_settles() {
        let headers = HeaderMap::new();
        let uri: Uri = "/?q=%2525".parse().expect("valid URI");
        let view = view(&uri, &headers, b"");
        let forms: Vec<&str> = view.query_forms.iter().map(|form| form.as_ref()).collect();
        assert_eq!(forms, vec!["q=%2525", "q=%25", "q=%"]);
    }

    #[test]
    fn body_forms_include_decoded_and_percent_passes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let uri: Uri = "/".parse().expect("valid URI");
        let view = view(&uri, &headers, b"q=%2527+union");
        let forms: Vec<&str> = view
            .body_forms
            .iter()
            .map(|form| std::str::from_utf8(form).expect("utf8"))
            .collect();
        assert_eq!(forms, vec!["q=%27 union", "q=' union"]);
    }

    #[test]
    fn body_forms_are_skipped_when_decoding_is_disabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let uri: Uri = "/".parse().expect("valid URI");
        let view = RequestView::with_body_decoding(
            &Method::POST,
            &uri,
            &headers,
            b"q=%27",
            "127.0.0.1".parse().expect("valid IP"),
            false,
        );
        assert!(view.body_forms.is_empty());
    }

    #[test]
    fn arbitrary_uri_forms_never_panic() {
        let headers = HeaderMap::new();
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..5_000 {
            let length = (next_random(&mut state) % 64) as usize;
            let text: String = (0..length)
                .map(|_| {
                    let byte = (next_random(&mut state) & 0x7f) as u8;
                    char::from(byte)
                })
                .collect();
            if let Ok(uri) = format!("/{text}?{text}").parse::<Uri>() {
                let view = view(&uri, &headers, b"");
                let _ = view.path_forms.len() + view.query_forms.len();
            }
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state ^ (*state >> 33)
    }
}
