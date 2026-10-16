use std::borrow::Cow;
use std::net::IpAddr;

use http::header::{COOKIE, HeaderMap};
use http::{Method, StatusCode, Uri};

use crate::decoding::{
    decoded_body_forms, normalize_path, percent_decode_forms, query_decode_forms,
};
use crate::protection::normalize_ip;

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
            path_forms: path_forms(uri.path()),
            query_forms: uri.query().map(query_decode_forms).unwrap_or_default(),
            headers,
            body,
            body_forms: if decode_body && !body.is_empty() {
                decoded_body_forms(body, headers)
            } else {
                Vec::new()
            },
            source_ip: normalize_ip(source_ip),
        }
    }
}

/// Percent-decoded variants of a path plus its normalized form, so rules see
/// the same path an upstream server that merges slashes and resolves dot
/// segments would route on.
fn path_forms(path: &str) -> Vec<Cow<'_, str>> {
    let mut forms = percent_decode_forms(path);
    let last = forms.last().map(|form| form.as_ref()).unwrap_or(path);
    if let Some(normalized) = normalize_path(last)
        && !forms
            .iter()
            .any(|form| form.as_ref() == normalized.as_str())
    {
        forms.push(Cow::Owned(normalized));
    }
    forms
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

pub fn cookie_pairs(headers: &HeaderMap) -> Vec<(Cow<'_, str>, Cow<'_, str>)> {
    let mut pairs = Vec::new();
    for value in headers.get_all(COOKIE) {
        match value.to_str() {
            Ok(value) => {
                for part in value.split(';') {
                    let part = part.trim();
                    if let Some((name, value)) = part.split_once('=') {
                        pairs.push((Cow::Borrowed(name.trim()), Cow::Borrowed(value.trim())));
                    }
                }
            }
            Err(_) => {
                let lossy = String::from_utf8_lossy(value.as_bytes());
                for part in lossy.split(';') {
                    let part = part.trim();
                    if let Some((name, value)) = part.split_once('=') {
                        pairs.push((
                            Cow::Owned(name.trim().to_owned()),
                            Cow::Owned(value.trim().to_owned()),
                        ));
                    }
                }
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
                "/files/../etc",
                "/etc"
            ]
        );
    }

    #[test]
    fn path_forms_include_the_normalized_path() {
        let headers = HeaderMap::new();
        for (raw, expected) in [
            ("//admin", "/admin"),
            ("/./admin", "/admin"),
            ("/x/../admin", "/admin"),
            ("/%2fadmin", "/admin"),
            ("/a/b/../../admin", "/admin"),
        ] {
            let uri: Uri = raw.parse().expect("valid URI");
            let view = view(&uri, &headers, b"");
            assert!(
                view.path_forms.iter().any(|form| form.as_ref() == expected),
                "expected {expected} among forms of {raw}: {:?}",
                view.path_forms
            );
        }
    }

    #[test]
    fn ipv4_mapped_source_addresses_are_normalized() {
        let headers = HeaderMap::new();
        let uri: Uri = "/".parse().expect("valid URI");
        let view = RequestView::new(
            &Method::GET,
            &uri,
            &headers,
            b"",
            "::ffff:10.0.0.1".parse().expect("valid IP"),
        );
        assert_eq!(
            view.source_ip,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn cookie_pairs_tolerate_non_utf8_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_bytes(b"session=abc; evil=\xff").expect("valid header bytes"),
        );
        let pairs = cookie_pairs(&headers);
        assert!(pairs.iter().any(|(name, _)| name.as_ref() == "session"));
        assert!(pairs.iter().any(|(name, _)| name.as_ref() == "evil"));
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
    fn query_forms_decode_plus_as_space() {
        let headers = HeaderMap::new();
        let uri: Uri = "/?q=union+select".parse().expect("valid URI");
        let view = view(&uri, &headers, b"");
        let forms: Vec<&str> = view.query_forms.iter().map(|form| form.as_ref()).collect();
        assert_eq!(forms, vec!["q=union+select", "q=union select"]);
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
