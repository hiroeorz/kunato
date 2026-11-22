use std::borrow::Cow;
use std::net::IpAddr;

use http::header::{COOKIE, HeaderMap};
use http::uri::Authority;
use http::{Method, StatusCode, Uri};

use crate::decoding::{
    decoded_body_forms, mask_multipart_file_payloads, normalize_path, percent_decode_forms,
    query_decode_forms,
};
use crate::geoip::CountryCode;
use crate::protection::normalize_ip;

pub struct RequestView<'a> {
    pub method: &'a Method,
    pub path_forms: Vec<Cow<'a, str>>,
    pub query_forms: Vec<Cow<'a, str>>,
    pub headers: &'a HeaderMap,
    /// Authority the client used to reach the proxy, from an absolute request
    /// target or the `Host` header. Used to ignore same-origin browser
    /// metadata headers when payload rules inspect headers.
    pub authority: Option<Authority>,
    pub body: &'a [u8],
    /// Bytes matched by body targets: the raw body with multipart file payloads
    /// masked out. Form field values, part headers, and boundaries remain in
    /// scope; uploaded file content is inspected by the upload checks instead.
    /// The text is converted once so every body rule reuses it instead of
    /// running a lossy UTF-8 conversion per rule.
    pub match_body: Cow<'a, str>,
    /// Decoded body variants, already converted to text once. Multipart
    /// messages with several boundaries or forms past the per-body budget set
    /// `body_forms_complete` to false instead of returning a partial set.
    pub body_forms: Vec<String>,
    /// False when the decoded body forms exceed the inspection budget or a
    /// multipart body declares several boundaries. Evaluation must fail closed
    /// instead of matching against a partial form set.
    pub body_forms_complete: bool,
    /// True when the inspected body is only a prefix of the message (either
    /// because the raw body exceeded the limit or because decoding could not
    /// finish). ALLOW rules must not trust an incomplete body.
    pub body_truncated: bool,
    /// True when the request path is a configured content route, where the body
    /// is authored content rather than request parameters. Body targets are
    /// skipped for every rule, so a body-only rule cannot match while other
    /// targets of the same rule are still evaluated.
    pub body_rules_exempt: bool,
    pub source_ip: IpAddr,
    /// Country resolved from `source_ip` once per request. `None` means the
    /// address is not covered by the active country database.
    pub country: Option<CountryCode>,
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
        let inspect_body = decode_body && !body.is_empty();
        let decoded = if inspect_body {
            Some(decoded_body_forms(body, headers))
        } else {
            None
        };
        let (body_forms, body_forms_complete) = match decoded {
            Some(decoded) => (decoded.forms, decoded.complete),
            None => (Vec::new(), true),
        };
        let authority = uri.authority().cloned().or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<Authority>().ok())
        });

        Self {
            method,
            authority,
            path_forms: path_forms(uri.path()),
            query_forms: uri.query().map(query_decode_forms).unwrap_or_default(),
            headers,
            body,
            match_body: if inspect_body {
                match mask_multipart_file_payloads(body, headers) {
                    Some(masked) => Cow::Owned(String::from_utf8_lossy(&masked).into_owned()),
                    None => String::from_utf8_lossy(body),
                }
            } else {
                String::from_utf8_lossy(body)
            },
            body_forms,
            body_forms_complete,
            body_truncated: false,
            body_rules_exempt: false,
            source_ip: normalize_ip(source_ip),
            country: None,
        }
    }

    pub fn with_country(mut self, country: Option<CountryCode>) -> Self {
        self.country = country;
        self
    }

    pub fn with_body_truncated(mut self, body_truncated: bool) -> Self {
        self.body_truncated = body_truncated;
        self
    }

    pub fn with_body_rules_exempt(mut self, body_rules_exempt: bool) -> Self {
        self.body_rules_exempt = body_rules_exempt;
        self
    }

    /// True when `value` is an absolute HTTP(S) URL whose authority matches
    /// the authority this request was sent to. Same-origin `Referer` and
    /// `Origin` values are browser metadata, not attacker-controlled SSRF
    /// targets, and must not trigger header payload rules.
    pub fn is_same_origin_url(&self, value: &str) -> bool {
        let Ok(uri) = value.parse::<Uri>() else {
            return false;
        };
        let Some(scheme) = uri.scheme_str() else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return false;
        }
        let (Some(reference), Some(own)) = (uri.authority(), self.authority.as_ref()) else {
            return false;
        };
        same_authority(own, reference)
    }
}

fn same_authority(left: &Authority, right: &Authority) -> bool {
    if !left.host().eq_ignore_ascii_case(right.host()) {
        return false;
    }
    match (left.port_u16(), right.port_u16()) {
        (Some(left), Some(right)) => left == right,
        (Some(port), None) | (None, Some(port)) => port == 80 || port == 443,
        (None, None) => true,
    }
}

/// Percent-decoded variants of a path plus its normalized form, so rules see
/// the same path an upstream server that merges slashes and resolves dot
/// segments would route on.
pub(crate) fn path_forms(path: &str) -> Vec<Cow<'_, str>> {
    let mut forms = percent_decode_forms(path);
    // Normalize every decode stage, not just the last one. An origin that
    // decodes exactly once and then resolves dot segments routes on a path
    // that the last stage never produces, so matching only the final
    // normalized form lets `%252f` plus `..` slip past path rules, ALLOW
    // rules, and content routes.
    let mut normalized = Vec::new();
    for form in &forms {
        let Some(candidate) = normalize_path(form.as_ref()) else {
            continue;
        };
        if forms.iter().any(|existing| existing.as_ref() == candidate)
            || normalized
                .iter()
                .any(|existing: &String| existing == &candidate)
        {
            continue;
        }
        normalized.push(candidate);
    }
    forms.extend(normalized.into_iter().map(Cow::Owned));
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
                    if part.is_empty() {
                        continue;
                    }
                    if let Some((name, value)) = part.split_once('=') {
                        pairs.push((Cow::Borrowed(name.trim()), Cow::Borrowed(value.trim())));
                    } else {
                        // PHP and several frameworks expose a valueless token
                        // as a cookie name with an empty value. Dropping it
                        // would hide that name from cookie-name rules.
                        pairs.push((Cow::Borrowed(part), Cow::Borrowed("")));
                    }
                }
            }
            Err(_) => {
                let lossy = String::from_utf8_lossy(value.as_bytes());
                for part in lossy.split(';') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some((name, value)) = part.split_once('=') {
                        pairs.push((
                            Cow::Owned(name.trim().to_owned()),
                            Cow::Owned(value.trim().to_owned()),
                        ));
                    } else {
                        pairs.push((Cow::Owned(part.to_owned()), Cow::Owned(String::new())));
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
    fn every_decode_stage_is_normalized() {
        let headers = HeaderMap::new();
        let uri: Uri = "/allowed/a%252fb/../../secret".parse().expect("valid URI");
        let view = view(&uri, &headers, b"");
        let forms: Vec<&str> = view.path_forms.iter().map(|form| form.as_ref()).collect();
        assert!(forms.contains(&"/secret"), "{forms:?}");
        assert!(
            !forms.iter().all(|form| form.starts_with("/allowed/")),
            "one decode stage routes outside the allowed prefix: {forms:?}"
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
        let forms: Vec<&str> = view.body_forms.iter().map(String::as_str).collect();
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
