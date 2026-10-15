use std::borrow::Cow;

use http::Method;
use http::header::HeaderName;
use ipnet::IpNet;
use regex::Regex;

use crate::request_view::{RequestView, ResponseView, cookie_pairs};

pub const TARGET_PATH: u8 = 1 << 0;
pub const TARGET_QUERY: u8 = 1 << 1;
pub const TARGET_BODY: u8 = 1 << 2;
pub const TARGET_COOKIES: u8 = 1 << 3;
pub const TARGET_HEADERS: u8 = 1 << 4;
pub const TARGET_RESPONSE_BODY: u8 = 1 << 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRange {
    pub start: u16,
    pub end: u16,
}

impl StatusRange {
    pub fn contains(self, status: u16) -> bool {
        (self.start..=self.end).contains(&status)
    }
}

/// Header values are matched lossily so that a single invalid byte cannot hide
/// an otherwise matching value (RFC 9110 allows obs-text bytes in field values).
fn header_text(value: &http::HeaderValue) -> Cow<'_, str> {
    String::from_utf8_lossy(value.as_bytes())
}

#[derive(Debug, Default)]
pub struct Matcher {
    pub paths: Vec<Regex>,
    pub methods: Option<Vec<Method>>,
    pub source_ips: Option<Vec<IpNet>>,
    pub headers: Vec<(HeaderName, Vec<Regex>)>,
    pub cookies: Vec<(String, Vec<Regex>)>,
    pub statuses: Vec<StatusRange>,
    pub response_headers: Vec<(HeaderName, Vec<Regex>)>,
    pub payload: Option<PayloadMatcher>,
}

#[derive(Debug)]
pub struct PayloadMatcher {
    pub regexes: Vec<Regex>,
    pub targets: u8,
}

impl Matcher {
    pub fn matches(&self, view: &RequestView<'_>) -> bool {
        self.matches_request(view) && self.matches_payload(view, None)
    }

    pub fn matches_response(&self, view: &RequestView<'_>, response: &ResponseView<'_>) -> bool {
        if !self.matches_request(view) {
            return false;
        }

        if !self.statuses.is_empty()
            && !self
                .statuses
                .iter()
                .any(|range| range.contains(response.status.as_u16()))
        {
            return false;
        }

        for (name, regexes) in &self.response_headers {
            let matched = response
                .headers
                .get_all(name)
                .iter()
                .any(|value| regexes.iter().any(|re| re.is_match(&header_text(value))));
            if !matched {
                return false;
            }
        }

        self.matches_payload(view, Some(response))
    }

    fn matches_request(&self, view: &RequestView<'_>) -> bool {
        if !self.paths.is_empty() {
            let matched = view
                .path_forms
                .iter()
                .any(|form| self.paths.iter().any(|regex| regex.is_match(form)));
            if !matched {
                return false;
            }
        }

        if let Some(methods) = &self.methods
            && !methods.contains(view.method)
        {
            return false;
        }

        if let Some(networks) = &self.source_ips
            && !networks
                .iter()
                .any(|network| network.contains(&view.source_ip))
        {
            return false;
        }

        for (name, regexes) in &self.headers {
            let matched = view
                .headers
                .get_all(name)
                .iter()
                .any(|value| regexes.iter().any(|re| re.is_match(&header_text(value))));
            if !matched {
                return false;
            }
        }

        for (name, regexes) in &self.cookies {
            let matched = cookie_pairs(view.headers)
                .iter()
                .any(|(cookie_name, value)| {
                    cookie_name.as_ref() == name.as_str()
                        && regexes.iter().any(|re| re.is_match(value.as_ref()))
                });
            if !matched {
                return false;
            }
        }

        true
    }

    fn matches_payload(&self, view: &RequestView<'_>, response: Option<&ResponseView<'_>>) -> bool {
        let Some(payload) = &self.payload else {
            return true;
        };
        payload.matches(view, response)
    }
}

impl PayloadMatcher {
    fn matches(&self, view: &RequestView<'_>, response: Option<&ResponseView<'_>>) -> bool {
        if self.targets & TARGET_PATH != 0 && view.path_forms.iter().any(|form| self.hits(form)) {
            return true;
        }

        if self.targets & TARGET_QUERY != 0 && view.query_forms.iter().any(|form| self.hits(form)) {
            return true;
        }

        if self.targets & TARGET_BODY != 0
            && ((!view.body.is_empty() && self.hits(&String::from_utf8_lossy(view.body)))
                || view
                    .body_forms
                    .iter()
                    .any(|form| self.hits(&String::from_utf8_lossy(form))))
        {
            return true;
        }

        if self.targets & TARGET_COOKIES != 0
            && cookie_pairs(view.headers)
                .iter()
                .any(|(_, value)| self.hits(value.as_ref()))
        {
            return true;
        }

        if self.targets & TARGET_HEADERS != 0
            && view
                .headers
                .values()
                .any(|value| self.hits(&header_text(value)))
        {
            return true;
        }

        if self.targets & TARGET_RESPONSE_BODY != 0
            && let Some(response) = response
            && !response.body.is_empty()
            && self.hits(&String::from_utf8_lossy(response.body))
        {
            return true;
        }

        false
    }

    fn hits(&self, text: &str) -> bool {
        self.regexes.iter().any(|regex| regex.is_match(text))
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};

    use super::*;

    fn view<'a>(
        method: &'a Method,
        uri: &'a Uri,
        headers: &'a HeaderMap,
        body: &'a [u8],
    ) -> RequestView<'a> {
        RequestView::new(
            method,
            uri,
            headers,
            body,
            "127.0.0.1".parse().expect("valid IP"),
        )
    }

    fn regex(pattern: &str) -> Regex {
        Regex::new(pattern).expect("valid test regex")
    }

    #[test]
    fn matches_decoded_query() {
        let method = Method::GET;
        let uri: Uri = "/?q=union%20select".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)union\s+select")],
                targets: TARGET_QUERY,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn matches_decoded_path() {
        let method = Method::GET;
        let uri: Uri = "/files/%2e%2e%2fetc/passwd".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            paths: vec![regex(r"\.\./")],
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn all_header_conditions_must_match() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("sqlmap/1.0"));
        let matcher = Matcher {
            headers: vec![
                (HeaderName::from_static("user-agent"), vec![regex("sqlmap")]),
                (HeaderName::from_static("x-api-key"), vec![regex(".+")]),
            ],
            ..Matcher::default()
        };
        assert!(!matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn non_utf8_header_values_are_still_matched() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_bytes(b"sqlmap/1.0\xff").expect("valid header bytes"),
        );
        let matcher = Matcher {
            headers: vec![(HeaderName::from_static("user-agent"), vec![regex("sqlmap")])],
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn non_utf8_headers_are_scanned_by_payload_targets() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api",
            HeaderValue::from_bytes(b"${jndi:ldap://x/a}\xff").expect("valid header bytes"),
        );
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"\$\{jndi:")],
                targets: TARGET_HEADERS,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn method_filter_rejects_other_methods() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            methods: Some(vec![Method::POST]),
            ..Matcher::default()
        };
        assert!(!matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn source_ip_cidr_is_respected() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            source_ips: Some(vec!["10.0.0.0/8".parse().expect("valid CIDR")]),
            ..Matcher::default()
        };
        assert!(!matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn body_pattern_matches_raw_bytes() {
        let method = Method::POST;
        let uri: Uri = "/submit".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)<script")],
                targets: TARGET_BODY,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(
            &method,
            &uri,
            &headers,
            b"x=<script>alert(1)</script>"
        )));
    }

    #[test]
    fn body_pattern_matches_decoded_form_body() {
        let method = Method::POST;
        let uri: Uri = "/submit".parse().expect("valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)union/select")],
                targets: TARGET_BODY,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"q=%27+union%2Fselect")));
    }

    #[test]
    fn double_encoded_query_is_matched() {
        let method = Method::GET;
        let uri: Uri = "/?q=union%2520select".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)union\s+select")],
                targets: TARGET_QUERY,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn double_encoded_path_is_matched() {
        let method = Method::GET;
        let uri: Uri = "/files/%252e%252e%252fetc/passwd"
            .parse()
            .expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            paths: vec![regex(r"\.\./")],
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn multipart_filename_is_scanned_by_body_targets() {
        let method = Method::POST;
        let uri: Uri = "/upload".parse().expect("valid URI");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        let body = b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../etc/passwd\"\r\n\r\nblob\r\n--X--\r\n";
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)\.\./")],
                targets: TARGET_BODY,
            }),
            ..Matcher::default()
        };
        assert!(matcher.matches(&view(&method, &uri, &headers, body)));
    }

    #[test]
    fn response_status_range_is_matched() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let response_headers = HeaderMap::new();
        let matcher = Matcher {
            statuses: vec![StatusRange {
                start: 500,
                end: 599,
            }],
            ..Matcher::default()
        };
        let request = view(&method, &uri, &headers, b"");
        let response = ResponseView::new(StatusCode::BAD_GATEWAY, &response_headers, b"", false);
        assert!(matcher.matches_response(&request, &response));

        let response = ResponseView::new(StatusCode::OK, &response_headers, b"", false);
        assert!(!matcher.matches_response(&request, &response));
    }

    #[test]
    fn response_header_condition_is_matched() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let mut response_headers = HeaderMap::new();
        response_headers.insert("server", HeaderValue::from_static("Apache/2.4.1"));
        let matcher = Matcher {
            response_headers: vec![(
                HeaderName::from_static("server"),
                vec![regex(r"(?i)apache")],
            )],
            ..Matcher::default()
        };
        let request = view(&method, &uri, &headers, b"");
        let response = ResponseView::new(StatusCode::OK, &response_headers, b"", false);
        assert!(matcher.matches_response(&request, &response));
    }

    #[test]
    fn response_body_target_scans_response_body() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let response_headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"(?i)segmentation fault")],
                targets: TARGET_RESPONSE_BODY,
            }),
            ..Matcher::default()
        };
        let request = view(&method, &uri, &headers, b"segmentation fault");
        let response = ResponseView::new(StatusCode::OK, &response_headers, b"all good", false);
        assert!(!matcher.matches_response(&request, &response));

        let response = ResponseView::new(
            StatusCode::OK,
            &response_headers,
            b"warning: Segmentation fault",
            false,
        );
        assert!(matcher.matches_response(&request, &response));
    }

    #[test]
    fn response_matcher_still_applies_request_conditions() {
        let method = Method::GET;
        let uri: Uri = "/admin".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let response_headers = HeaderMap::new();
        let matcher = Matcher {
            paths: vec![regex("^/admin")],
            payload: Some(PayloadMatcher {
                regexes: vec![regex("leak")],
                targets: TARGET_RESPONSE_BODY,
            }),
            ..Matcher::default()
        };
        let request = view(&method, &uri, &headers, b"");
        let response = ResponseView::new(StatusCode::OK, &response_headers, b"leak", false);
        assert!(matcher.matches_response(&request, &response));

        let uri: Uri = "/public".parse().expect("valid URI");
        let request = view(&method, &uri, &headers, b"");
        assert!(!matcher.matches_response(&request, &response));
    }
}
