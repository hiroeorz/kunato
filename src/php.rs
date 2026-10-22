//! Explicitly scoped PHP lifecycle mitigations; these do not replace PHP updates.

use http::header::{HOST, HeaderMap, SET_COOKIE};

use crate::config::Php;
use crate::decoding::{normalize_path, percent_decode_forms};

impl Php {
    pub(crate) fn matches(&self, request: &http::request::Parts) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(hosts) = &self.hosts {
            let matches = request
                .headers
                .get_all(HOST)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|host| hosts.matches(host))
                || request
                    .uri
                    .authority()
                    .is_some_and(|host| hosts.matches(host.as_str()));
            if !matches {
                return false;
            }
        }
        self.paths.is_empty()
            || percent_decode_forms(request.uri.path()).iter().any(|path| {
                self.matches_path(path)
                    || normalize_path(path).is_some_and(|path| self.matches_path(&path))
            })
    }

    fn matches_path(&self, path: &str) -> bool {
        self.paths.iter().any(|prefix| {
            prefix == "/"
                || path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(['/', ';']))
        })
    }

    pub(crate) fn rejects_response(&self, headers: &HeaderMap) -> bool {
        headers.get_all(SET_COOKIE).iter().any(|header| {
            let pair = header
                .as_bytes()
                .split(|&byte| byte == b';')
                .next()
                .unwrap_or_default();
            let Some(equal) = pair.iter().position(|&byte| byte == b'=') else {
                return false;
            };
            let name = std::str::from_utf8(&pair[..equal])
                .unwrap_or_default()
                .trim();
            if !self.session_cookies.iter().any(|cookie| cookie == name) {
                return false;
            }
            let value = &pair[equal + 1..];
            let value = value
                .strip_prefix(b"\"")
                .and_then(|v| v.strip_suffix(b"\""))
                .unwrap_or(value);
            // Deleting a session cookie must remain possible.
            if value.is_empty() {
                return false;
            }
            if value.len() > self.max_session_id_bytes.saturating_mul(3) {
                return true;
            }
            let mut decoded = Vec::with_capacity(value.len());
            let mut index = 0;
            while index < value.len() {
                if value[index] == b'%' {
                    let Some(high) = value.get(index + 1).and_then(|b| hex(*b)) else {
                        return true;
                    };
                    let Some(low) = value.get(index + 2).and_then(|b| hex(*b)) else {
                        return true;
                    };
                    decoded.push(high * 16 + low);
                    index += 3;
                } else {
                    decoded.push(value[index]);
                    index += 1;
                }
                if decoded.len() > self.max_session_id_bytes {
                    return true;
                }
            }
            let Ok(value) = std::str::from_utf8(&decoded) else {
                return true;
            };
            !self.session_id_pattern.is_match(value)
        })
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use http::{HeaderValue, Request};

    fn profile(extra: &str) -> Php {
        config::parse(&format!("listen: 127.0.0.1:0\nupstream: http://127.0.0.1:3000\nphp:\n  enabled: true\n  paths: [/php]\n{extra}")).unwrap().php
    }

    #[test]
    fn scope_matches_prefix_boundaries_decoding_and_hosts() {
        let profile = profile("  hosts: [php.example]\n");
        for (path, expected) in [
            ("/php", true),
            ("/php/upload", true),
            ("/phpish", false),
            ("/%70hp/upload", true),
            ("/x/../php/upload", true),
            ("/php;v=1", true),
        ] {
            let (request, _) = Request::builder()
                .uri(path)
                .header(HOST, "php.example")
                .body(())
                .unwrap()
                .into_parts();
            assert_eq!(profile.matches(&request), expected, "{path}");
        }
        let (request, _) = Request::builder()
            .uri("/php")
            .header(HOST, "rails.example")
            .body(())
            .unwrap()
            .into_parts();
        assert!(!profile.matches(&request));
    }

    fn rejects(profile: &Php, cookie: &str) -> bool {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("ordinary=ok"));
        headers.append(SET_COOKIE, HeaderValue::from_str(cookie).unwrap());
        profile.rejects_response(&headers)
    }

    #[test]
    fn validates_only_configured_session_cookies_and_preserves_deletion() {
        let profile = profile("  session_cookies: [PHPSESSID, CUSTOMSID]\n");
        assert!(rejects(
            &profile,
            &format!("CUSTOMSID={}; Path=/", "a".repeat(257))
        ));
        assert!(!rejects(
            &profile,
            &format!("_goodify_space_session={}", "a".repeat(2000))
        ));
        assert!(!rejects(&profile, "PHPSESSID=; Max-Age=0"));
        assert!(!rejects(&profile, "PHPSESSID=abc123%2Cdef-123; Secure"));
        assert!(!rejects(
            &profile,
            &format!("PHPSESSID={}", "%41".repeat(256))
        ));
        assert!(rejects(
            &profile,
            &format!("PHPSESSID={}", "%41".repeat(257))
        ));
        for cookie in [
            "PHPSESSID=%00secret",
            "PHPSESSID=%ff",
            "PHPSESSID=%",
            "PHPSESSID=abc%0Adef",
            "PHPSESSID=abc.def",
        ] {
            assert!(rejects(&profile, cookie), "{cookie}");
        }
    }

    #[test]
    fn custom_handler_can_define_its_own_valid_representation() {
        let profile =
            profile("  max_session_id_bytes: 512\n  session_id_pattern: '^[A-Za-z0-9_.-]+$'\n");
        assert!(!rejects(&profile, "PHPSESSID=opaque_value.signed"));
        assert!(!rejects(
            &profile,
            &format!("PHPSESSID={}", "a".repeat(512))
        ));
        assert!(rejects(&profile, &format!("PHPSESSID={}", "a".repeat(513))));
    }
}
