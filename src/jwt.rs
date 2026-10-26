//! Bounded JWT header inspection for deployments that pin accepted algorithms.
//!
//! The WAF cannot know which algorithm an application expects, but a local
//! policy can. When `limits.jwt.allowed_algorithms` is non-empty, bearer tokens
//! and JWT-shaped cookie values whose header names a different algorithm are
//! rejected before rule evaluation. Opaque session tokens and malformed JWTs
//! are ignored so this check does not turn into a general token validator.

use http::HeaderMap;
use http::header::AUTHORIZATION;

use crate::request_view::cookie_pairs;

const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_BYTES: usize = 1024;

/// Returns the disallowed `alg` value when a JWT in the request names one.
pub fn disallowed_algorithm(headers: &HeaderMap, allowed: &[String]) -> Option<String> {
    if allowed.is_empty() {
        return None;
    }
    for value in headers.get_all(AUTHORIZATION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let Some((scheme, token)) = value.split_once(' ') else {
            continue;
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            continue;
        }
        if let Some(algorithm) = check_token(token, allowed) {
            return Some(algorithm);
        }
    }
    for (_, value) in cookie_pairs(headers) {
        if let Some(algorithm) = check_token(value.as_ref(), allowed) {
            return Some(algorithm);
        }
    }
    None
}

fn check_token(token: &str, allowed: &[String]) -> Option<String> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(header), Some(_payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if header.len() > MAX_HEADER_BYTES {
        return None;
    }
    let decoded = decode_base64url(header)?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let algorithm = value.get("alg")?.as_str()?;
    let normalized = algorithm.to_ascii_uppercase();
    (!allowed.iter().any(|candidate| candidate == &normalized)).then_some(normalized)
}

fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    const HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.c2ln";
    const RS256: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.c2ln";

    fn allowed(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn rejects_a_disallowed_bearer_algorithm() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln"),
        );
        assert_eq!(
            disallowed_algorithm(&headers, &allowed(&["RS256"])),
            Some("HS256".to_owned())
        );
    }

    #[test]
    fn allows_the_configured_algorithm() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {RS256}")).unwrap(),
        );
        assert_eq!(disallowed_algorithm(&headers, &allowed(&["RS256"])), None);
    }

    #[test]
    fn rejects_a_disallowed_cookie_algorithm() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("session=opaque; access_token={HS256}")).unwrap(),
        );
        assert_eq!(
            disallowed_algorithm(&headers, &allowed(&["RS256"])),
            Some("HS256".to_owned())
        );
    }

    #[test]
    fn opaque_tokens_and_malformed_headers_are_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer opaque-session-token"),
        );
        assert_eq!(disallowed_algorithm(&headers, &allowed(&["RS256"])), None);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer !!!.e30.c2ln"),
        );
        assert_eq!(disallowed_algorithm(&headers, &allowed(&["RS256"])), None);
    }

    #[test]
    fn empty_policy_disables_the_check() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln"),
        );
        assert_eq!(disallowed_algorithm(&headers, &[]), None);
    }
}
