//! Bounded JWT header and claim inspection for deployments that pin accepted
//! algorithms and claims.
//!
//! The WAF cannot know which keys an application trusts, so this module does
//! not verify signatures. It rejects a token whose header names an algorithm
//! outside the local policy and, when configured, enforces `exp`, `nbf`, `iss`,
//! and `aud`. Opaque session tokens and malformed JWTs are ignored unless a
//! claim policy makes the malformed payload relevant.

use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use http::header::AUTHORIZATION;

use crate::config::Jwt;
use crate::request_view::cookie_pairs;

const MAX_TOKEN_BYTES: usize = 8192;
const MAX_HEADER_BYTES: usize = 1024;

/// Returns a human-readable policy violation for the first matching JWT.
pub fn violation(headers: &HeaderMap, policy: &Jwt) -> Option<String> {
    if !policy.enabled || policy.allowed_algorithms.is_empty() {
        return None;
    }
    for value in headers.get_all(AUTHORIZATION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        // RFC 9110 allows any amount of optional whitespace between the
        // scheme and the credentials, including a tab.
        let mut parts = value.splitn(2, char::is_whitespace);
        let (Some(scheme), Some(token)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            continue;
        }
        if let Some(reason) = check_token(token, policy) {
            return Some(reason);
        }
    }
    for (_, value) in cookie_pairs(headers) {
        for form in crate::decoding::percent_decode_forms(value.as_ref()) {
            if let Some(reason) = check_token(form.as_ref(), policy) {
                return Some(reason);
            }
        }
    }
    None
}

/// Whether a token has the three base64url segments of a JWT and a header
/// segment that decodes to a JSON object.
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(_), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    decode_base64url(header).is_some_and(|decoded| decoded.trim_ascii_start().starts_with(b"{"))
}

fn check_token(token: &str, policy: &Jwt) -> Option<String> {
    let token = token.trim().trim_matches('"');
    if token.is_empty() {
        return None;
    }
    // An opaque token is out of scope, but a token shaped like a JWT that is
    // too large to inspect must fail closed: the algorithm check cannot see
    // its header.
    if token.len() > MAX_TOKEN_BYTES {
        return looks_like_jwt(token).then(|| "jwt is too large to inspect".to_owned());
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if header.len() > MAX_HEADER_BYTES {
        return Some("jwt header is too large to inspect".to_owned());
    }
    let decoded = decode_base64url(header)?;
    if crate::hardening::has_duplicate_json_key(&decoded) {
        // The WAF and the application may read different duplicate keys
        // (`{"alg":"none","alg":"RS256"}`), so any duplicate is rejected.
        return Some("jwt header has duplicate keys".to_owned());
    }
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let algorithm = value.get("alg")?.as_str()?;
    if !policy
        .allowed_algorithms
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(algorithm))
    {
        return Some(format!("jwt algorithm `{algorithm}` is not allowed"));
    }
    if !policy.require_exp
        && policy.allowed_issuers.is_empty()
        && policy.allowed_audiences.is_empty()
    {
        return None;
    }
    let Some(payload) = decode_base64url(payload) else {
        return Some("jwt payload is not valid base64url".to_owned());
    };
    if crate::hardening::has_duplicate_json_key(&payload) {
        return Some("jwt payload has duplicate keys".to_owned());
    }
    let claims: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(claims) => claims,
        Err(_) => return Some("jwt payload is not valid JSON".to_owned()),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let leeway = i64::try_from(policy.leeway.as_secs()).unwrap_or(i64::MAX);
    if policy.require_exp {
        let Some(exp) = claims.get("exp").and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        }) else {
            return Some("jwt is missing the exp claim".to_owned());
        };
        if exp.saturating_add(leeway) < now {
            return Some("jwt is expired".to_owned());
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
    }) && nbf.saturating_sub(leeway) > now
    {
        return Some("jwt is not yet valid".to_owned());
    }
    if !policy.allowed_issuers.is_empty() {
        let issuer = claims.get("iss").and_then(|value| value.as_str());
        if !issuer.is_some_and(|issuer| {
            policy
                .allowed_issuers
                .iter()
                .any(|allowed| allowed == issuer)
        }) {
            return Some("jwt issuer is not allowed".to_owned());
        }
    }
    if !policy.allowed_audiences.is_empty() && !audience_allowed(&claims, &policy.allowed_audiences)
    {
        return Some("jwt audience is not allowed".to_owned());
    }
    None
}

fn audience_allowed(claims: &serde_json::Value, allowed: &[String]) -> bool {
    match claims.get("aud") {
        Some(serde_json::Value::String(audience)) => allowed.iter().any(|entry| entry == audience),
        Some(serde_json::Value::Array(audiences)) => audiences.iter().any(|audience| {
            audience
                .as_str()
                .is_some_and(|audience| allowed.iter().any(|entry| entry == audience))
        }),
        _ => false,
    }
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

    fn policy() -> Jwt {
        Jwt {
            enabled: true,
            allowed_algorithms: vec!["RS256".to_owned()],
            require_exp: false,
            allowed_issuers: Vec::new(),
            allowed_audiences: Vec::new(),
            leeway: std::time::Duration::ZERO,
        }
    }

    fn token(header: &str, payload: &str) -> String {
        format!("{header}.{payload}.c2ln")
    }

    fn encode(value: &str) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in value.as_bytes().chunks(3) {
            let mut buffer = 0u32;
            for (index, byte) in chunk.iter().enumerate() {
                buffer |= u32::from(*byte) << (16 - index * 8);
            }
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(TABLE[((buffer >> (18 - index * 6)) & 0x3f) as usize] as char);
                }
            }
        }
        output
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[test]
    fn rejects_a_disallowed_bearer_algorithm() {
        let hs = token("eyJhbGciOiJIUzI1NiJ9", "e30");
        assert!(violation(&bearer(&hs), &policy()).is_some());
    }

    #[test]
    fn allows_the_configured_algorithm() {
        let rs = token("eyJhbGciOiJSUzI1NiJ9", "e30");
        assert_eq!(violation(&bearer(&rs), &policy()), None);
    }

    #[test]
    fn rejects_a_disallowed_cookie_algorithm() {
        let hs = token("eyJhbGciOiJIUzI1NiJ9", "e30");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("session=opaque; access_token={hs}")).unwrap(),
        );
        assert!(violation(&headers, &policy()).is_some());
    }

    #[test]
    fn opaque_tokens_and_malformed_headers_are_ignored() {
        assert_eq!(violation(&bearer("opaque-session-token"), &policy()), None);
        assert_eq!(violation(&bearer("!!!.e30.c2ln"), &policy()), None);
    }

    #[test]
    fn empty_policy_disables_the_check() {
        let mut disabled = policy();
        disabled.enabled = false;
        let hs = token("eyJhbGciOiJIUzI1NiJ9", "e30");
        assert_eq!(violation(&bearer(&hs), &disabled), None);
    }

    #[test]
    fn claim_policy_enforces_exp_issuer_and_audience() {
        let mut policy = policy();
        policy.require_exp = true;
        policy.allowed_issuers = vec!["https://issuer.example".to_owned()];
        policy.allowed_audiences = vec!["kunato-lab".to_owned()];
        let good = format!(
            "{{\"exp\":{},\"iss\":\"https://issuer.example\",\"aud\":\"kunato-lab\"}}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600
        );
        let good_token = token("eyJhbGciOiJSUzI1NiJ9", &encode(&good));
        assert_eq!(violation(&bearer(&good_token), &policy), None);

        let expired = format!(
            "{{\"exp\":{},\"iss\":\"https://issuer.example\",\"aud\":\"kunato-lab\"}}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 10
        );
        assert!(
            violation(
                &bearer(&token("eyJhbGciOiJSUzI1NiJ9", &encode(&expired))),
                &policy
            )
            .is_some()
        );

        let wrong_issuer =
            "{\"exp\":9999999999,\"iss\":\"https://evil.example\",\"aud\":\"kunato-lab\"}";
        assert!(
            violation(
                &bearer(&token("eyJhbGciOiJSUzI1NiJ9", &encode(wrong_issuer))),
                &policy
            )
            .is_some()
        );
    }

    #[test]
    fn oversized_jwt_headers_fail_closed() {
        let padding = "a".repeat(1200);
        let header = encode(&format!("{{\"alg\":\"HS256\",\"x\":\"{padding}\"}}"));
        let oversized = token(&header, "e30");
        assert_eq!(
            violation(&bearer(&oversized), &policy()),
            Some("jwt header is too large to inspect".to_owned())
        );

        let long = format!("{header}.{}.c2ln", "e".repeat(9000));
        assert_eq!(
            violation(&bearer(&long), &policy()),
            Some("jwt is too large to inspect".to_owned())
        );

        let opaque = "a".repeat(9000);
        assert_eq!(violation(&bearer(&opaque), &policy()), None);
    }

    #[test]
    fn duplicate_header_keys_are_rejected() {
        let header = encode(r#"{"alg":"RS256","alg":"none"}"#);
        assert_eq!(
            violation(&bearer(&token(&header, "e30")), &policy()),
            Some("jwt header has duplicate keys".to_owned())
        );

        let mut claim_policy = policy();
        claim_policy.require_exp = true;
        let payload = encode(r#"{"exp":1,"exp":9999999999}"#);
        assert_eq!(
            violation(
                &bearer(&token("eyJhbGciOiJSUzI1NiJ9", &payload)),
                &claim_policy
            ),
            Some("jwt payload has duplicate keys".to_owned())
        );

        let whitespace_header = encode(r#" {"alg":"none"}"#);
        let oversized = format!("{whitespace_header}.{}.c2ln", "e".repeat(9000));
        assert_eq!(
            violation(&bearer(&oversized), &policy()),
            Some("jwt is too large to inspect".to_owned())
        );
    }

    #[test]
    fn whitespace_and_encoded_cookies_are_inspected() {
        let hs = token("eyJhbGciOiJIUzI1NiJ9", "e30");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer\t{hs}")).unwrap(),
        );
        assert!(violation(&headers, &policy()).is_some());

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_str(&format!("access={}", hs.replace('.', "%2E"))).unwrap(),
        );
        assert!(violation(&headers, &policy()).is_some());
    }
}
