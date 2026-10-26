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
const MAX_PAYLOAD_BYTES: usize = 16384;

/// Returns a human-readable policy violation for the first matching JWT.
pub fn violation(headers: &HeaderMap, policy: &Jwt) -> Option<String> {
    if !policy.enabled || policy.allowed_algorithms.is_empty() {
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
        if let Some(reason) = check_token(token, policy) {
            return Some(reason);
        }
    }
    for (_, value) in cookie_pairs(headers) {
        if let Some(reason) = check_token(value.as_ref(), policy) {
            return Some(reason);
        }
    }
    None
}

fn check_token(token: &str, policy: &Jwt) -> Option<String> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_signature), None) =
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
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Some("jwt payload is too large to inspect".to_owned());
    }
    let Some(payload) = decode_base64url(payload) else {
        return Some("jwt payload is not valid base64url".to_owned());
    };
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
}
