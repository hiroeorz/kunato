//! Optional request-shape hardening that cannot be expressed as a robust regex.
//!
//! The policy is disabled by default. When enabled, Kunato rejects URL values
//! that target configured internal hostnames, conflicting duplicate parameters
//! or JSON keys, and authenticated requests addressed as static assets.

use std::collections::{HashMap, HashSet};

use http::header::CONTENT_TYPE;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::config::Hardening;
use crate::decoding::{disposition_param, multipart_boundaries, multipart_parts, percent_decode};
use crate::request_view::{RequestView, cookie_pairs};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    Incomplete,
    InternalHost(String),
    DuplicateParameter(String),
    CacheDeception,
    Redirect(String),
}

impl Violation {
    pub fn status(&self) -> http::StatusCode {
        match self {
            Self::Incomplete => http::StatusCode::PAYLOAD_TOO_LARGE,
            Self::DuplicateParameter(_) => http::StatusCode::BAD_REQUEST,
            Self::InternalHost(_) | Self::CacheDeception | Self::Redirect(_) => {
                http::StatusCode::FORBIDDEN
            }
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::Incomplete => "request body is too large to inspect",
            Self::InternalHost(_) => "request targets an internal host",
            Self::DuplicateParameter(_) => "conflicting duplicate request parameter",
            Self::CacheDeception => "authenticated request addressed as a static asset",
            Self::Redirect(_) => "redirect target is not allowed",
        }
    }
}

pub fn inspect(view: &RequestView<'_>, policy: &Hardening) -> Option<Violation> {
    if view.body_truncated
        && (policy.ssrf.enabled || policy.duplicates.enabled || policy.redirects.enabled)
    {
        return Some(Violation::Incomplete);
    }
    if policy.ssrf.enabled
        && let Some(host) = internal_host(view, policy)
    {
        return Some(Violation::InternalHost(host));
    }
    if policy.duplicates.enabled
        && let Some(name) = duplicate_parameter(view, policy)
    {
        return Some(Violation::DuplicateParameter(name));
    }
    if policy.redirects.enabled
        && let Some(host) = redirect_target(view, policy)
    {
        return Some(Violation::Redirect(host));
    }
    if policy.cache.enabled && cache_deception(view, policy) {
        return Some(Violation::CacheDeception);
    }
    None
}

fn internal_host(view: &RequestView<'_>, policy: &Hardening) -> Option<String> {
    for form in &view.query_forms {
        if let Some(host) = internal_host_in(form, policy) {
            return Some(host);
        }
    }
    // `body_forms` only carries the decoded variants that differ from the raw
    // body, so the raw body has to be scanned as well.
    if !view.body.is_empty()
        && let Some(host) = internal_host_in(&String::from_utf8_lossy(view.body), policy)
    {
        return Some(host);
    }
    for form in &view.body_forms {
        if let Some(host) = internal_host_in(&String::from_utf8_lossy(form), policy) {
            return Some(host);
        }
    }
    for value in view.headers.values() {
        if let Some(host) = internal_host_in(&String::from_utf8_lossy(value.as_bytes()), policy) {
            return Some(host);
        }
    }
    None
}

/// Return the first URL host in `text` that the policy treats as internal.
/// Unlike [`find_host`], every URL is examined: putting a public URL first must
/// not hide an internal target later in the same parameter.
fn internal_host_in(text: &str, policy: &Hardening) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        if &bytes[index..index + 3] != b"://" {
            index += 1;
            continue;
        }
        if scheme_precedes(text, index)
            && let Some(host) = authority_host(&text[index + 3..])
            && matches_host(&host, policy)
        {
            return Some(host);
        }
        index += 3;
    }
    for (at, _) in text.match_indices("//") {
        if at > 0 && bytes[at - 1] == b':' {
            continue;
        }
        if let Some(host) = authority_host(&text[at + 2..])
            && matches_host(&host, policy)
        {
            return Some(host);
        }
    }
    None
}

/// Whether a URL scheme ends immediately before the `://` at `scheme_end`.
fn scheme_precedes(text: &str, scheme_end: usize) -> bool {
    for (examined, ch) in text[..scheme_end].chars().rev().enumerate() {
        if examined >= 64 {
            break;
        }
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
            return examined > 0;
        }
    }
    !text[..scheme_end].is_empty() && scheme_end <= 64
}

fn matches_host(host: &str, policy: &Hardening) -> bool {
    policy.ssrf.internal_hosts.iter().any(|entry| entry == host)
        || policy
            .ssrf
            .internal_suffixes
            .iter()
            .any(|suffix| host == suffix || host.ends_with(&format!(".{suffix}")))
}

/// Extracts the authority host from the first absolute or protocol-relative
/// URL in `text`. A trailing DNS root dot is removed before comparison.
fn find_host(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for scheme_end in 0..bytes.len().saturating_sub(2) {
        if &bytes[scheme_end..scheme_end + 3] == b"://" {
            let scheme_start = text[..scheme_end]
                .rfind(|character: char| {
                    !(character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'))
                })
                .map_or(0, |index| index + 1);
            if scheme_start != scheme_end
                && let Some(host) = authority_host(&text[scheme_end + 3..])
            {
                return Some(host);
            }
        }
    }
    for (index, _) in text.match_indices("//") {
        if index > 0 && bytes[index - 1] == b':' {
            continue;
        }
        if let Some(host) = authority_host(&text[index + 2..]) {
            return Some(host);
        }
    }
    None
}

fn authority_host(rest: &str) -> Option<String> {
    if let Some(bracketed) = rest.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = bracketed[..end].trim_end_matches('.').to_ascii_lowercase();
        return (!host.is_empty()).then_some(host);
    }
    let end = rest
        .find(|character: char| {
            matches!(
                character,
                '/' | ':' | '?' | '#' | '&' | '"' | '\'' | ' ' | '\t' | '\r' | '\n'
            )
        })
        .unwrap_or(rest.len());
    let mut authority = &rest[..end];
    if let Some((_, host)) = authority.rsplit_once('@') {
        authority = host;
    }
    let host = authority
        .trim_matches(|character| character == '[' || character == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn duplicate_parameter(view: &RequestView<'_>, policy: &Hardening) -> Option<String> {
    if let Some(raw) = view.query_forms.first()
        && let Some(name) = duplicate_in_pairs(raw, &policy.duplicates.allow_parameters)
    {
        return Some(name);
    }
    let content_type_header = view
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let content_type = content_type_header.to_ascii_lowercase();
    if content_type.starts_with("application/x-www-form-urlencoded")
        && let Ok(body) = std::str::from_utf8(view.body)
        && let Some(name) = duplicate_in_pairs(body, &policy.duplicates.allow_parameters)
    {
        return Some(name);
    }
    if content_type.starts_with("multipart/form-data")
        && let Some(name) = duplicate_in_multipart(view, content_type_header, &policy.duplicates)
    {
        return Some(name);
    }
    if policy.duplicates.json_keys
        && (content_type.contains("json")
            || view.body.starts_with(b"{")
            || view.body.starts_with(b"["))
        && has_duplicate_json_key(view.body)
    {
        return Some("json".to_owned());
    }
    None
}

fn duplicate_in_multipart(
    view: &RequestView<'_>,
    content_type: &str,
    policy: &crate::config::DuplicatePolicy,
) -> Option<String> {
    let mut values: HashMap<String, Vec<u8>> = HashMap::new();
    for (name, value, is_file) in multipart_fields(view.body, content_type) {
        if is_file
            || name.is_empty()
            || name.ends_with("[]")
            || policy.allow_parameters.iter().any(|entry| entry == &name)
        {
            continue;
        }
        if let Some(previous) = values.get(&name) {
            if previous.as_slice() != value {
                return Some(name);
            }
        } else {
            values.insert(name, value.to_vec());
        }
    }
    None
}

/// Multipart fields as `(lowercased name, value, is_file)`, checked for every
/// declared boundary interpretation.
fn multipart_fields<'a>(body: &'a [u8], content_type: &str) -> Vec<(String, &'a [u8], bool)> {
    let mut fields = Vec::new();
    let Ok(boundaries) = multipart_boundaries(content_type) else {
        return fields;
    };
    for boundary in boundaries {
        let Some(parts) = multipart_parts(body, &boundary) else {
            continue;
        };
        for part in parts {
            let headers = String::from_utf8_lossy(part.headers);
            let Some(disposition) = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-disposition")
                    .then(|| value.trim())
            }) else {
                continue;
            };
            let Some(name) = disposition_param(disposition, "name") else {
                continue;
            };
            let is_file = disposition_param(disposition, "filename")
                .is_some_and(|filename| !filename.is_empty());
            fields.push((name.to_ascii_lowercase(), part.value, is_file));
        }
    }
    fields
}

fn duplicate_in_pairs(pairs: &str, allow: &[String]) -> Option<String> {
    let mut values: HashMap<String, String> = HashMap::new();
    for pair in pairs.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = form_value(raw_name).to_ascii_lowercase();
        if name.is_empty() || name.ends_with("[]") || allow.iter().any(|entry| entry == &name) {
            continue;
        }
        let value = form_value(raw_value);
        if let Some(previous) = values.get(&name) {
            if previous != &value {
                return Some(name);
            }
        } else {
            values.insert(name, value);
        }
    }
    None
}

/// Decode a form-encoded name or value: `+` means space and `%XX` escapes are
/// resolved, matching what servlet and PHP parsers hand to the application.
fn form_value(value: &str) -> String {
    percent_decode(&value.replace('+', " ")).into_owned()
}

fn redirect_host(value: &str, policy: &Hardening) -> Option<String> {
    let candidate = absolute_redirect(value)?;
    let host = find_host(&candidate)?;
    if policy
        .redirects
        .allowed_hosts
        .iter()
        .any(|allowed| allowed == &host)
    {
        return None;
    }
    Some(host)
}

fn redirect_target(view: &RequestView<'_>, policy: &Hardening) -> Option<String> {
    if let Some(raw) = view.query_forms.first()
        && let Some(host) = redirect_in_pairs(raw, policy)
    {
        return Some(host);
    }
    let content_type_header = view
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let content_type = content_type_header.to_ascii_lowercase();
    if content_type.starts_with("application/x-www-form-urlencoded")
        && let Ok(body) = std::str::from_utf8(view.body)
    {
        return redirect_in_pairs(body, policy);
    }
    if content_type.starts_with("multipart/form-data") {
        for (name, value, is_file) in multipart_fields(view.body, content_type_header) {
            if is_file
                || !policy
                    .redirects
                    .parameters
                    .iter()
                    .any(|entry| entry == &name)
            {
                continue;
            }
            let Ok(text) = std::str::from_utf8(value) else {
                continue;
            };
            if let Some(host) = redirect_host(text, policy) {
                return Some(host);
            }
        }
    }
    if (content_type.contains("json") || view.body.starts_with(b"{"))
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(view.body)
        && let Some(host) = redirect_in_json(&value, policy, 0)
    {
        return Some(host);
    }
    None
}

/// Walk JSON values to any depth so a redirect parameter nested in an object
/// or array is still checked.
fn redirect_in_json(value: &serde_json::Value, policy: &Hardening, depth: usize) -> Option<String> {
    if depth > 16 {
        return None;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (name, value) in map {
                if policy
                    .redirects
                    .parameters
                    .iter()
                    .any(|entry| entry == &name.to_ascii_lowercase())
                    && let Some(text) = value.as_str()
                    && let Some(host) = redirect_host(text, policy)
                {
                    return Some(host);
                }
                if let Some(host) = redirect_in_json(value, policy, depth + 1) {
                    return Some(host);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| redirect_in_json(item, policy, depth + 1)),
        _ => None,
    }
}

/// Normalize a redirect candidate the way a browser does before deciding
/// whether it leaves the site: strip control characters (tabs and newlines are
/// dropped anywhere in a URL), trim leading whitespace, and treat `\\` as `/`.
fn absolute_redirect(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\n' | '\r'))
        .map(|ch| if ch == '\\' { '/' } else { ch })
        .collect();
    let trimmed = normalized.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some(trimmed.to_owned())
    } else if trimmed.starts_with("//") {
        Some(format!("http:{trimmed}"))
    } else {
        None
    }
}

fn redirect_in_pairs(pairs: &str, policy: &Hardening) -> Option<String> {
    for pair in pairs.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(raw_name).to_ascii_lowercase();
        if !policy
            .redirects
            .parameters
            .iter()
            .any(|entry| entry == &name)
        {
            continue;
        }
        if let Some(host) = redirect_host(&form_value(raw_value), policy) {
            return Some(host);
        }
    }
    None
}

pub(crate) fn has_duplicate_json_key(body: &[u8]) -> bool {
    serde_json::from_slice::<DuplicateChecker>(body)
        .err()
        .is_some_and(|error| error.to_string().contains("duplicate object key"))
}

struct DuplicateChecker;

impl<'de> Deserialize<'de> for DuplicateChecker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)?;
        Ok(Self)
    }
}

struct DuplicateVisitor;

impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateChecker::deserialize(deserializer)?;
        Ok(())
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<DuplicateChecker>()?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            map.next_value::<DuplicateChecker>()?;
        }
        Ok(())
    }
}

fn cache_deception(view: &RequestView<'_>, policy: &Hardening) -> bool {
    // Every decoded and normalized form is a path the origin might route on,
    // so a static-looking suffix in any of them is enough to apply the policy.
    let wants_static = view.path_forms.iter().any(|form| {
        let path = form.to_ascii_lowercase();
        policy
            .cache
            .static_suffixes
            .iter()
            .any(|suffix| path.ends_with(suffix))
    });
    if !wants_static {
        return false;
    }
    cookie_pairs(view.headers).iter().any(|(name, _)| {
        policy
            .cache
            .auth_cookies
            .iter()
            .any(|cookie| cookie == &name.to_ascii_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, Uri};

    use super::*;
    use crate::config::{CachePolicy, DuplicatePolicy, Hardening, SsrfPolicy};

    fn view<'a>(uri: &'a Uri, headers: &'a HeaderMap, body: &'a [u8]) -> RequestView<'a> {
        RequestView::new(
            &Method::POST,
            uri,
            headers,
            body,
            "127.0.0.1".parse().unwrap(),
        )
    }

    fn policy() -> Hardening {
        Hardening {
            ssrf: SsrfPolicy {
                enabled: true,
                internal_hosts: vec!["vuln.corp".to_owned()],
                internal_suffixes: vec!["internal".to_owned()],
            },
            duplicates: DuplicatePolicy {
                enabled: true,
                json_keys: true,
                allow_parameters: vec!["tag".to_owned()],
            },
            cache: CachePolicy {
                enabled: true,
                static_suffixes: vec![".avif".to_owned()],
                auth_cookies: vec!["session".to_owned()],
            },
            redirects: crate::config::RedirectPolicy {
                enabled: true,
                allowed_hosts: vec!["app.test".to_owned()],
                parameters: vec!["redirect_uri".to_owned()],
            },
        }
    }

    #[test]
    fn detects_configured_internal_hosts_and_suffixes() {
        let headers = HeaderMap::new();
        for target in [
            "/fetch?url=http%3A%2F%2Fvuln.corp%2Fsafe",
            "/fetch?url=http%3A%2F%2Fapi.internal%2F",
        ] {
            let uri: Uri = target.parse().unwrap();
            assert!(matches!(
                inspect(&view(&uri, &headers, b""), &policy()),
                Some(Violation::InternalHost(_))
            ));
        }
    }

    #[test]
    fn detects_conflicting_duplicates_but_allows_configured_lists() {
        let headers = HeaderMap::new();
        let uri: Uri = "/?account=one&account=two".parse().unwrap();
        assert!(matches!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::DuplicateParameter(_))
        ));
        let uri: Uri = "/?tag=one&tag=two".parse().unwrap();
        assert_eq!(inspect(&view(&uri, &headers, b""), &policy()), None);
    }

    #[test]
    fn detects_duplicate_json_keys() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let uri: Uri = "/".parse().unwrap();
        assert!(matches!(
            inspect(
                &view(&uri, &headers, br#"{"role":"user","role":"admin"}"#),
                &policy()
            ),
            Some(Violation::DuplicateParameter(_))
        ));
    }

    #[test]
    fn rejects_unlisted_redirect_targets() {
        let headers = HeaderMap::new();
        let uri: Uri = "/oauth/authorize?redirect_uri=https%3A%2F%2Fevil.example%2Fcb"
            .parse()
            .unwrap();
        assert_eq!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::Redirect("evil.example".to_owned()))
        );
        let uri: Uri = "/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.test%2Fcb"
            .parse()
            .unwrap();
        assert_eq!(inspect(&view(&uri, &headers, b""), &policy()), None);
        let uri: Uri = "/oauth/authorize?redirect_uri=%2Fcb".parse().unwrap();
        assert_eq!(inspect(&view(&uri, &headers, b""), &policy()), None);
        let uri: Uri = "/oauth/authorize?redirect_uri=HTTPS%3A%2F%2Fevil.example%2Fcb"
            .parse()
            .unwrap();
        assert_eq!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::Redirect("evil.example".to_owned()))
        );

        let mut json_headers = HeaderMap::new();
        json_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let uri: Uri = "/oauth/authorize".parse().unwrap();
        assert_eq!(
            inspect(
                &view(
                    &uri,
                    &json_headers,
                    br#"{"redirect_uri":"https://evil.example/cb"}"#
                ),
                &policy()
            ),
            Some(Violation::Redirect("evil.example".to_owned()))
        );
    }

    #[test]
    fn truncated_bodies_fail_closed_for_body_policies() {
        let headers = HeaderMap::new();
        let uri: Uri = "/".parse().unwrap();
        let mut view = view(&uri, &headers, b"");
        view.body_truncated = true;
        assert_eq!(inspect(&view, &policy()), Some(Violation::Incomplete));
    }

    #[test]
    fn detects_authenticated_static_assets() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            HeaderValue::from_static("session=alice"),
        );
        let uri: Uri = "/account/profile.avif".parse().unwrap();
        assert_eq!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::CacheDeception)
        );
        let uri: Uri = "/account/profile.avif".parse().unwrap();
        assert_eq!(
            inspect(&view(&uri, &HeaderMap::new(), b""), &policy()),
            None
        );
    }

    #[test]
    fn scans_the_raw_body_for_internal_hosts() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let uri: Uri = "/fetch".parse().unwrap();
        let body = br#"{"url":"http://vuln.corp/admin"}"#;
        assert!(matches!(
            inspect(&view(&uri, &headers, body), &policy()),
            Some(Violation::InternalHost(_))
        ));
    }

    #[test]
    fn checks_every_url_in_a_parameter() {
        let headers = HeaderMap::new();
        let uri: Uri = "/fetch?ok=https%3A%2F%2Fexample.com%2F&target=http%3A%2F%2Fvuln.corp%2F"
            .parse()
            .unwrap();
        assert!(matches!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::InternalHost(_))
        ));
        let uri: Uri = "/fetch?ok=https%3A%2F%2Fexample.com%2F".parse().unwrap();
        assert_eq!(inspect(&view(&uri, &headers, b""), &policy()), None);
    }

    #[test]
    fn detects_redirects_with_leading_space_and_backslashes() {
        let headers = HeaderMap::new();
        for target in [
            "/login?redirect_uri=%20https%3A%2F%2Fevil.test%2F",
            "/login?redirect_uri=https%3A%5C%5Cevil.test%2F",
        ] {
            let uri: Uri = target.parse().unwrap();
            assert!(
                matches!(
                    inspect(&view(&uri, &headers, b""), &policy()),
                    Some(Violation::Redirect(_))
                ),
                "{target}"
            );
        }
    }

    #[test]
    fn decodes_plus_in_duplicate_parameter_names() {
        let headers = HeaderMap::new();
        let uri: Uri = "/?key+name=1&key%20name=2".parse().unwrap();
        assert!(matches!(
            inspect(&view(&uri, &headers, b""), &policy()),
            Some(Violation::DuplicateParameter(_))
        ));
    }

    #[test]
    fn detects_nested_json_redirect_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let uri: Uri = "/login".parse().unwrap();
        let body = br#"{"data":{"redirect_uri":"https://evil.test/"}}"#;
        assert!(matches!(
            inspect(&view(&uri, &headers, body), &policy()),
            Some(Violation::Redirect(_))
        ));
    }

    #[test]
    fn detects_duplicate_multipart_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "multipart/form-data; boundary=X".parse().unwrap(),
        );
        let uri: Uri = "/upload".parse().unwrap();
        let body = b"--X\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n--X\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--X--\r\n";
        assert!(matches!(
            inspect(&view(&uri, &headers, body), &policy()),
            Some(Violation::DuplicateParameter(_))
        ));
    }

    #[test]
    fn detects_multipart_redirect_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "multipart/form-data; boundary=X".parse().unwrap(),
        );
        let uri: Uri = "/login".parse().unwrap();
        let body = b"--X\r\nContent-Disposition: form-data; name=\"redirect_uri\"\r\n\r\nhttps://evil.test/\r\n--X--\r\n";
        assert!(matches!(
            inspect(&view(&uri, &headers, body), &policy()),
            Some(Violation::Redirect(_))
        ));
    }
}
