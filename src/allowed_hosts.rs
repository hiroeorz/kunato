//! Host and authority allowlist for the request entry point.
//!
//! `allowed_hosts` is a request policy, not a rule signature: when the list is
//! configured, every request must address one of the listed names before rule
//! evaluation starts. The check covers the HTTP/1.1 `Host` header and the
//! HTTP/2 / HTTP/3 `:authority` when the transport exposes it.

use std::net::{Ipv4Addr, Ipv6Addr};

use http::StatusCode;
use http::header::HOST;
use http::request::Parts;

/// Maximum number of entries accepted in `allowed_hosts`.
pub const MAX_ENTRIES: usize = 256;

/// Maximum length of a raw Host value or a configured entry. DNS names are
/// capped at 253 bytes by [`MAX_HOST_BYTES`]; the extra room covers a port,
/// brackets around an IPv6 literal, and the `*.` prefix.
const MAX_RAW_BYTES: usize = 512;

/// Maximum length of a DNS name (RFC 1035).
const MAX_HOST_BYTES: usize = 253;

/// Maximum length of a single DNS label.
const MAX_LABEL_BYTES: usize = 63;

/// A compiled `allowed_hosts` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedHosts {
    entries: Vec<AllowedHost>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AllowedHost {
    host: String,
    port: Option<u16>,
    wildcard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestHost {
    host: String,
    port: Option<u16>,
}

/// Why a request was rejected by the host policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostViolation {
    /// No `Host` header and no `:authority` were available.
    Missing,
    /// A source was present but could not be parsed (including duplicate
    /// `Host` headers).
    Malformed,
    /// A well-formed name that is not in the allowlist. Carries the normalized
    /// name for server-side diagnostics.
    NotAllowed(String),
}

impl HostViolation {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Missing | Self::Malformed => StatusCode::BAD_REQUEST,
            Self::NotAllowed(_) => StatusCode::MISDIRECTED_REQUEST,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Missing => "missing Host header",
            Self::Malformed => "malformed Host or authority",
            Self::NotAllowed(_) => "host not allowed",
        }
    }

    pub fn host(&self) -> Option<&str> {
        match self {
            Self::NotAllowed(host) => Some(host),
            Self::Missing | Self::Malformed => None,
        }
    }
}

impl AllowedHosts {
    /// Validate and normalize a configured list. Returns `None` when any entry
    /// is invalid; every issue is appended to `issues`.
    pub fn validate(entries: &[String], issues: &mut Vec<String>) -> Option<Self> {
        if entries.is_empty() {
            issues.push(
                "allowed_hosts must not be empty; omit the field to disable host checking"
                    .to_owned(),
            );
            return None;
        }
        if entries.len() > MAX_ENTRIES {
            issues.push(format!(
                "allowed_hosts must not contain more than {MAX_ENTRIES} entries"
            ));
            return None;
        }

        let mut parsed = Vec::with_capacity(entries.len());
        let mut valid = true;
        for entry in entries {
            match AllowedHost::parse(entry) {
                Ok(host) => parsed.push(host),
                Err(reason) => {
                    issues.push(format!("allowed_hosts: `{entry}` {reason}"));
                    valid = false;
                }
            }
        }
        if !valid {
            return None;
        }

        parsed.sort();
        parsed.dedup();
        Some(Self { entries: parsed })
    }

    /// True when `host` (a Host header or authority value) matches an entry.
    pub fn matches(&self, host: &str) -> bool {
        let Ok(host) = RequestHost::parse(host) else {
            return false;
        };
        self.matches_parsed(&host)
    }

    /// Check the Host header and the URI authority of a request. Every source
    /// that is present must match; a duplicate Host header is malformed.
    pub fn check(&self, parts: &Parts) -> Result<(), HostViolation> {
        let mut values = parts.headers.get_all(HOST).iter();
        let header = match values.next() {
            Some(value) => {
                if values.next().is_some() {
                    return Err(HostViolation::Malformed);
                }
                let value = value.to_str().map_err(|_| HostViolation::Malformed)?;
                Some(RequestHost::parse(value).map_err(|_| HostViolation::Malformed)?)
            }
            None => None,
        };
        let authority = match parts.uri.authority() {
            Some(authority) => {
                Some(RequestHost::parse(authority.as_str()).map_err(|_| HostViolation::Malformed)?)
            }
            None => None,
        };

        if header.is_none() && authority.is_none() {
            return Err(HostViolation::Missing);
        }
        for host in [header, authority].into_iter().flatten() {
            if !self.matches_parsed(&host) {
                return Err(HostViolation::NotAllowed(host.host));
            }
        }
        Ok(())
    }

    fn matches_parsed(&self, host: &RequestHost) -> bool {
        self.entries.iter().any(|entry| entry.matches(host))
    }
}

impl AllowedHost {
    fn parse(entry: &str) -> Result<Self, String> {
        if entry.is_empty() {
            return Err("must not be empty".to_owned());
        }
        if entry.len() > MAX_RAW_BYTES + 2 {
            return Err(format!("is longer than {} bytes", MAX_RAW_BYTES + 2));
        }

        let (wildcard, rest) = match entry.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None if entry.contains('*') => {
                return Err("must use `*.` as the only wildcard".to_owned());
            }
            None => (false, entry),
        };
        if rest.contains('*') {
            return Err("must use exactly one leading `*.` wildcard".to_owned());
        }

        let parsed = RequestHost::parse(rest).map_err(|reason| reason.to_owned())?;
        if wildcard && parsed.host.parse::<std::net::IpAddr>().is_ok() {
            return Err("must not use a wildcard with an IP address".to_owned());
        }

        Ok(Self {
            host: parsed.host,
            port: parsed.port,
            wildcard,
        })
    }

    fn matches(&self, request: &RequestHost) -> bool {
        if let Some(port) = self.port
            && request.port != Some(port)
        {
            return false;
        }
        if self.wildcard {
            // `*.example.com` matches one or more subdomain labels but never
            // the apex, and a suffix match must end on a label boundary.
            request.host.len() > self.host.len() + 1
                && request.host.ends_with(&self.host)
                && request.host.as_bytes()[request.host.len() - self.host.len() - 1] == b'.'
        } else {
            request.host == self.host
        }
    }
}

impl RequestHost {
    fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.is_empty() {
            return Err("must not be empty");
        }
        if raw.len() > MAX_RAW_BYTES {
            return Err("is too long");
        }
        if raw.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
            return Err("must not contain whitespace or control characters");
        }
        if raw.bytes().any(|byte| !byte.is_ascii()) {
            return Err("must be ASCII (use punycode for internationalized names)");
        }
        if raw.bytes().any(|byte| {
            matches!(
                byte,
                b'/' | b'?' | b'#' | b'@' | b'\\' | b',' | b';' | b'=' | b'*'
            )
        }) {
            return Err("contains an invalid character");
        }

        if let Some(rest) = raw.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                return Err("has an unterminated IPv6 literal");
            };
            let literal = &rest[..end];
            if literal.contains('[') || literal.contains(']') {
                return Err("has an invalid IPv6 literal");
            }
            let address: Ipv6Addr = literal.parse().map_err(|_| "has an invalid IPv6 literal")?;
            let after = &rest[end + 1..];
            let port = match after {
                "" => None,
                _ => {
                    let digits = after
                        .strip_prefix(':')
                        .ok_or("has characters after the IPv6 literal")?;
                    Some(parse_port(digits)?)
                }
            };
            return Ok(Self {
                host: address.to_string(),
                port,
            });
        }
        if raw.contains('[') || raw.contains(']') {
            return Err("has an unexpected bracket");
        }
        if raw.bytes().filter(|byte| *byte == b':').count() > 1 {
            return Err("has more than one colon; bracket IPv6 literals as [addr]");
        }

        let mut parts = raw.splitn(2, ':');
        let host = parts.next().unwrap_or("");
        let port = match parts.next() {
            Some(port) => Some(parse_port(port)?),
            None => None,
        };
        Ok(Self {
            host: normalize_host(host)?,
            port,
        })
    }
}

fn normalize_host(host: &str) -> Result<String, &'static str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err("has an empty host");
    }
    if host.len() > MAX_HOST_BYTES {
        return Err("has a host name longer than 253 bytes");
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(address.to_string());
    }

    for label in host.split('.') {
        if label.is_empty() {
            return Err("has an empty label");
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err("has a label longer than 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("has a label starting or ending with a hyphen");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(
                "contains characters other than ASCII letters, digits, hyphens, and underscores",
            );
        }
    }
    Ok(host.to_ascii_lowercase())
}

fn parse_port(raw: &str) -> Result<u16, &'static str> {
    if raw.is_empty() {
        return Err("has an empty port");
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("has a non-numeric port");
    }
    let port: u16 = raw.parse().map_err(|_| "has a port outside 1-65535")?;
    if port == 0 {
        return Err("has a port outside 1-65535");
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use http::header::HeaderValue;

    fn allow(entries: &[&str]) -> AllowedHosts {
        let entries: Vec<String> = entries.iter().map(|entry| (*entry).to_owned()).collect();
        let mut issues = Vec::new();
        let allowed = AllowedHosts::validate(&entries, &mut issues).expect("valid allowlist");
        assert!(issues.is_empty(), "{issues:?}");
        allowed
    }

    fn request_parts(uri: &str, host: Option<&str>) -> Parts {
        let mut builder = Request::builder().method("GET").uri(uri);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        builder.body(()).expect("valid request").into_parts().0
    }

    #[test]
    fn matches_exact_names_case_insensitively_and_without_a_trailing_dot() {
        let allowed = allow(&["Example.COM"]);
        assert!(allowed.matches("example.com"));
        assert!(allowed.matches("EXAMPLE.COM."));
        assert!(!allowed.matches("www.example.com"));
        assert!(!allowed.matches("notexample.com"));
        assert!(!allowed.matches("example.com.evil"));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        let allowed = allow(&["*.example.com"]);
        assert!(allowed.matches("www.example.com"));
        assert!(allowed.matches("a.b.example.com"));
        assert!(!allowed.matches("example.com"));
        assert!(!allowed.matches("notexample.com"));
        assert!(!allowed.matches("evil-example.com"));
        assert!(!allowed.matches("example.com.evil"));
    }

    #[test]
    fn ports_are_exact_when_configured_and_optional_otherwise() {
        let any_port = allow(&["example.com"]);
        assert!(any_port.matches("example.com"));
        assert!(any_port.matches("example.com:8443"));
        assert!(any_port.matches("example.com:443"));

        let port_8443 = allow(&["example.com:8443"]);
        assert!(port_8443.matches("example.com:8443"));
        assert!(!port_8443.matches("example.com:443"));
        assert!(!port_8443.matches("example.com"));

        let wildcard_port = allow(&["*.example.com:8443"]);
        assert!(wildcard_port.matches("a.example.com:8443"));
        assert!(!wildcard_port.matches("a.example.com"));
        assert!(!wildcard_port.matches("example.com:8443"));
    }

    #[test]
    fn matches_ipv4_and_bracketed_ipv6_literals() {
        let v4 = allow(&["127.0.0.1"]);
        assert!(v4.matches("127.0.0.1"));
        assert!(v4.matches("127.0.0.1:8080"));
        assert!(!v4.matches("127.0.0.2"));

        let v6 = allow(&["[::1]"]);
        assert!(v6.matches("[::1]"));
        assert!(v6.matches("[0:0:0:0:0:0:0:1]"));
        assert!(v6.matches("[::1]:8443"));
        assert!(!v6.matches("[::2]"));
    }

    #[test]
    fn deduplicates_entries_after_normalization() {
        let allowed = allow(&["Example.com", "example.com.", "EXAMPLE.COM:443"]);
        assert_eq!(allowed.entries.len(), 2);
        assert!(allowed.matches("example.com"));
        assert!(allowed.matches("example.com:443"));
    }

    #[test]
    fn rejects_an_empty_or_oversized_list() {
        let mut issues = Vec::new();
        assert!(AllowedHosts::validate(&[], &mut issues).is_none());
        assert!(issues[0].contains("must not be empty"));

        let entries: Vec<String> = (0..=MAX_ENTRIES)
            .map(|index| format!("host{index}.example.com"))
            .collect();
        let mut issues = Vec::new();
        assert!(AllowedHosts::validate(&entries, &mut issues).is_none());
        assert!(issues[0].contains("more than"));
    }

    #[test]
    fn rejects_invalid_entries() {
        for entry in [
            "",
            "*",
            "*.",
            "*.*.example.com",
            "example.*.com",
            "*.127.0.0.1",
            "http://example.com",
            "example.com/path",
            "user@example.com",
            "example.com?x=1",
            "example.com:0",
            "example.com:65536",
            "example.com:http",
            "example.com:",
            "::1",
            "[::1",
            "[not-ip]",
            "foo..com",
            "-foo.com",
            "foo-.com",
            "foo bar",
            "例え.jp",
        ] {
            let entries = vec![entry.to_owned()];
            let mut issues = Vec::new();
            assert!(
                AllowedHosts::validate(&entries, &mut issues).is_none(),
                "`{entry}` must be rejected"
            );
            assert!(!issues.is_empty(), "`{entry}` must report an issue");
        }

        let entries = vec!["::1".to_owned()];
        let mut issues = Vec::new();
        assert!(AllowedHosts::validate(&entries, &mut issues).is_none());
        assert!(issues[0].contains("IPv6"));
    }

    #[test]
    fn rejects_names_longer_than_the_dns_limit() {
        let long_label = "a".repeat(63);
        let entry = format!("{long_label}.{long_label}.{long_label}.{long_label}");
        let entries = vec![entry];
        let mut issues = Vec::new();
        assert!(AllowedHosts::validate(&entries, &mut issues).is_none());
        assert!(issues[0].contains("253") || issues[0].contains("label"));
    }

    #[test]
    fn matches_reject_malformed_input() {
        let allowed = allow(&["example.com"]);
        assert!(!allowed.matches(""));
        assert!(!allowed.matches("bad host"));
        assert!(!allowed.matches("example.com:0"));
        assert!(!allowed.matches("user@example.com"));
    }

    #[test]
    fn check_uses_the_header_and_the_authority() {
        let allowed = allow(&["example.com"]);

        assert_eq!(
            allowed.check(&request_parts("/", Some("example.com"))),
            Ok(())
        );
        assert_eq!(
            allowed.check(&request_parts("/", Some("EXAMPLE.COM."))),
            Ok(())
        );
        assert_eq!(
            allowed.check(&request_parts("/", Some("evil.example"))),
            Err(HostViolation::NotAllowed("evil.example".to_owned()))
        );

        assert_eq!(
            allowed.check(&request_parts("http://example.com/path", None)),
            Ok(())
        );
        assert_eq!(
            allowed.check(&request_parts("http://evil.example/path", None)),
            Err(HostViolation::NotAllowed("evil.example".to_owned()))
        );

        // Both sources are present: every one of them must be allowed.
        assert_eq!(
            allowed.check(&request_parts(
                "http://evil.example/path",
                Some("example.com")
            )),
            Err(HostViolation::NotAllowed("evil.example".to_owned()))
        );
        let both = allow(&["example.com", "other.example"]);
        assert_eq!(
            both.check(&request_parts(
                "http://other.example/path",
                Some("example.com")
            )),
            Ok(())
        );
    }

    #[test]
    fn check_rejects_missing_malformed_and_duplicate_hosts() {
        let allowed = allow(&["example.com"]);

        assert_eq!(
            allowed.check(&request_parts("/", None)),
            Err(HostViolation::Missing)
        );
        assert_eq!(
            allowed.check(&request_parts("/", Some("bad host"))),
            Err(HostViolation::Malformed)
        );
        assert_eq!(
            allowed.check(&request_parts("/", Some("user@example.com"))),
            Err(HostViolation::Malformed)
        );

        let (mut parts, ()) = Request::builder()
            .uri("/")
            .body(())
            .expect("valid request")
            .into_parts();
        parts
            .headers
            .append(HOST, HeaderValue::from_static("example.com"));
        parts
            .headers
            .append(HOST, HeaderValue::from_static("evil.example"));
        assert_eq!(allowed.check(&parts), Err(HostViolation::Malformed));
    }

    #[test]
    fn violation_status_and_messages_are_stable() {
        assert_eq!(HostViolation::Missing.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            HostViolation::Malformed.message(),
            "malformed Host or authority"
        );
        assert_eq!(
            HostViolation::NotAllowed("evil.example".to_owned()).status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            HostViolation::NotAllowed("evil.example".to_owned()).message(),
            "host not allowed"
        );
        assert_eq!(
            HostViolation::NotAllowed("evil.example".to_owned()).host(),
            Some("evil.example")
        );
    }
}
