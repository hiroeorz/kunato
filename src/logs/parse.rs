use std::collections::BTreeMap;

/// One journal entry, normalized just enough for filtering and display.
///
/// `raw` keeps the complete `journalctl` line (including its local-time
/// prefix); `message` and `fields` come from the tracing text or JSON payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEntry {
    pub raw: String,
    pub journal_timestamp: Option<String>,
    pub timestamp: Option<String>,
    pub level: Option<String>,
    pub target: Option<String>,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

impl LogEntry {
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub(crate) fn category(&self) -> Option<&str> {
        self.field("category")
    }

    pub(crate) fn action(&self) -> Option<&str> {
        self.field("action")
    }

    pub(crate) fn client(&self) -> Option<&str> {
        self.field("client").or_else(|| self.field("client_ip"))
    }

    pub(crate) fn peer(&self) -> Option<&str> {
        self.field("peer")
    }

    pub(crate) fn event(&self) -> &'static str {
        if let Some(event) = self.field("event") {
            return match event {
                "protection.rate_limit" => "rate-limit",
                "protection.ban" => "ban",
                "request.blocked" | "response.blocked" => "block",
                "request.matched" | "response.matched" => "match",
                "request.rejected" => "reject",
                _ => "service",
            };
        }
        if self.field("signal").is_some() || self.message.starts_with("behavior") {
            return "behavior";
        }
        match self.action() {
            Some(action) if action.eq_ignore_ascii_case("BLOCK") => "block",
            Some(action) if action.eq_ignore_ascii_case("LOG") => "match",
            _ if self.message == "request rejected" => "reject",
            _ if self.message.contains("rate limit") => "rate-limit",
            _ if self.message.contains("temporarily banned") => "ban",
            _ => "service",
        }
    }
}

pub(crate) fn parse_line(line: &str) -> LogEntry {
    let raw = line.trim_end_matches('\r').to_owned();
    let (journal_timestamp, message) = split_journal_prefix(&raw);
    let mut entry = if message.trim_start().starts_with('{') {
        parse_json(&raw, journal_timestamp.clone(), message)
            .unwrap_or_else(|| parse_text(&raw, journal_timestamp.clone(), message))
    } else {
        parse_text(&raw, journal_timestamp.clone(), message)
    };
    if entry.message.is_empty() {
        entry.message = message.trim().to_owned();
    }
    entry
}

/// Split `journalctl --output=short-iso` into its local-time prefix and the
/// original log message. Lines that do not carry the prefix are returned whole.
fn split_journal_prefix(line: &str) -> (Option<String>, &str) {
    let mut parts = line.splitn(4, ' ');
    let Some(timestamp) = parts.next() else {
        return (None, line);
    };
    let Some(_host) = parts.next() else {
        return (None, line);
    };
    let Some(identifier) = parts.next() else {
        return (None, line);
    };
    let Some(message) = parts.next() else {
        return (None, line);
    };
    if !looks_like_timestamp(timestamp) || !identifier.ends_with(':') {
        return (None, line);
    }
    (
        Some(timestamp.to_owned()),
        message.strip_prefix(' ').unwrap_or(message),
    )
}

fn parse_text(raw: &str, journal_timestamp: Option<String>, input: &str) -> LogEntry {
    let mut rest = input.trim();
    let mut timestamp = None;
    if let Some((token, after)) = split_token(rest)
        && looks_like_timestamp(token)
    {
        timestamp = Some(token.to_owned());
        rest = after.trim_start();
    }

    let mut level = None;
    if let Some((token, after)) = split_token(rest)
        && is_level(token)
    {
        level = Some(token.to_owned());
        rest = after.trim_start();
    }

    let mut target = None;
    if let Some((token, after)) = split_token(rest)
        && is_target(token)
    {
        target = Some(token.trim_end_matches(':').to_owned());
        rest = after.trim_start();
    }

    let (message, fields) = split_fields(rest);
    LogEntry {
        raw: raw.to_owned(),
        journal_timestamp,
        timestamp,
        level,
        target,
        message,
        fields,
    }
}

fn parse_json(raw: &str, journal_timestamp: Option<String>, input: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(input).ok()?;
    let object = value.as_object()?;
    let timestamp = object
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let level = object
        .get("level")
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_uppercase);
    let target = object
        .get("target")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    let mut fields = BTreeMap::new();
    let mut message = String::new();
    if let Some(values) = object.get("fields").and_then(serde_json::Value::as_object) {
        for (key, value) in values {
            if key == "message" {
                message = value_to_string(value);
            } else {
                fields.insert(key.clone(), value_to_string(value));
            }
        }
    }
    if message.is_empty()
        && let Some(value) = object.get("message").and_then(serde_json::Value::as_str)
    {
        message = value.to_owned();
    }
    if fields.is_empty() {
        for (key, value) in object {
            if matches!(
                key.as_str(),
                "timestamp" | "level" | "target" | "message" | "span" | "spans"
            ) {
                continue;
            }
            if value.is_object() {
                continue;
            }
            fields.insert(key.clone(), value_to_string(value));
        }
    }

    Some(LogEntry {
        raw: raw.to_owned(),
        journal_timestamp,
        timestamp,
        level,
        target,
        message,
        fields,
    })
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn split_token(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..end], &input[end..]))
}

fn looks_like_timestamp(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 19
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
}

fn is_level(token: &str) -> bool {
    matches!(token, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR")
}

fn is_target(token: &str) -> bool {
    let Some(name) = token.strip_suffix(':') else {
        return false;
    };
    !name.is_empty()
        && (name.contains("::")
            || name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':')))
}

/// Split a tracing text tail into its message and `key=value` fields.
///
/// Fields are appended after the message and may contain quoted values with
/// spaces (`reason="host not allowed"`). A malformed tail falls back to the
/// whole string as the message so no log content disappears.
fn split_fields(input: &str) -> (String, BTreeMap<String, String>) {
    let input = input.trim();
    let Some(start) = first_field_start(input) else {
        return (input.to_owned(), BTreeMap::new());
    };
    let message = input[..start].trim_end().to_owned();
    let Some(fields) = parse_fields(&input[start..]) else {
        return (input.to_owned(), BTreeMap::new());
    };
    (message, fields)
}

fn first_field_start(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        while start < bytes.len() && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        if start >= bytes.len() {
            break;
        }
        let mut end = start;
        while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
            end += 1;
        }
        if let Some(equal) = input[start..end].find('=')
            && is_field_key(&input[start..start + equal])
        {
            return Some(start);
        }
        start = end;
    }
    None
}

fn parse_fields(input: &str) -> Option<BTreeMap<String, String>> {
    let bytes = input.as_bytes();
    let mut fields = BTreeMap::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' && !bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            return None;
        }
        let key = &input[key_start..index];
        if !is_field_key(key) {
            return None;
        }
        index += 1;
        let value = if index < bytes.len() && bytes[index] == b'"' {
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        index += 1;
                        closed = true;
                        break;
                    }
                    b'\\' if index + 1 < bytes.len() => {
                        index += 1;
                        value.push(match bytes[index] {
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            byte => byte as char,
                        });
                        index += 1;
                    }
                    _ => {
                        let ch = input[index..].chars().next()?;
                        value.push(ch);
                        index += ch.len_utf8();
                    }
                }
            }
            if !closed {
                return None;
            }
            value
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            input[value_start..index].to_owned()
        };
        fields.insert(key.to_owned(), value);
    }
    Some(fields)
}

fn is_field_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "2026-10-21T18:35:17+0900 host kunato[22992]: ";

    #[test]
    fn parses_text_rule_match_with_quoted_fields() {
        let line = format!(
            "{PREFIX}2026-10-21T09:35:17.234772Z  INFO kunato::proxy::server: rule matched category=scanners-and-bots rule=seo-and-ai-crawlers action=\"LOG\" client=216.73.217.12 method=GET path=/robots.txt"
        );
        let entry = parse_line(&line);
        assert_eq!(
            entry.journal_timestamp.as_deref(),
            Some("2026-10-21T18:35:17+0900")
        );
        assert_eq!(
            entry.timestamp.as_deref(),
            Some("2026-10-21T09:35:17.234772Z")
        );
        assert_eq!(entry.level.as_deref(), Some("INFO"));
        assert_eq!(entry.target.as_deref(), Some("kunato::proxy::server"));
        assert_eq!(entry.message, "rule matched");
        assert_eq!(entry.action(), Some("LOG"));
        assert_eq!(entry.category(), Some("scanners-and-bots"));
        assert_eq!(entry.client(), Some("216.73.217.12"));
        assert_eq!(entry.field("path"), Some("/robots.txt"));
    }

    #[test]
    fn parses_quoted_reason_with_spaces() {
        let line = format!(
            "{PREFIX}2026-10-21T09:35:17.234772Z  WARN kunato::proxy::server: request rejected client=185.73.23.161 status=421 reason=\"host not allowed\""
        );
        let entry = parse_line(&line);
        assert_eq!(entry.message, "request rejected");
        assert_eq!(entry.field("reason"), Some("host not allowed"));
        assert_eq!(entry.field("status"), Some("421"));
        assert_eq!(entry.event(), "reject");
    }

    #[test]
    fn parses_json_logs_after_the_journal_prefix() {
        let line = format!(
            "{PREFIX}{{\"timestamp\":\"2026-10-21T09:35:17.234772Z\",\"level\":\"INFO\",\"fields\":{{\"message\":\"request blocked\",\"category\":\"sql-injection\",\"rule\":\"union-select\",\"action\":\"BLOCK\",\"client\":\"203.0.113.9\",\"status\":403}},\"target\":\"kunato::proxy::server\"}}"
        );
        let entry = parse_line(&line);
        assert_eq!(entry.message, "request blocked");
        assert_eq!(entry.level.as_deref(), Some("INFO"));
        assert_eq!(entry.target.as_deref(), Some("kunato::proxy::server"));
        assert_eq!(entry.category(), Some("sql-injection"));
        assert_eq!(entry.field("status"), Some("403"));
        assert_eq!(entry.event(), "block");
    }

    #[test]
    fn parses_ipv6_and_rate_limit_fields() {
        let line = format!(
            "{PREFIX}2026-10-21T09:35:17.234772Z  INFO kunato::proxy::server: rate limit exceeded event=\"protection.rate_limit\" client=2001:db8::1 peer=[2001:db8::1]:443 status=429 retry_after_ms=250 suppressed=3"
        );
        let entry = parse_line(&line);
        assert_eq!(entry.client(), Some("2001:db8::1"));
        assert_eq!(entry.peer(), Some("[2001:db8::1]:443"));
        assert_eq!(entry.field("suppressed"), Some("3"));
        assert_eq!(entry.event(), "rate-limit");
    }

    #[test]
    fn parses_root_targets() {
        let line = format!(
            "{PREFIX}2026-10-21T09:35:17.234772Z  INFO kunato: kunato started addr=[::]:443"
        );
        let entry = parse_line(&line);
        assert_eq!(entry.target.as_deref(), Some("kunato"));
        assert_eq!(entry.message, "kunato started");
        assert_eq!(entry.field("addr"), Some("[::]:443"));
    }

    #[test]
    fn leaves_non_tracing_lines_whole() {
        let line = format!("{PREFIX}Started Kunato WAF reverse proxy.");
        let entry = parse_line(&line);
        assert_eq!(entry.message, "Started Kunato WAF reverse proxy.");
        assert!(entry.fields.is_empty());
        assert_eq!(entry.event(), "service");
    }
}
