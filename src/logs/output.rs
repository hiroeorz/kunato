use std::io::{self, Write};

use crate::cli::LogOutputFormat;

use super::attack::attack_name;
use super::parse::LogEntry;

pub(crate) fn write_header(out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{:<26} {:<5} {:<10} {:<6} {:<22} {:<25} {:<6} {:<30} {:<6} {:<32} DETAIL",
        "TIME", "LEVEL", "EVENT", "ACTION", "ATTACK", "CLIENT", "METHOD", "PATH", "STATUS", "RULE"
    )
}

pub(crate) fn write_entry(
    out: &mut impl Write,
    entry: &LogEntry,
    format: LogOutputFormat,
    color: bool,
) -> io::Result<()> {
    match format {
        LogOutputFormat::Raw => writeln!(out, "{}", entry.raw),
        LogOutputFormat::Json => write_json(out, entry),
        LogOutputFormat::Table => write_table(out, entry, color),
    }
}

fn write_json(out: &mut impl Write, entry: &LogEntry) -> io::Result<()> {
    let mut object = serde_json::Map::new();
    if let Some(value) = &entry.journal_timestamp {
        object.insert(
            "journal_timestamp".to_owned(),
            serde_json::Value::String(value.clone()),
        );
    }
    if let Some(value) = &entry.timestamp {
        object.insert(
            "timestamp".to_owned(),
            serde_json::Value::String(value.clone()),
        );
    }
    if let Some(value) = &entry.level {
        object.insert("level".to_owned(), serde_json::Value::String(value.clone()));
    }
    if let Some(value) = &entry.target {
        object.insert(
            "target".to_owned(),
            serde_json::Value::String(value.clone()),
        );
    }
    object.insert(
        "event".to_owned(),
        serde_json::Value::String(entry.event().to_owned()),
    );
    for (key, value) in [
        ("action", entry.action()),
        ("client", entry.client()),
        ("peer", entry.peer()),
        ("method", entry.field("method")),
        ("path", entry.field("path")),
        ("category", entry.category()),
        ("rule", entry.field("rule")),
    ] {
        if let Some(value) = value {
            object.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
        }
    }
    if let Some(category) = entry.category() {
        object.insert(
            "attack".to_owned(),
            serde_json::Value::String(attack_name(category).to_owned()),
        );
    }
    if let Some(status) = entry
        .field("status")
        .and_then(|status| status.parse::<u64>().ok())
    {
        object.insert("status".to_owned(), serde_json::Value::from(status));
    }
    if !entry.fields.is_empty() {
        object.insert(
            "fields".to_owned(),
            serde_json::Value::Object(
                entry
                    .fields
                    .iter()
                    .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
                    .collect(),
            ),
        );
    }
    object.insert(
        "message".to_owned(),
        serde_json::Value::String(entry.message.clone()),
    );
    serde_json::to_writer(&mut *out, &serde_json::Value::Object(object))
        .map_err(|err| io::Error::other(err.to_string()))?;
    writeln!(out)
}

fn write_table(out: &mut impl Write, entry: &LogEntry, color: bool) -> io::Result<()> {
    let time = entry
        .journal_timestamp
        .as_deref()
        .or(entry.timestamp.as_deref())
        .unwrap_or("-");
    let level = entry.level.as_deref().unwrap_or("-");
    let event = entry.event();
    let action = entry.action().unwrap_or("-");
    let attack = entry.category().map_or("-", attack_name);
    let client = entry.client().unwrap_or("-");
    let method = entry.field("method").unwrap_or("-");
    let path = entry.field("path").unwrap_or("-");
    let status = entry.field("status").unwrap_or("-");
    let rule = entry.field("rule").unwrap_or("-");
    let detail = entry.field("reason").unwrap_or(&entry.message);
    let line = format!(
        "{:<26} {:<5} {:<10} {:<6} {:<22} {:<25} {:<6} {:<30} {:<6} {:<32} {}",
        sanitize(time),
        sanitize(level),
        sanitize(event),
        sanitize(action),
        sanitize(attack),
        sanitize(client),
        sanitize(method),
        sanitize(path),
        sanitize(status),
        sanitize(rule),
        sanitize(detail),
    );
    if color {
        let code = match event {
            "block" | "ban" => "\x1b[31m",
            "rate-limit" | "reject" => "\x1b[33m",
            "match" => "\x1b[32m",
            "behavior" => "\x1b[35m",
            _ => "",
        };
        if !code.is_empty() {
            return writeln!(out, "{code}{line}\x1b[0m");
        }
    }
    writeln!(out, "{line}")
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn entry() -> LogEntry {
        LogEntry {
            raw: "raw line".to_owned(),
            journal_timestamp: Some("2026-10-21T18:36:02+0900".to_owned()),
            timestamp: Some("2026-10-21T09:36:02.123456Z".to_owned()),
            level: Some("INFO".to_owned()),
            target: Some("kunato::proxy::server".to_owned()),
            message: "request blocked".to_owned(),
            fields: [
                ("action", "BLOCK"),
                ("category", "sql-injection"),
                ("rule", "union-select"),
                ("client", "203.0.113.9"),
                ("method", "GET"),
                ("path", "/search"),
                ("status", "403"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn renders_raw_preserving_the_journal_line() {
        let mut out = Vec::new();
        write_entry(&mut out, &entry(), LogOutputFormat::Raw, false).expect("write");
        assert_eq!(String::from_utf8(out).expect("utf8"), "raw line\n");
    }

    #[test]
    fn renders_normalized_json() {
        let mut out = Vec::new();
        write_entry(&mut out, &entry(), LogOutputFormat::Json, false).expect("write");
        let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
        assert_eq!(value["event"], "block");
        assert_eq!(value["attack"], "sql-injection");
        assert_eq!(value["status"], 403);
        assert_eq!(value["journal_timestamp"], "2026-10-21T18:36:02+0900");
        assert_eq!(value["fields"]["rule"], "union-select");
    }

    #[test]
    fn table_sanitizes_control_characters() {
        let mut entry = entry();
        entry
            .fields
            .insert("path".to_owned(), "/x\u{1b}[31m".to_owned());
        let mut out = Vec::new();
        write_entry(&mut out, &entry, LogOutputFormat::Table, false).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("/x?[31m"));
    }
}
