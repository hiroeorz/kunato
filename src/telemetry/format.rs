use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use tracing::Level;

use crate::cli::LogFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timestamp {
    seconds: u64,
    micros: u32,
}

impl Timestamp {
    pub(crate) fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: duration.as_secs(),
            micros: duration.subsec_micros(),
        }
    }

    pub(crate) fn to_rfc3339(self) -> String {
        let days = (self.seconds / 86_400) as i64;
        let seconds = self.seconds % 86_400;
        let (year, month, day) = civil_from_days(days);
        let hour = seconds / 3_600;
        let minute = (seconds % 3_600) / 60;
        let second = seconds % 60;
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:06}Z",
            self.micros
        )
    }
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[derive(Debug, Default)]
pub(crate) struct Fields {
    pub(crate) message: Option<String>,
    pub(crate) values: Vec<(String, FieldValue)>,
}

#[derive(Debug, Clone)]
pub(crate) enum FieldValue {
    Text(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
}

impl FieldValue {
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Text(value) => value.clone(),
            Self::I64(value) => value.to_string(),
            Self::U64(value) => value.to_string(),
            Self::F64(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
        }
    }

    fn json(&self) -> Value {
        match self {
            Self::Text(value) => Value::String(value.clone()),
            Self::I64(value) => Value::Number((*value).into()),
            Self::U64(value) => Value::Number((*value).into()),
            Self::F64(value) => serde_json::Number::from_f64(*value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Self::Bool(value) => Value::Bool(*value),
        }
    }
}

pub(crate) fn write(
    writer: &mut dyn io::Write,
    format: LogFormat,
    timestamp: Timestamp,
    level: Level,
    target: &str,
    fields: &Fields,
    color: bool,
) -> io::Result<()> {
    match format {
        LogFormat::Text => write_text(writer, timestamp, level, target, fields, color),
        LogFormat::Json => write_json(writer, timestamp, level, target, fields),
    }
}

fn write_text(
    writer: &mut dyn io::Write,
    timestamp: Timestamp,
    level: Level,
    target: &str,
    fields: &Fields,
    color: bool,
) -> io::Result<()> {
    let level_text = format!("{:>5}", level.as_str());
    if color {
        let code = match level {
            Level::ERROR => "\x1b[31m",
            Level::WARN => "\x1b[33m",
            Level::INFO => "\x1b[32m",
            Level::DEBUG => "\x1b[34m",
            Level::TRACE => "\x1b[35m",
        };
        write!(
            writer,
            "{} {code}{level_text}\x1b[0m {target}:",
            timestamp.to_rfc3339()
        )?;
    } else {
        write!(writer, "{} {level_text} {target}:", timestamp.to_rfc3339())?;
    }
    if let Some(message) = &fields.message {
        write!(writer, " {message}")?;
    }
    for (key, value) in &fields.values {
        write!(writer, " {key}={}", value.text())?;
    }
    writeln!(writer)
}

fn write_json(
    writer: &mut dyn io::Write,
    timestamp: Timestamp,
    level: Level,
    target: &str,
    fields: &Fields,
) -> io::Result<()> {
    let mut event = Map::new();
    event.insert(
        "timestamp".to_owned(),
        Value::String(timestamp.to_rfc3339()),
    );
    event.insert("level".to_owned(), Value::String(level.as_str().to_owned()));
    let mut field_values = Map::new();
    if let Some(message) = &fields.message {
        field_values.insert("message".to_owned(), Value::String(message.clone()));
    }
    for (key, value) in &fields.values {
        field_values.insert(key.clone(), value.json());
    }
    event.insert("fields".to_owned(), Value::Object(field_values));
    event.insert("target".to_owned(), Value::String(target.to_owned()));
    serde_json::to_writer(&mut *writer, &Value::Object(event)).map_err(io::Error::other)?;
    writeln!(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(seconds: u64, micros: u32) -> Timestamp {
        Timestamp { seconds, micros }
    }

    #[test]
    fn timestamp_formats_epoch() {
        assert_eq!(timestamp(0, 0).to_rfc3339(), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn timestamp_formats_known_instant() {
        assert_eq!(
            timestamp(1_700_000_000, 123_456).to_rfc3339(),
            "2023-11-14T22:13:20.123456Z"
        );
    }

    #[test]
    fn timestamp_formats_leap_day() {
        assert_eq!(
            timestamp(1_709_164_800, 0).to_rfc3339(),
            "2024-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn text_matches_the_existing_format() {
        let fields = Fields {
            message: Some("request blocked".to_owned()),
            values: vec![
                ("answer".to_owned(), FieldValue::U64(42)),
                (
                    "action".to_owned(),
                    FieldValue::Text("\"BLOCK\"".to_owned()),
                ),
                ("rate_limited".to_owned(), FieldValue::Bool(false)),
            ],
        };
        let mut output = Vec::new();
        write(
            &mut output,
            LogFormat::Text,
            timestamp(0, 0),
            Level::INFO,
            "kunato::proxy",
            &fields,
            false,
        )
        .expect("write text");
        assert_eq!(
            String::from_utf8(output).expect("utf-8"),
            "1970-01-01T00:00:00.000000Z  INFO kunato::proxy: request blocked answer=42 action=\"BLOCK\" rate_limited=false\n"
        );
    }

    #[test]
    fn json_matches_the_existing_schema() {
        let fields = Fields {
            message: Some("request blocked".to_owned()),
            values: vec![
                ("answer".to_owned(), FieldValue::U64(42)),
                (
                    "action".to_owned(),
                    FieldValue::Text("\"BLOCK\"".to_owned()),
                ),
                ("rate_limited".to_owned(), FieldValue::Bool(false)),
            ],
        };
        let mut output = Vec::new();
        write(
            &mut output,
            LogFormat::Json,
            timestamp(0, 0),
            Level::ERROR,
            "kunato",
            &fields,
            false,
        )
        .expect("write json");
        let value: Value = serde_json::from_slice(&output).expect("valid json");
        assert_eq!(value["timestamp"], "1970-01-01T00:00:00.000000Z");
        assert_eq!(value["level"], "ERROR");
        assert_eq!(value["target"], "kunato");
        assert_eq!(value["fields"]["message"], "request blocked");
        assert_eq!(value["fields"]["answer"], 42);
        assert_eq!(value["fields"]["action"], "\"BLOCK\"");
        assert_eq!(value["fields"]["rate_limited"], false);
    }

    #[test]
    fn json_escapes_messages() {
        let fields = Fields {
            message: Some("line one\nline \"two\"".to_owned()),
            values: Vec::new(),
        };
        let mut output = Vec::new();
        write(
            &mut output,
            LogFormat::Json,
            timestamp(0, 0),
            Level::INFO,
            "kunato",
            &fields,
            false,
        )
        .expect("write json");
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        let value: Value = serde_json::from_slice(&output).expect("valid json");
        assert_eq!(value["fields"]["message"], "line one\nline \"two\"");
    }
}
