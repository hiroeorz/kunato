use std::collections::HashSet;

use crate::yaml::error::Error;

/// A YAML scalar with its source spelling and style.
///
/// The spelling is retained because string fields receive the raw text
/// (`0x10`, `TRUE`, `1.0`) rather than a canonical value, and because quoted
/// numbers must stay strings for untagged enums while typed numeric fields
/// still accept them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Scalar {
    pub(crate) text: String,
    pub(crate) plain: bool,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl Scalar {
    pub(crate) fn is_null(&self) -> bool {
        self.plain
            && (self.text.is_empty() || self.text == "~" || self.text.eq_ignore_ascii_case("null"))
    }
}

/// A parsed YAML node. Mappings keep their entries as a vector so duplicate
/// keys can be detected before serde sees them and every key reaches derive's
/// `deny_unknown_fields` handling.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Scalar(Scalar),
    Seq {
        items: Vec<Value>,
        line: usize,
        column: usize,
    },
    Map {
        entries: Vec<(Value, Value)>,
        line: usize,
        column: usize,
    },
}

impl Value {
    pub(crate) fn location(&self) -> (usize, usize) {
        match self {
            Self::Scalar(scalar) => (scalar.line, scalar.column),
            Self::Seq { line, column, .. } | Self::Map { line, column, .. } => (*line, *column),
        }
    }
}

/// YAML node identity for duplicate-key detection: a plain integer and its
/// hexadecimal spelling are duplicates, while a plain integer and a quoted
/// string are not.
#[derive(Debug, PartialEq, Eq, Hash)]
enum Key {
    Null,
    Bool(bool),
    Int(i128),
    UInt(u128),
    Float(u64),
    Str(String),
}

fn same_key(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Scalar(left), Value::Scalar(right)) => key_of(left) == key_of(right),
        (Value::Seq { items: left, .. }, Value::Seq { items: right, .. }) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| same_key(left, right))
        }
        (Value::Map { entries: left, .. }, Value::Map { entries: right, .. }) => {
            left.len() == right.len()
                && left.iter().all(|(left_key, left_value)| {
                    right.iter().any(|(right_key, right_value)| {
                        same_key(left_key, right_key) && same_key(left_value, right_value)
                    })
                })
        }
        _ => false,
    }
}

fn key_of(scalar: &Scalar) -> Key {
    if scalar.is_null() {
        return Key::Null;
    }
    if scalar.plain {
        if let Ok(value) = parse_bool_text(&scalar.text) {
            return Key::Bool(value);
        }
        if let Ok(value) = parse_int_text(&scalar.text) {
            return match value {
                Int::I(value) => Key::Int(value),
                Int::U(value) => Key::UInt(value),
            };
        }
        if let Ok(value) = parse_float_text(&scalar.text) {
            return Key::Float(value.to_bits());
        }
    }
    Key::Str(scalar.text.clone())
}

fn display_key(value: &Value) -> String {
    match value {
        Value::Scalar(scalar) => scalar.text.clone(),
        _ => "a complex key".to_owned(),
    }
}

/// Builds a mapping while rejecting duplicate and merge keys.
pub(crate) struct MapBuilder {
    entries: Vec<(Value, Value)>,
    keys: HashSet<Key>,
    line: usize,
    column: usize,
}

impl MapBuilder {
    pub(crate) fn new(line: usize, column: usize) -> Self {
        Self {
            entries: Vec::new(),
            keys: HashSet::new(),
            line,
            column,
        }
    }

    pub(crate) fn insert(
        &mut self,
        key: Value,
        value: Value,
        line: usize,
        column: usize,
    ) -> Result<(), Error> {
        if let Value::Scalar(scalar) = &key
            && scalar.plain
            && scalar.text == "<<"
        {
            return Err(Error::syntax(
                "YAML merge keys are not supported",
                line,
                column,
            ));
        }
        let duplicate = if let Value::Scalar(scalar) = &key {
            !self.keys.insert(key_of(scalar))
        } else {
            self.entries
                .iter()
                .any(|(existing, _)| same_key(existing, &key))
        };
        if duplicate {
            return Err(Error::syntax(
                format!("duplicate mapping key `{}`", display_key(&key)),
                line,
                column,
            ));
        }
        self.entries.push((key, value));
        Ok(())
    }

    pub(crate) fn finish(self) -> Value {
        Value::Map {
            entries: self.entries,
            line: self.line,
            column: self.column,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Int {
    I(i128),
    U(u128),
}

pub(crate) fn parse_bool_text(raw: &str) -> Result<bool, String> {
    let text = raw.trim();
    if text.eq_ignore_ascii_case("true")
        || text.eq_ignore_ascii_case("yes")
        || text.eq_ignore_ascii_case("y")
        || text.eq_ignore_ascii_case("on")
    {
        Ok(true)
    } else if text.eq_ignore_ascii_case("false")
        || text.eq_ignore_ascii_case("no")
        || text.eq_ignore_ascii_case("n")
        || text.eq_ignore_ascii_case("off")
    {
        Ok(false)
    } else {
        Err("invalid boolean".to_owned())
    }
}

pub(crate) fn parse_int_text(raw: &str) -> Result<Int, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err("empty integer".to_owned());
    }
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if body.is_empty() {
        return Err("invalid integer".to_owned());
    }
    let (radix, digits) =
        if let Some(rest) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            (16, rest)
        } else if let Some(rest) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
            (8, rest)
        } else if let Some(rest) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
            (2, rest)
        } else {
            if leading_zero_decimal(body) {
                return Err("legacy octal integers are not supported".to_owned());
            }
            (10, body)
        };
    let digits = normalize_digits(digits, radix)?;
    if negative {
        let value =
            i128::from_str_radix(&digits, radix).map_err(|_| "integer out of range".to_owned())?;
        Ok(Int::I(-value))
    } else {
        let value =
            u128::from_str_radix(&digits, radix).map_err(|_| "integer out of range".to_owned())?;
        Ok(Int::U(value))
    }
}

fn leading_zero_decimal(digits: &str) -> bool {
    let mut chars = digits.chars();
    match chars.next() {
        Some('0') => chars.next().is_some_and(|next| next.is_ascii_digit()),
        _ => false,
    }
}

fn normalize_digits(digits: &str, radix: u32) -> Result<String, String> {
    if digits.is_empty() {
        return Err("invalid integer".to_owned());
    }
    let mut normalized = String::with_capacity(digits.len());
    let mut previous_underscore = false;
    for (index, ch) in digits.chars().enumerate() {
        if ch == '_' {
            if index == 0 || previous_underscore || index + 1 == digits.len() {
                return Err("invalid underscore in integer".to_owned());
            }
            previous_underscore = true;
            continue;
        }
        if !ch.is_digit(radix) {
            return Err("invalid integer digit".to_owned());
        }
        previous_underscore = false;
        normalized.push(ch);
    }
    if normalized.is_empty() {
        return Err("invalid integer".to_owned());
    }
    Ok(normalized)
}

pub(crate) fn parse_float_text(raw: &str) -> Result<f64, String> {
    let text = raw.trim();
    let lower = text.to_ascii_lowercase();
    match lower.as_str() {
        ".inf" | "+.inf" => return Ok(f64::INFINITY),
        "-.inf" => return Ok(f64::NEG_INFINITY),
        ".nan" => return Ok(f64::NAN),
        _ => {}
    }
    if text.contains('_') {
        return Err("invalid float".to_owned());
    }
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    if !unsigned
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return Err("invalid float".to_owned());
    }
    text.parse::<f64>().map_err(|_| "invalid float".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(text: &str) -> Scalar {
        Scalar {
            text: text.to_owned(),
            plain: true,
            line: 1,
            column: 0,
        }
    }

    #[test]
    fn resolves_null_and_boolean_words() {
        assert!(scalar("").is_null());
        assert!(scalar("~").is_null());
        assert!(scalar("NULL").is_null());
        assert!(!scalar("'null'").is_null());
        assert_eq!(parse_bool_text("YES"), Ok(true));
        assert_eq!(parse_bool_text("off"), Ok(false));
        assert!(parse_bool_text("1").is_err());
    }

    #[test]
    fn parses_yaml_integers() {
        assert_eq!(parse_int_text("16"), Ok(Int::U(16)));
        assert_eq!(parse_int_text("+16"), Ok(Int::U(16)));
        assert_eq!(parse_int_text("-16"), Ok(Int::I(-16)));
        assert_eq!(parse_int_text("0x10"), Ok(Int::U(16)));
        assert_eq!(parse_int_text("0o20"), Ok(Int::U(16)));
        assert_eq!(parse_int_text("0b10000"), Ok(Int::U(16)));
        assert_eq!(parse_int_text("1_000"), Ok(Int::U(1000)));
        assert!(parse_int_text("0123").is_err());
        assert!(parse_int_text("1__0").is_err());
        assert!(parse_int_text("0x_10").is_err());
    }

    #[test]
    fn parses_yaml_floats() {
        assert_eq!(parse_float_text("1.5"), Ok(1.5));
        assert_eq!(parse_float_text("404"), Ok(404.0));
        assert_eq!(parse_float_text("0123"), Ok(123.0));
        assert_eq!(parse_float_text(".inf"), Ok(f64::INFINITY));
        assert!(parse_float_text("1_000.5").is_err());
        assert!(parse_float_text("1m").is_err());
    }

    #[test]
    fn map_builder_rejects_duplicates_and_merge_keys() {
        let mut builder = MapBuilder::new(1, 0);
        builder
            .insert(Value::Scalar(scalar("a")), Value::Scalar(scalar("1")), 1, 0)
            .expect("first key");
        assert!(
            builder
                .insert(Value::Scalar(scalar("a")), Value::Scalar(scalar("2")), 1, 0,)
                .is_err()
        );
        assert!(
            builder
                .insert(Value::Scalar(scalar("<<")), Value::Scalar(scalar("")), 1, 0,)
                .is_err()
        );
    }
}
