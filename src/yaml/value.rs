use std::collections::HashSet;

use granit_parser::{Event, Parser, ScalarStyle, options};

use crate::yaml::error::Error;

/// A YAML scalar with its source spelling and style.
///
/// The spelling is retained because the previous parser handed `String` fields
/// the raw text (`0x10`, `TRUE`, `1.0`) rather than a canonical value, and
/// because quoted numbers must stay strings for untagged enums while typed
/// numeric fields still accept them.
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

/// Bound recursion so a hostile document cannot exhaust the stack.
const MAX_DEPTH: usize = 128;
/// Bound the value tree. A typical rule set has a few thousand nodes; this
/// limit only rejects pathological documents. At the cap the tree uses roughly
/// 130 MB, as measured during the design spike.
const MAX_NODES: usize = 1_000_000;

enum Frame {
    Seq {
        items: Vec<Value>,
        line: usize,
        column: usize,
    },
    Map {
        entries: Vec<(Value, Value)>,
        pending: Option<Value>,
        /// Scalar keys already present, so duplicate detection stays linear in
        /// the number of mapping entries.
        keys: HashSet<Key>,
        line: usize,
        column: usize,
    },
}

pub(crate) fn parse(input: &str) -> Result<Value, Error> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Value> = None;
    let mut documents = 0usize;
    let mut nodes = 0usize;

    let parser = Parser::new_from_str_with_options(input, options! { emit_comments: false });
    for item in parser {
        let (event, span) = item.map_err(|error| {
            let marker = error.marker();
            Error::syntax(error.info(), marker.line(), marker.col())
        })?;
        let line = span.start.line();
        let column = span.start.col();
        match event {
            Event::StreamStart | Event::StreamEnd | Event::Comment(..) => {}
            Event::DocumentStart(explicit, version) => {
                if version.is_some() {
                    return Err(Error::syntax(
                        "YAML directives are not supported",
                        line,
                        column,
                    ));
                }
                documents += 1;
                if documents > 1 {
                    return Err(Error::syntax(
                        "multiple YAML documents are not supported",
                        line,
                        column,
                    ));
                }
                if explicit && !stack.is_empty() {
                    return Err(Error::syntax("unexpected document start", line, column));
                }
            }
            Event::DocumentEnd => {}
            Event::Alias(_) => {
                return Err(Error::syntax(
                    "YAML aliases are not supported",
                    line,
                    column,
                ));
            }
            Event::Scalar(raw, style, anchor, tag) => {
                reject_node_properties(anchor, tag.is_some(), line, column)?;
                nodes += 1;
                if nodes > MAX_NODES {
                    return Err(Error::syntax("document has too many nodes", line, column));
                }
                let scalar = Scalar {
                    text: raw.into_owned(),
                    plain: matches!(style, ScalarStyle::Plain),
                    line,
                    column,
                };
                add_value(&mut stack, &mut root, Value::Scalar(scalar), line, column)?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                reject_node_properties(anchor, tag.is_some(), line, column)?;
                if stack.len() >= MAX_DEPTH {
                    return Err(Error::syntax("document is nested too deeply", line, column));
                }
                stack.push(Frame::Seq {
                    items: Vec::new(),
                    line,
                    column,
                });
            }
            Event::SequenceEnd => {
                let Some(Frame::Seq {
                    items,
                    line: start_line,
                    column: start_column,
                }) = stack.pop()
                else {
                    return Err(Error::syntax("unexpected sequence end", line, column));
                };
                nodes += 1;
                if nodes > MAX_NODES {
                    return Err(Error::syntax("document has too many nodes", line, column));
                }
                add_value(
                    &mut stack,
                    &mut root,
                    Value::Seq {
                        items,
                        line: start_line,
                        column: start_column,
                    },
                    line,
                    column,
                )?;
            }
            Event::MappingStart(_, anchor, tag) => {
                reject_node_properties(anchor, tag.is_some(), line, column)?;
                if stack.len() >= MAX_DEPTH {
                    return Err(Error::syntax("document is nested too deeply", line, column));
                }
                stack.push(Frame::Map {
                    entries: Vec::new(),
                    pending: None,
                    keys: HashSet::new(),
                    line,
                    column,
                });
            }
            Event::MappingEnd => {
                let Some(Frame::Map {
                    entries,
                    pending,
                    keys: _,
                    line: start_line,
                    column: start_column,
                }) = stack.pop()
                else {
                    return Err(Error::syntax("unexpected mapping end", line, column));
                };
                if pending.is_some() {
                    return Err(Error::syntax("mapping key without a value", line, column));
                }
                nodes += 1;
                if nodes > MAX_NODES {
                    return Err(Error::syntax("document has too many nodes", line, column));
                }
                add_value(
                    &mut stack,
                    &mut root,
                    Value::Map {
                        entries,
                        line: start_line,
                        column: start_column,
                    },
                    line,
                    column,
                )?;
            }
            _ => {}
        }
    }

    if !stack.is_empty() {
        return Err(Error::syntax("unexpected end of document", 0, 0));
    }
    if documents == 0 || root.is_none() {
        return Err(Error::syntax("unexpected end of input", 1, 0));
    }
    let Some(root) = root else {
        return Err(Error::syntax("unexpected end of input", 1, 0));
    };
    Ok(root)
}

fn reject_node_properties(
    anchor: usize,
    has_tag: bool,
    line: usize,
    column: usize,
) -> Result<(), Error> {
    if anchor != 0 {
        return Err(Error::syntax(
            "YAML anchors are not supported",
            line,
            column,
        ));
    }
    if has_tag {
        return Err(Error::syntax(
            "explicit YAML tags are not supported",
            line,
            column,
        ));
    }
    Ok(())
}

fn add_value(
    stack: &mut [Frame],
    root: &mut Option<Value>,
    value: Value,
    line: usize,
    column: usize,
) -> Result<(), Error> {
    match stack.last_mut() {
        None => {
            if root.is_some() {
                return Err(Error::syntax("unexpected second root node", line, column));
            }
            *root = Some(value);
        }
        Some(Frame::Seq { items, .. }) => items.push(value),
        Some(Frame::Map {
            entries,
            pending,
            keys,
            ..
        }) => {
            if pending.is_none() {
                if let Value::Scalar(scalar) = &value
                    && scalar.plain
                    && scalar.text == "<<"
                {
                    return Err(Error::syntax(
                        "YAML merge keys are not supported",
                        line,
                        column,
                    ));
                }
                let duplicate = if let Value::Scalar(scalar) = &value {
                    !keys.insert(key_of(scalar))
                } else {
                    entries
                        .iter()
                        .any(|(existing, _)| same_key(existing, &value))
                };
                if duplicate {
                    return Err(Error::syntax(
                        format!("duplicate mapping key `{}`", display_key(&value)),
                        line,
                        column,
                    ));
                }
                *pending = Some(value);
            } else if let Some(key) = pending.take() {
                entries.push((key, value));
            }
        }
    }
    Ok(())
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
    fn parses_block_and_flow_collections() {
        let value = parse("a: 1\nb: [x, 'y']\nc:\n  - {d: true}\n  - |\n      text\n")
            .expect("valid document");
        let Value::Map { entries, .. } = value else {
            panic!("expected mapping");
        };
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn preserves_scalar_spelling_and_style() {
        let Value::Scalar(plain) = parse("0x10").expect("plain") else {
            panic!("expected scalar");
        };
        assert_eq!(plain.text, "0x10");
        assert!(plain.plain);
        let Value::Scalar(quoted) = parse("'404'").expect("quoted") else {
            panic!("expected scalar");
        };
        assert_eq!(quoted.text, "404");
        assert!(!quoted.plain);
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
    fn duplicate_keys_are_type_aware() {
        assert!(parse("{1: a, 0x1: b}").is_err());
        assert!(parse("{1: a, '1': b}").is_ok());
        assert!(parse("{1: a, 1: b}").is_err());
    }

    #[test]
    fn rejects_unsupported_constructs() {
        for (document, expected) in [
            ("a: &x 1\nb: *x\n", "anchors are not supported"),
            ("a: !!str 1\n", "tags are not supported"),
            ("a: 1\n---\nb: 2\n", "multiple YAML documents"),
            ("<<: {a: 1}\n", "merge keys are not supported"),
            ("%YAML 1.2\n---\na: 1\n", "directives are not supported"),
        ] {
            let error = parse(document).expect_err(document);
            assert!(
                error.to_string().contains(expected),
                "{document}: {error} (expected {expected})"
            );
        }
    }

    #[test]
    fn rejects_deep_nesting_and_empty_input() {
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        let error = parse(&deep).expect_err("deep");
        assert!(error.to_string().contains("nested too deeply"), "{error}");
        assert!(parse("").is_err());
        assert!(parse("# only a comment\n").is_err());
    }
}
