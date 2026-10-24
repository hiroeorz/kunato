use std::cell::Cell;
use std::fmt;

/// Why a YAML document could not be parsed or deserialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    /// The document is not valid YAML, or uses an unsupported construct.
    Syntax,
    /// Serde rejected a field this build does not know.
    UnknownField,
    /// Serde rejected an enum variant this build does not know.
    UnknownVariant,
    /// Serde required a field that is absent.
    MissingField,
    /// Any other deserialization failure.
    Message,
}

/// A parse or schema error with an optional source location.
///
/// `Display` includes the location and, when the source text is available, a
/// single cropped source line with a caret. The type is public so the crate
/// error can carry it as a source; the module itself stays private.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    line: usize,
    column: usize,
    snippet: Option<String>,
}

thread_local! {
    /// Location of the node currently being deserialized. Serde's derive
    /// creates schema errors without a location, so the deserializer records
    /// the current key or mapping here and the error constructors fall back to
    /// it. Parsing is synchronous per thread, so this cannot cross requests.
    static CURRENT_LOCATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

pub(crate) fn reset_location() {
    CURRENT_LOCATION.with(|cell| cell.set((0, 0)));
}

pub(crate) fn set_location(line: usize, column: usize) {
    CURRENT_LOCATION.with(|cell| cell.set((line, column)));
}

pub(crate) fn with_location<R>(line: usize, column: usize, f: impl FnOnce() -> R) -> R {
    let previous = CURRENT_LOCATION.with(|cell| cell.replace((line, column)));
    let result = f();
    CURRENT_LOCATION.with(|cell| cell.set(previous));
    result
}

fn current_location() -> (usize, usize) {
    CURRENT_LOCATION.with(Cell::get)
}

fn sanitize_char(ch: char) -> char {
    match ch {
        '\t' => ' ',
        '\u{2028}' | '\u{2029}' => '\u{fffd}',
        ch if ch.is_control() => '\u{fffd}',
        _ => ch,
    }
}

fn sanitize(text: &str) -> String {
    text.chars().map(sanitize_char).collect()
}

impl Error {
    pub(crate) fn new(
        kind: ErrorKind,
        message: impl Into<String>,
        line: usize,
        column: usize,
    ) -> Self {
        let message = message.into();
        Self {
            kind,
            message: sanitize(&message),
            line,
            column,
            snippet: None,
        }
    }

    pub(crate) fn syntax(message: impl Into<String>, line: usize, column: usize) -> Self {
        Self::new(ErrorKind::Syntax, message, line, column)
    }

    /// True when the failure means a newer rule-set or configuration format.
    /// This is the signal `rules_update` turns into `RulesNeedNewerBuild`.
    pub(crate) fn is_unsupported_construct(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::UnknownField | ErrorKind::UnknownVariant | ErrorKind::MissingField
        )
    }

    /// Message and location without the source snippet. Rule-update logs keep
    /// this form so a rejected download reports the construct itself.
    pub(crate) fn summary(&self) -> String {
        if self.line == 0 {
            self.message.clone()
        } else {
            format!(
                "{} at line {}, column {}",
                self.message,
                self.line,
                self.column + 1
            )
        }
    }

    /// Attach one cropped source line and a caret to the error.
    pub(crate) fn attach_source(&mut self, source: &str) {
        if self.line == 0 {
            return;
        }
        let Some(text) = source.lines().nth(self.line - 1) else {
            return;
        };
        let chars: Vec<char> = text.chars().collect();
        let column = self.column.min(chars.len());
        let start = column.saturating_sub(64);
        let end = (column + 64).min(chars.len());
        let cropped: String = chars[start..end]
            .iter()
            .copied()
            .map(sanitize_char)
            .collect();
        let caret = " ".repeat(2 + (column - start));
        let width = self.line.to_string().len();
        let line_label = format!("{:>width$} | ", self.line, width = width);
        let caret_label = format!("{:width$} | ", "", width = width);
        self.snippet = Some(format!("{line_label}{cropped}\n{caret_label}{caret}^"));
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())?;
        if let Some(snippet) = &self.snippet {
            write!(f, "\n{snippet}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

fn expected_list(expected: &[&str]) -> String {
    match expected {
        [] => String::new(),
        [one] => format!(", expected `{one}`"),
        _ => format!(
            ", expected one of {}",
            expected
                .iter()
                .map(|value| format!("`{value}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        let (line, column) = current_location();
        Self::new(ErrorKind::Message, message.to_string(), line, column)
    }

    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Self {
        let (line, column) = current_location();
        Self::new(
            ErrorKind::UnknownField,
            format!("unknown field `{field}`{}", expected_list(expected)),
            line,
            column,
        )
    }

    fn missing_field(field: &'static str) -> Self {
        let (line, column) = current_location();
        Self::new(
            ErrorKind::MissingField,
            format!("missing field `{field}`"),
            line,
            column,
        )
    }

    fn unknown_variant(variant: &str, expected: &'static [&'static str]) -> Self {
        let (line, column) = current_location();
        Self::new(
            ErrorKind::UnknownVariant,
            format!("unknown variant `{variant}`{}", expected_list(expected)),
            line,
            column,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_errors_use_the_current_location() {
        reset_location();
        set_location(7, 4);
        let error = <Error as serde::de::Error>::unknown_field("new_field", &["known"]);
        assert!(error.is_unsupported_construct());
        assert_eq!(
            error.summary(),
            "unknown field `new_field`, expected `known` at line 7, column 5"
        );
        reset_location();
    }

    #[test]
    fn snippets_crop_long_lines() {
        let source = format!("{}needle\n", " ".repeat(200));
        let mut error = Error::syntax("bad node", 1, 200);
        error.attach_source(&source);
        let rendered = error.to_string();
        assert!(rendered.contains("needle"), "{rendered}");
        assert!(rendered.contains('^'), "{rendered}");
    }

    #[test]
    fn control_characters_are_sanitized() {
        let mut error = Error::new(
            ErrorKind::UnknownField,
            "unknown field `bad\u{1b}[31m`",
            1,
            0,
        );
        error.attach_source("bad\tkey\u{1b}[31m: value\n");
        let rendered = error.to_string();
        assert!(
            !rendered.chars().any(|ch| ch.is_control() && ch != '\n'),
            "{rendered:?}"
        );
        assert!(rendered.contains("bad"), "{rendered:?}");
    }

    #[test]
    fn syntax_errors_are_not_rule_format_errors() {
        let error = Error::syntax("bad", 1, 0);
        assert!(!error.is_unsupported_construct());
        assert_eq!(error.summary(), "bad at line 1, column 1");
    }
}
