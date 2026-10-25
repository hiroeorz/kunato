//! Human-readable rendering of the Prometheus text exposition behind
//! `kunato metrics`.
//!
//! The admin listener answers with the text format: `# HELP` and `# TYPE`
//! comments interleaved with `name value` samples. For terminal output the
//! comments are dropped, the samples become a bordered two-column table, and
//! timestamp gauges also show the local date and time instead of a bare Unix
//! value.

use std::fmt::Write as _;

use crate::error::Error;

/// Name suffix of gauges that hold a Unix timestamp.
const TIMESTAMP_SUFFIX: &str = "_timestamp_seconds";
const NAME_HEADER: &str = "NAME";
const VALUE_HEADER: &str = "VALUE";

/// Render an exposition body as a bordered `name` / `value` table.
///
/// Comment and blank lines are dropped. Gauges whose name ends with
/// [`TIMESTAMP_SUFFIX`] show the local date and time in parentheses after the
/// Unix value, or `(never)` while the value is `0`. Values are right-aligned.
pub(crate) fn render(exposition: &str) -> Result<String, Error> {
    let mut samples = Vec::new();
    for line in exposition.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let name = fields.next().unwrap_or_default();
        let Some(value) = fields.next() else {
            return Err(Error::Message(format!("unexpected metrics line: `{line}`")));
        };
        samples.push((name, value.to_owned()));
    }

    if samples.is_empty() {
        return Err(Error::Message(
            "the admin listener returned no metrics".to_owned(),
        ));
    }

    let name_width = samples
        .iter()
        .map(|(name, _)| name.chars().count())
        .chain(std::iter::once(NAME_HEADER.len()))
        .max()
        .unwrap_or(0);
    let rows: Vec<(&str, String)> = samples
        .into_iter()
        .map(|(name, value)| (name, annotate(name, &value)))
        .collect();
    let value_width = rows
        .iter()
        .map(|(_, value)| value.chars().count())
        .chain(std::iter::once(VALUE_HEADER.len()))
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    border(&mut out, '┌', '┬', '┐', name_width, value_width);
    row(&mut out, NAME_HEADER, VALUE_HEADER, name_width, value_width);
    border(&mut out, '├', '┼', '┤', name_width, value_width);
    for (name, value) in rows {
        row(&mut out, name, &value, name_width, value_width);
    }
    border(&mut out, '└', '┴', '┘', name_width, value_width);
    Ok(out)
}

fn border(
    out: &mut String,
    left: char,
    joint: char,
    right: char,
    name_width: usize,
    value_width: usize,
) {
    let _ = writeln!(
        out,
        "{left}{}{joint}{}{right}",
        "─".repeat(name_width + 2),
        "─".repeat(value_width + 2)
    );
}

fn row(out: &mut String, name: &str, value: &str, name_width: usize, value_width: usize) {
    let _ = writeln!(out, "│ {name:<name_width$} │ {value:>value_width$} │");
}

fn annotate(name: &str, value: &str) -> String {
    if !name.ends_with(TIMESTAMP_SUFFIX) {
        return value.to_owned();
    }

    let Ok(seconds) = value.parse::<u64>() else {
        return value.to_owned();
    };
    if seconds == 0 {
        return format!("{value} (never)");
    }
    match local_timestamp(seconds) {
        Some(timestamp) => format!("{value} ({timestamp})"),
        None => value.to_owned(),
    }
}

/// Convert Unix seconds to the local `YYYY/MM/DD HH:MM:SS` representation.
fn local_timestamp(seconds: u64) -> Option<String> {
    let time = libc::time_t::try_from(seconds).ok()?;
    // SAFETY: `localtime_r` only writes through the out pointer, is thread-safe,
    // and the initialized `tm` buffer stays valid for the formatting below.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&time, &mut tm).is_null() {
            return None;
        }
        tm
    };
    Some(format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPOSITION: &str = "\
# HELP kunato_requests_total Total HTTP requests handled.
# TYPE kunato_requests_total counter
kunato_requests_total 12

# HELP kunato_acme_last_success_timestamp_seconds Unix time of the last deployed ACME certificate.
# TYPE kunato_acme_last_success_timestamp_seconds gauge
kunato_acme_last_success_timestamp_seconds 1761395525
";

    #[test]
    fn renders_name_and_value_without_the_comment_lines() {
        let table = render(EXPOSITION).expect("render");

        assert!(!table.contains("# HELP"));
        assert!(!table.contains("# TYPE"));
        assert!(table.contains("│ NAME "));
        assert!(table.contains("│ kunato_requests_total "));
        assert!(table.contains("│ kunato_acme_last_success_timestamp_seconds "));
    }

    #[test]
    fn draws_a_border_around_the_table_and_under_the_header() {
        let table = render(EXPOSITION).expect("render");
        let lines: Vec<&str> = table.lines().collect();

        assert_eq!(lines.len(), 6);
        let widths: Vec<usize> = lines.iter().map(|line| line.chars().count()).collect();
        assert!(widths.iter().all(|width| *width == widths[0]), "{widths:?}");
        assert!(lines[0].starts_with('┌') && lines[0].ends_with('┐'));
        assert!(lines[1].starts_with('│') && lines[1].ends_with("VALUE │"));
        assert!(lines[2].starts_with('├') && lines[2].ends_with('┤'));
        assert!(lines[5].starts_with('└') && lines[5].ends_with('┘'));
    }

    #[test]
    fn right_aligns_the_value_column() {
        let table = render("a 7\nlonger_name 123456\n").expect("render");
        let lines: Vec<&str> = table.lines().collect();

        assert!(lines[3].ends_with(" 7 │"), "{}", lines[3]);
        assert!(lines[4].ends_with("123456 │"), "{}", lines[4]);
        assert!(lines[3].contains("│      7 │"), "{}", lines[3]);
    }

    #[test]
    fn annotates_timestamp_gauges_with_local_time() {
        let table = render(EXPOSITION).expect("render");
        let line = table
            .lines()
            .find(|line| line.contains("kunato_acme_last_success_timestamp_seconds"))
            .expect("timestamp row");
        let (value, rest) = line.split_once(" (").expect("annotation");
        let timestamp = rest.split(')').next().expect("closing parenthesis");

        assert!(value.ends_with("1761395525"), "{value}");
        assert_eq!(timestamp.len(), 19);
        assert_eq!(&timestamp[4..5], "/");
        assert_eq!(&timestamp[7..8], "/");
        assert_eq!(&timestamp[10..11], " ");
        assert_eq!(&timestamp[13..14], ":");
        assert_eq!(&timestamp[16..17], ":");
        assert!(
            timestamp
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
        );
    }

    #[test]
    fn reports_a_zero_timestamp_as_never() {
        let table = render("kunato_rules_last_success_timestamp_seconds 0\n").expect("render");

        assert!(
            table.lines().any(|line| line.ends_with("0 (never) │")),
            "{table}"
        );
    }

    #[test]
    fn keeps_values_that_are_not_timestamps_verbatim() {
        let table = render("kunato_upstream_timeouts_total 0.5\n").expect("render");

        assert!(table.lines().any(|line| line.ends_with("0.5 │")));
    }

    #[test]
    fn rejects_a_malformed_sample() {
        let error = render("# HELP kunato_total Help.\nkunato_total\n").expect_err("no value");

        assert!(
            error.to_string().contains("unexpected metrics line"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_body_without_samples() {
        let error = render("# TYPE kunato_total counter\n\n").expect_err("no samples");

        assert!(error.to_string().contains("returned no metrics"), "{error}");
    }
}
