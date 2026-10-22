//! Bounded, origin-facing resource checks for decoded form bodies.

use http::header::{CONTENT_TYPE, HeaderMap};

use crate::config::FormLimits;
use crate::decoding::{
    MAX_MULTIPART_BOUNDARIES, MultipartError, MultipartPart, disposition_parameters,
    multipart_boundaries, multipart_parts_limited, percent_decode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Violation {
    Malformed,
    Incomplete,
    Parts,
    Headers,
    HeaderBytes,
    NameBytes,
    Depth,
    Fields,
    EmptyFiles,
    Complexity,
    DisabledField,
}

impl Violation {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Malformed => "malformed or ambiguous form data",
            Self::Incomplete => "form body too large to inspect completely",
            Self::Parts => "too many multipart parts",
            Self::Headers => "too many multipart part headers",
            Self::HeaderBytes => "multipart part headers too large",
            Self::NameBytes => "form field name or filename too large",
            Self::Depth => "form nesting too deep",
            Self::Fields => "too many form fields",
            Self::EmptyFiles => "too many empty file inputs",
            Self::Complexity => "form parsing complexity too high",
            Self::DisabledField => "PHP upload progress is disabled",
        }
    }
}

pub(crate) fn is_form(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_TYPE).iter().any(|value| {
        let bytes = value
            .as_bytes()
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default();
        let media = String::from_utf8_lossy(bytes);
        matches!(
            media.trim().to_ascii_lowercase().as_str(),
            "multipart/form-data" | "application/x-www-form-urlencoded"
        )
    })
}

pub(crate) fn inspect(
    headers: &HeaderMap,
    body: &[u8],
    truncated: bool,
    limits: &FormLimits,
    disabled_fields: &[String],
) -> Result<(), Violation> {
    if truncated {
        return Err(Violation::Incomplete);
    }
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    if values.any(|value| value != first) {
        return Err(Violation::Malformed);
    }
    let content_type = first.to_str().map_err(|_| Violation::Malformed)?;
    let media = content_type.split(';').next().unwrap_or_default().trim();
    if media.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let mut stats = Stats::default();
        for field in body.split(|&b| b == b'&').filter(|field| !field.is_empty()) {
            let name = field.split(|&b| b == b'=').next().unwrap_or_default();
            if name.len() > limits.max_field_name_bytes.saturating_mul(3) {
                return Err(Violation::NameBytes);
            }
            let name = String::from_utf8_lossy(name).replace('+', " ");
            let name = percent_decode(&name);
            stats.field(&name, false, limits)?;
        }
        return Ok(());
    }
    if !media.eq_ignore_ascii_case("multipart/form-data") {
        return Err(Violation::Malformed);
    }
    let boundaries = multipart_boundaries(content_type);
    if boundaries.is_empty() || boundaries.len() > MAX_MULTIPART_BOUNDARIES {
        return Err(Violation::Malformed);
    }
    for boundary in boundaries {
        let parts = multipart_parts_limited(body, &boundary, limits.max_parts).map_err(
            |error| match error {
                MultipartError::Malformed => Violation::Malformed,
                MultipartError::TooManyParts => Violation::Parts,
            },
        )?;
        let mut stats = Stats::default();
        for part in parts {
            inspect_part(part, limits, disabled_fields, &mut stats)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Stats {
    fields: usize,
    empty_files: usize,
    complexity: usize,
}

impl Stats {
    fn charge(&mut self, work: usize, limits: &FormLimits) -> Result<(), Violation> {
        self.complexity = self.complexity.saturating_add(work);
        if self.complexity > limits.max_complexity {
            return Err(Violation::Complexity);
        }
        Ok(())
    }

    fn field(&mut self, name: &str, file: bool, limits: &FormLimits) -> Result<(), Violation> {
        if name.len() > limits.max_field_name_bytes {
            return Err(Violation::NameBytes);
        }
        if name.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(Violation::Malformed);
        }
        let depth = name.bytes().filter(|&b| b == b'[').count();
        if depth > limits.max_nesting_depth {
            return Err(Violation::Depth);
        }
        self.fields += 1;
        if self.fields > limits.max_fields {
            return Err(Violation::Fields);
        }
        self.charge((depth + 1) * if file { 6 } else { 1 }, limits)
    }
}

fn inspect_part(
    part: MultipartPart<'_>,
    limits: &FormLimits,
    disabled_fields: &[String],
    stats: &mut Stats,
) -> Result<(), Violation> {
    if part.headers.len() > limits.max_part_header_bytes {
        return Err(Violation::HeaderBytes);
    }
    let mut disposition = None;
    let mut content_type = false;
    for (index, line) in part
        .headers
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if index >= limits.max_headers_per_part {
            return Err(Violation::Headers);
        }
        if line.first().is_some_and(u8::is_ascii_whitespace) {
            return Err(Violation::Malformed);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(Violation::Malformed);
        };
        let name = http::header::HeaderName::from_bytes(&line[..colon])
            .map_err(|_| Violation::Malformed)?;
        if name == "content-disposition" {
            if disposition.is_some() {
                return Err(Violation::Malformed);
            }
            disposition = Some(
                String::from_utf8_lossy(&line[colon + 1..])
                    .trim()
                    .to_owned(),
            );
        } else if name == CONTENT_TYPE {
            if content_type {
                return Err(Violation::Malformed);
            }
            content_type = true;
        }
        stats.charge(1, limits)?;
    }
    let Some(disposition) = disposition else {
        return Ok(());
    };
    let params = disposition_parameters(&disposition).ok_or(Violation::Malformed)?;
    stats.charge(params.len(), limits)?;
    let mut name = None;
    let mut filename = None;
    for (key, value) in params {
        if key.eq_ignore_ascii_case("name") {
            if name.is_some() {
                return Err(Violation::Malformed);
            }
            name = Some(value);
        } else if key.eq_ignore_ascii_case("filename") || key.eq_ignore_ascii_case("filename*") {
            // Competing filename interpretations are rejected, not guessed.
            if filename.is_some() {
                return Err(Violation::Malformed);
            }
            filename = Some(value);
        }
    }
    if let Some(filename) = &filename {
        if filename.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(Violation::Malformed);
        }
        if filename.len() > limits.max_field_name_bytes {
            return Err(Violation::NameBytes);
        }
        if filename.is_empty() {
            stats.empty_files += 1;
            if stats.empty_files > limits.max_empty_files {
                return Err(Violation::EmptyFiles);
            }
        }
    }
    let name = name.as_deref().unwrap_or_default();
    if disabled_fields.iter().any(|disabled| disabled == name) {
        return Err(Violation::DisabledField);
    }
    stats.field(name, filename.is_some(), limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        headers
    }

    fn part(name: &str, filename: &str, extra: &str) -> String {
        format!(
            "--X\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\n{extra}\r\nvalue\r\n--X--\r\n"
        )
    }

    fn check(body: &str, limits: &FormLimits) -> Result<(), Violation> {
        inspect(&headers(), body.as_bytes(), false, limits, &[])
    }

    #[test]
    fn normal_uploads_and_browser_empty_inputs_pass() {
        let limits = FormLimits::default();
        for filename in ["", "; filename=\"\"", "; filename=\"photo.jpg\""] {
            assert_eq!(
                check(
                    &part("user[files][]", filename, "Content-Type: image/jpeg\r\n"),
                    &limits
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn enforces_part_header_count_and_bytes() {
        let limits = FormLimits::default();
        assert_eq!(
            check(&part("f", "", &"X-Test: ok\r\n".repeat(15)), &limits),
            Ok(())
        );
        assert_eq!(
            check(&part("f", "", &"X-Test: ok\r\n".repeat(16)), &limits),
            Err(Violation::Headers)
        );
        assert_eq!(
            check(
                &part("f", "", &format!("X-Test: {}\r\n", "x".repeat(8192))),
                &limits
            ),
            Err(Violation::HeaderBytes)
        );
    }

    #[test]
    fn checks_part_empty_upload_field_name_and_depth_limits() {
        let mut limits = FormLimits::default();
        assert_eq!(
            check(&part(&"x".repeat(1025), "", ""), &limits),
            Err(Violation::NameBytes)
        );
        assert_eq!(
            check(&part(&format!("f{}", "[]".repeat(17)), "", ""), &limits),
            Err(Violation::Depth)
        );
        let record = "--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\"\r\n\r\n\r\n";
        assert_eq!(
            check(&(record.repeat(17) + "--X--\r\n"), &limits),
            Err(Violation::EmptyFiles)
        );
        limits.max_empty_files = 100;
        limits.max_parts = 2;
        assert_eq!(
            check(&(record.repeat(3) + "--X--\r\n"), &limits),
            Err(Violation::Parts)
        );
    }

    #[test]
    fn counts_cumulative_array_work_even_below_individual_limits() {
        let limits = FormLimits {
            max_complexity: 22,
            ..FormLimits::default()
        };
        assert_eq!(
            check(&part("f[a][b][c]", "; filename=\"\"", ""), &limits),
            Err(Violation::Complexity)
        );
        assert_eq!(
            check(&part("f[a][b]", "; filename=\"\"", ""), &limits),
            Ok(())
        );
    }

    #[test]
    fn rejects_incomplete_malformed_ambiguous_and_folded_forms() {
        let limits = FormLimits::default();
        assert_eq!(
            inspect(&headers(), b"partial", true, &limits, &[]),
            Err(Violation::Incomplete)
        );
        assert_eq!(check("--X\r\n", &limits), Err(Violation::Malformed));
        for disposition in [
            "name=\"a\"; name=\"b\"",
            "name=\"a\"; filename=\"a\"; filename=\"b\"",
            "name=\"unterminated",
        ] {
            let body = format!(
                "--X\r\nContent-Disposition: form-data; {disposition}\r\n\r\nv\r\n--X--\r\n"
            );
            assert_eq!(check(&body, &limits), Err(Violation::Malformed));
        }
        assert_eq!(
            check(&part("f", "", " Content-Type: text/plain\r\n"), &limits),
            Err(Violation::Malformed)
        );
        assert_eq!(
            check(&part("f", "; filename=\"\0\"", ""), &limits),
            Err(Violation::Malformed)
        );
        for (extra, expected) in [(63, Ok(())), (64, Err(Violation::Malformed))] {
            let body = part("f", &"; x=y".repeat(extra), "");
            assert_eq!(check(&body, &limits), expected);
        }
    }

    #[test]
    fn all_boundary_interpretations_are_bounded_without_false_blocks() {
        let mut headers = headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X; boundary=Y"),
        );
        let body = format!(
            "{}{}",
            part("a", "", ""),
            part("b", "", "").replace("--X", "--Y")
        );
        assert_eq!(
            inspect(
                &headers,
                body.as_bytes(),
                false,
                &FormLimits::default(),
                &[]
            ),
            Ok(())
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(
                "multipart/form-data; boundary=X; boundary=Y; boundary=Z; boundary=W; boundary=V",
            ),
        );
        assert_eq!(
            inspect(
                &headers,
                body.as_bytes(),
                false,
                &FormLimits::default(),
                &[]
            ),
            Err(Violation::Malformed)
        );
    }

    #[test]
    fn upload_progress_policy_uses_parsed_field_names_not_file_contents() {
        let names = vec!["CUSTOM_PROGRESS".to_owned()];
        for params in [
            "name=CUSTOM_PROGRESS",
            "name= 'CUSTOM_PROGRESS'",
            "name=\"CUSTOM_PROGRESS\"",
        ] {
            let body =
                format!("--X\r\nContent-Disposition: form-data; {params}\r\n\r\np\r\n--X--\r\n");
            assert_eq!(
                inspect(
                    &headers(),
                    body.as_bytes(),
                    false,
                    &FormLimits::default(),
                    &names
                ),
                Err(Violation::DisabledField)
            );
        }
        let body = part("file", "; filename=\"note.txt\"", "").replace("value", "CUSTOM_PROGRESS");
        assert_eq!(
            inspect(
                &headers(),
                body.as_bytes(),
                false,
                &FormLimits::default(),
                &names
            ),
            Ok(())
        );
    }

    #[test]
    fn urlencoded_fields_decode_names_once_and_bound_counts() {
        let mut headers = headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let limits = FormLimits {
            max_nesting_depth: 2,
            max_fields: 2,
            ..FormLimits::default()
        };
        for (body, expected) in [
            ("a[b][c]=ok", Ok(())),
            ("a%5bb%5d%5bc%5d%5bd%5d=ok", Err(Violation::Depth)),
            ("a=1&a=2&a=3", Err(Violation::Fields)),
            ("a%00b=1", Err(Violation::Malformed)),
        ] {
            assert_eq!(
                inspect(&headers, body.as_bytes(), false, &limits, &[]),
                expected
            );
        }
    }

    #[test]
    fn arbitrary_form_bytes_never_panic() {
        let mut seed = 0x1234_5678u32;
        for length in 0..256 {
            let body: Vec<u8> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = inspect(&headers(), &body, false, &FormLimits::default(), &[]);
        }
    }
}
