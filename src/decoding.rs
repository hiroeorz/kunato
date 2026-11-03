use std::borrow::Cow;
use std::io::Read;

use brotli_decompressor::Decompressor as BrotliDecoder;
use flate2::read::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue};
use ruzstd::decoding::StreamingDecoder as ZstdDecoder;

const DECODE_BUFFER_BYTES: usize = 8 * 1024;
/// Largest zstd frame window accepted for inspection. Frames that declare a
/// larger window fall back to raw inspection so decode state stays bounded.
const MAX_ZSTD_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PERCENT_DECODE_PASSES: usize = 2;
const MAX_CONTENT_ENCODING_LAYERS: usize = 3;
const MAX_MULTIPART_PARTS: usize = 64;
const MAX_MULTIPART_NAME_BYTES: usize = 1024;
const MAX_MULTIPART_BOUNDARY_BYTES: usize = 70;
const MAX_DISPOSITION_PARAMETERS: usize = 64;
pub(crate) const MAX_MULTIPART_BOUNDARIES: usize = 4;

pub struct DecodedBody {
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// Result of decoding a message body for inspection. Unlike
/// [`decode_content_encoding`], this distinguishes "no encoding was declared"
/// from an encoding that cannot be decoded, so callers can fail closed when
/// body rules depend on seeing the decoded bytes.
#[derive(Debug)]
pub enum DecodeOutcome {
    NotEncoded,
    Decoded { body: Vec<u8>, complete: bool },
    Unsupported,
    Malformed,
}

/// A declared charset whose text the inspection cannot read. The body is
/// decoded as UTF-8, while the origin reads UTF-16, UTF-32, UTF-7, or an EBCDIC
/// code page, so every regex rule would see bytes instead of the text the
/// application executes.
const NON_INSPECTABLE_CHARSETS: &[&str] = &[
    "utf-16", "utf-16le", "utf-16be", "ucs-2", "ucs-2le", "ucs-2be", "utf-32", "utf-32le",
    "utf-32be", "ucs-4", "utf-7", "ebcdic", "ibm037", "cp037", "ibm500", "cp500", "ibm1047",
    "cp1047", "ibm1140",
];

/// Returns the charset that makes a body uninspectable, if any. A UTF-16 or
/// UTF-32 byte-order mark counts too: the declared type may be missing or
/// generic, while the XML or JSON parser on the origin still reads the BOM.
pub(crate) fn uninspectable_charset(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    uninspectable_charset_inner(headers, body, true)
}

/// Response bodies are allowed to contain raw binary even under a textual
/// content type because an origin may echo an uploaded file. A BOM, an XML
/// declaration, or a wide XML signature is still uninspectable, but a bare NUL
/// does not reject the response.
pub(crate) fn uninspectable_response_charset(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    uninspectable_charset_inner(headers, body, false)
}

fn uninspectable_charset_inner(
    headers: &HeaderMap,
    body: &[u8],
    check_nul: bool,
) -> Option<String> {
    let content_type = content_type_header(headers);
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if let Some(charset) = uninspectable_charset_in_header(&content_type) {
        return Some(charset);
    }
    if let Some(encoding) = uninspectable_xml_declaration(body) {
        return Some(encoding);
    }
    if media_type == "multipart/form-data" {
        return uninspectable_multipart_charset(&content_type, body, check_nul);
    }
    uninspectable_text_body(&media_type, body, check_nul)
}

/// The top-level `Content-Type` charset alone. This is the only part that can
/// be trusted before a `Content-Encoding` layer has been removed: compressed
/// bytes are not text, so BOM, XML-declaration, and NUL checks must wait for
/// [`uninspectable_charset`] to run on the decoded body.
pub(crate) fn declared_charset(headers: &HeaderMap) -> Option<String> {
    uninspectable_charset_in_header(&content_type_header(headers))
}

fn content_type_header(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// Wide encodings that make ASCII matching blind. The XML parser discovers
/// these from the first bytes even without a BOM (XML 1.0, appendix F), so a
/// body that starts with one of these signatures must not be inspected as
/// UTF-8. The last entry is the EBCDIC XML signature (`<?xm`).
const WIDE_ENCODING_SIGNATURES: &[&[u8]] = &[
    &[0x00, 0x00, 0x00, 0x3C],
    &[0x3C, 0x00, 0x00, 0x00],
    &[0x00, 0x3C, 0x00, 0x3F],
    &[0x3C, 0x00, 0x3F, 0x00],
    &[0x4C, 0x6F, 0xA7, 0x94],
];

fn uninspectable_text_body(media_type: &str, body: &[u8], check_nul: bool) -> Option<String> {
    if !is_textual_media_type(media_type) {
        return None;
    }
    if has_wide_bom(body) {
        return Some("utf-16/utf-32 byte-order mark".to_owned());
    }
    if WIDE_ENCODING_SIGNATURES
        .iter()
        .any(|signature| body.starts_with(signature))
    {
        return Some("utf-16/utf-32 byte order".to_owned());
    }
    if check_nul && body.contains(&0) {
        return Some("NUL byte in a textual body".to_owned());
    }
    None
}

/// The `encoding` pseudo-attribute of an XML declaration. It is ASCII even
/// when the rest of the document is UTF-7, so a declaration that names an
/// encoding the inspection cannot read lets the origin see markup that the
/// regex rules do not.
fn uninspectable_xml_declaration(body: &[u8]) -> Option<String> {
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let body = body.trim_ascii_start();
    if body.len() < 5 || !body[..5].eq_ignore_ascii_case(b"<?xml") {
        return None;
    }
    let end = body.windows(2).position(|window| window == b"?>")?;
    let declaration = &body[..end];
    let mut index = 5;
    while index < declaration.len() {
        while index < declaration.len() && declaration[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= declaration.len() {
            break;
        }
        let name_start = index;
        while index < declaration.len()
            && !declaration[index].is_ascii_whitespace()
            && declaration[index] != b'='
            && declaration[index] != b'?'
        {
            index += 1;
        }
        if index == name_start {
            index += 1;
            continue;
        }
        let name = &declaration[name_start..index];
        while index < declaration.len() && declaration[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= declaration.len() || declaration[index] != b'=' {
            continue;
        }
        index += 1;
        while index < declaration.len() && declaration[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= declaration.len() || !matches!(declaration[index], b'"' | b'\'') {
            continue;
        }
        let quote = declaration[index];
        index += 1;
        let value_start = index;
        while index < declaration.len() && declaration[index] != quote {
            index += 1;
        }
        let value = String::from_utf8_lossy(&declaration[value_start..index])
            .trim()
            .to_ascii_lowercase();
        if name.eq_ignore_ascii_case(b"encoding") && is_uninspectable_charset_name(&value) {
            return Some(value);
        }
        if index < declaration.len() {
            index += 1;
        }
    }
    None
}

fn is_textual_media_type(media_type: &str) -> bool {
    media_type.is_empty()
        || media_type.starts_with("text/")
        || matches!(
            media_type,
            "application/json"
                | "application/xml"
                | "application/x-www-form-urlencoded"
                | "application/graphql"
                | "application/xhtml+xml"
        )
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
        || media_type.contains("/json")
        || media_type.contains("-json")
}

fn has_wide_bom(body: &[u8]) -> bool {
    body.starts_with(&[0xFE, 0xFF])
        || body.starts_with(&[0xFF, 0xFE])
        || body.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
}

fn is_uninspectable_charset_name(charset: &str) -> bool {
    let trimmed = charset
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .trim()
        .to_ascii_lowercase();
    if NON_INSPECTABLE_CHARSETS.contains(&trimmed.as_str()) {
        return true;
    }
    let compact: String = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    compact.starts_with("utf16")
        || compact.starts_with("utf32")
        || compact.starts_with("utf7")
        || compact.ends_with("utf7")
        || compact.starts_with("xutf16")
        || compact.starts_with("xutf32")
        || compact.starts_with("xutf7")
        || compact.starts_with("ucs2")
        || compact.starts_with("ucs4")
        || compact.starts_with("iso10646ucs")
        || compact == "csunicode"
        || compact.starts_with("unicodefeff")
        || compact.starts_with("unicodefffe")
        || compact.contains("ebcdic")
        || matches!(
            compact.as_str(),
            "ibm037"
                | "cp037"
                | "csibm037"
                | "ibm500"
                | "cp500"
                | "csibm500"
                | "ibm875"
                | "cp875"
                | "ibm1026"
                | "cp1026"
                | "ibm1047"
                | "cp1047"
                | "ibm1140"
                | "cp1140"
                | "ibm273"
                | "cp273"
                | "ibm277"
                | "cp277"
                | "ibm278"
                | "cp278"
                | "ibm280"
                | "cp280"
                | "ibm284"
                | "cp284"
                | "ibm285"
                | "cp285"
                | "ibm297"
                | "cp297"
                | "ibm420"
                | "cp420"
                | "ibm424"
                | "cp424"
        )
}

/// Checks every `charset` parameter on a `Content-Type` header value. Multiple
/// distinct `charset` declarations are rejected too, so an origin that picks
/// the last parameter cannot see a different encoding than the inspection.
fn uninspectable_charset_in_header(content_type: &str) -> Option<String> {
    let mut seen: Option<String> = None;
    for raw in content_type_params(content_type, "charset") {
        let normalized = raw
            .trim()
            .trim_matches(|ch| ch == '"' || ch == '\'')
            .trim()
            .to_ascii_lowercase();
        if normalized.is_empty() || is_uninspectable_charset_name(&normalized) {
            return Some(if normalized.is_empty() {
                "empty".to_owned()
            } else {
                normalized
            });
        }
        if let Some(previous) = &seen {
            if previous != &normalized {
                return Some(format!("{previous}, {normalized}"));
            }
        } else {
            seen = Some(normalized);
        }
    }
    None
}

fn uninspectable_multipart_charset(
    content_type: &str,
    body: &[u8],
    check_nul: bool,
) -> Option<String> {
    let Ok(boundaries) = multipart_boundaries(content_type) else {
        return None;
    };
    for boundary in boundaries {
        let Some(parts) = multipart_parts(body, &boundary) else {
            continue;
        };
        for part in parts {
            let headers = String::from_utf8_lossy(part.headers);
            if let Some(part_ct) = header_value(&headers, "content-type") {
                if let Some(charset) = uninspectable_charset_in_header(part_ct) {
                    return Some(charset);
                }
                let part_media = part_ct
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if let Some(encoding) = uninspectable_xml_declaration(part.value) {
                    return Some(encoding);
                }
                if let Some(encoding) = uninspectable_text_body(&part_media, part.value, check_nul)
                {
                    return Some(encoding);
                }
            } else {
                if let Some(encoding) = uninspectable_xml_declaration(part.value) {
                    return Some(encoding);
                }
                if part.filename().is_none()
                    && let Some(encoding) = uninspectable_text_body("", part.value, check_nul)
                {
                    return Some(encoding);
                }
            }
            if let Some(disposition) = header_value(&headers, "content-disposition")
                && disposition_param(disposition, "name")
                    .is_some_and(|name| name.eq_ignore_ascii_case("_charset_"))
            {
                let value = String::from_utf8_lossy(trim_line_end(part.value));
                let charset = value.trim().to_ascii_lowercase();
                if is_uninspectable_charset_name(&charset) {
                    return Some(charset);
                }
            }
        }
    }
    None
}

/// Values of every matching parameter (such as `charset`) in a `Content-Type`
/// header, respecting quoted strings so a `;` inside another parameter cannot
/// hide a trailing `charset=`.
fn content_type_params(content_type: &str, target: &str) -> Vec<String> {
    let bytes = content_type.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] != b';' {
        index += 1;
    }
    let mut matches = Vec::new();
    while index < bytes.len() {
        index += 1; // ';'
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len() && bytes[index] != b'=' && bytes[index] != b';' {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            continue;
        }
        let name = content_type[name_start..index].trim();
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let value = if index < bytes.len() && matches!(bytes[index], b'"' | b'\'') {
            let quote = bytes[index];
            index += 1;
            let mut value = Vec::new();
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    value.push(bytes[index + 1]);
                    index += 2;
                } else {
                    value.push(bytes[index]);
                    index += 1;
                }
            }
            if index < bytes.len() {
                index += 1;
            }
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            String::from_utf8_lossy(&value).into_owned()
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            content_type[start..index].trim().to_owned()
        };
        if name.eq_ignore_ascii_case(target) {
            matches.push(value);
        }
    }
    matches
}

pub fn decode_body_for_inspection(body: &[u8], headers: &HeaderMap, limit: usize) -> DecodeOutcome {
    if body.is_empty() {
        return DecodeOutcome::NotEncoded;
    }
    if limit == 0 {
        return DecodeOutcome::Unsupported;
    }
    if !headers.contains_key(CONTENT_ENCODING) {
        return DecodeOutcome::NotEncoded;
    }
    let Some(encodings) = header_content_encodings(headers) else {
        return DecodeOutcome::Unsupported;
    };
    if encodings.is_empty() {
        return DecodeOutcome::NotEncoded;
    }

    let mut decoded: Vec<u8> = Vec::new();
    let mut first = true;
    for encoding in encodings.iter().rev() {
        let input: &[u8] = if first { body } else { &decoded };
        let (layer, status) = match encoding.as_str() {
            "gzip" | "x-gzip" => read_bounded(MultiGzDecoder::new(input), limit),
            "deflate" => decode_deflate(input, limit),
            "br" => read_bounded(BrotliDecoder::new(input, DECODE_BUFFER_BYTES), limit),
            "zstd" => match ZstdDecoder::new_with_max_window_size(input, MAX_ZSTD_WINDOW_BYTES) {
                Ok(decoder) => read_bounded(decoder, limit),
                Err(_) => return DecodeOutcome::Malformed,
            },
            _ => return DecodeOutcome::Unsupported,
        };
        match status {
            ReadStatus::Malformed => return DecodeOutcome::Malformed,
            ReadStatus::Truncated => {
                return DecodeOutcome::Decoded {
                    body: layer,
                    complete: false,
                };
            }
            ReadStatus::Complete => {
                decoded = layer;
                first = false;
            }
        }
    }

    DecodeOutcome::Decoded {
        body: decoded,
        complete: true,
    }
}

pub fn decode_content_encoding(
    body: &[u8],
    headers: &HeaderMap,
    limit: usize,
) -> Option<DecodedBody> {
    match decode_body_for_inspection(body, headers, limit) {
        DecodeOutcome::Decoded { body, complete } => Some(DecodedBody {
            body,
            truncated: !complete,
        }),
        DecodeOutcome::NotEncoded | DecodeOutcome::Unsupported | DecodeOutcome::Malformed => None,
    }
}

/// True when the message declares a `Content-Encoding` that cannot be decoded
/// for inspection: an unknown encoding, an invalid value, or more than
/// [`MAX_CONTENT_ENCODING_LAYERS`] layers. `identity` is not uninspectable.
pub fn encoding_is_uninspectable(headers: &HeaderMap) -> bool {
    headers.contains_key(CONTENT_ENCODING) && header_content_encodings(headers).is_none()
}

pub fn decode_body_format(body: &[u8], headers: &HeaderMap) -> Option<Vec<u8>> {
    decode_body_formats(body, headers).into_iter().next()
}

/// Largest JSON/XML nesting the rule engine and the origin are expected to
/// handle. A deeper body is rejected instead of being forwarded uninspected
/// because the analyzer cannot bound recursive parser behavior.
const MAX_STRUCTURED_DEPTH: usize = 128;

/// Return a description when a JSON or XML body nests past
/// [`MAX_STRUCTURED_DEPTH`]. The scan is linear and only counts structure
/// outside strings, comments, CDATA, and processing instructions.
pub(crate) fn structured_body_depth_error(
    headers: &HeaderMap,
    body: &[u8],
) -> Option<&'static str> {
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let body = body.trim_ascii_start();
    if body.is_empty() {
        return None;
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).to_ascii_lowercase())
        .unwrap_or_default();
    let json = content_type.contains("json") || matches!(body.first(), Some(b'{' | b'['));
    let xml = content_type.contains("xml")
        || content_type.contains("xhtml")
        || matches!(body.first(), Some(b'<'));
    if json && json_depth_exceeds(body, MAX_STRUCTURED_DEPTH) {
        return Some("json");
    }
    if xml && xml_depth_exceeds(body, MAX_STRUCTURED_DEPTH) {
        return Some("xml");
    }
    None
}

fn json_depth_exceeds(body: &[u8], limit: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn xml_depth_exceeds(body: &[u8], limit: usize) -> bool {
    let mut depth = 0usize;
    let mut index = 0usize;
    while index < body.len() {
        if body[index] != b'<' {
            index += 1;
            continue;
        }
        if body[index..].starts_with(b"<!--") {
            index = body[index + 4..]
                .windows(3)
                .position(|window| window == b"-->")
                .map_or(body.len(), |offset| index + 4 + offset + 3);
            continue;
        }
        if body[index..].starts_with(b"<![CDATA[") {
            index = body[index + 9..]
                .windows(3)
                .position(|window| window == b"]]>")
                .map_or(body.len(), |offset| index + 9 + offset + 3);
            continue;
        }
        if body[index..].starts_with(b"<?") {
            index = body[index + 2..]
                .windows(2)
                .position(|window| window == b"?>")
                .map_or(body.len(), |offset| index + 2 + offset + 2);
            continue;
        }
        let closing = body.get(index + 1) == Some(&b'/');
        let declaration = matches!(body.get(index + 1), Some(b'!' | b'?'));
        let mut cursor = index + 1;
        let mut quote: Option<u8> = None;
        while cursor < body.len() {
            let byte = body[cursor];
            if let Some(current_quote) = quote {
                if byte == current_quote {
                    quote = None;
                }
            } else if matches!(byte, b'"' | b'\'') {
                quote = Some(byte);
            } else if byte == b'>' {
                break;
            }
            cursor += 1;
        }
        if cursor >= body.len() {
            break;
        }
        let self_closing = cursor > index && body[cursor - 1] == b'/';
        if closing {
            depth = depth.saturating_sub(1);
        } else if !declaration && !self_closing {
            depth += 1;
            if depth > limit {
                return true;
            }
        }
        index = cursor + 1;
    }
    false
}

/// Decoded forms derived from the declared content type. Multipart bodies
/// yield one flattened form per declared boundary: a message may name several
/// (Rack parses the last, most servers the first), so every interpretation has
/// to be inspected. Content types with no usable boundary, or more than
/// [`MAX_MULTIPART_BOUNDARIES`], are treated as uninspectable and fall back to
/// the raw percent passes.
pub(crate) fn decode_body_formats(body: &[u8], headers: &HeaderMap) -> Vec<Vec<u8>> {
    if body.is_empty() {
        return Vec::new();
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()))
        .unwrap_or_default();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if media_type == "application/x-www-form-urlencoded" {
        vec![form_decode(body)]
    } else if media_type == "application/json"
        || media_type.ends_with("+json")
        || media_type.contains("/json")
        || media_type.contains("-json")
        || looks_like_escaped_json(body)
    {
        vec![json_unescape(body)]
    } else if media_type == "multipart/form-data" {
        let Ok(boundaries) = multipart_boundaries(&content_type) else {
            return Vec::new();
        };
        if boundaries.is_empty() {
            return Vec::new();
        }
        boundaries
            .iter()
            .filter_map(|boundary| multipart_flatten(body, boundary))
            .collect()
    } else {
        Vec::new()
    }
}

fn looks_like_escaped_json(body: &[u8]) -> bool {
    let body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let trimmed = body.trim_ascii_start();
    matches!(trimmed.first(), Some(b'{' | b'[')) && trimmed.contains(&b'\\')
}

/// Decoded variants of a request body for inspection: the content-type decoded
/// forms followed by up to [`MAX_PERCENT_DECODE_PASSES`] percent-encoded passes
/// each. Unknown content types still get the percent passes, because
/// applications may decode the body regardless of the declared type. The raw
/// body is inspected separately and is not repeated here.
pub fn decoded_body_forms(body: &[u8], headers: &HeaderMap) -> Vec<Vec<u8>> {
    let mut forms = Vec::new();
    let decoded = decode_body_formats(body, headers);
    if decoded.is_empty() {
        let text = String::from_utf8_lossy(body);
        push_text_decode_passes(&text, &mut forms);
        return forms;
    }
    for formatted in decoded {
        let formatted = String::from_utf8_lossy(&formatted).into_owned();
        if formatted.is_empty() {
            continue;
        }
        if formatted.as_bytes() != body {
            push_unique(&mut forms, formatted.as_bytes());
        }
        push_text_decode_passes(&formatted, &mut forms);
    }
    forms
}

fn push_percent_passes(current: &str, forms: &mut Vec<Vec<u8>>) {
    let mut current = current.to_owned();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = percent_decode(&current).into_owned();
        if next == current {
            break;
        }
        push_unique(forms, next.as_bytes());
        current = next;
    }
}

/// Add percent- and HTML/XML-entity-decoded variants. Applications routinely
/// decode numeric character references before evaluating XML, SOAP, or HTML
/// attributes, so a rule that only sees the raw body can miss the payload the
/// origin executes.
fn push_text_decode_passes(current: &str, forms: &mut Vec<Vec<u8>>) {
    push_percent_passes(current, forms);
    let mut current = current.to_owned();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = decode_entities(&current).into_owned();
        if next == current {
            break;
        }
        push_unique(forms, next.as_bytes());
        push_percent_passes(&next, forms);
        current = next;
    }
}

/// Decode HTML/XML character references (`&#x3c;`, `&#60;`, and the common
/// named entities) in one pass. Unknown entities are left untouched.
pub(crate) fn decode_entities(input: &str) -> Cow<'_, str> {
    if !input.contains('&') {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut index = 0usize;
    let mut changed = false;
    while index < bytes.len() {
        if bytes[index] != b'&' {
            index += 1;
            continue;
        }
        let Some(end_offset) = bytes[index + 1..]
            .iter()
            .take(32)
            .position(|byte| *byte == b';')
        else {
            index += 1;
            continue;
        };
        let end = index + 1 + end_offset;
        let entity = &input[index + 1..end];
        let decoded = if let Some(hex) = entity
            .strip_prefix("#x")
            .or_else(|| entity.strip_prefix("#X"))
        {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(decimal) = entity.strip_prefix('#') {
            decimal.parse::<u32>().ok().and_then(char::from_u32)
        } else {
            named_entity(entity)
        };
        if let Some(decoded) = decoded {
            output.push_str(&input[last..index]);
            output.push(decoded);
            changed = true;
            last = end + 1;
            index = end + 1;
        } else {
            index += 1;
        }
    }
    if changed {
        output.push_str(&input[last..]);
        Cow::Owned(output)
    } else {
        Cow::Borrowed(input)
    }
}

fn named_entity(entity: &str) -> Option<char> {
    Some(match entity {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "colon" => ':',
        "sol" => '/',
        "bsol" => '\\',
        "lpar" => '(',
        "rpar" => ')',
        "num" => '#',
        "percnt" => '%',
        "plus" => '+',
        "equals" => '=',
        "excl" => '!',
        "quest" => '?',
        "tab" => '\t',
        "newline" => '\n',
        "commat" => '@',
        "period" => '.',
        "comma" => ',',
        "semi" => ';',
        "lowbar" => '_',
        "dollar" => '$',
        "ast" => '*',
        "vert" => '|',
        "grave" => '`',
        "lbrace" => '{',
        "rbrace" => '}',
        "lbrack" => '[',
        "rbrack" => ']',
        _ => return None,
    })
}

fn push_unique(forms: &mut Vec<Vec<u8>>, bytes: &[u8]) {
    if !forms.iter().any(|form| form.as_slice() == bytes) {
        forms.push(bytes.to_vec());
    }
}

/// Percent-decoded variants of `input`, starting with the raw form, with at
/// most [`MAX_PERCENT_DECODE_PASSES`] passes. Repeating or unchanged forms are
/// dropped, so plain text yields a single borrowed variant.
pub fn percent_decode_forms(input: &str) -> Vec<Cow<'_, str>> {
    let mut forms = Vec::with_capacity(MAX_PERCENT_DECODE_PASSES + 1);
    forms.push(Cow::Borrowed(input));
    if !input.contains('%') {
        return forms;
    }
    let mut current = input.to_owned();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = percent_decode(&current).into_owned();
        if next == current {
            break;
        }
        forms.push(Cow::Owned(next.clone()));
        current = next;
    }
    forms
}

/// Decoded variants of a query string, starting with the raw form, with at
/// most [`MAX_PERCENT_DECODE_PASSES`] passes. Query strings are parsed with
/// `application/x-www-form-urlencoded` rules by application frameworks, so
/// `+` decodes to a space in addition to the `%XX` escapes.
pub fn query_decode_forms(input: &str) -> Vec<Cow<'_, str>> {
    let mut forms = Vec::with_capacity(MAX_PERCENT_DECODE_PASSES + 1);
    forms.push(Cow::Borrowed(input));
    if !input.contains('%') && !input.contains('+') && !input.contains('&') {
        return forms;
    }
    let mut current = input.to_owned();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = String::from_utf8_lossy(&form_decode(current.as_bytes())).into_owned();
        if next == current {
            break;
        }
        forms.push(Cow::Owned(next.clone()));
        current = next;
    }
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = decode_entities(&current).into_owned();
        if next == current {
            break;
        }
        current = next;
        let decoded = String::from_utf8_lossy(&form_decode(current.as_bytes())).into_owned();
        if decoded != current {
            forms.push(Cow::Owned(decoded.clone()));
            current = decoded;
        }
        if !forms.iter().any(|form| form.as_ref() == current) {
            forms.push(Cow::Owned(current.clone()));
        }
    }
    forms
}

/// Normalizes an absolute path the way a typical upstream server does:
/// removes `.` and `..` segments and merges duplicate slashes. Returns `None`
/// when `path` is not absolute.
pub fn normalize_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }

    let mut segments: Vec<&str> = Vec::new();
    for segment in path[1..].split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }

    if segments.is_empty() {
        return Some("/".to_owned());
    }

    let mut normalized = String::with_capacity(path.len());
    for segment in &segments {
        normalized.push('/');
        normalized.push_str(segment);
    }
    if path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..") {
        normalized.push('/');
    }
    Some(normalized)
}

pub fn percent_decode(input: &str) -> Cow<'_, str> {
    if !input.contains('%') {
        return Cow::Borrowed(input);
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }

    Cow::Owned(String::from_utf8_lossy(&decoded).into_owned())
}

/// Parse the `Content-Encoding` field into the ordered list of encodings this
/// build can decode. Returns `None` for unknown encodings, invalid values, or
/// more than [`MAX_CONTENT_ENCODING_LAYERS`] layers; `identity` entries are
/// dropped, so an empty list means there is nothing to decode.
fn content_encodings(value: &HeaderValue) -> Option<Vec<String>> {
    let mut encodings = Vec::new();
    let text = String::from_utf8_lossy(value.as_bytes());
    for token in text.split(',') {
        let token = token.trim();
        if token.is_empty() || token.eq_ignore_ascii_case("identity") {
            continue;
        }
        if encodings.len() >= MAX_CONTENT_ENCODING_LAYERS {
            return None;
        }
        let token = token.to_ascii_lowercase();
        if !matches!(
            token.as_str(),
            "gzip" | "x-gzip" | "deflate" | "br" | "zstd"
        ) {
            return None;
        }
        encodings.push(token);
    }
    Some(encodings)
}

/// Combine every `Content-Encoding` field in order, as HTTP semantics require:
/// a message may carry the header more than once, and treating only the first
/// value would let a second encoding hide an uninspected body.
fn header_content_encodings(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut encodings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        encodings.extend(content_encodings(value)?);
        if encodings.len() > MAX_CONTENT_ENCODING_LAYERS {
            return None;
        }
    }
    Some(encodings)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStatus {
    Complete,
    Truncated,
    Malformed,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> (Vec<u8>, ReadStatus) {
    let mut output = Vec::new();
    let mut buffer = [0u8; DECODE_BUFFER_BYTES];
    while output.len() < limit {
        let want = (limit - output.len()).min(buffer.len());
        match reader.read(&mut buffer[..want]) {
            Ok(0) => return (output, ReadStatus::Complete),
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(_) => return (output, ReadStatus::Malformed),
        }
    }

    if limit > 0 && output.len() >= limit {
        let mut probe = [0u8; 1];
        return match reader.read(&mut probe) {
            Ok(0) => (output, ReadStatus::Complete),
            Ok(_) => (output, ReadStatus::Truncated),
            Err(_) => (output, ReadStatus::Malformed),
        };
    }
    (output, ReadStatus::Complete)
}

fn decode_deflate(input: &[u8], limit: usize) -> (Vec<u8>, ReadStatus) {
    let decoded = read_bounded(ZlibDecoder::new(input), limit);
    if decoded.0.is_empty() && decoded.1 == ReadStatus::Malformed {
        read_bounded(DeflateDecoder::new(input), limit)
    } else {
        decoded
    }
}

fn form_decode(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        match body[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < body.len() => {
                match (hex_value(body[index + 1]), hex_value(body[index + 2])) {
                    (Some(high), Some(low)) => {
                        output.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        output.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

/// A part of a `multipart/form-data` body, borrowed from the request body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MultipartPart<'a> {
    pub(crate) headers: &'a [u8],
    pub(crate) value: &'a [u8],
}

impl MultipartPart<'_> {
    /// The `filename` parameter of the part's `Content-Disposition`, if any.
    /// Header bytes are decoded lossily so a single invalid byte cannot hide
    /// the filename (and its extension) from inspection. Empty file names are
    /// treated as absent.
    pub(crate) fn filename(&self) -> Option<String> {
        let headers = String::from_utf8_lossy(self.headers);
        let disposition = header_value(&headers, "content-disposition")?;
        disposition_filename(disposition).filter(|filename| !filename.is_empty())
    }

    /// The media type declared by the part's `Content-Type`, lowercased and
    /// stripped of parameters. Header bytes are decoded lossily for the same
    /// reason as [`Self::filename`].
    pub(crate) fn declared_content_type(&self) -> Option<String> {
        let headers = String::from_utf8_lossy(self.headers);
        let value = header_value(&headers, "content-type")?;
        let media_type = value.split(';').next()?.trim();
        (!media_type.is_empty()).then(|| media_type.to_ascii_lowercase())
    }
}

/// Every valid `boundary` parameter of a `multipart/form-data` Content-Type,
/// in declaration order and deduplicated. A message may declare several
/// boundaries and different parsers pick different ones (Rack parses the last,
/// most servers the first), so each interpretation has to be inspected.
/// Callers treat more than [`MAX_MULTIPART_BOUNDARIES`] candidates as
/// uninspectable.
/// Boundary parameters declared by a `multipart/form-data` content type.
///
/// Parsing is strict on purpose: a declaration this parser cannot read (an
/// unterminated quote, a control or non-ASCII byte, a value over 70 bytes, a
/// token with characters outside RFC 2046's set, or more than
/// [`MAX_MULTIPART_BOUNDARIES`] boundaries) is an error, so callers can fail
/// closed instead of inspecting a body the origin splits differently.
pub(crate) fn multipart_boundaries(
    content_type: &str,
) -> Result<Vec<String>, MultipartBoundaryError> {
    let bytes = content_type.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] != b';' {
        index += 1;
    }
    let mut boundaries = Vec::new();
    while index < bytes.len() {
        index += 1; // ';'
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let name_start = index;
        while index < bytes.len() && bytes[index] != b'=' && bytes[index] != b';' {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            if index > name_start {
                return Err(MultipartBoundaryError::Malformed);
            }
            continue;
        }
        let name = content_type[name_start..index].trim();
        if name.is_empty()
            || name.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte == b'"'
                    || byte == b'\''
                    || byte.is_ascii_control()
                    || !byte.is_ascii()
            })
        {
            return Err(MultipartBoundaryError::Malformed);
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let boundary_name = name.eq_ignore_ascii_case("boundary");
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
                        if bytes[index] < 0x20 || bytes[index] == 0x7f || !bytes[index].is_ascii() {
                            return Err(MultipartBoundaryError::Malformed);
                        }
                        value.push(bytes[index] as char);
                        index += 1;
                    }
                    byte if byte < 0x20 || byte == 0x7f || !byte.is_ascii() => {
                        return Err(MultipartBoundaryError::Malformed);
                    }
                    byte => {
                        value.push(byte as char);
                        index += 1;
                    }
                }
            }
            if !closed {
                return Err(MultipartBoundaryError::Malformed);
            }
            // Only whitespace or the next parameter may follow a quoted value.
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && bytes[index] != b';' {
                return Err(MultipartBoundaryError::Malformed);
            }
            value
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            let value = content_type[start..index].trim();
            if value.is_empty()
                || value.bytes().any(|byte| {
                    byte == b'"' || byte == b'\'' || byte.is_ascii_control() || !byte.is_ascii()
                })
            {
                return Err(MultipartBoundaryError::Malformed);
            }
            // A parameter we do not consume may use any token; only the
            // boundary itself has to stay inside the RFC 2046 character set.
            if boundary_name && !is_boundary_token(value) {
                return Err(MultipartBoundaryError::Malformed);
            }
            value.to_owned()
        };
        if !boundary_name {
            continue;
        }
        if value.is_empty()
            || value.len() > MAX_MULTIPART_BOUNDARY_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(MultipartBoundaryError::Malformed);
        }
        if !boundaries.iter().any(|boundary| boundary == &value) {
            boundaries.push(value);
        }
        if boundaries.len() > MAX_MULTIPART_BOUNDARIES {
            return Err(MultipartBoundaryError::TooMany);
        }
    }
    Ok(boundaries)
}

fn is_boundary_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'\''
                        | b'('
                        | b')'
                        | b'+'
                        | b'_'
                        | b','
                        | b'-'
                        | b'.'
                        | b'/'
                        | b':'
                        | b'='
                        | b'?'
                )
        })
}

/// Splits a `multipart/form-data` body into parts without copying. Parts are
/// returned in document order; the preamble and epilogue are ignored.
///
/// Returns `None` when the body is malformed (no closing delimiter) or has more
/// than [`MAX_MULTIPART_PARTS`] parts, so callers treat it as uninspectable
/// rather than acting on a partial interpretation.
pub(crate) fn multipart_parts<'a>(
    body: &'a [u8],
    boundary: &str,
) -> Option<Vec<MultipartPart<'a>>> {
    multipart_parts_limited(body, boundary, MAX_MULTIPART_PARTS).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MultipartBoundaryError {
    Malformed,
    TooMany,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MultipartError {
    Malformed,
    TooManyParts,
}

pub(crate) fn multipart_parts_limited<'a>(
    body: &'a [u8],
    boundary: &str,
    max_parts: usize,
) -> Result<Vec<MultipartPart<'a>>, MultipartError> {
    let delimiter = format!("--{boundary}");
    let closing = format!("--{boundary}--");
    let mut parts = Vec::new();
    let mut part_start: Option<usize> = None;
    let mut offset = 0usize;
    let mut closed = false;

    while offset < body.len() {
        let line_end = body[offset..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(body.len(), |index| offset + index + 1);
        let line = trim_line_end(&body[offset..line_end]);
        let trimmed = if line.starts_with(b"--") {
            line.trim_ascii_end()
        } else {
            line
        };
        let is_delimiter = trimmed == delimiter.as_bytes();
        let is_closing = trimmed == closing.as_bytes();
        if is_delimiter || is_closing {
            if let Some(start) = part_start.take() {
                if parts.len() == max_parts {
                    return Err(MultipartError::TooManyParts);
                }
                let (headers, value) = split_part(&body[start..offset]);
                parts.push(MultipartPart { headers, value });
            }
            if is_closing {
                closed = true;
                break;
            }
            part_start = Some(line_end);
        }
        offset = line_end;
    }

    if closed {
        Ok(parts)
    } else {
        Err(MultipartError::Malformed)
    }
}

/// Flattens the parts of a `multipart/form-data` body into one document for
/// inspection: field values and file names joined by newlines. Binary part
/// payloads are included verbatim; the result is bounded by the input size and
/// the part/name limits. Malformed or oversized input yields `None`.
fn multipart_flatten(body: &[u8], boundary: &str) -> Option<Vec<u8>> {
    let parts = multipart_parts(body, boundary)?;
    let mut output = Vec::new();
    for part in parts {
        flatten_part(part, &mut output);
    }
    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

fn flatten_part(part: MultipartPart<'_>, output: &mut Vec<u8>) {
    let value = trim_line_end(part.value);
    if !value.is_empty() {
        output.extend_from_slice(value);
        output.push(b'\n');
    }
    if let Some(filename) = part.filename() {
        // Emit the `filename=` spelling the signatures match, including the
        // RFC 5987 (`filename*=UTF-8''...`) forms flattened to their decoded
        // name. Without the prefix a percent-encoded name never matched the
        // upload rules.
        let filename = truncate_utf8(filename, MAX_MULTIPART_NAME_BYTES);
        output.extend_from_slice(b"filename=\"");
        output.extend_from_slice(
            filename
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .as_bytes(),
        );
        output.extend_from_slice(b"\"\n");
    }
    // Preserve empty-upload metadata in a canonical spelling for signatures;
    // the forwarded body remains byte-for-byte unchanged.
    let headers = String::from_utf8_lossy(part.headers);
    if let Some(disposition) = header_value(&headers, "content-disposition")
        && disposition_param(disposition, "filename").is_some_and(|value| value.is_empty())
        && let Some(name) = disposition_param(disposition, "name")
    {
        let name = truncate_utf8(name, MAX_MULTIPART_NAME_BYTES);
        output.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        output.extend_from_slice(name.replace('\\', "\\\\").replace('"', "\\\"").as_bytes());
        output.extend_from_slice(b"\"; filename=\"\"\n");
    }
}

fn split_part(part: &[u8]) -> (&[u8], &[u8]) {
    let mut offset = 0;
    for line in part.split_inclusive(|&byte| byte == b'\n') {
        if trim_line_end(line).is_empty() {
            return (&part[..offset], &part[offset + line.len()..]);
        }
        offset += line.len();
    }
    (part, &[])
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.lines() {
        let Some((header_name, value)) = line.split_once(':') else {
            continue;
        };
        if header_name.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn disposition_filename(disposition: &str) -> Option<String> {
    if let Some(encoded) = disposition_param(disposition, "filename*") {
        let value = match encoded.split_once('\'') {
            Some((_, rest)) => rest.split_once('\'').map_or(rest, |(_, value)| value),
            None => encoded.as_str(),
        };
        return Some(percent_decode(value).into_owned());
    }
    disposition_param(disposition, "filename")
}

pub(crate) fn disposition_param(header: &str, key: &str) -> Option<String> {
    parse_disposition_parameters(header, false, Some(key))?
        .into_iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

pub(crate) fn disposition_parameters(header: &str) -> Option<Vec<(String, String)>> {
    parse_disposition_parameters(header, true, None)
}

fn parse_disposition_parameters(
    header: &str,
    strict: bool,
    target: Option<&str>,
) -> Option<Vec<(String, String)>> {
    let bytes = header.as_bytes();
    let mut index = 0;
    let mut parameters = Vec::new();
    while index < bytes.len() {
        while index < bytes.len() && bytes[index] != b';' {
            index += 1;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let name_start = index;
        while index < bytes.len() && bytes[index] != b'=' && bytes[index] != b';' {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            if strict && index > name_start {
                return None;
            }
            continue;
        }
        let name = header[name_start..index].trim();
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let is_filename_star = name.eq_ignore_ascii_case("filename*");
        let single_quote_closed_in_param = index < bytes.len()
            && bytes[index] == b'\''
            && !is_filename_star
            && bytes[index + 1..]
                .iter()
                .take_while(|&&byte| byte != b';')
                .any(|&byte| byte == b'\'');
        if strict
            && index < bytes.len()
            && bytes[index] == b'\''
            && !is_filename_star
            && !single_quote_closed_in_param
        {
            return None;
        }
        let value = if index < bytes.len() && (bytes[index] == b'"' || single_quote_closed_in_param)
        {
            let quote = bytes[index];
            index += 1;
            let mut out = Vec::new();
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    out.push(bytes[index + 1]);
                    index += 2;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            if index < bytes.len() {
                index += 1;
            } else if strict {
                return None;
            }
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if strict && index < bytes.len() && bytes[index] != b';' {
                return None;
            }
            String::from_utf8_lossy(&out).into_owned()
        } else {
            let value_start = index;
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            let raw = header[value_start..index].trim();
            if strict && !is_filename_star && raw.bytes().any(|byte| byte == b'"' || byte == b'\'')
            {
                return None;
            }
            raw.to_owned()
        };
        if let Some(target) = target {
            if name.eq_ignore_ascii_case(target) {
                return Some(vec![(name.to_owned(), value)]);
            }
            continue;
        }
        if parameters.len() == MAX_DISPOSITION_PARAMETERS {
            return None;
        }
        parameters.push((name.to_owned(), value));
    }
    Some(parameters)
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn json_unescape(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        let byte = body[index];
        if byte != b'\\' {
            output.push(byte);
            index += 1;
            continue;
        }

        let Some(&escape) = body.get(index + 1) else {
            output.push(byte);
            break;
        };

        match escape {
            b'u' => {
                let Some(high) = body.get(index + 2..index + 6).and_then(hex4) else {
                    output.push(byte);
                    index += 1;
                    continue;
                };
                if (0xd800..=0xdbff).contains(&high)
                    && body.get(index + 6) == Some(&b'\\')
                    && body.get(index + 7) == Some(&b'u')
                    && let Some(low) = body.get(index + 8..index + 12).and_then(hex4)
                    && (0xdc00..=0xdfff).contains(&low)
                {
                    let code =
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                    push_char(&mut output, code);
                    index += 12;
                    continue;
                }
                push_char(&mut output, u32::from(high));
                index += 6;
            }
            b'"' | b'\\' | b'/' => {
                output.push(escape);
                index += 2;
            }
            b'b' => {
                output.push(0x08);
                index += 2;
            }
            b'f' => {
                output.push(0x0c);
                index += 2;
            }
            b'n' => {
                output.push(b'\n');
                index += 2;
            }
            b'r' => {
                output.push(b'\r');
                index += 2;
            }
            b't' => {
                output.push(b'\t');
                index += 2;
            }
            _ => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

fn hex4(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let mut value = 0u16;
    for &byte in bytes {
        value = value.checked_mul(16)? + u16::from(hex_value(byte)?);
    }
    Some(value)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn push_char(output: &mut Vec<u8>, code: u32) {
    if let Some(character) = char::from_u32(code) {
        let mut buffer = [0u8; 4];
        output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
    } else {
        output.extend_from_slice("\u{FFFD}".as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HeaderName};

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("zlib write");
        encoder.finish().expect("zlib finish")
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("deflate write");
        encoder.finish().expect("deflate finish")
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(&mut &data[..], &mut output, &params).expect("brotli compress");
        output
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn headers(name: HeaderName, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name, HeaderValue::from_str(value).expect("valid header"));
        map
    }

    #[test]
    fn decodes_numeric_and_named_entities() {
        assert_eq!(
            decode_entities("&#x3C;script&#62; &amp; &#x1F600;").as_ref(),
            "<script> & 😀"
        );
        assert_eq!(decode_entities("plain").as_ref(), "plain");
    }

    #[test]
    fn body_forms_include_entity_decoding() {
        let headers = headers(CONTENT_TYPE, "text/xml");
        let forms = decoded_body_forms(b"<x>&#x3C;script&#x3E;</x>", &headers);
        assert!(
            forms
                .iter()
                .any(|form| form.windows(7).any(|window| window == b"<script")),
            "{forms:?}"
        );
    }

    #[test]
    fn structured_depth_limits_are_enforced() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert_eq!(
            structured_body_depth_error(&headers, deep.as_bytes()),
            Some("json")
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        let xml = format!("{}x{}", "<a>".repeat(129), "</a>".repeat(129));
        assert_eq!(
            structured_body_depth_error(&headers, xml.as_bytes()),
            Some("xml")
        );
    }

    #[test]
    fn gzip_body_is_decoded() {
        let payload = b"q=1 union select password";
        let decoded = decode_content_encoding(
            &gzip(payload),
            &headers(CONTENT_ENCODING, "gzip"),
            payload.len(),
        )
        .expect("decoded");
        assert_eq!(decoded.body, payload);
        assert!(!decoded.truncated);
    }

    #[test]
    fn zlib_and_raw_deflate_bodies_are_decoded() {
        let payload = b"q=1 union select password";
        for encoded in [zlib(payload), raw_deflate(payload)] {
            let decoded = decode_content_encoding(
                &encoded,
                &headers(CONTENT_ENCODING, "deflate"),
                payload.len(),
            )
            .expect("decoded");
            assert_eq!(decoded.body, payload);
        }
    }

    #[test]
    fn brotli_body_is_decoded() {
        let payload = b"q=1 union select password";
        let decoded = decode_content_encoding(
            &brotli(payload),
            &headers(CONTENT_ENCODING, "br"),
            payload.len(),
        )
        .expect("decoded");
        assert_eq!(decoded.body, payload);
    }

    #[test]
    fn zstd_body_is_decoded() {
        let payload = b"q=1 union select password";
        let decoded = decode_content_encoding(
            &zstd(payload),
            &headers(CONTENT_ENCODING, "zstd"),
            payload.len(),
        )
        .expect("decoded");
        assert_eq!(decoded.body, payload);
        assert!(!decoded.truncated);
    }

    #[test]
    fn multi_member_gzip_bodies_are_decoded() {
        let mut encoded = gzip(b"benign-first-member");
        encoded.extend_from_slice(&gzip(b" UNION SELECT password"));

        let decoded =
            decode_content_encoding(&encoded, &headers(CONTENT_ENCODING, "gzip"), 1024 * 1024)
                .expect("decoded");
        assert_eq!(
            decoded.body,
            b"benign-first-member UNION SELECT password".to_vec()
        );
        assert!(!decoded.truncated);
    }

    #[test]
    fn stacked_encodings_are_decoded_in_reverse_order() {
        let payload = b"q=1 union select password";
        let stacked = zlib(&gzip(payload));
        let decoded =
            decode_content_encoding(&stacked, &headers(CONTENT_ENCODING, "gzip, deflate"), 1024)
                .expect("decoded");
        assert_eq!(decoded.body, payload);
        assert!(!decoded.truncated);
    }

    #[test]
    fn zstd_stacked_with_gzip_is_decoded_in_reverse_order() {
        let payload = b"q=1 union select password";
        let stacked = zstd(&gzip(payload));
        let decoded =
            decode_content_encoding(&stacked, &headers(CONTENT_ENCODING, "gzip, zstd"), 1024)
                .expect("decoded");
        assert_eq!(decoded.body, payload);
        assert!(!decoded.truncated);
    }

    #[test]
    fn too_many_encoding_layers_are_left_uninspected() {
        let mut payload = gzip(b"payload");
        for _ in 0..3 {
            payload = gzip(&payload);
        }
        let stacked = headers(CONTENT_ENCODING, "gzip, gzip, gzip, gzip");
        assert!(decode_content_encoding(&payload, &stacked, 1024).is_none());
        assert!(encoding_is_uninspectable(&stacked));
    }

    #[test]
    fn encoding_classification_covers_identity_and_unknown() {
        assert!(!encoding_is_uninspectable(&HeaderMap::new()));
        assert!(!encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "identity"
        )));
        assert!(!encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "gzip"
        )));
        assert!(!encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "identity, br"
        )));
        assert!(!encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "zstd"
        )));
        assert!(!encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "gzip, zstd"
        )));
        assert!(encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "compress"
        )));
        assert!(encoding_is_uninspectable(&headers(
            CONTENT_ENCODING,
            "gzip, compress"
        )));
    }

    #[test]
    fn query_forms_decode_plus_as_space() {
        let decoded = query_decode_forms("q=union+select&x=%2527");
        let forms: Vec<&str> = decoded.iter().map(|form| form.as_ref()).collect();
        assert_eq!(
            forms,
            vec![
                "q=union+select&x=%2527",
                "q=union select&x=%27",
                "q=union select&x='"
            ]
        );
    }

    #[test]
    fn query_forms_keep_plain_input_borrowed() {
        let forms = query_decode_forms("q=plain");
        assert_eq!(forms.len(), 1);
        assert!(matches!(forms[0], Cow::Borrowed("q=plain")));
    }

    #[test]
    fn body_percent_decoding_applies_without_a_known_content_type() {
        let forms = decoded_body_forms(b"q=%27%20or%201%3D1", &HeaderMap::new());
        let decoded = String::from_utf8_lossy(&forms[0]);
        assert_eq!(decoded, "q=' or 1=1");
    }

    #[test]
    fn body_forms_are_empty_without_percent_escapes() {
        assert!(decoded_body_forms(b"plain text", &HeaderMap::new()).is_empty());
    }

    #[test]
    fn decoded_output_is_bounded() {
        let encoded = gzip(&vec![b'a'; 64 * 1024]);
        let decoded = decode_content_encoding(&encoded, &headers(CONTENT_ENCODING, "gzip"), 128)
            .expect("decoded");
        assert_eq!(decoded.body.len(), 128);
    }

    #[test]
    fn truncated_decoding_is_reported() {
        let encoded = gzip(&vec![b'a'; 64 * 1024]);
        let decoded = decode_content_encoding(&encoded, &headers(CONTENT_ENCODING, "gzip"), 128)
            .expect("decoded");
        assert!(decoded.truncated);

        let payload = b"a".repeat(128);
        let decoded = decode_content_encoding(
            &gzip(&payload),
            &headers(CONTENT_ENCODING, "gzip"),
            payload.len(),
        )
        .expect("decoded");
        assert_eq!(decoded.body, payload);
        assert!(!decoded.truncated);
    }

    #[test]
    fn zstd_decoding_is_bounded_and_reports_truncation() {
        let decoded = decode_content_encoding(
            &zstd(&vec![b'a'; 64 * 1024]),
            &headers(CONTENT_ENCODING, "zstd"),
            128,
        )
        .expect("decoded");
        assert_eq!(decoded.body.len(), 128);
        assert!(decoded.truncated);
    }

    #[test]
    fn oversized_zstd_windows_fall_back_to_raw_inspection() {
        // A valid raw-block frame declaring a 16 MiB window (exponent 14),
        // above the 8 MiB inspection cap. ruzstd's default limit accepts it,
        // but Kunato's capped decoder must decline it.
        let frame: [u8; 16] = [
            0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x70, 0x39, 0x00, 0x00, b'p', b'a', b'y', b'l', b'o',
            b'a', b'd',
        ];
        let mut decoder = ZstdDecoder::new(&frame[..]).expect("frame is valid");
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).expect("decodes");
        assert_eq!(decoded, b"payload");

        assert!(
            decode_content_encoding(&frame, &headers(CONTENT_ENCODING, "zstd"), 1024).is_none()
        );
    }

    #[test]
    fn unknown_or_invalid_encodings_fall_back() {
        let payload = b"payload";
        assert!(
            decode_content_encoding(payload, &headers(CONTENT_ENCODING, "compress"), 1024)
                .is_none()
        );
        assert!(
            decode_content_encoding(payload, &headers(CONTENT_ENCODING, "gzip"), 1024).is_none()
        );
        assert!(decode_content_encoding(payload, &HeaderMap::new(), 1024).is_none());
        assert!(
            decode_content_encoding(
                payload,
                &headers(CONTENT_ENCODING, "gzip, deflate, br, compress"),
                1024
            )
            .is_none()
        );
    }

    #[test]
    fn inspection_outcome_distinguishes_uninspectable_bodies() {
        let payload = b"q=1 union select password";

        assert!(matches!(
            decode_body_for_inspection(payload, &HeaderMap::new(), 1024),
            DecodeOutcome::NotEncoded
        ));
        assert!(matches!(
            decode_body_for_inspection(payload, &headers(CONTENT_ENCODING, "identity"), 1024),
            DecodeOutcome::NotEncoded
        ));
        assert!(matches!(
            decode_body_for_inspection(payload, &headers(CONTENT_ENCODING, "compress"), 1024),
            DecodeOutcome::Unsupported
        ));
        assert!(matches!(
            decode_body_for_inspection(payload, &headers(CONTENT_ENCODING, "gzip"), 1024),
            DecodeOutcome::Malformed
        ));

        let decoded =
            decode_body_for_inspection(&gzip(payload), &headers(CONTENT_ENCODING, "gzip"), 1024);
        assert!(matches!(
            decoded,
            DecodeOutcome::Decoded { complete: true, .. }
        ));

        let truncated = decode_body_for_inspection(
            &gzip(&vec![b'a'; 4096]),
            &headers(CONTENT_ENCODING, "gzip"),
            64,
        );
        assert!(matches!(
            truncated,
            DecodeOutcome::Decoded {
                complete: false,
                ..
            }
        ));
    }

    #[test]
    fn repeated_content_encoding_headers_are_combined() {
        let payload = b"q=1 union select password";
        let mut repeated = HeaderMap::new();
        repeated.append(CONTENT_ENCODING, HeaderValue::from_static("identity"));
        repeated.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(matches!(
            decode_body_for_inspection(&gzip(payload), &repeated, 1024),
            DecodeOutcome::Decoded { complete: true, .. }
        ));

        let mut unsupported = HeaderMap::new();
        unsupported.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        unsupported.append(CONTENT_ENCODING, HeaderValue::from_static("compress"));
        assert!(matches!(
            decode_body_for_inspection(&gzip(payload), &unsupported, 1024),
            DecodeOutcome::Unsupported
        ));
        assert!(encoding_is_uninspectable(&unsupported));
    }

    #[test]
    fn truncated_compressed_stream_is_malformed_not_over_limit() {
        let mut encoded = gzip(&vec![b'a'; 4096]);
        encoded.truncate(encoded.len() / 2);
        assert!(matches!(
            decode_body_for_inspection(&encoded, &headers(CONTENT_ENCODING, "gzip"), 1024 * 1024),
            DecodeOutcome::Malformed
        ));
    }

    #[test]
    fn form_bodies_are_decoded() {
        let decoded = decode_body_format(
            b"q=%27+union%2Fselect+&x=1",
            &headers(CONTENT_TYPE, "application/x-www-form-urlencoded"),
        );
        assert_eq!(decoded.as_deref(), Some(&b"q=' union/select &x=1"[..]));
    }

    #[test]
    fn json_string_escapes_are_decoded() {
        let body = br#"{"q":"\u0075nion\u0020select","path":"a\/b","note":"say \"hi\"","emoji":"\uD83D\uDE00"}"#;
        let decoded = decode_body_format(
            body,
            &headers(CONTENT_TYPE, "application/json; charset=utf-8"),
        )
        .expect("json decoded");
        let text = String::from_utf8(decoded).expect("valid utf8");
        assert!(text.contains("union select"));
        assert!(text.contains("a/b"));
        assert!(text.contains("say \"hi\""));
        assert!(text.contains('\u{1F600}'));
    }

    #[test]
    fn json_suffix_content_types_are_decoded() {
        let decoded = decode_body_format(
            br#"{"q":"\u0075nion"}"#,
            &headers(CONTENT_TYPE, "application/problem+json"),
        );
        assert_eq!(decoded.as_deref(), Some(&br#"{"q":"union"}"#[..]));
    }

    #[test]
    fn other_content_types_are_left_alone() {
        assert!(decode_body_format(b"<script>", &headers(CONTENT_TYPE, "text/html")).is_none());
        assert!(decode_body_format(b"plain", &HeaderMap::new()).is_none());
        assert!(decode_body_format(b"", &headers(CONTENT_TYPE, "application/json")).is_none());
    }

    #[test]
    fn percent_decode_forms_include_intermediate_passes() {
        let decoded = percent_decode_forms("%252e%252e");
        let forms: Vec<&str> = decoded.iter().map(|form| form.as_ref()).collect();
        assert_eq!(forms, vec!["%252e%252e", "%2e%2e", ".."]);
    }

    #[test]
    fn percent_decode_forms_keep_plain_input_borrowed() {
        let forms = percent_decode_forms("/plain");
        assert_eq!(forms.len(), 1);
        assert!(matches!(forms[0], Cow::Borrowed("/plain")));
    }

    #[test]
    fn percent_decode_forms_keep_invalid_escapes() {
        let forms = percent_decode_forms("100%%zz");
        assert_eq!(forms, vec![Cow::Borrowed("100%%zz")]);
    }

    #[test]
    fn percent_decode_forms_decode_lossy_utf8() {
        let forms = percent_decode_forms("%FF%FE");
        assert_eq!(forms.len(), 2);
        assert_eq!(forms[0], "%FF%FE");
        assert_eq!(forms[1], "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn multipart_boundaries_are_parsed_strictly() {
        assert_eq!(
            multipart_boundaries("multipart/form-data; boundary=dummy").expect("valid"),
            vec!["dummy".to_owned()]
        );
        assert_eq!(
            multipart_boundaries("multipart/form-data; boundary=\"a b\"").expect("quoted space"),
            vec!["a b".to_owned()]
        );
        assert_eq!(
            multipart_boundaries("multipart/form-data; boundary=dummy; boundary=a b")
                .expect_err("unquoted space"),
            MultipartBoundaryError::Malformed
        );
        assert_eq!(
            multipart_boundaries("multipart/form-data; boundary=\"unterminated")
                .expect_err("unterminated"),
            MultipartBoundaryError::Malformed
        );
        assert_eq!(
            multipart_boundaries("multipart/form-data; boundary=").expect_err("empty"),
            MultipartBoundaryError::Malformed
        );
        assert_eq!(
            multipart_boundaries(
                "multipart/form-data; boundary=a; boundary=b; boundary=c; boundary=d; boundary=e"
            )
            .expect_err("too many"),
            MultipartBoundaryError::TooMany
        );
        assert_eq!(
            multipart_boundaries(
                "multipart/form-data; foo= \"a; boundary=safe; x=\"; boundary=evil"
            )
            .expect("space after = before quote"),
            vec!["evil".to_owned()]
        );
    }

    #[test]
    fn flags_charsets_and_boms_the_inspection_cannot_read() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-16"),
        );
        assert_eq!(
            uninspectable_charset(&headers, br#"{"a":1}"#).as_deref(),
            Some("utf-16")
        );

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=shift_jis"),
        );
        assert_eq!(uninspectable_charset(&headers, b"hello"), None);

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/xml"));
        assert!(uninspectable_charset(&headers, &[0xFF, 0xFE, 0x3C, 0x00]).is_some());
        assert!(uninspectable_charset(&headers, b"<a/>").is_none());

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        assert_eq!(uninspectable_charset(&headers, &[0xFF, 0xFE]), None);
        assert_eq!(
            uninspectable_charset(
                &headers,
                b"--X\r\nContent-Disposition: form-data; name=\"q\"\r\nContent-Type: text/plain; charset=utf16le\r\n\r\nhi\r\n--X--\r\n"
            )
            .as_deref(),
            Some("utf16le")
        );
        assert_eq!(
            uninspectable_charset(
                &headers,
                b"--X\r\nContent-Disposition: form-data; name=\"_charset_\"\r\n\r\nutf-7\r\n--X--\r\n"
            )
            .as_deref(),
            Some("utf-7")
        );

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8; charset=utf-16le"),
        );
        assert!(uninspectable_charset(&headers, br#"{"a":1}"#).is_some());

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/xml"));
        for body in [
            "<\0?\0x\0m\0l\0".as_bytes(),
            "\0<\0?\0x\0m\0l".as_bytes(),
            "<\0\0\0?\0\0\0x\0\0\0m".as_bytes(),
            "\0\0\0<\0\0\0?".as_bytes(),
        ] {
            assert!(
                uninspectable_charset(&headers, body).is_some(),
                "wide signature must be rejected"
            );
        }
        assert_eq!(
            uninspectable_charset(
                &headers,
                br#"<?xml version="1.0" encoding="UTF-7"?><root/>"#,
            )
            .as_deref(),
            Some("utf-7")
        );
        assert_eq!(
            uninspectable_charset(
                &headers,
                br#"<?xml version='1.0' standalone='yes' encoding='utf-16'?><root/>"#,
            )
            .as_deref(),
            Some("utf-16")
        );
        assert_eq!(
            uninspectable_charset(
                &headers,
                br#"<?xml version="1.0" encoding="UTF-8"?><root/>"#,
            ),
            None
        );
        assert_eq!(
            uninspectable_charset(&headers, b"<root>plain\0text</root>"),
            Some("NUL byte in a textual body".to_owned())
        );

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        assert_eq!(
            uninspectable_charset(
                &headers,
                b"--X\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.xml\"\r\nContent-Type: application/xml\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-7\"?><a/>\r\n--X--\r\n"
            )
            .as_deref(),
            Some("utf-7")
        );
    }

    #[test]
    fn normalize_path_removes_dot_segments_and_merges_slashes() {
        assert_eq!(normalize_path("/admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("//admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/./admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("/x/../admin").as_deref(), Some("/admin"));
        assert_eq!(
            normalize_path("/a/b/../../admin").as_deref(),
            Some("/admin")
        );
        assert_eq!(normalize_path("/a/../..").as_deref(), Some("/"));
        assert_eq!(normalize_path("/admin/").as_deref(), Some("/admin/"));
        assert_eq!(normalize_path("/admin/.").as_deref(), Some("/admin/"));
        assert_eq!(normalize_path("/").as_deref(), Some("/"));
        assert_eq!(normalize_path("relative"), None);
    }

    fn multipart_headers(boundary: &str) -> HeaderMap {
        headers(
            CONTENT_TYPE,
            &format!("multipart/form-data; boundary={boundary}"),
        )
    }

    #[test]
    fn multipart_values_and_filenames_are_flattened() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../etc/passwd\"\r\nContent-Type: text/plain\r\n\r\nblob\r\n--X--\r\n";
        let decoded = decode_body_format(body, &multipart_headers("X")).expect("multipart decoded");
        let text = String::from_utf8(decoded).expect("valid utf8");
        assert!(text.contains("admin"));
        assert!(text.contains("../../etc/passwd"));
    }

    #[test]
    fn multipart_parts_expose_filenames_and_declared_types() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg; charset=binary\r\n\r\nJPEGDATA\r\n--X--\r\n";
        let parts = multipart_parts(body, "X").expect("parts");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].filename(), None);
        assert_eq!(parts[0].declared_content_type(), None);
        assert_eq!(parts[0].value, b"admin\r\n");
        assert_eq!(parts[1].filename().as_deref(), Some("photo.jpg"));
        assert_eq!(
            parts[1].declared_content_type().as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(parts[1].value, b"JPEGDATA\r\n");
    }

    #[test]
    fn multipart_quoted_boundary_is_supported() {
        let body = b"--b-1\r\n\r\nvalue\r\n--b-1--\r\n";
        let decoded = decode_body_format(
            body,
            &headers(
                CONTENT_TYPE,
                "multipart/form-data; charset=utf-8; boundary=\"b-1\"",
            ),
        )
        .expect("multipart decoded");
        assert_eq!(decoded, b"value\n");
    }

    #[test]
    fn multipart_filename_star_is_percent_decoded() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd\r\n\r\nx\r\n--X--\r\n";
        let decoded = decode_body_format(body, &multipart_headers("X")).expect("multipart decoded");
        let text = String::from_utf8(decoded).expect("valid utf8");
        assert!(text.contains("../../etc/passwd"));
    }

    #[test]
    fn multipart_lf_only_bodies_are_supported() {
        let body = b"--X\nContent-Disposition: form-data; name=\"a\"\n\nv\n--X--\n";
        let decoded = decode_body_format(body, &multipart_headers("X")).expect("multipart decoded");
        assert_eq!(decoded, b"v\n");
    }

    #[test]
    fn multipart_without_closing_delimiter_is_left_raw() {
        let body = b"--X\r\n\r\nvalue";
        assert!(decode_body_format(body, &multipart_headers("X")).is_none());
    }

    #[test]
    fn multipart_without_boundary_is_left_alone() {
        assert!(
            decode_body_format(
                b"--X\r\n\r\nv\r\n--X--\r\n",
                &headers(CONTENT_TYPE, "multipart/form-data")
            )
            .is_none()
        );
        assert!(decode_body_format(b"not multipart", &multipart_headers("X")).is_none());
    }

    #[test]
    fn multipart_part_limit_falls_back() {
        let mut body = Vec::new();
        for index in 0..=MAX_MULTIPART_PARTS {
            body.extend_from_slice(format!("--X\r\n\r\nv{index}\r\n").as_bytes());
        }
        body.extend_from_slice(b"--X--\r\n");
        assert!(decode_body_format(&body, &multipart_headers("X")).is_none());
    }

    #[test]
    fn multipart_bodies_are_percent_decoded_after_flattening() {
        let body = b"--X\r\n\r\nq=%2527\r\n--X--\r\n";
        let forms = decoded_body_forms(body, &multipart_headers("X"));
        let forms: Vec<&str> = forms
            .iter()
            .map(|form| std::str::from_utf8(form).expect("utf8"))
            .collect();
        assert_eq!(forms, vec!["q=%2527\n", "q=%27\n", "q='\n"]);
    }

    #[test]
    fn multipart_multi_boundary_bodies_inspect_each_interpretation() {
        let body = b"--safe\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--safe--\r\n--malicious\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\nunion%20select%201\r\n--malicious--\r\n";
        let forms = decoded_body_forms(
            body,
            &headers(
                CONTENT_TYPE,
                "multipart/form-data; boundary=safe; boundary=malicious",
            ),
        );
        let forms: Vec<&str> = forms
            .iter()
            .map(|form| std::str::from_utf8(form).expect("utf8"))
            .collect();
        assert!(
            forms.iter().any(|form| form.contains("v\n")),
            "first boundary interpretation missing: {forms:?}"
        );
        assert!(
            forms.iter().any(|form| form.contains("union select")),
            "last boundary interpretation missing: {forms:?}"
        );
    }

    #[test]
    fn multipart_excess_boundaries_fall_back_to_percent_passes() {
        let body = b"payload=%75nion%20select";
        let forms = decoded_body_forms(
            body,
            &headers(
                CONTENT_TYPE,
                "multipart/form-data; boundary=a; boundary=b; boundary=c; boundary=d; boundary=e",
            ),
        );
        let forms: Vec<&str> = forms
            .iter()
            .map(|form| std::str::from_utf8(form).expect("utf8"))
            .collect();
        assert_eq!(forms, vec!["payload=union select"]);
    }

    #[test]
    fn multipart_duplicate_boundaries_flatten_once() {
        let body = b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--X--\r\n";
        let forms = decoded_body_forms(
            body,
            &headers(CONTENT_TYPE, "multipart/form-data; boundary=X; boundary=X"),
        );
        let forms: Vec<&str> = forms
            .iter()
            .map(|form| std::str::from_utf8(form).expect("utf8"))
            .collect();
        assert_eq!(forms, vec!["v\n"]);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let multipart = multipart_headers("boundary");
        for _ in 0..5_000 {
            let length = (next_random(&mut state) % 48) as usize;
            let body: Vec<u8> = (0..length)
                .map(|_| (next_random(&mut state) & 0xff) as u8)
                .collect();
            let _ = decode_body_format(
                &body,
                &headers(CONTENT_TYPE, "application/x-www-form-urlencoded"),
            );
            let _ = decode_body_format(&body, &headers(CONTENT_TYPE, "application/json"));
            let _ = decode_body_format(&body, &multipart);
            let _ = decoded_body_forms(&body, &multipart);
            let _ = percent_decode_forms(&String::from_utf8_lossy(&body));
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "gzip"), 1024);
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "deflate"), 1024);
            let _ = decode_content_encoding(&body, &headers(CONTENT_ENCODING, "br"), 1024);
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state ^ (*state >> 33)
    }

    #[test]
    fn permissive_filename_inspection_does_not_disappear_when_form_guard_is_disabled() {
        assert_eq!(
            disposition_param("form-data; name=x; filename=\"photo.jpg", "filename").as_deref(),
            Some("photo.jpg")
        );
        assert!(disposition_parameters("form-data; name=x; filename=\"photo.jpg").is_none());
        assert_eq!(
            disposition_param("form-data; name= 'file'; filename='photo.jpg'", "filename")
                .as_deref(),
            Some("photo.jpg")
        );
        let padded = format!(
            "form-data; {}filename=\"photo.jpg\"; {}",
            "x=y; ".repeat(70),
            "x=y; ".repeat(70)
        );
        assert_eq!(
            disposition_param(&padded, "filename").as_deref(),
            Some("photo.jpg")
        );
        assert!(disposition_parameters(&padded).is_none());
        assert_eq!(
            disposition_filename("form-data; name=\"f\"; dummy='; filename*=UTF-8''%73hell.%70hp")
                .as_deref(),
            Some("shell.php")
        );
        assert!(
            disposition_parameters(
                "form-data; name=\"f\"; dummy='; filename*=UTF-8''%73hell.%70hp"
            )
            .is_none()
        );
        assert_eq!(
            disposition_filename("form-data; name=\"f\"; filename*=''%73hell.%70hp").as_deref(),
            Some("shell.php")
        );
    }
}
