//! SAML message inspection: bounded base64/DEFLATE decoding and structural
//! checks for XML signature wrapping.
//!
//! The engine cannot verify XML signatures without the identity provider's
//! certificates and a canonicalization implementation. It can, however,
//! detect the structural shapes that wrapping attacks leave behind: duplicate
//! element IDs, a signature reference that does not name the element carrying
//! the signature, assertions moved out of the response, and multiple plaintext
//! assertions with different subjects. Identity providers normally send a
//! single assertion, a signature over the response or the assertion, and a
//! reference that names its own parent.

use std::collections::BTreeSet;
use std::io::Read;

use flate2::read::{DeflateDecoder, ZlibDecoder};
use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderMap};

use crate::config::{SamlFindingAction, SamlInspection, SamlLimits};
use crate::decoding::form_decode;

/// Elements inspected in one SAML message.
const MAX_ELEMENTS: usize = 4096;
/// XML nesting depth inspected in one SAML message.
const MAX_DEPTH: usize = 64;
/// Attributes inspected on one XML element.
const MAX_ATTRIBUTES: usize = 64;
/// Bytes retained from one `NameID` for subject comparison.
const MAX_NAME_ID_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Finding {
    Doctype,
    DuplicateId,
    SignatureReferenceMismatch,
    AssertionOutsideResponse,
    MultipleNameIds,
    Unsigned,
    Malformed,
    TooLarge,
    TooComplex,
    UnsupportedEncoding,
}

impl Finding {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Doctype => "doctype",
            Self::DuplicateId => "duplicate-id",
            Self::SignatureReferenceMismatch => "signature-reference-mismatch",
            Self::AssertionOutsideResponse => "assertion-outside-response",
            Self::MultipleNameIds => "multiple-name-ids",
            Self::Unsigned => "unsigned",
            Self::Malformed => "malformed",
            Self::TooLarge => "too-large",
            Self::TooComplex => "too-complex",
            Self::UnsupportedEncoding => "unsupported-encoding",
        }
    }

    /// Findings that reject the request in `strict` mode. Multiple assertions
    /// with different subjects and an unsigned response are logged unless the
    /// deployment raises their configured action to `block`.
    fn blocks(self, limits: &SamlLimits) -> bool {
        match self {
            Self::MultipleNameIds => limits.multi_assertion == SamlFindingAction::Block,
            Self::Unsigned => limits.unsigned == SamlFindingAction::Block,
            Self::Doctype
            | Self::DuplicateId
            | Self::SignatureReferenceMismatch
            | Self::AssertionOutsideResponse
            | Self::Malformed
            | Self::TooLarge
            | Self::TooComplex
            | Self::UnsupportedEncoding => true,
        }
    }

    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedEncoding => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Malformed | Self::TooComplex => StatusCode::BAD_REQUEST,
            _ => StatusCode::FORBIDDEN,
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "SAML message too large to inspect",
            Self::UnsupportedEncoding => "unsupported SAML message encoding",
            Self::Malformed | Self::TooComplex => "malformed SAML message",
            _ => "SAML message failed integrity checks",
        }
    }
}

/// Findings for one request and, in `strict` mode, the finding that rejects it.
pub(crate) struct Inspection {
    pub(crate) findings: Vec<Finding>,
    pub(crate) blocking: Option<Finding>,
}

struct Message {
    value: Vec<u8>,
    is_response: bool,
}

/// Inspect a form-encoded or JSON SAML message. Returns `None` when the
/// request does not carry a `SAMLResponse` or `SAMLRequest` field, so ordinary
/// traffic pays only a media-type check.
pub(crate) fn inspect(headers: &HeaderMap, body: &[u8], limits: &SamlLimits) -> Option<Inspection> {
    inspect_with(headers, body, false, limits)
}

/// Inspect a body that was cut at `limits.max_body_bytes`.
///
/// The message may sit past the inspected prefix, and no prefix scan can prove
/// it absent, so a SAML-capable media type fails closed in strict mode. The
/// trade-off is documented in `docs/development.md`: every over-limit form or
/// JSON body is rejected while SAML strict mode is on.
pub(crate) fn inspect_truncated(
    headers: &HeaderMap,
    body: &[u8],
    limits: &SamlLimits,
) -> Option<Inspection> {
    inspect_with(headers, body, true, limits)
}

fn inspect_with(
    headers: &HeaderMap,
    body: &[u8],
    truncated: bool,
    limits: &SamlLimits,
) -> Option<Inspection> {
    if limits.mode == SamlInspection::Off || limits.max_decoded_bytes == 0 {
        return None;
    }
    if truncated {
        if !is_saml_content_type(headers) {
            return None;
        }
        let findings = vec![Finding::TooLarge];
        let blocking = (limits.mode == SamlInspection::Strict).then_some(Finding::TooLarge);
        return Some(Inspection { findings, blocking });
    }
    if body.is_empty() {
        return None;
    }
    let messages = messages(headers, body)?;
    let mut findings = BTreeSet::new();
    for message in messages {
        match decode_message(&message.value, limits.max_decoded_bytes) {
            Ok(xml) => findings.extend(analyze(&xml, message.is_response)),
            Err(finding) => {
                findings.insert(finding);
            }
        }
    }
    let blocking = if limits.mode == SamlInspection::Strict {
        findings
            .iter()
            .copied()
            .find(|finding| finding.blocks(limits))
    } else {
        None
    };
    Some(Inspection {
        findings: findings.into_iter().collect(),
        blocking,
    })
}

fn messages(headers: &HeaderMap, body: &[u8]) -> Option<Vec<Message>> {
    let media_type = media_type(headers)?;
    if !has_saml_hint(body) {
        return None;
    }
    if media_type == "application/x-www-form-urlencoded" {
        form_messages(body)
    } else if media_type == "application/json"
        || media_type.ends_with("+json")
        || media_type.contains("/json")
    {
        json_messages(body)
    } else {
        None
    }
}

/// True when the declared media type can carry a SAML POST binding. The
/// server uses this to decide whether an encoded body must be decompressed for
/// inspection; the guard itself still requires a `SAMLResponse` field.
pub(crate) fn is_saml_content_type(headers: &HeaderMap) -> bool {
    media_type(headers).is_some_and(|media| {
        media == "application/x-www-form-urlencoded"
            || media == "application/json"
            || media.ends_with("+json")
            || media.contains("/json")
    })
}

/// A cheap prefilter before the body is parsed. It must be a **superset** of
/// the field-name decoders used by `form_messages` and `json_messages`: a
/// literal `SAMLResponse`/`SAMLRequest` contains `SAML`, and any escaped
/// spelling of it contains a percent escape (form) or a backslash (JSON). If a
/// decoder is added that can produce the field name without either byte, this
/// prefilter must be removed rather than extended, because a spelling it does
/// not recognize would skip the structural checks entirely.
fn has_saml_hint(body: &[u8]) -> bool {
    let mut index = 0;
    while index < body.len() {
        match body[index] {
            b'%' | b'\\' => return true,
            b'S' | b's'
                if body
                    .get(index..index.saturating_add(4))
                    .is_some_and(|window| window.eq_ignore_ascii_case(b"SAML")) =>
            {
                return true;
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_TYPE)?;
    let text = String::from_utf8_lossy(value.as_bytes());
    Some(
        text.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase(),
    )
}

fn key_kind(key: &[u8]) -> Option<bool> {
    if key.eq_ignore_ascii_case(b"SAMLResponse") {
        Some(true)
    } else if key.eq_ignore_ascii_case(b"SAMLRequest") {
        Some(false)
    } else {
        None
    }
}

fn form_messages(body: &[u8]) -> Option<Vec<Message>> {
    let decoded = form_decode(body);
    let mut messages = Vec::new();
    for pair in decoded.split(|byte| *byte == b'&') {
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let Some(is_response) = key_kind(&pair[..separator]) else {
            continue;
        };
        messages.push(Message {
            value: pair[separator + 1..].to_vec(),
            is_response,
        });
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages)
    }
}

fn json_messages(body: &[u8]) -> Option<Vec<Message>> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let mut messages = Vec::new();
    for (key, value) in object {
        let Some(is_response) = key_kind(key.as_bytes()) else {
            continue;
        };
        messages.push(Message {
            value: value.as_str().unwrap_or_default().as_bytes().to_vec(),
            is_response,
        });
    }
    if messages.is_empty() {
        None
    } else {
        Some(messages)
    }
}

fn decode_message(value: &[u8], limit: usize) -> Result<Vec<u8>, Finding> {
    let decoded = decode_base64(value).ok_or(Finding::Malformed)?;
    if decoded.is_empty() {
        return Err(Finding::Malformed);
    }
    if starts_with_utf16_bom(&decoded) {
        return Err(Finding::UnsupportedEncoding);
    }
    if decoded.len() > limit {
        return Err(Finding::TooLarge);
    }
    if looks_like_xml(&decoded) {
        return Ok(decoded);
    }
    let inflated = inflate(&decoded, limit)?;
    if starts_with_utf16_bom(&inflated) {
        return Err(Finding::UnsupportedEncoding);
    }
    if !looks_like_xml(&inflated) {
        return Err(Finding::Malformed);
    }
    Ok(inflated)
}

fn starts_with_utf16_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF])
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    bytes.trim_ascii_start().first() == Some(&b'<')
}

fn inflate(input: &[u8], limit: usize) -> Result<Vec<u8>, Finding> {
    let raw = read_limited(DeflateDecoder::new(input), limit);
    if let Ok(output) = &raw
        && !output.is_empty()
        && looks_like_xml(output)
    {
        return Ok(output.clone());
    }
    if matches!(raw, Err(Finding::TooLarge)) {
        return Err(Finding::TooLarge);
    }
    let zlib = read_limited(ZlibDecoder::new(input), limit);
    if let Ok(output) = &zlib
        && !output.is_empty()
        && looks_like_xml(output)
    {
        return Ok(output.clone());
    }
    if matches!(zlib, Err(Finding::TooLarge)) {
        return Err(Finding::TooLarge);
    }
    Err(Finding::Malformed)
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, Finding> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| Finding::Malformed)?;
    if output.len() > limit {
        Err(Finding::TooLarge)
    } else {
        Ok(output)
    }
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len().saturating_mul(3) / 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;
    for &byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            padding += 1;
            if padding > 2 {
                return None;
            }
            continue;
        }
        if padding != 0 {
            return None;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        accumulator = ((accumulator << 6) | value) & 0x00FF_FFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits >= 6 {
        return None;
    }
    if bits > 0 && accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(output)
}

fn analyze(xml: &[u8], is_response: bool) -> BTreeSet<Finding> {
    let mut findings = BTreeSet::new();
    if starts_with_utf16_bom(xml) {
        findings.insert(Finding::UnsupportedEncoding);
        return findings;
    }
    let xml = xml.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(xml);
    let Ok(text) = std::str::from_utf8(xml) else {
        findings.insert(Finding::Malformed);
        return findings;
    };
    let mut analyzer = Analyzer::new(text);
    analyzer.run();
    findings.extend(analyzer.finish(is_response));
    findings
}

struct Element {
    name: String,
    id: Option<String>,
}

struct SignatureInfo {
    parent_id: Option<String>,
    references: Vec<String>,
}

struct AssertionInfo {
    name_id: Option<String>,
}

struct NameIdCapture {
    assertion: usize,
    value: String,
}

struct Analyzer<'a> {
    input: &'a str,
    position: usize,
    stack: Vec<Element>,
    signatures: Vec<SignatureInfo>,
    signature_stack: Vec<usize>,
    assertions: Vec<AssertionInfo>,
    current_assertion: Option<usize>,
    name_id: Option<NameIdCapture>,
    ids: BTreeSet<String>,
    root: Option<String>,
    elements: usize,
    findings: BTreeSet<Finding>,
}

impl<'a> Analyzer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            position: 0,
            stack: Vec::new(),
            signatures: Vec::new(),
            signature_stack: Vec::new(),
            assertions: Vec::new(),
            current_assertion: None,
            name_id: None,
            ids: BTreeSet::new(),
            root: None,
            elements: 0,
            findings: BTreeSet::new(),
        }
    }

    fn run(&mut self) {
        while self.position < self.input.len() {
            if self.input.as_bytes()[self.position] != b'<' {
                let end = self.input[self.position..]
                    .find('<')
                    .map(|offset| self.position + offset)
                    .unwrap_or(self.input.len());
                self.text(&self.input[self.position..end]);
                self.position = end;
                continue;
            }
            if self.input[self.position..].starts_with("<!--") {
                if !self.skip_past("-->", 4) {
                    self.findings.insert(Finding::Malformed);
                    return;
                }
                continue;
            }
            if self.input[self.position..].starts_with("<![CDATA[") {
                let start = self.position + 9;
                let Some(end) = self.input[start..].find("]]>") else {
                    self.findings.insert(Finding::Malformed);
                    return;
                };
                self.text(&self.input[start..start + end]);
                self.position = start + end + 3;
                continue;
            }
            if self.input[self.position..].starts_with("<?") {
                if !self.skip_past("?>", 2) {
                    self.findings.insert(Finding::Malformed);
                    return;
                }
                continue;
            }
            if self
                .input
                .get(self.position..self.position.saturating_add(9))
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<!DOCTYPE"))
            {
                self.findings.insert(Finding::Doctype);
                return;
            }
            if self.input[self.position..].starts_with("<!") {
                self.findings.insert(Finding::Malformed);
                return;
            }
            if self.input[self.position..].starts_with("</") {
                if !self.end_tag() {
                    return;
                }
                continue;
            }
            if !self.start_tag() {
                return;
            }
        }
        if !self.stack.is_empty() {
            self.findings.insert(Finding::Malformed);
        }
    }

    fn skip_past(&mut self, terminator: &str, prefix_len: usize) -> bool {
        let start = self.position + prefix_len;
        let Some(offset) = self.input[start..].find(terminator) else {
            return false;
        };
        self.position = start + offset + terminator.len();
        true
    }

    fn text(&mut self, text: &str) {
        let Some(capture) = &mut self.name_id else {
            return;
        };
        for character in text.chars() {
            if capture.value.len() >= MAX_NAME_ID_BYTES {
                break;
            }
            capture.value.push(character);
        }
    }

    fn start_tag(&mut self) -> bool {
        let bytes = self.input.as_bytes();
        let mut index = self.position + 1;
        let name_start = index;
        while index < bytes.len()
            && !matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>')
        {
            index += 1;
        }
        if index == name_start {
            self.findings.insert(Finding::Malformed);
            return false;
        }
        let name = self.input[name_start..index].to_owned();
        let mut attributes = Vec::new();
        let self_closing;
        loop {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index >= bytes.len() {
                self.findings.insert(Finding::Malformed);
                return false;
            }
            if bytes[index] == b'>' {
                index += 1;
                self_closing = false;
                break;
            }
            if bytes[index] == b'/' {
                if bytes.get(index + 1) == Some(&b'>') {
                    index += 2;
                    self_closing = true;
                    break;
                }
                self.findings.insert(Finding::Malformed);
                return false;
            }
            let attribute_start = index;
            while index < bytes.len()
                && !matches!(
                    bytes[index],
                    b'=' | b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>'
                )
            {
                index += 1;
            }
            if index == attribute_start {
                self.findings.insert(Finding::Malformed);
                return false;
            }
            let attribute_name = &self.input[attribute_start..index];
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) != Some(&b'=') {
                self.findings.insert(Finding::Malformed);
                return false;
            }
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            let Some(&quote) = bytes.get(index) else {
                self.findings.insert(Finding::Malformed);
                return false;
            };
            if quote != b'"' && quote != b'\'' {
                self.findings.insert(Finding::Malformed);
                return false;
            }
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            if index >= bytes.len() {
                self.findings.insert(Finding::Malformed);
                return false;
            }
            attributes.push((
                attribute_name.to_owned(),
                self.input[value_start..index].to_owned(),
            ));
            index += 1;
            if attributes.len() > MAX_ATTRIBUTES {
                self.findings.insert(Finding::TooComplex);
                return false;
            }
        }
        self.position = index;
        self.element(&name, &attributes, self_closing);
        true
    }

    fn element(&mut self, name: &str, attributes: &[(String, String)], self_closing: bool) {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            self.findings.insert(Finding::TooComplex);
            self.stack.clear();
            return;
        }
        if self.stack.len() >= MAX_DEPTH {
            self.findings.insert(Finding::TooComplex);
            self.stack.clear();
            return;
        }
        let local = local_name(name);
        if self.stack.is_empty() {
            if self.root.is_some() {
                self.findings.insert(Finding::Malformed);
                return;
            }
            self.root = Some(local.to_owned());
        }
        let id = attributes
            .iter()
            .find(|(attribute, _)| local_name(attribute).eq_ignore_ascii_case("id"))
            .map(|(_, value)| value.clone());
        if let Some(id) = &id
            && !self.ids.insert(id.clone())
        {
            self.findings.insert(Finding::DuplicateId);
        }
        if local == "Signature" {
            let parent_id = self.stack.last().and_then(|element| element.id.clone());
            self.signatures.push(SignatureInfo {
                parent_id,
                references: Vec::new(),
            });
            self.signature_stack.push(self.signatures.len() - 1);
        }
        if local == "Reference"
            && let Some(&signature) = self.signature_stack.last()
            && let Some((_, value)) = attributes
                .iter()
                .find(|(attribute, _)| local_name(attribute).eq_ignore_ascii_case("uri"))
        {
            self.signatures[signature].references.push(value.clone());
        }
        if local == "Assertion" {
            // Only a direct child of the message `Response` is the assertion
            // the signature is expected to cover. Comparing against the root
            // (rather than any ancestor) rejects a wrapper element named
            // `Response` and a root-level assertion.
            let placed_directly = self.stack.len() == 1
                && self
                    .stack
                    .first()
                    .is_some_and(|parent| local_name(&parent.name) == "Response");
            if !placed_directly {
                self.findings.insert(Finding::AssertionOutsideResponse);
            }
            self.assertions.push(AssertionInfo { name_id: None });
            self.current_assertion = Some(self.assertions.len() - 1);
        }
        if local == "NameID"
            && !self_closing
            && let Some(assertion) = self.current_assertion
        {
            self.name_id = Some(NameIdCapture {
                assertion,
                value: String::new(),
            });
        }
        if self_closing {
            if local == "Signature" {
                self.signature_stack.pop();
            }
            if local == "Assertion" {
                self.current_assertion = None;
            }
            return;
        }
        self.stack.push(Element {
            name: name.to_owned(),
            id,
        });
    }

    fn end_tag(&mut self) -> bool {
        let bytes = self.input.as_bytes();
        let mut index = self.position + 2;
        let name_start = index;
        while index < bytes.len() && !matches!(bytes[index], b' ' | b'\t' | b'\r' | b'\n' | b'>') {
            index += 1;
        }
        if index == name_start {
            self.findings.insert(Finding::Malformed);
            return false;
        }
        let name = &self.input[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'>') {
            self.findings.insert(Finding::Malformed);
            return false;
        }
        index += 1;
        self.position = index;
        let Some(element) = self.stack.pop() else {
            self.findings.insert(Finding::Malformed);
            return false;
        };
        if element.name != name {
            self.findings.insert(Finding::Malformed);
            return false;
        }
        let local = local_name(&element.name);
        if local == "Signature" {
            self.signature_stack.pop();
        }
        if local == "NameID"
            && let Some(capture) = self.name_id.take()
            && let Some(assertion) = self.assertions.get_mut(capture.assertion)
        {
            let decoded = crate::decoding::decode_entities(&capture.value).into_owned();
            assertion.name_id.get_or_insert(decoded);
        }
        if local == "Assertion" {
            self.current_assertion = None;
        }
        true
    }

    fn finish(mut self, is_response: bool) -> BTreeSet<Finding> {
        if !self.stack.is_empty() {
            self.findings.insert(Finding::Malformed);
        }
        if self.findings.contains(&Finding::Malformed) {
            return self.findings;
        }
        for signature in &self.signatures {
            let Some(parent_id) = &signature.parent_id else {
                self.findings.insert(Finding::SignatureReferenceMismatch);
                continue;
            };
            if signature.references.is_empty() {
                self.findings.insert(Finding::SignatureReferenceMismatch);
                continue;
            }
            for reference in &signature.references {
                let Some(referenced) = reference.trim().strip_prefix('#') else {
                    self.findings.insert(Finding::SignatureReferenceMismatch);
                    continue;
                };
                if referenced != parent_id {
                    self.findings.insert(Finding::SignatureReferenceMismatch);
                }
            }
        }
        if is_response && self.root.as_deref() == Some("Response") && self.signatures.is_empty() {
            self.findings.insert(Finding::Unsigned);
        }
        let subjects: BTreeSet<&str> = self
            .assertions
            .iter()
            .filter_map(|assertion| assertion.name_id.as_deref())
            .filter(|name_id| !name_id.is_empty())
            .collect();
        if subjects.len() > 1 {
            self.findings.insert(Finding::MultipleNameIds);
        }
        self.findings
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, ZlibEncoder};
    use http::HeaderValue;
    use std::io::Write;

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("type"),
        );
        headers
    }

    fn limits(mode: SamlInspection, max_decoded_bytes: usize) -> SamlLimits {
        SamlLimits {
            mode,
            max_decoded_bytes,
            ..SamlLimits::default()
        }
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(ALPHABET[((value >> (18 - index * 6)) & 0x3f) as usize] as char);
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    fn form_body(xml: &str) -> Vec<u8> {
        let encoded = base64_encode(xml.as_bytes());
        let encoded = encoded
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("SAMLResponse={encoded}&RelayState=state").into_bytes()
    }

    fn json_body(xml: &str) -> Vec<u8> {
        serde_json::json!({
            "SAMLResponse": base64_encode(xml.as_bytes()),
            "RelayState": "state",
        })
        .to_string()
        .into_bytes()
    }

    fn response(assertions: &str, signature: &str) -> String {
        format!(
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
             xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_response\" \
             Version=\"2.0\" IssueInstant=\"2026-11-14T00:00:00Z\">\
             <saml:Issuer>https://idp.example</saml:Issuer>{signature}{assertions}\
             </samlp:Response>"
        )
    }

    fn assertion(id: &str, name_id: &str) -> String {
        format!(
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{id}\" \
             Version=\"2.0\" IssueInstant=\"2026-11-14T00:00:00Z\">\
             <saml:Issuer>https://idp.example</saml:Issuer>\
             <saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">{name_id}</saml:NameID></saml:Subject>\
             </saml:Assertion>"
        )
    }

    fn response_signature(uri: &str) -> String {
        format!(
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
             <ds:SignedInfo><ds:Reference URI=\"{uri}\"/></ds:SignedInfo>\
             <ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue></ds:Signature>"
        )
    }

    fn valid_response() -> String {
        response(
            &assertion("_assertion", "alice@example.com"),
            &response_signature("#_response"),
        )
    }

    fn check(xml: &str, is_response: bool) -> BTreeSet<Finding> {
        analyze(xml.as_bytes(), is_response)
    }

    #[test]
    fn valid_response_has_no_findings() {
        let findings = check(&valid_response(), true);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn assertion_level_signature_is_accepted() {
        let xml = response(
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_assertion\" Version=\"2.0\" IssueInstant=\"2026-11-14T00:00:00Z\">\
             <saml:Issuer>https://idp.example</saml:Issuer>\
             <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>\
             <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:Reference URI=\"#_assertion\"/></ds:SignedInfo></ds:Signature>\
             </saml:Assertion>",
            "",
        );
        let findings = check(&xml, true);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn duplicate_ids_are_reported() {
        let xml = response(
            &format!(
                "{}<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_assertion\" Version=\"2.0\">\
                 <saml:Subject><saml:NameID>mallory@example.com</saml:NameID></saml:Subject></saml:Assertion>",
                assertion("_assertion", "alice@example.com")
            ),
            &response_signature("#_response"),
        );
        let findings = check(&xml, true);
        assert!(findings.contains(&Finding::DuplicateId), "{findings:?}");
    }

    #[test]
    fn signature_reference_mismatch_is_reported() {
        let xml = response(
            &assertion("_assertion", "alice@example.com"),
            &response_signature("#_other"),
        );
        let findings = check(&xml, true);
        assert!(
            findings.contains(&Finding::SignatureReferenceMismatch),
            "{findings:?}"
        );
    }

    #[test]
    fn signature_without_a_parent_id_is_reported() {
        let xml = response(
            &assertion("_assertion", "alice@example.com"),
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:Reference URI=\"#_response\"/></ds:SignedInfo></ds:Signature>",
        );
        // The Response has an ID in `response`, so use a response without one.
        let xml = xml.replace(" ID=\"_response\"", "");
        let findings = check(&xml, true);
        assert!(
            findings.contains(&Finding::SignatureReferenceMismatch),
            "{findings:?}"
        );
    }

    #[test]
    fn assertion_inside_advice_is_reported() {
        let xml = response(
            "<saml:Advice><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_wrapped\" Version=\"2.0\"><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></saml:Advice>",
            &response_signature("#_response"),
        );
        let findings = check(&xml, true);
        assert!(
            findings.contains(&Finding::AssertionOutsideResponse),
            "{findings:?}"
        );
    }

    #[test]
    fn assertion_under_a_wrapped_response_element_is_reported() {
        // The wrapper is only named `Response`; the assertion is not a direct
        // child of the message response, so a provider that resolves assertions
        // by descendant search could be confused.
        let xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
             xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_response\" \
             Version=\"2.0\"><samlp:Extensions><samlp:Response>\
             <saml:Assertion ID=\"_assertion\" Version=\"2.0\"><saml:Subject>\
             <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
             alice@example.com</saml:NameID></saml:Subject></saml:Assertion>\
             </samlp:Response></samlp:Extensions></samlp:Response>";
        let findings = check(xml, true);
        assert!(
            findings.contains(&Finding::AssertionOutsideResponse),
            "{findings:?}"
        );
    }

    #[test]
    fn root_level_assertion_is_reported() {
        let xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
             ID=\"_assertion\" Version=\"2.0\"><saml:Subject>\
             <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
             alice@example.com</saml:NameID></saml:Subject></saml:Assertion>";
        let findings = check(xml, true);
        assert!(
            findings.contains(&Finding::AssertionOutsideResponse),
            "{findings:?}"
        );
    }

    #[test]
    fn distinct_name_ids_are_reported() {
        let xml = response(
            &format!(
                "{}{}",
                assertion("_assertion1", "alice@example.com"),
                assertion("_assertion2", "mallory@example.com")
            ),
            &response_signature("#_response"),
        );
        let findings = check(&xml, true);
        assert!(findings.contains(&Finding::MultipleNameIds), "{findings:?}");
    }

    #[test]
    fn repeated_name_ids_are_not_reported() {
        let xml = response(
            &format!(
                "{}{}",
                assertion("_assertion1", "alice@example.com"),
                assertion("_assertion2", "alice@example.com")
            ),
            &response_signature("#_response"),
        );
        let findings = check(&xml, true);
        assert!(
            !findings.contains(&Finding::MultipleNameIds),
            "{findings:?}"
        );
    }

    #[test]
    fn unsigned_response_is_reported() {
        let xml = response(&assertion("_assertion", "alice@example.com"), "");
        let findings = check(&xml, true);
        assert!(findings.contains(&Finding::Unsigned), "{findings:?}");
    }

    #[test]
    fn unsigned_request_is_not_reported() {
        let xml = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_request\"/>";
        let findings = check(xml, false);
        assert!(!findings.contains(&Finding::Unsigned), "{findings:?}");
    }

    #[test]
    fn doctype_is_reported() {
        let xml = "<!DOCTYPE Response [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Response ID=\"_r\"/>";
        let findings = check(xml, true);
        assert!(findings.contains(&Finding::Doctype), "{findings:?}");
    }

    #[test]
    fn comments_and_cdata_are_skipped() {
        let xml = format!(
            "<?xml version=\"1.0\"?><!-- comment -->{}",
            valid_response().replace(
                "<saml:Issuer>https://idp.example</saml:Issuer>",
                "<saml:Issuer><![CDATA[https://idp.example]]></saml:Issuer>"
            )
        );
        let findings = check(&xml, true);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn malformed_xml_is_reported() {
        let findings = check("<Response><Assertion></Response>", true);
        assert!(findings.contains(&Finding::Malformed), "{findings:?}");
    }

    #[test]
    fn deep_xml_is_too_complex() {
        let xml = "<Response ID=\"_r\">".to_owned()
            + &"<a>".repeat(MAX_DEPTH + 1)
            + &"</a>".repeat(MAX_DEPTH + 1)
            + "</Response>";
        let findings = check(&xml, true);
        assert!(findings.contains(&Finding::TooComplex), "{findings:?}");
    }

    #[test]
    fn form_message_is_decoded() {
        let body = form_body(&valid_response());
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
        assert!(inspection.blocking.is_none());
    }

    #[test]
    fn json_message_is_decoded() {
        let body = json_body(&valid_response());
        let inspection = inspect(
            &headers("application/json"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
    }

    #[test]
    fn deflated_redirect_binding_is_decoded() {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(valid_response().as_bytes())
            .expect("deflate");
        let compressed = encoder.finish().expect("deflate");
        let encoded = base64_encode(&compressed)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let body = format!("SAMLResponse={encoded}").into_bytes();
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
    }

    #[test]
    fn zlib_compressed_message_is_decoded() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(valid_response().as_bytes())
            .expect("zlib");
        let compressed = encoder.finish().expect("zlib");
        let encoded = base64_encode(&compressed)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let body = format!("SAMLResponse={encoded}").into_bytes();
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
    }

    #[test]
    fn json_escaped_field_name_is_detected() {
        let encoded = base64_encode(valid_response().as_bytes());
        let body = format!("{{\"\\u0053AMLResponse\":\"{encoded}\"}}").into_bytes();
        let inspection = inspect(
            &headers("application/json"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
    }

    #[test]
    fn percent_encoded_field_name_is_detected() {
        let body = String::from_utf8(form_body(&valid_response()))
            .expect("form body")
            .replace("SAMLResponse=", "%53AMLResponse=")
            .into_bytes();
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.findings.is_empty(), "{:?}", inspection.findings);
    }

    #[test]
    fn mid_name_form_escapes_are_inspected() {
        let xml = "<!DOCTYPE Response><samlp:Response/>";
        for name in ["SAM%4CResponse", "S%41MLResponse", "SAM%4cResponse"] {
            let body = String::from_utf8(form_body(xml))
                .expect("form body")
                .replace("SAMLResponse=", &format!("{name}="))
                .into_bytes();
            let inspection = inspect(
                &headers("application/x-www-form-urlencoded"),
                &body,
                &limits(SamlInspection::Strict, 1024 * 1024),
            )
            .unwrap_or_else(|| panic!("{name} must reach the extractor"));
            assert!(
                inspection.findings.contains(&Finding::Doctype),
                "{name}: {:?}",
                inspection.findings
            );
        }
    }

    #[test]
    fn mid_name_json_escapes_are_inspected() {
        let encoded = base64_encode(b"<!DOCTYPE Response><samlp:Response/>");
        for name in ["S\\u0041MLResponse", "SAM\\u004cResponse"] {
            let body = format!("{{\"{name}\":\"{encoded}\"}}").into_bytes();
            let inspection = inspect(
                &headers("application/json"),
                &body,
                &limits(SamlInspection::Strict, 1024 * 1024),
            )
            .unwrap_or_else(|| panic!("{name} must reach the extractor"));
            assert!(
                inspection.findings.contains(&Finding::Doctype),
                "{name}: {:?}",
                inspection.findings
            );
        }
    }

    #[test]
    fn truncated_saml_bodies_fail_closed_in_strict_mode() {
        let inspection = inspect_truncated(
            &headers("application/json"),
            b"{\"padding\":\"",
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("a truncated SAML-capable body must be inspected");
        assert_eq!(inspection.findings, vec![Finding::TooLarge]);
        assert_eq!(inspection.blocking, Some(Finding::TooLarge));
    }

    #[test]
    fn truncated_saml_bodies_are_logged_in_log_mode() {
        let inspection = inspect_truncated(
            &headers("application/json"),
            b"{\"padding\":\"",
            &limits(SamlInspection::Log, 1024 * 1024),
        )
        .expect("a truncated SAML-capable body must be inspected");
        assert_eq!(inspection.findings, vec![Finding::TooLarge]);
        assert!(inspection.blocking.is_none());
    }

    #[test]
    fn truncated_non_saml_content_types_are_ignored() {
        assert!(
            inspect_truncated(
                &headers("text/plain"),
                b"padding",
                &limits(SamlInspection::Strict, 1024 * 1024)
            )
            .is_none()
        );
    }

    #[test]
    fn ordinary_json_is_skipped() {
        let body = br#"{"data":"hello","count":1}"#;
        assert!(
            inspect(
                &headers("application/json"),
                body,
                &limits(SamlInspection::Strict, 1024 * 1024)
            )
            .is_none()
        );
    }

    #[test]
    fn malformed_base64_is_rejected_in_strict_mode() {
        let body = b"SAMLResponse=not-base64!";
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert_eq!(inspection.blocking, Some(Finding::Malformed));
    }

    #[test]
    fn malformed_base64_is_logged_only_in_log_mode() {
        let body = b"SAMLResponse=not-base64!";
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            body,
            &limits(SamlInspection::Log, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.blocking.is_none());
        assert!(inspection.findings.contains(&Finding::Malformed));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let body = form_body(&valid_response());
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 8),
        )
        .expect("saml inspection");
        assert_eq!(inspection.blocking, Some(Finding::TooLarge));
    }

    #[test]
    fn wrapping_finding_blocks_in_strict_mode() {
        let xml = response(
            &assertion("_assertion", "mallory@example.com"),
            &response_signature("#_other"),
        );
        let body = form_body(&xml);
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert_eq!(
            inspection.blocking,
            Some(Finding::SignatureReferenceMismatch)
        );
    }

    #[test]
    fn multiple_name_ids_can_block() {
        let xml = response(
            &format!(
                "{}{}",
                assertion("_assertion1", "alice@example.com"),
                assertion("_assertion2", "mallory@example.com")
            ),
            &response_signature("#_response"),
        );
        let body = form_body(&xml);
        let mut policy = limits(SamlInspection::Strict, 1024 * 1024);
        policy.multi_assertion = SamlFindingAction::Block;
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &policy,
        )
        .expect("saml inspection");
        assert_eq!(inspection.blocking, Some(Finding::MultipleNameIds));
    }

    #[test]
    fn unsigned_response_can_block() {
        let body = form_body(&response(&assertion("_assertion", "alice@example.com"), ""));
        let mut policy = limits(SamlInspection::Strict, 1024 * 1024);
        policy.unsigned = SamlFindingAction::Block;
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &policy,
        )
        .expect("saml inspection");
        assert_eq!(inspection.blocking, Some(Finding::Unsigned));
    }

    #[test]
    fn unsigned_response_does_not_block_in_strict_mode() {
        let body = form_body(&response(&assertion("_assertion", "alice@example.com"), ""));
        let inspection = inspect(
            &headers("application/x-www-form-urlencoded"),
            &body,
            &limits(SamlInspection::Strict, 1024 * 1024),
        )
        .expect("saml inspection");
        assert!(inspection.blocking.is_none());
        assert!(inspection.findings.contains(&Finding::Unsigned));
    }

    #[test]
    fn non_saml_requests_are_ignored() {
        assert!(
            inspect(
                &headers("text/plain"),
                b"SAMLResponse=x",
                &limits(SamlInspection::Strict, 1024)
            )
            .is_none()
        );
        assert!(
            inspect(
                &headers("application/json"),
                b"{\"other\":1}",
                &limits(SamlInspection::Strict, 1024)
            )
            .is_none()
        );
        assert!(
            inspect(
                &headers("application/json"),
                b"not json",
                &limits(SamlInspection::Strict, 1024)
            )
            .is_none()
        );
        assert!(
            inspect(
                &headers("application/json"),
                b"{}",
                &limits(SamlInspection::Off, 1024)
            )
            .is_none()
        );
    }
}
