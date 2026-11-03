//! Bounded inspection of `multipart/form-data` uploads.
//!
//! A part that carries a `filename` is treated as a file upload. Its declared
//! `Content-Type` (or, when that is generic or absent, its filename extension)
//! is compared with the bytes of the part: executable, server-side script, or
//! markup content behind an image, PDF, office, media, or font claim is
//! rejected. A part that claims such a type must also start with that format's
//! signature, so plain text or source code renamed to `.jpg` or `.pdf` is
//! rejected even when it contains no dangerous marker. This closes the
//! MIME-spoofing class where an upload filter trusts the declared type while
//! the upstream stores an executable or HTML file.
//!
//! The check shares the multipart boundary, part, and body limits with rule
//! inspection and never copies the body. It runs before rule evaluation, so an
//! `ALLOW` rule cannot bypass it. Uploaded gzip and ZIP archives are limited to
//! `limits.upload_expansion`, but nested archives and encrypted entries are not
//! expanded. It is deliberately a heuristic: server-side script markers are
//! scanned throughout the inspected part, but executable and markup detection
//! beyond the leading bytes, a matching signature followed by script code, an
//! unsupported boundary interpretation, archive contents, or an upload larger
//! than `max_body_bytes` without `body_inspection: stream` is not fully
//! inspected.

use std::io::Read;

use flate2::read::{DeflateDecoder, MultiGzDecoder};
use http::header::{CONTENT_TYPE, HeaderMap};
use http::{Method, StatusCode, Uri};

use crate::config::{UploadExpansion, UploadInspection};
use crate::decoding::{MultipartPart, multipart_boundaries, multipart_parts, percent_decode_forms};

const SAFE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "jpe", "png", "gif", "webp", "bmp", "tif", "tiff", "ico", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "mp3", "mp4", "m4a", "wav", "ogg",
    "flac", "webm", "mov", "avi", "mkv", "woff", "woff2", "ttf", "otf",
];

const ACTIVE_WEB_EXTENSIONS: &[&str] = &["html", "htm", "xhtml", "shtml", "svg", "js", "mjs"];

/// Extensions that explicitly name executable or server-side script content.
/// A file with one of these names is not treated as a safe claim: the
/// application has been told what it is.
const EXPLICIT_DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "elf", "bin", "sh", "bash", "zsh", "ps1", "bat", "cmd", "vbs",
    "wsf", "hta", "php", "php3", "php4", "php5", "php7", "php8", "pht", "phtml", "phps", "pgif",
    "phar", "inc", "htaccess", "ini", "jsp", "jspx", "asp", "aspx", "ashx", "asmx", "cgi", "pl",
    "py", "rb", "war", "jar",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DangerousKind {
    Executable,
    Script,
    ActiveWeb,
    /// The part claims a safe type but its leading bytes are not that format.
    FormatMismatch,
    /// The declared type and the filename extension promise different things.
    ClaimMismatch,
    /// The upload decompresses past `limits.upload_expansion`.
    ArchiveExpansion,
    /// The upload claims to be an archive that cannot be parsed.
    ArchiveMalformed,
}

impl DangerousKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Script => "script",
            Self::ActiveWeb => "active-web",
            Self::FormatMismatch => "format-mismatch",
            Self::ClaimMismatch => "claim-mismatch",
            Self::ArchiveExpansion => "archive-expansion",
            Self::ArchiveMalformed => "archive-malformed",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Rejection {
    pub(crate) filename: String,
    pub(crate) declared: Option<String>,
    pub(crate) kind: DangerousKind,
}

impl Rejection {
    pub(crate) fn status(&self) -> StatusCode {
        match self.kind {
            DangerousKind::ArchiveExpansion => StatusCode::PAYLOAD_TOO_LARGE,
            DangerousKind::ArchiveMalformed => StatusCode::BAD_REQUEST,
            _ => StatusCode::FORBIDDEN,
        }
    }

    pub(crate) fn message(&self) -> &'static str {
        match self.kind {
            DangerousKind::ArchiveExpansion => "upload expands beyond the configured limit",
            DangerousKind::ArchiveMalformed => "upload archive could not be parsed",
            _ => "upload content does not match its declared type",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    /// The upload claims to be an image, document, media, or font file.
    Safe,
    /// The upload claims to be HTML, SVG, or JavaScript.
    ActiveWeb,
    /// The upload explicitly names an executable or server-side script.
    ExplicitDangerous,
    /// The upload declares no useful type and has no recognised extension.
    Generic,
}

/// True when the request declares a `multipart/form-data` body.
pub(crate) fn is_multipart(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_multipart_media_type)
}

/// Checks every file part in a multipart body. Returns the first rejection, or
/// `None` when the request is not an inspectable multipart upload or nothing
/// dangerous was found.
pub(crate) fn inspect(
    headers: &HeaderMap,
    body: &[u8],
    mode: UploadInspection,
    expansion: UploadExpansion,
) -> Option<Rejection> {
    if mode == UploadInspection::Off || body.is_empty() {
        return None;
    }
    let content_type = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    if !is_multipart_media_type(content_type) {
        return None;
    }
    let Ok(boundaries) = multipart_boundaries(content_type) else {
        return None;
    };
    if boundaries.is_empty() {
        return None;
    }

    let mut budget = expansion.max_total_bytes;
    for boundary in &boundaries {
        let Some(parts) = multipart_parts(body, boundary) else {
            continue;
        };
        for part in parts {
            let Some(rejection) = inspect_part(part, mode, expansion, &mut budget) else {
                continue;
            };
            return Some(rejection);
        }
    }
    None
}

/// True when a non-multipart write request names an executable or server-side
/// script in its `Content-Type` or path, so its raw body must be scanned too.
/// Applications that store generated or authored script files through an API
/// disable this by setting `upload_inspection: off`.
pub(crate) fn wants_raw_inspection(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH)
        && raw_claim_is_dangerous(uri, headers)
}

fn raw_claim_is_dangerous(uri: &Uri, headers: &HeaderMap) -> bool {
    let script_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            is_explicit_dangerous_media_type(&media_type) || is_script_media_type(&media_type)
        });
    if script_type {
        return true;
    }
    let path = uri.path();
    if !path.contains('.') && !path.contains('%') {
        return false;
    }
    percent_decode_forms(path)
        .iter()
        .any(|form| path_claims_dangerous_extension(form))
}

fn path_claims_dangerous_extension(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|segment| extension_claim(segment) == Claim::ExplicitDangerous)
}

/// Checks the raw body of a non-multipart request whose declared type or path
/// names executable or server-side script content. Returns the first
/// rejection, or `None` when the request is not in scope or the body carries
/// no executable header, shebang, or script marker.
pub(crate) fn inspect_raw(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    mode: UploadInspection,
) -> Option<Rejection> {
    if mode == UploadInspection::Off || body.is_empty() || is_multipart(headers) {
        return None;
    }
    if !wants_raw_inspection(method, uri, headers) {
        return None;
    }
    let kind = raw_script_content(body)?;
    Some(Rejection {
        filename: uri
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_else(|| uri.path())
            .to_owned(),
        declared: declared_media_type(headers),
        kind,
    })
}

fn declared_media_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let media_type = value.split(';').next()?.trim();
    (!media_type.is_empty()).then(|| media_type.to_ascii_lowercase())
}

fn raw_script_content(value: &[u8]) -> Option<DangerousKind> {
    if is_executable(value) {
        return Some(DangerousKind::Executable);
    }
    if value[leading_content_start(value)..].starts_with(b"#!") {
        return Some(DangerousKind::Script);
    }
    if contains_script_marker(value) || contains_short_script_tag(value) {
        return Some(DangerousKind::Script);
    }
    None
}

fn inspect_part(
    part: MultipartPart<'_>,
    mode: UploadInspection,
    expansion: UploadExpansion,
    budget: &mut usize,
) -> Option<Rejection> {
    let filename = part.filename()?;
    if part.value.is_empty() {
        return None;
    }
    let declared = part.declared_content_type();
    if mode != UploadInspection::Off && claim_mismatch(mode, declared.as_deref(), &filename) {
        return Some(Rejection {
            filename,
            declared,
            kind: DangerousKind::ClaimMismatch,
        });
    }
    if mode != UploadInspection::Off
        && let Some(kind) = archive_expansion_rejection(&part, expansion, budget)
    {
        return Some(Rejection {
            filename,
            declared,
            kind,
        });
    }
    let claim = claim_for(declared.as_deref(), &filename);
    let kind = match mode {
        UploadInspection::Off => return None,
        UploadInspection::Mismatch
            if matches!(claim, Claim::ExplicitDangerous | Claim::Generic) =>
        {
            return None;
        }
        UploadInspection::Mismatch if claim == Claim::ActiveWeb => {
            if !is_executable(part.value) {
                return None;
            }
            DangerousKind::Executable
        }
        _ => match dangerous_content(part.value) {
            Some(kind) => kind,
            None if claim == Claim::Safe => {
                let format = expected_format(declared.as_deref(), &filename)?;
                if format.matches(part.value) {
                    return None;
                }
                DangerousKind::FormatMismatch
            }
            None => return None,
        },
    };
    blocks(mode, claim, kind).then_some(Rejection {
        filename,
        declared,
        kind,
    })
}

const ZIP_LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const ZIP_CENTRAL_HEADER: &[u8; 4] = b"PK\x01\x02";
const ZIP_END_OF_CENTRAL_DIRECTORY: &[u8; 4] = b"PK\x05\x06";
const ZIP64_END_OF_CENTRAL_DIRECTORY: &[u8; 4] = b"PK\x06\x06";
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR: &[u8; 4] = b"PK\x06\x07";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Gzip,
    Zip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpansionError {
    TooLarge,
    Malformed,
}

struct ZipEntry {
    flags: u16,
    method: u16,
    compressed: u64,
    uncompressed: u64,
    local_offset: u64,
    next: usize,
}

/// Rejects an uploaded gzip or ZIP archive whose contents expand past the
/// configured budget. Detection uses the leading gzip magic or a valid ZIP
/// end-of-central-directory record, so a renamed part or a self-extracting
/// prefix does not hide the archive. The budget is shared by every archive in
/// the request. Returns `None` when the part is not an archive, the budget is
/// disabled, or the expansion fits.
fn archive_expansion_rejection(
    part: &MultipartPart<'_>,
    expansion: UploadExpansion,
    budget: &mut usize,
) -> Option<DangerousKind> {
    if !expansion.enabled {
        return None;
    }
    let value = archive_value(part.value);
    let kind = if value.starts_with(&[0x1f, 0x8b]) {
        ArchiveKind::Gzip
    } else if find_zip_end(value).is_some() {
        ArchiveKind::Zip
    } else {
        return None;
    };
    let limit = expansion.max_bytes.min(*budget);
    if limit == 0 {
        return Some(DangerousKind::ArchiveExpansion);
    }
    let result = match kind {
        ArchiveKind::Gzip => gzip_expansion(value, limit),
        ArchiveKind::Zip => zip_expansion(value, limit, expansion.max_entries),
    };
    match result {
        Ok(expanded) => {
            let expanded = usize::try_from(expanded).unwrap_or(usize::MAX);
            *budget = budget.saturating_sub(expanded);
            None
        }
        Err(ExpansionError::TooLarge) => Some(DangerousKind::ArchiveExpansion),
        Err(ExpansionError::Malformed) => Some(DangerousKind::ArchiveMalformed),
    }
}

/// The multipart framing leaves the CRLF that precedes the boundary on the
/// part value; an archive parser must not see it as trailing content.
fn archive_value(value: &[u8]) -> &[u8] {
    value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value)
}

fn gzip_expansion(value: &[u8], limit: usize) -> Result<u64, ExpansionError> {
    let mut decoder = MultiGzDecoder::new(value);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => return Ok(total as u64),
            Ok(read) => {
                total = total.saturating_add(read);
                if total > limit {
                    return Err(ExpansionError::TooLarge);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ExpansionError::Malformed),
        }
    }
}

fn zip_expansion(value: &[u8], limit: usize, max_entries: usize) -> Result<u64, ExpansionError> {
    let end = find_zip_end(value).ok_or(ExpansionError::Malformed)?;
    let (entries, directory_offset, directory_size, central_end) = zip_directory(value, end)?;
    if entries > max_entries as u64 {
        return Err(ExpansionError::TooLarge);
    }
    // A self-extracting archive may carry an arbitrary prefix before the
    // first local header. The central directory records offsets relative to
    // the original archive start, so derive the prefix length from the EOCD
    // position and apply it to every offset.
    let claimed_end = directory_offset
        .checked_add(directory_size)
        .ok_or(ExpansionError::Malformed)?;
    let concat = (central_end as u64)
        .checked_sub(claimed_end)
        .ok_or(ExpansionError::Malformed)?;
    let directory_offset = directory_offset
        .checked_add(concat)
        .ok_or(ExpansionError::Malformed)?;
    let directory_end = directory_offset
        .checked_add(directory_size)
        .ok_or(ExpansionError::Malformed)?;
    if directory_end > value.len() as u64 {
        return Err(ExpansionError::Malformed);
    }
    let concat = usize::try_from(concat).map_err(|_| ExpansionError::Malformed)?;
    let mut position = usize::try_from(directory_offset).map_err(|_| ExpansionError::Malformed)?;
    let directory_end = usize::try_from(directory_end).map_err(|_| ExpansionError::Malformed)?;
    let mut total = 0u64;
    for _ in 0..entries {
        let mut entry = parse_zip_entry(value, position, directory_end)?;
        entry.local_offset = entry
            .local_offset
            .checked_add(concat as u64)
            .ok_or(ExpansionError::Malformed)?;
        position = entry.next;
        let remaining = limit.saturating_sub(total as usize);
        let expanded = zip_entry_expansion(value, &entry, remaining)?;
        total = total
            .checked_add(expanded)
            .ok_or(ExpansionError::Malformed)?;
        if total > limit as u64 {
            return Err(ExpansionError::TooLarge);
        }
    }
    Ok(total)
}

fn find_zip_end(value: &[u8]) -> Option<usize> {
    let minimum = 22;
    if value.len() < minimum {
        return None;
    }
    let last = value.len() - minimum;
    let first = last.saturating_sub(65_535);
    for position in (first..=last).rev() {
        if value.get(position..position + 4) != Some(&ZIP_END_OF_CENTRAL_DIRECTORY[..]) {
            continue;
        }
        let comment = read_u16(value, position + 20).ok()? as usize;
        // Trailing bytes after the EOCD are not part of the archive but common
        // in uploads (and a one-byte suffix must not hide a bomb). The central
        // directory check below still rejects a chance EOCD signature.
        if position
            .checked_add(minimum)
            .and_then(|end| end.checked_add(comment))
            .is_none_or(|end| end > value.len())
        {
            continue;
        }
        if zip_eocd_has_central_directory(value, position) {
            return Some(position);
        }
    }
    None
}

fn zip_eocd_has_central_directory(value: &[u8], position: usize) -> bool {
    let entries = read_u16(value, position + 10).unwrap_or(0);
    let size = read_u32(value, position + 12).unwrap_or(0) as u64;
    let offset = read_u32(value, position + 16).unwrap_or(0) as u64;
    if entries == 0 && size == 0 {
        return true;
    }
    if entries == u16::MAX || size == u32::MAX as u64 || offset == u32::MAX as u64 {
        return position >= 20
            && value.get(position - 20..position - 16)
                == Some(&ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR[..]);
    }
    let Some(claimed_end) = offset.checked_add(size) else {
        return false;
    };
    let Some(prefix) = (position as u64).checked_sub(claimed_end) else {
        return false;
    };
    let Some(central_start) = prefix.checked_add(offset) else {
        return false;
    };
    let Ok(central_start) = usize::try_from(central_start) else {
        return false;
    };
    value.get(central_start..central_start.saturating_add(4)) == Some(&ZIP_CENTRAL_HEADER[..])
}

fn zip_directory(value: &[u8], end: usize) -> Result<(u64, u64, u64, usize), ExpansionError> {
    let disk = read_u16(value, end + 4)?;
    let directory_disk = read_u16(value, end + 6)?;
    if disk != 0 || directory_disk != 0 {
        return Err(ExpansionError::Malformed);
    }
    let mut entries = read_u16(value, end + 10)? as u64;
    let mut directory_size = read_u32(value, end + 12)? as u64;
    let mut directory_offset = read_u32(value, end + 16)? as u64;
    let mut central_end = end;
    if entries == u16::MAX as u64
        || directory_size == u32::MAX as u64
        || directory_offset == u32::MAX as u64
    {
        let locator = end.checked_sub(20).ok_or(ExpansionError::Malformed)?;
        if value.get(locator..locator + 4) != Some(&ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR[..]) {
            return Err(ExpansionError::Malformed);
        }
        let record = read_u64(value, locator + 8)?;
        let record = usize::try_from(record).map_err(|_| ExpansionError::Malformed)?;
        let record_end = record.checked_add(4).ok_or(ExpansionError::Malformed)?;
        if value.get(record..record_end) != Some(&ZIP64_END_OF_CENTRAL_DIRECTORY[..]) {
            return Err(ExpansionError::Malformed);
        }
        entries = read_u64(value, record + 32)?;
        directory_size = read_u64(value, record + 40)?;
        directory_offset = read_u64(value, record + 48)?;
        central_end = record;
    }
    Ok((entries, directory_offset, directory_size, central_end))
}

fn parse_zip_entry(value: &[u8], position: usize, end: usize) -> Result<ZipEntry, ExpansionError> {
    let fixed_end = position.checked_add(46).ok_or(ExpansionError::Malformed)?;
    if fixed_end > end || value.get(position..position + 4) != Some(&ZIP_CENTRAL_HEADER[..]) {
        return Err(ExpansionError::Malformed);
    }
    let flags = read_u16(value, position + 8)?;
    let method = read_u16(value, position + 10)?;
    let mut compressed = read_u32(value, position + 20)? as u64;
    let mut uncompressed = read_u32(value, position + 24)? as u64;
    let name = read_u16(value, position + 28)? as usize;
    let extra = read_u16(value, position + 30)? as usize;
    let comment = read_u16(value, position + 32)? as usize;
    let mut local_offset = read_u32(value, position + 42)? as u64;
    let extra_start = fixed_end
        .checked_add(name)
        .ok_or(ExpansionError::Malformed)?;
    let extra_end = extra_start
        .checked_add(extra)
        .ok_or(ExpansionError::Malformed)?;
    if extra_end > end {
        return Err(ExpansionError::Malformed);
    }
    if uncompressed == u32::MAX as u64
        || compressed == u32::MAX as u64
        || local_offset == u32::MAX as u64
    {
        let mut cursor = extra_start;
        let mut found = false;
        while cursor + 4 <= extra_end {
            let id = read_u16(value, cursor)?;
            let size = read_u16(value, cursor + 2)? as usize;
            let data = cursor + 4;
            let data_end = data.checked_add(size).ok_or(ExpansionError::Malformed)?;
            if data_end > extra_end {
                return Err(ExpansionError::Malformed);
            }
            if id == 0x0001 {
                let mut field = data;
                if uncompressed == u32::MAX as u64 {
                    check_field(value, field, data_end)?;
                    uncompressed = read_u64(value, field)?;
                    field += 8;
                }
                if compressed == u32::MAX as u64 {
                    check_field(value, field, data_end)?;
                    compressed = read_u64(value, field)?;
                    field += 8;
                }
                if local_offset == u32::MAX as u64 {
                    check_field(value, field, data_end)?;
                    local_offset = read_u64(value, field)?;
                }
                found = true;
                break;
            }
            cursor = data_end;
        }
        if !found
            || uncompressed == u32::MAX as u64
            || compressed == u32::MAX as u64
            || local_offset == u32::MAX as u64
        {
            return Err(ExpansionError::Malformed);
        }
    }
    let next = fixed_end
        .checked_add(name)
        .and_then(|value| value.checked_add(extra))
        .and_then(|value| value.checked_add(comment))
        .ok_or(ExpansionError::Malformed)?;
    if next > end {
        return Err(ExpansionError::Malformed);
    }
    Ok(ZipEntry {
        flags,
        method,
        compressed,
        uncompressed,
        local_offset,
        next,
    })
}

fn check_field(value: &[u8], field: usize, data_end: usize) -> Result<(), ExpansionError> {
    let field_end = field.checked_add(8).ok_or(ExpansionError::Malformed)?;
    if field_end > data_end || field_end > value.len() {
        return Err(ExpansionError::Malformed);
    }
    Ok(())
}

fn zip_entry_expansion(
    value: &[u8],
    entry: &ZipEntry,
    remaining: usize,
) -> Result<u64, ExpansionError> {
    if entry.flags & 1 != 0 {
        return Ok(entry.uncompressed);
    }
    match entry.method {
        0 => Ok(entry.compressed),
        8 => zip_deflate_expansion(value, entry, remaining),
        _ => Ok(entry.uncompressed),
    }
}

fn zip_deflate_expansion(
    value: &[u8],
    entry: &ZipEntry,
    remaining: usize,
) -> Result<u64, ExpansionError> {
    if entry.compressed == 0 {
        return Ok(0);
    }
    let start = usize::try_from(entry.local_offset).map_err(|_| ExpansionError::Malformed)?;
    let header_end = start.checked_add(30).ok_or(ExpansionError::Malformed)?;
    if header_end > value.len() || value.get(start..start + 4) != Some(&ZIP_LOCAL_HEADER[..]) {
        return Err(ExpansionError::Malformed);
    }
    let name = read_u16(value, start + 26)? as usize;
    let extra = read_u16(value, start + 28)? as usize;
    let data = header_end
        .checked_add(name)
        .and_then(|value| value.checked_add(extra))
        .ok_or(ExpansionError::Malformed)?;
    let compressed = usize::try_from(entry.compressed).map_err(|_| ExpansionError::Malformed)?;
    let data_end = data
        .checked_add(compressed)
        .ok_or(ExpansionError::Malformed)?;
    if data_end > value.len() {
        return Err(ExpansionError::Malformed);
    }
    let mut decoder = DeflateDecoder::new(&value[data..data_end]);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => return Ok(total as u64),
            Ok(read) => {
                total = total.saturating_add(read);
                if total > remaining {
                    return Err(ExpansionError::TooLarge);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ExpansionError::Malformed),
        }
    }
}

fn read_u16(value: &[u8], offset: usize) -> Result<u16, ExpansionError> {
    let end = offset.checked_add(2).ok_or(ExpansionError::Malformed)?;
    let bytes = value.get(offset..end).ok_or(ExpansionError::Malformed)?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| ExpansionError::Malformed)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(value: &[u8], offset: usize) -> Result<u32, ExpansionError> {
    let end = offset.checked_add(4).ok_or(ExpansionError::Malformed)?;
    let bytes = value.get(offset..end).ok_or(ExpansionError::Malformed)?;
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| ExpansionError::Malformed)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(value: &[u8], offset: usize) -> Result<u64, ExpansionError> {
    let end = offset.checked_add(8).ok_or(ExpansionError::Malformed)?;
    let bytes = value.get(offset..end).ok_or(ExpansionError::Malformed)?;
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| ExpansionError::Malformed)?;
    Ok(u64::from_le_bytes(bytes))
}

fn is_multipart_media_type(content_type: &str) -> bool {
    content_type.split(';').next().is_some_and(|media_type| {
        media_type
            .trim()
            .eq_ignore_ascii_case("multipart/form-data")
    })
}

fn claim_for(declared: Option<&str>, filename: &str) -> Claim {
    if let Some(media_type) = declared {
        if is_active_web_media_type(media_type) {
            return Claim::ActiveWeb;
        }
        if is_explicit_dangerous_media_type(media_type) || is_script_media_type(media_type) {
            return Claim::ExplicitDangerous;
        }
        if is_safe_media_type(media_type) {
            return Claim::Safe;
        }
    }
    extension_claim(filename)
}

fn extension_claim(filename: &str) -> Claim {
    let Some(extension) = extension(filename) else {
        return Claim::Generic;
    };
    if ACTIVE_WEB_EXTENSIONS.contains(&extension.as_str()) {
        Claim::ActiveWeb
    } else if EXPLICIT_DANGEROUS_EXTENSIONS.contains(&extension.as_str()) {
        Claim::ExplicitDangerous
    } else if SAFE_EXTENSIONS.contains(&extension.as_str()) {
        Claim::Safe
    } else {
        Claim::Generic
    }
}

fn extension(filename: &str) -> Option<String> {
    let basename = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    // NUL bytes and trailing dots or whitespace are stripped by some upstream
    // path and filename handlers, so they must not hide the extension here.
    let cleaned: String = basename
        .chars()
        .filter(|character| *character != '\0')
        .collect();
    let basename = cleaned
        .trim_end_matches(|character: char| character == '.' || character.is_ascii_whitespace());
    let (_, extension) = basename.rsplit_once('.')?;
    let extension = extension.trim().to_ascii_lowercase();
    (!extension.is_empty()).then_some(extension)
}

fn is_safe_media_type(media_type: &str) -> bool {
    (media_type.starts_with("image/") && media_type != "image/svg+xml")
        || media_type == "application/pdf"
        || media_type.starts_with("audio/")
        || media_type.starts_with("video/")
        || media_type.starts_with("font/")
        || media_type.starts_with("application/vnd.openxmlformats-officedocument.")
        || matches!(
            media_type,
            "application/msword"
                | "application/vnd.ms-excel"
                | "application/vnd.ms-powerpoint"
                | "application/vnd.ms-fontobject"
                | "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.presentation"
        )
}

fn is_active_web_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "application/javascript"
            | "text/javascript"
            | "application/ecmascript"
            | "text/ecmascript"
            | "application/x-javascript"
    )
}

fn is_explicit_dangerous_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/x-msdownload"
            | "application/x-msdos-program"
            | "application/x-dosexec"
            | "application/x-executable"
            | "application/x-elf"
            | "application/x-sh"
            | "application/x-shellscript"
            | "application/x-php"
            | "application/x-httpd-php"
            | "application/java-archive"
            | "application/wasm"
    ) || media_type == "application/vnd.microsoft.portable-executable"
}

fn is_script_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/php"
            | "text/php"
            | "text/x-php"
            | "text/x-shellscript"
            | "text/x-sh"
            | "application/x-csh"
            | "application/x-perl"
            | "text/x-perl"
            | "application/x-ruby"
            | "text/x-ruby"
            | "application/x-python"
            | "text/x-python"
            | "application/x-bat"
            | "text/x-bat"
            | "application/x-powershell"
            | "text/x-powershell"
    )
}

fn blocks(mode: UploadInspection, claim: Claim, kind: DangerousKind) -> bool {
    match mode {
        UploadInspection::Off => false,
        UploadInspection::Mismatch => match claim {
            Claim::Safe => true,
            Claim::ActiveWeb => kind == DangerousKind::Executable,
            Claim::ExplicitDangerous | Claim::Generic => false,
        },
        UploadInspection::Strict => match kind {
            DangerousKind::Executable
            | DangerousKind::Script
            | DangerousKind::FormatMismatch
            | DangerousKind::ClaimMismatch
            | DangerousKind::ArchiveExpansion
            | DangerousKind::ArchiveMalformed => true,
            DangerousKind::ActiveWeb => claim != Claim::ActiveWeb,
        },
    }
}

/// Whether the declared media type and the filename extension promise
/// different things. A safe claim hides an active or executable name, and in
/// `strict` mode an active or dangerous claim must not hide behind a safe
/// extension either.
fn claim_mismatch(mode: UploadInspection, declared: Option<&str>, filename: &str) -> bool {
    let Some(declared) = declared else {
        return false;
    };
    let claimed = claim_for(Some(declared), filename);
    let from_extension = extension_claim(filename);
    match claimed {
        Claim::Safe => matches!(from_extension, Claim::ActiveWeb | Claim::ExplicitDangerous),
        Claim::ActiveWeb => {
            from_extension == Claim::ExplicitDangerous
                || (mode == UploadInspection::Strict && from_extension == Claim::Safe)
        }
        Claim::ExplicitDangerous => {
            mode == UploadInspection::Strict
                && matches!(from_extension, Claim::Safe | Claim::ActiveWeb)
        }
        Claim::Generic => false,
    }
}

/// The format a safe claim promises, verified from the leading bytes of the
/// part. Claims for formats without an entry here are not verified, so
/// uncommon but legitimate types keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedFormat {
    Jpeg,
    Png,
    Gif,
    Webp,
    Bmp,
    Tiff,
    Icon,
    Pdf,
    Zip,
    LegacyOffice,
    Rtf,
    Mp3,
    Mp4,
    Ogg,
    Wav,
    Avi,
    Flac,
    Ebml,
    Woff,
    Woff2,
    Sfnt,
}

impl ExpectedFormat {
    fn matches(self, value: &[u8]) -> bool {
        match self {
            Self::Jpeg => value.starts_with(b"\xff\xd8\xff"),
            Self::Png => value.starts_with(b"\x89PNG\r\n\x1a\n"),
            Self::Gif => value.starts_with(b"GIF87a") || value.starts_with(b"GIF89a"),
            Self::Webp => riff(value, b"WEBP"),
            Self::Wav => riff(value, b"WAVE"),
            Self::Avi => riff(value, b"AVI "),
            Self::Bmp => value.starts_with(b"BM"),
            Self::Tiff => {
                value.starts_with(b"II*\x00")
                    || value.starts_with(b"MM\x00*")
                    || value.starts_with(b"II+\x00")
                    || value.starts_with(b"MM\x00+")
            }
            Self::Icon => value.starts_with(b"\x00\x00\x01\x00"),
            Self::Pdf => value
                .get(..value.len().min(1024))
                .is_some_and(|head| head.windows(5).any(|window| window == b"%PDF-")),
            Self::Zip => {
                value.starts_with(b"PK\x03\x04")
                    || value.starts_with(b"PK\x05\x06")
                    || value.starts_with(b"PK\x07\x08")
            }
            Self::LegacyOffice => {
                value.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
                    || value.starts_with(b"{\\rtf")
            }
            Self::Rtf => value.starts_with(b"{\\rtf"),
            Self::Mp3 => {
                value.starts_with(b"ID3")
                    || (value.len() >= 2 && value[0] == 0xff && value[1] & 0xe0 == 0xe0)
            }
            Self::Mp4 => {
                if value.len() < 8 {
                    return false;
                }
                let atom = &value[4..8];
                atom == b"ftyp"
                    || atom == b"moov"
                    || atom == b"mdat"
                    || atom == b"wide"
                    || atom == b"free"
                    || atom == b"skip"
            }
            Self::Ogg => value.starts_with(b"OggS"),
            Self::Flac => value.starts_with(b"fLaC"),
            Self::Ebml => value.starts_with(b"\x1a\x45\xdf\xa3"),
            Self::Woff => value.starts_with(b"wOFF"),
            Self::Woff2 => value.starts_with(b"wOF2"),
            Self::Sfnt => {
                value.starts_with(b"\x00\x01\x00\x00")
                    || value.starts_with(b"true")
                    || value.starts_with(b"ttcf")
                    || value.starts_with(b"OTTO")
            }
        }
    }
}

fn riff(value: &[u8], kind: &[u8; 4]) -> bool {
    value.len() >= 12 && value.starts_with(b"RIFF") && value[8..12] == *kind
}

/// The format a safe claim promises. A declared safe type wins over the
/// filename, mirroring [`claim_for`]; a declared type the inspection cannot
/// verify disables the signature check instead of guessing from the name.
fn expected_format(declared: Option<&str>, filename: &str) -> Option<ExpectedFormat> {
    if let Some(media_type) = declared {
        if let Some(format) = format_for_media_type(media_type) {
            return Some(format);
        }
        if is_safe_media_type(media_type) {
            // A safe but unverifiable type (`image/heic`) must not disable the
            // signature check the filename promises.
            return format_for_extension(filename);
        }
    }
    format_for_extension(filename)
}

fn format_for_media_type(media_type: &str) -> Option<ExpectedFormat> {
    let format = match media_type {
        "image/jpeg" | "image/jpg" | "image/pjpeg" => ExpectedFormat::Jpeg,
        "image/png" | "image/apng" => ExpectedFormat::Png,
        "image/gif" => ExpectedFormat::Gif,
        "image/webp" => ExpectedFormat::Webp,
        "image/bmp" | "image/x-bmp" | "image/x-ms-bmp" => ExpectedFormat::Bmp,
        "image/tiff" | "image/x-tiff" => ExpectedFormat::Tiff,
        "image/x-icon" | "image/vnd.microsoft.icon" => ExpectedFormat::Icon,
        "application/pdf" => ExpectedFormat::Pdf,
        "application/msword" | "application/vnd.ms-excel" | "application/vnd.ms-powerpoint" => {
            ExpectedFormat::LegacyOffice
        }
        "application/rtf" | "text/rtf" => ExpectedFormat::Rtf,
        "audio/mpeg" | "audio/mp3" => ExpectedFormat::Mp3,
        "audio/mp4" | "audio/x-m4a" | "video/mp4" | "video/quicktime" => ExpectedFormat::Mp4,
        "audio/ogg" | "video/ogg" | "application/ogg" => ExpectedFormat::Ogg,
        "audio/wav" | "audio/wave" | "audio/x-wav" => ExpectedFormat::Wav,
        "video/x-msvideo" | "video/avi" => ExpectedFormat::Avi,
        "audio/flac" | "audio/x-flac" => ExpectedFormat::Flac,
        "video/webm" | "video/x-matroska" | "audio/webm" => ExpectedFormat::Ebml,
        "font/woff" | "application/font-woff" => ExpectedFormat::Woff,
        "font/woff2" | "application/font-woff2" => ExpectedFormat::Woff2,
        "font/ttf"
        | "font/otf"
        | "application/font-sfnt"
        | "application/x-font-ttf"
        | "application/x-font-otf" => ExpectedFormat::Sfnt,
        _ if media_type.starts_with("application/vnd.openxmlformats-officedocument.")
            || media_type.starts_with("application/vnd.oasis.opendocument.") =>
        {
            ExpectedFormat::Zip
        }
        _ => return None,
    };
    Some(format)
}

fn format_for_extension(filename: &str) -> Option<ExpectedFormat> {
    let extension = extension(filename)?;
    let format = match extension.as_str() {
        "jpg" | "jpeg" | "jpe" => ExpectedFormat::Jpeg,
        "png" => ExpectedFormat::Png,
        "gif" => ExpectedFormat::Gif,
        "webp" => ExpectedFormat::Webp,
        "bmp" => ExpectedFormat::Bmp,
        "tif" | "tiff" => ExpectedFormat::Tiff,
        "ico" => ExpectedFormat::Icon,
        "pdf" => ExpectedFormat::Pdf,
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" => ExpectedFormat::Zip,
        "doc" | "xls" | "ppt" => ExpectedFormat::LegacyOffice,
        "rtf" => ExpectedFormat::Rtf,
        "mp3" => ExpectedFormat::Mp3,
        "mp4" | "m4a" | "mov" => ExpectedFormat::Mp4,
        "ogg" => ExpectedFormat::Ogg,
        "wav" => ExpectedFormat::Wav,
        "avi" => ExpectedFormat::Avi,
        "flac" => ExpectedFormat::Flac,
        "webm" | "mkv" => ExpectedFormat::Ebml,
        "woff" => ExpectedFormat::Woff,
        "woff2" => ExpectedFormat::Woff2,
        "ttf" | "otf" => ExpectedFormat::Sfnt,
        _ => return None,
    };
    Some(format)
}

fn dangerous_content(value: &[u8]) -> Option<DangerousKind> {
    if is_executable(value) {
        return Some(DangerousKind::Executable);
    }
    let start = leading_content_start(value);
    let leading = &value[start..];
    if starts_with_ignore_ascii_case(leading, b"<?php")
        || starts_with_ignore_ascii_case(leading, b"<?=")
        || leading.starts_with(b"<%")
        || leading.starts_with(b"#!")
        || contains_script_marker(value)
        || contains_short_script_tag(value)
    {
        return Some(DangerousKind::Script);
    }
    if leading.starts_with(b"<") {
        return Some(DangerousKind::ActiveWeb);
    }
    None
}

fn is_executable(value: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"\x7fELF",
        b"MZ",
        b"\xca\xfe\xba\xbe",
        b"\xca\xfe\xba\xbf",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\x00asm",
    ];
    MAGICS.iter().any(|magic| value.starts_with(magic))
}

fn leading_content_start(value: &[u8]) -> usize {
    let mut start = if value.starts_with(b"\xef\xbb\xbf") {
        3
    } else {
        0
    };
    while start < value.len() && value[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn contains_script_marker(bytes: &[u8]) -> bool {
    if bytes.len() >= 5
        && bytes
            .windows(5)
            .any(|window| window.eq_ignore_ascii_case(b"<?php"))
    {
        return true;
    }
    contains_open_echo(bytes)
        || contains_asp_scriptlet(bytes)
        || contains_jsp_tag(bytes)
        || contains_server_script_tag(bytes)
}

/// JSP documents use XML element syntax (`<jsp:scriptlet>`,
/// `<jsp:directive.page ...>`) instead of the `<%` delimiters.
fn contains_jsp_tag(bytes: &[u8]) -> bool {
    bytes.len() >= 5
        && bytes
            .windows(5)
            .any(|window| window.eq_ignore_ascii_case(b"<jsp:"))
}

/// ASP.NET Web Forms put server code in a plain `<script runat="server">` tag.
fn contains_server_script_tag(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index + 7 <= bytes.len() {
        if !bytes[index..index + 7].eq_ignore_ascii_case(b"<script") {
            index += 1;
            continue;
        }
        let rest = &bytes[index + 7..];
        let tag_len = rest
            .iter()
            .position(|&byte| byte == b'>')
            .unwrap_or(rest.len());
        let attributes = rest[..tag_len].to_ascii_lowercase();
        if attributes.windows(5).any(|window| window == b"runat")
            && attributes.windows(6).any(|window| window == b"server")
        {
            return true;
        }
        index += 7 + tag_len;
    }
    false
}

/// `<?=` is only three bytes, so scrambled image or media content contains it
/// by chance; the expression that follows must look like one.
fn contains_open_echo(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes
            .windows(4)
            .any(|window| window[..3].eq_ignore_ascii_case(b"<?=") && is_code_start(window[3]))
}

/// `<%` starts an ASP or JSP scriptlet. Two- and three-byte coincidences are
/// common in compressed media, so the tag must be followed by a real scriptlet
/// opening: an echo or directive marker, a language keyword, or a longer
/// identifier used as a call or member access.
fn contains_asp_scriptlet(bytes: &[u8]) -> bool {
    const KEYWORDS: &[&[u8]] = &[
        b"out",
        b"if",
        b"for",
        b"while",
        b"do",
        b"switch",
        b"int",
        b"long",
        b"float",
        b"double",
        b"char",
        b"boolean",
        b"byte",
        b"short",
        b"void",
        b"String",
        b"Object",
        b"request",
        b"response",
        b"session",
        b"application",
        b"pageContext",
        b"Runtime",
        b"System",
        b"Class",
        b"Thread",
        b"new",
        b"try",
        b"catch",
        b"finally",
        b"throw",
        b"return",
        b"break",
        b"continue",
        b"print",
        b"write",
        b"eval",
        b"import",
        b"include",
        b"taglib",
        b"page",
        b"Response",
        b"Request",
        b"Server",
        b"class",
        b"public",
        b"private",
        b"protected",
        b"static",
        b"else",
        b"case",
        b"package",
        b"interface",
        b"extends",
        b"implements",
        b"this",
        b"super",
    ];

    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'<' && bytes[index + 1] == b'%' {
            let rest = &bytes[index + 2..];
            let Some(&first) = rest.first() else {
                break;
            };
            let hit = match first {
                b'=' | b'@' | b'!' | b'#' => rest.get(1).is_some_and(|byte| is_code_start(*byte)),
                _ => {
                    let rest = skip_ascii_spaces(rest);
                    let name_len = rest
                        .iter()
                        .take(64)
                        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                        .count();
                    if name_len == 0 {
                        false
                    } else {
                        let name = &rest[..name_len];
                        let after = skip_ascii_spaces(&rest[name_len..]);
                        let call =
                            name_len >= 3 && matches!(after.first(), Some(b'(' | b'.' | b'['));
                        call || KEYWORDS
                            .iter()
                            .any(|keyword| name.eq_ignore_ascii_case(keyword))
                    }
                }
            };
            if hit {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn is_code_start(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'$' | b'(' | b'[' | b'"' | b'\'' | b'_' | b'/' | b'\\' | b'`'
        )
}

/// PHP short open tags (`<?`) are only detected when what follows looks like
/// code: a variable, a call, a parenthesized callable, or a language keyword.
/// Whitespace, `@`, and comments may sit between the tag and the first
/// expression. A bare two-byte scan would match random bytes inside compressed
/// images and media, and XML processing instructions (`<?xml`, `<?xpacket`,
/// `<?mso-application`) must not match.
fn contains_short_script_tag(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] != b'<' || bytes[index + 1] != b'?' {
            index += 1;
            continue;
        }
        let mut rest = &bytes[index + 2..];
        let mut consumed = 0;
        // `<?=` is the echo shorthand; what follows is an expression, possibly
        // behind a comment.
        if rest.first() == Some(&b'=') {
            rest = &rest[1..];
            consumed = 1;
        }
        loop {
            let before = rest.len();
            rest = skip_ascii_spaces(rest);
            let suppressed = rest
                .iter()
                .take(8)
                .take_while(|byte| **byte == b'@')
                .count();
            rest = &rest[suppressed..];
            if let Some(tail) = strip_block_comment(rest) {
                rest = tail;
            } else if let Some(tail) = strip_line_comment(rest) {
                rest = tail;
            }
            consumed += before - rest.len();
            if rest.len() == before {
                break;
            }
        }
        if short_tag_body(rest) {
            return true;
        }
        index += 2 + consumed;
    }
    false
}

fn strip_block_comment(value: &[u8]) -> Option<&[u8]> {
    let body = value.strip_prefix(b"/*")?;
    // The comment may be arbitrarily long: a fixed 256-byte window let a longer
    // comment hide the tag. An unterminated comment runs to the end of the
    // part, so there is nothing left to execute.
    match body.windows(2).position(|window| window == b"*/") {
        Some(end) => Some(&body[end + 2..]),
        None => Some(&[]),
    }
}

fn strip_line_comment(value: &[u8]) -> Option<&[u8]> {
    let body = value
        .strip_prefix(b"//")
        .or_else(|| value.strip_prefix(b"#"))?;
    for index in 0..body.len() {
        if matches!(body[index], b'\n' | b'\r') {
            return Some(&body[index + 1..]);
        }
        // In PHP a closing `?>` ends the script block even inside a `//` or
        // `#` comment, so the comment must not swallow a following `<?` tag.
        if body[index..].starts_with(b"?>") {
            return Some(&body[index..]);
        }
    }
    Some(&[])
}

fn short_tag_body(rest: &[u8]) -> bool {
    const KEYWORDS: &[&[u8]] = &[
        b"echo",
        b"print",
        b"system",
        b"exec",
        b"eval",
        b"shell_exec",
        b"passthru",
        b"assert",
        b"include",
        b"include_once",
        b"require",
        b"require_once",
        b"if",
        b"foreach",
        b"while",
        b"switch",
        b"function",
        b"class",
        b"return",
        b"die",
        b"exit",
        b"isset",
        b"unset",
        b"empty",
        b"global",
        b"static",
        b"new",
        b"use",
        b"fn",
        b"match",
        b"var_dump",
        b"file_get_contents",
        b"call_user_func",
        b"declare",
        b"namespace",
        b"trait",
        b"interface",
        b"abstract",
        b"final",
        b"throw",
        b"try",
        b"yield",
    ];
    const MAX_NAME_BYTES: usize = 64;

    let rest = skip_ascii_spaces(rest);
    let Some(&first) = rest.first() else {
        return false;
    };
    if first == b'$' {
        return true;
    }
    if first == b'(' {
        return parenthesized_callable(rest);
    }
    // A leading backslash calls into the global namespace and a backtick runs a
    // shell command; both are code even though they are not names.
    if matches!(first, b'\\' | b'`') {
        return true;
    }
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    let name_len = rest
        .iter()
        .take(MAX_NAME_BYTES)
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    let name = &rest[..name_len];
    if name.eq_ignore_ascii_case(b"xml") {
        return false;
    }
    if skip_ascii_spaces(&rest[name_len..]).first() == Some(&b'(') {
        return true;
    }
    KEYWORDS
        .iter()
        .any(|keyword| name.eq_ignore_ascii_case(keyword))
}

/// A parenthesized callable (`(system)(...)`, `($f)(...)`) is only treated as
/// code when an identifier or variable fills the parentheses and the closing
/// paren is followed by something that can start a call or argument list.
fn parenthesized_callable(rest: &[u8]) -> bool {
    const MAX_NAME_BYTES: usize = 64;

    let inner = skip_ascii_spaces(&rest[1..]);
    let name_len = inner
        .iter()
        .take(MAX_NAME_BYTES)
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_' || **byte == b'$')
        .count();
    if name_len == 0 {
        return false;
    }
    let after = skip_ascii_spaces(&inner[name_len..]);
    if after.first() != Some(&b')') {
        return false;
    }
    matches!(
        skip_ascii_spaces(&after[1..]).first(),
        Some(b'(' | b';' | b',' | b'[' | b'-' | b':')
    )
}

fn skip_ascii_spaces(value: &[u8]) -> &[u8] {
    let skip = value
        .iter()
        .take_while(|byte| matches!(**byte, b' ' | b'\t' | b'\r' | b'\n'))
        .count();
    &value[skip..]
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;

    use super::*;

    fn inspect(headers: &HeaderMap, body: &[u8], mode: UploadInspection) -> Option<Rejection> {
        super::inspect(headers, body, mode, UploadExpansion::disabled())
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        headers
    }

    fn body(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (filename, content_type, value) in parts {
            body.extend_from_slice(b"--X\r\n");
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
                )
                .as_bytes(),
            );
            if let Some(content_type) = content_type {
                body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--X--\r\n");
        body
    }

    fn inspect_mismatch(body: &[u8]) -> Option<Rejection> {
        inspect(&headers(), body, UploadInspection::Mismatch)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).expect("write gzip");
        encoder.finish().expect("finish gzip")
    }

    fn zip(data: &[u8], method: u16) -> Vec<u8> {
        use std::io::Write;

        let name = b"entry.bin";
        let payload = if method == 8 {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(data).expect("write deflate");
            encoder.finish().expect("finish deflate")
        } else {
            data.to_vec()
        };
        let mut archive = Vec::new();
        archive.extend_from_slice(&ZIP_LOCAL_HEADER[..]);
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&method.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(&payload);
        let directory_offset = archive.len();
        archive.extend_from_slice(&ZIP_CENTRAL_HEADER[..]);
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&method.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(name);
        let directory_size = archive.len() - directory_offset;
        archive.extend_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY[..]);
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&(directory_size as u32).to_le_bytes());
        archive.extend_from_slice(&(directory_offset as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive
    }

    fn zip64_stored(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend_from_slice(&ZIP_LOCAL_HEADER[..]);
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(data);
        let directory_offset = archive.len();
        archive.extend_from_slice(&ZIP_CENTRAL_HEADER[..]);
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&28u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(&0x0001u16.to_le_bytes());
        archive.extend_from_slice(&24u16.to_le_bytes());
        archive.extend_from_slice(&(data.len() as u64).to_le_bytes());
        archive.extend_from_slice(&(data.len() as u64).to_le_bytes());
        archive.extend_from_slice(&0u64.to_le_bytes());
        let directory_size = archive.len() - directory_offset;
        let zip64_record = archive.len();
        archive.extend_from_slice(&ZIP64_END_OF_CENTRAL_DIRECTORY[..]);
        archive.extend_from_slice(&44u64.to_le_bytes());
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&1u64.to_le_bytes());
        archive.extend_from_slice(&1u64.to_le_bytes());
        archive.extend_from_slice(&(directory_size as u64).to_le_bytes());
        archive.extend_from_slice(&(directory_offset as u64).to_le_bytes());
        archive.extend_from_slice(&ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR[..]);
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&(zip64_record as u64).to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY[..]);
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&u16::MAX.to_le_bytes());
        archive.extend_from_slice(&u16::MAX.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive
    }

    fn expansion(max_bytes: usize) -> UploadExpansion {
        UploadExpansion {
            enabled: true,
            max_bytes,
            max_total_bytes: max_bytes,
            max_entries: 4096,
        }
    }

    #[test]
    fn uploaded_gzip_expansion_is_bounded() {
        let archive = gzip(&vec![b'a'; 128 * 1024]);
        let body = body(&[("data.tar.gz", Some("application/gzip"), &archive)]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            expansion(32 * 1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
        assert_eq!(rejection.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn small_gzip_and_stored_zip_pass_the_expansion_budget() {
        let gzip_body = body(&[("data.tar.gz", Some("application/gzip"), &gzip(b"hello"))]);
        assert!(
            super::inspect(
                &headers(),
                &gzip_body,
                UploadInspection::Strict,
                expansion(1024),
            )
            .is_none()
        );
        let stored = zip(b"hello", 0);
        let zip_body = body(&[("data.zip", Some("application/zip"), &stored)]);
        assert!(
            super::inspect(
                &headers(),
                &zip_body,
                UploadInspection::Strict,
                expansion(1024),
            )
            .is_none()
        );
    }

    #[test]
    fn zip64_archives_are_parsed() {
        let archive = zip64_stored(b"entry.bin", b"hello");
        let body = body(&[("data.zip", Some("application/zip"), &archive)]);
        assert!(
            super::inspect(&headers(), &body, UploadInspection::Strict, expansion(1024),).is_none()
        );
    }

    #[test]
    fn uploaded_zip_deflate_expansion_is_bounded() {
        let archive = zip(&vec![b'a'; 128 * 1024], 8);
        let body = body(&[("data.zip", Some("application/zip"), &archive)]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            expansion(32 * 1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
    }

    #[test]
    fn zip_entry_count_is_bounded() {
        let archive = zip(b"hello", 0);
        let body = body(&[("data.zip", Some("application/zip"), &archive)]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            UploadExpansion {
                enabled: true,
                max_bytes: 1024,
                max_total_bytes: 1024,
                max_entries: 0,
            },
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
    }

    #[test]
    fn archive_expansion_is_ignored_when_disabled() {
        let archive = gzip(&vec![b'a'; 128 * 1024]);
        let body = body(&[("data.tar.gz", Some("application/gzip"), &archive)]);
        assert!(
            super::inspect(
                &headers(),
                &body,
                UploadInspection::Strict,
                UploadExpansion::disabled(),
            )
            .is_none()
        );
    }

    #[test]
    fn unparseable_archive_claims_are_left_to_the_existing_checks() {
        let body = body(&[("data.zip", Some("application/zip"), b"not a zip")]);
        assert!(
            super::inspect(&headers(), &body, UploadInspection::Strict, expansion(1024)).is_none()
        );
    }

    #[test]
    fn malformed_archives_with_a_valid_header_or_eocd_are_rejected() {
        let gzip_body = body(&[("data.gz", Some("application/gzip"), b"\x1f\x8bnot gzip")]);
        let rejection = super::inspect(
            &headers(),
            &gzip_body,
            UploadInspection::Strict,
            expansion(1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveMalformed);
        assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);

        let mut zip = vec![0u8; 22];
        zip[18..22].copy_from_slice(&ZIP_CENTRAL_HEADER[..]);
        zip.extend_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY[..]);
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&4u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        let zip_body = body(&[("data.zip", Some("application/zip"), &zip)]);
        let rejection = super::inspect(
            &headers(),
            &zip_body,
            UploadInspection::Strict,
            expansion(1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveMalformed);
    }

    #[test]
    fn zip_with_prepended_bytes_is_still_bounded() {
        let archive = zip(&vec![b'a'; 128 * 1024], 8);
        let mut prefixed = b"JUNK".to_vec();
        prefixed.extend_from_slice(&archive);
        let body = body(&[("data.zip", Some("application/zip"), &prefixed)]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            expansion(32 * 1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
    }

    #[test]
    fn zip_with_trailing_bytes_is_still_bounded() {
        let mut archive = zip(&vec![b'a'; 128 * 1024], 8);
        archive.extend_from_slice(b"JUNK");
        let body = body(&[("data.zip", Some("application/zip"), &archive)]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            expansion(32 * 1024),
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
    }

    #[test]
    fn zip_name_normalization_and_content_detection_are_bounded() {
        let archive = zip(&vec![b'a'; 128 * 1024], 8);
        for (filename, content_type) in [
            ("data.zip ", Some("application/octet-stream")),
            ("data.zip.", Some("application/octet-stream")),
            ("data.bin", Some("application/octet-stream")),
            ("data.zip", None),
        ] {
            let body = body(&[(filename, content_type, &archive)]);
            let rejection = super::inspect(
                &headers(),
                &body,
                UploadInspection::Strict,
                expansion(32 * 1024),
            )
            .expect("rejected");
            assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
        }
    }

    #[test]
    fn expansion_budget_is_shared_across_parts() {
        let first = gzip(&vec![b'a'; 64 * 1024]);
        let second = gzip(&vec![b'b'; 64 * 1024]);
        let body = body(&[
            ("first.gz", Some("application/gzip"), &first),
            ("second.gz", Some("application/gzip"), &second),
        ]);
        let rejection = super::inspect(
            &headers(),
            &body,
            UploadInspection::Strict,
            UploadExpansion {
                enabled: true,
                max_bytes: 128 * 1024,
                max_total_bytes: 96 * 1024,
                max_entries: 4096,
            },
        )
        .expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ArchiveExpansion);
    }

    #[test]
    fn recognises_multipart_content_types() {
        assert!(is_multipart(&headers()));
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=X"),
        );
        assert!(is_multipart(&headers));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_multipart(&headers));
    }

    #[test]
    fn benign_uploads_pass() {
        for (filename, media_type, value) in [
            (
                "photo.jpg",
                "image/jpeg",
                b"\xff\xd8\xff\xe0JFIF".as_slice(),
            ),
            ("sheet.pdf", "application/pdf", b"%PDF-1.7\n"),
            ("archive.zip", "application/zip", b"PK\x03\x04"),
            ("report.docx", "application/octet-stream", b"PK\x03\x04"),
        ] {
            let body = body(&[(filename, Some(media_type), value)]);
            assert!(
                inspect_mismatch(&body).is_none(),
                "false positive for {filename} ({media_type})"
            );
        }
    }

    #[test]
    fn script_content_behind_an_image_claim_is_rejected() {
        let body = body(&[(
            "photo.jpg",
            Some("image/jpeg"),
            b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
        assert_eq!(rejection.filename, "photo.jpg");
        assert_eq!(rejection.declared.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn markup_behind_a_pdf_claim_is_rejected() {
        let body = body(&[(
            "document.pdf",
            Some("application/pdf"),
            b"<html><script>alert(1)</script></html>",
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ActiveWeb);
    }

    #[test]
    fn executable_behind_an_image_claim_is_rejected() {
        let body = body(&[("image.png", Some("image/png"), b"\x7fELF\x02\x01\x01")]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Executable);
    }

    #[test]
    fn a_safe_extension_is_a_claim_when_the_type_is_generic() {
        let body = body(&[(
            "photo.jpg",
            Some("application/octet-stream"),
            b"<svg onload=alert(1)>",
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ActiveWeb);
    }

    #[test]
    fn rejects_a_claim_that_hides_a_dangerous_extension() {
        let php = body(&[("shell.php", Some("image/heic"), b"print(1)")]);
        let rejection = inspect(&headers(), &php, UploadInspection::Strict).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ClaimMismatch);

        let html = body(&[("photo.jpg", Some("text/html"), b"<html></html>")]);
        let rejection = inspect(&headers(), &html, UploadInspection::Strict).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::ClaimMismatch);

        // The documented active-type upload keeps passing: the extension
        // promises markup too.
        let page = body(&[("page.html", Some("text/html"), b"<html></html>")]);
        assert!(inspect(&headers(), &page, UploadInspection::Strict).is_none());

        let php_as_html = body(&[(
            "shell.php",
            Some("text/html"),
            b"<html><?php system($_GET['c']); ?></html>",
        )]);
        assert!(inspect_mismatch(&php_as_html).is_some());
        assert!(inspect(&headers(), &php_as_html, UploadInspection::Strict).is_some());

        let html_with_php = body(&[(
            "page.html",
            Some("text/html"),
            b"<html><?php system($_GET['c']); ?></html>",
        )]);
        let rejection =
            inspect(&headers(), &html_with_php, UploadInspection::Strict).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn unverifiable_safe_types_still_verify_the_filename_signature() {
        let bytes = body(&[("photo.jpg", Some("image/heic"), b"not a jpeg")]);
        let rejection = inspect(&headers(), &bytes, UploadInspection::Strict).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::FormatMismatch);

        let bytes = body(&[("photo.jpg", Some("image/heic"), b"\xff\xd8\xff\xe0JFIF")]);
        assert!(inspect(&headers(), &bytes, UploadInspection::Strict).is_none());
    }

    #[test]
    fn generic_uploads_are_only_checked_in_strict_mode() {
        let executable_body = body(&[(
            "tool",
            Some("application/octet-stream"),
            b"\x7fELF\x02\x01\x01",
        )]);
        assert!(inspect_mismatch(&executable_body).is_none());
        let rejection =
            inspect(&headers(), &executable_body, UploadInspection::Strict).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Executable);

        let script_body = body(&[(
            "notes.txt",
            Some("application/octet-stream"),
            b"<?php echo 'snippet'; ?>",
        )]);
        assert!(inspect_mismatch(&script_body).is_none());
        assert!(inspect(&headers(), &script_body, UploadInspection::Strict).is_some());
    }

    #[test]
    fn explicitly_active_and_executable_claims_are_respected() {
        let html = body(&[(
            "page.html",
            Some("text/html"),
            b"<!doctype html><script>alert(1)</script>",
        )]);
        assert!(inspect_mismatch(&html).is_none());

        let executable = body(&[(
            "installer.exe",
            Some("application/x-msdownload"),
            b"MZ\x90\x00",
        )]);
        assert!(inspect_mismatch(&executable).is_none());
        assert!(inspect(&headers(), &executable, UploadInspection::Strict).is_some());
    }

    #[test]
    fn a_web_file_with_binary_content_is_rejected() {
        let body = body(&[("page.html", Some("text/html"), b"\x7fELF\x02\x01\x01")]);
        assert!(inspect_mismatch(&body).is_some());
    }

    #[test]
    fn leading_whitespace_and_bom_do_not_hide_markup() {
        let body = body(&[(
            "photo.png",
            Some("image/png"),
            b"\xef\xbb\xbf \r\n<?php echo 1;",
        )]);
        assert!(inspect_mismatch(&body).is_some());
    }

    #[test]
    fn invalid_filename_bytes_do_not_hide_an_extension() {
        let mut body = Vec::new();
        body.extend_from_slice(
            b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"",
        );
        body.extend_from_slice(
            b"\xffphoto.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo 1;\r\n--X--\r\n",
        );
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn a_gif_php_polyglot_is_rejected() {
        let body = body(&[(
            "pixel.gif",
            Some("image/gif"),
            b"GIF89a\x01\x00\x01\x00<?php echo 1; ?>",
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn a_deep_gif_php_polyglot_is_rejected() {
        let mut value = b"GIF89a\x01\x00\x01\x00".to_vec();
        value.extend(std::iter::repeat_n(b'A', 4096));
        value.extend_from_slice(b"<?php echo 1; ?>");
        let body = body(&[("pixel.gif", Some("image/gif"), &value)]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
        assert_eq!(rejection.filename, "pixel.gif");
    }

    #[test]
    fn deep_script_markers_are_case_insensitive() {
        let mut value = b"\xff\xd8\xff\xe0JFIF".to_vec();
        value.extend(std::iter::repeat_n(b'\0', 4096));
        value.extend_from_slice(b"<?PHP echo 1; ?>");
        let body = body(&[("photo.jpg", Some("image/jpeg"), &value)]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn a_large_benign_image_passes() {
        let mut value = b"GIF89a\x01\x00\x01\x00".to_vec();
        value.extend(std::iter::repeat_n(b'\0', 8192));
        let body = body(&[("pixel.gif", Some("image/gif"), &value)]);
        assert!(inspect_mismatch(&body).is_none());
    }

    #[test]
    fn non_file_parts_are_ignored() {
        let mut body = Vec::new();
        body.extend_from_slice(
            b"--X\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<?php echo 1; ?>\r\n--X--\r\n",
        );
        assert!(inspect_mismatch(&body).is_none());
    }

    #[test]
    fn malformed_and_oversized_bodies_are_not_inspected() {
        let mut body =
            b"--X\r\nContent-Disposition: form-data; filename=\"x.jpg\"\r\n\r\n<?php".to_vec();
        assert!(inspect_mismatch(&body).is_none());
        body.extend_from_slice(b"\r\n--X--\r\n");
        assert!(inspect_mismatch(&body).is_some());

        let mut flood = Vec::new();
        for _ in 0..65 {
            flood.extend_from_slice(
                b"--X\r\nContent-Disposition: form-data; filename=\"x.jpg\"\r\n\r\n\x7fELF\r\n",
            );
        }
        flood.extend_from_slice(b"--X--\r\n");
        assert!(inspect_mismatch(&flood).is_none());
    }

    #[test]
    fn every_declared_boundary_interpretation_is_checked() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=safe; boundary=other"),
        );
        let body = b"--safe\r\nContent-Disposition: form-data; filename=\"safe.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xe0OK\r\n--safe--\r\n--other\r\nContent-Disposition: form-data; filename=\"evil.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo 1;\r\n--other--\r\n";
        let rejection = inspect(&headers, body, UploadInspection::Mismatch).expect("rejected");
        assert_eq!(rejection.filename, "evil.jpg");
    }

    #[test]
    fn content_that_is_not_the_claimed_format_is_rejected() {
        for (filename, media_type, value) in [
            ("photo.jpg", "image/jpeg", b"puts \"hi\"".as_slice()),
            ("photo.png", "image/png", b"\xff\xd8\xff\xe0JFIF"),
            ("report.pdf", "application/pdf", b"puts 1\n"),
            ("sheet.docx", "application/octet-stream", b"puts 1\n"),
            ("pixel.gif", "image/gif", b"\x89PNG\r\n\x1a\n"),
            ("photo.jpg", "text/plain", b"echo hi\n"),
        ] {
            let body = body(&[(filename, Some(media_type), value)]);
            let rejection = inspect_mismatch(&body)
                .unwrap_or_else(|| panic!("accepted {filename} ({media_type})"));
            assert_eq!(rejection.kind, DangerousKind::FormatMismatch, "{filename}");
        }
    }

    #[test]
    fn matching_signatures_pass_for_every_verifiable_family() {
        for (filename, media_type, value) in [
            ("a.jpg", "image/jpeg", b"\xff\xd8\xff\xe0JFIF".as_slice()),
            ("a.png", "image/png", b"\x89PNG\r\n\x1a\n"),
            ("a.webp", "image/webp", b"RIFF\x24\x00\x00\x00WEBPVP8 "),
            ("a.gif", "image/gif", b"GIF89a\x01\x00"),
            ("a.bmp", "image/bmp", b"BM\x00\x00\x00\x00"),
            ("a.tiff", "image/tiff", b"II*\x00\x08\x00"),
            ("a.ico", "image/x-icon", b"\x00\x00\x01\x00\x01\x00"),
            ("a.pdf", "application/pdf", b"%PDF-1.7\n"),
            ("a.docx", "application/octet-stream", b"PK\x03\x04docx"),
            (
                "a.doc",
                "application/octet-stream",
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1doc",
            ),
            ("a.rtf", "application/rtf", b"{\\rtf1\\ansi"),
            ("a.mp3", "audio/mpeg", b"ID3\x04\x00"),
            ("a.mp4", "video/mp4", b"\x00\x00\x00\x18ftypmp42"),
            ("a.ogg", "audio/ogg", b"OggS\x00\x02"),
            ("a.wav", "audio/wav", b"RIFF\x24\x00\x00\x00WAVEfmt "),
            ("a.avi", "video/x-msvideo", b"RIFF\x24\x00\x00\x00AVI LIST"),
            ("a.flac", "audio/flac", b"fLaC\x00\x00"),
            ("a.webm", "video/webm", b"\x1a\x45\xdf\xa3\x01\x00"),
            ("a.woff", "font/woff", b"wOFF\x00\x01"),
            ("a.woff2", "font/woff2", b"wOF2\x00\x01"),
            ("a.ttf", "font/ttf", b"\x00\x01\x00\x00\x00\x0c"),
            ("a.otf", "font/otf", b"OTTO\x00\x0c"),
        ] {
            let body = body(&[(filename, Some(media_type), value)]);
            assert!(
                inspect_mismatch(&body).is_none(),
                "false positive for {filename} ({media_type})"
            );
        }
    }

    #[test]
    fn a_pdf_header_may_follow_a_short_junk_prefix() {
        let value = b"\xef\xbb\xbfjunk\r\n%PDF-1.4\n";
        let body = body(&[("report.pdf", Some("application/pdf"), value)]);
        assert!(inspect_mismatch(&body).is_none());
    }

    #[test]
    fn unverifiable_safe_claims_are_not_signature_checked() {
        for (filename, media_type) in [("photo.heic", "image/heic"), ("track.opus", "audio/x-opus")]
        {
            let body = body(&[(filename, Some(media_type), b"not that format")]);
            assert!(
                inspect_mismatch(&body).is_none(),
                "signature check applied to {media_type}"
            );
        }
    }

    #[test]
    fn the_signature_check_reads_only_the_leading_bytes() {
        let mut value = b"\xff\xd8\xff\xe0JFIF".to_vec();
        value.extend(std::iter::repeat_n(b'A', 4096));
        let body = body(&[("photo.jpg", Some("image/jpeg"), &value)]);
        assert!(inspect_mismatch(&body).is_none());
    }

    fn uri(path: &str) -> Uri {
        format!("http://example.com{path}").parse().expect("uri")
    }

    fn raw(method: Method, path: &str, content_type: &str, value: &[u8]) -> Option<Rejection> {
        let mut headers = HeaderMap::new();
        if !content_type.is_empty() {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).expect("type"),
            );
        }
        inspect_raw(
            &method,
            &uri(path),
            &headers,
            value,
            UploadInspection::Mismatch,
        )
    }

    #[test]
    fn marker_bytes_inside_compressed_media_do_not_match() {
        let mut value = b"\x89PNG\r\n\x1a\n".to_vec();
        value.extend_from_slice(b"<%u\xae\xd3\x0f<%i#E<?=\xedi\xbb<%\xdd\x1c<%Wt=\x83<%I\x8c\xd9");
        let body = body(&[("photo.png", Some("image/png"), &value)]);
        assert!(inspect_mismatch(&body).is_none());
    }

    #[test]
    fn real_world_images_with_marker_like_bytes_pass() {
        for (filename, media_type, value) in [
            (
                "photo.png",
                "image/png",
                include_bytes!("../tests/fixtures/real-world-infographic.png").as_slice(),
            ),
            (
                "diagram.webp",
                "image/webp",
                include_bytes!("../tests/fixtures/real-world-response-diagram.webp").as_slice(),
            ),
        ] {
            let body = body(&[(filename, Some(media_type), value)]);
            assert!(
                inspect_mismatch(&body).is_none(),
                "{filename} rejected as mismatch"
            );
            assert!(
                inspect(&headers(), &body, UploadInspection::Strict).is_none(),
                "{filename} rejected in strict mode"
            );
        }
    }

    #[test]
    fn asp_and_echo_markers_still_match_when_code_follows() {
        for marker in [
            b"<% out.print(1); %>".as_slice(),
            b"<%= 1 %>",
            b"<%if (x) {}%>",
            b"<%@ page import=\"java.io.*\" %>",
            b"<%! int x; %>",
            b"<%Runtime.getRuntime();%>",
            b"<%response.getWriter().print(1);%>",
            b"<?= $x ?>",
            b"<?=htmlspecialchars($x)?>",
            b"<?= 1 ?>",
            b"<?php echo 1; ?>",
            b"<?PHP echo 1; ?>",
        ] {
            assert!(contains_script_marker(marker), "{marker:?}");
        }
    }

    #[test]
    fn short_tags_are_detected_only_when_the_body_looks_like_code() {
        for value in [
            b"<? system($_GET['cmd']);".as_slice(),
            b"<?$x=$_GET['cmd'];",
            b"<?\n echo 'hi';",
            b"<?phpinfo();",
            b"<?@eval($_GET['cmd']);",
            b"<?@ system('id');",
            b"<?/*x*/system($_GET['cmd']);",
            b"<?/* a */ @ include('x');",
            b"<?//x\nsystem('id');",
            b"<?#x\nsystem('id');",
            b"<?(system)(\"id\");",
            b"<?($f)(1);",
            b"<? \\system('id');",
            b"<? `id`;",
            b"<?=/*c*/system('id') ?>",
            b"\xff\xd8\xff\xe0JFIF<? shell_exec('id');",
            b"\xff\xd8\xff\xe0<?#?><? system($_GET['c']); ?>",
        ] {
            assert!(contains_short_script_tag(value), "{value:?}");
        }
        for value in [
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>".as_slice(),
            b"<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>",
            b"<?mso-application progid=\"Word.Document\"?>",
            b"<? not a tag ?",
            b"<?/* unterminated system('id');",
            b"<? /* only a comment */ ?>",
            b"<?(1)",
            b"<?(system) nonsense",
            b"\x3c\x3f\x00\x01\x02",
        ] {
            assert!(!contains_short_script_tag(value), "{value:?}");
        }
    }

    #[test]
    fn jsp_and_aspnet_server_markers_are_detected() {
        for value in [
            b"<?xml version=\"1.0\"?><jsp:root><jsp:scriptlet>Runtime.getRuntime().exec(\"id\")</jsp:scriptlet></jsp:root>".as_slice(),
            b"<html><script runat=\"server\">Response.Write(1)</script></html>",
            b"<html><script language=\"C#\" runat=server>Response.Write(1)</script></html>",
        ] {
            assert!(contains_script_marker(value), "{value:?}");
        }
        assert!(
            !contains_script_marker(b"<html><script>alert(1)</script></html>"),
            "client-side script tags are not server code"
        );
    }

    #[test]
    fn a_short_tag_behind_an_image_claim_is_rejected() {
        let body = body(&[(
            "photo.jpg",
            Some("image/jpeg"),
            b"\xff\xd8\xff\xe0JFIF<? system($_GET['cmd']); ?>".as_slice(),
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn a_short_tag_is_detected_even_for_an_unverifiable_safe_type() {
        let body = body(&[(
            "photo.heic",
            Some("image/heic"),
            b"\xff\xd8\xff\xe0<? system('id');".as_slice(),
        )]);
        let rejection = inspect_mismatch(&body).expect("rejected");
        assert_eq!(rejection.kind, DangerousKind::Script);
    }

    #[test]
    fn xml_processing_instructions_in_a_safe_claim_pass() {
        let body = body(&[(
            "report.docx",
            Some("application/octet-stream"),
            b"PK\x03\x04<?xml version=\"1.0\"?><Types/>".as_slice(),
        )]);
        assert!(inspect_mismatch(&body).is_none());
    }

    #[test]
    fn raw_bodies_with_a_dangerous_claim_are_inspected() {
        for (path, content_type, value) in [
            (
                "/upload/polyglot.php",
                "application/x-httpd-php",
                b"<?php eval($_GET['cmd']);?>".as_slice(),
            ),
            (
                "/upload/notes",
                "text/x-php",
                b"\xff\xd8\xff\xe0JFIF<? system('id');",
            ),
            ("/files/shell.PHP", "application/octet-stream", b"<?= 1 ?>"),
            (
                "/upload/polyglot%2Ephp",
                "application/octet-stream",
                b"<?php echo 1;",
            ),
            ("/upload/tool.php", "image/jpeg", b"\x7fELF\x02\x01\x01"),
            ("/upload/tool.sh", "text/plain", b"#!/bin/sh\necho hi"),
        ] {
            let rejection = raw(Method::PUT, path, content_type, value)
                .unwrap_or_else(|| panic!("accepted {path} ({content_type})"));
            assert_eq!(rejection.filename, path.rsplit('/').next().unwrap_or(path));
        }
    }

    #[test]
    fn raw_bodies_without_a_dangerous_claim_are_not_inspected() {
        for (path, content_type) in [
            ("/api/notes", "application/json"),
            ("/upload/photo.jpg", "image/jpeg"),
            ("/upload/report.pdf", "application/pdf"),
            ("/index.html", "text/html"),
        ] {
            assert!(
                raw(Method::POST, path, content_type, b"<?php echo 1;").is_none(),
                "inspected {path} ({content_type})"
            );
        }
    }

    #[test]
    fn a_php_route_with_an_ordinary_body_is_not_rejected() {
        let value = b"{\"query\":\"annual report\",\"page\":2}";
        assert!(raw(Method::POST, "/api/items.php", "application/json", value).is_none());
        assert!(
            raw(
                Method::PUT,
                "/upload/polyglot.php",
                "image/jpeg",
                b"JPEGDATA"
            )
            .is_none()
        );
    }

    #[test]
    fn raw_inspection_covers_write_methods_and_skips_the_rest() {
        assert!(raw(Method::POST, "/x.php", "", b"<?php echo 1;").is_some());
        assert!(raw(Method::PUT, "/x.php", "", b"<?php echo 1;").is_some());
        assert!(raw(Method::PATCH, "/x.php", "", b"<?php echo 1;").is_some());
        assert!(raw(Method::GET, "/x.php", "", b"<?php echo 1;").is_none());
    }

    #[test]
    fn raw_inspection_skips_multipart_and_disabled_modes() {
        let headers = headers();
        assert!(
            inspect_raw(
                &Method::POST,
                &uri("/upload/x.php"),
                &headers,
                b"<?php echo 1;",
                UploadInspection::Mismatch,
            )
            .is_none()
        );
        assert!(
            inspect_raw(
                &Method::PUT,
                &uri("/upload/x.php"),
                &HeaderMap::new(),
                b"<?php echo 1;",
                UploadInspection::Off,
            )
            .is_none()
        );
    }

    #[test]
    fn disabled_inspection_accepts_everything() {
        let body = body(&[("x.jpg", Some("image/jpeg"), b"<?php echo 1;")]);
        assert!(inspect(&headers(), &body, UploadInspection::Off).is_none());
    }

    #[test]
    fn recognized_media_types_and_extensions_are_classified() {
        assert_eq!(claim_for(Some("image/png"), "a.bin"), Claim::Safe);
        assert_eq!(claim_for(Some("image/svg+xml"), "a.png"), Claim::ActiveWeb);
        assert_eq!(claim_for(Some("text/plain"), "a.html"), Claim::ActiveWeb);
        assert_eq!(claim_for(Some("text/plain"), "a.jpg"), Claim::Safe);
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.jpg."),
            Claim::Safe
        );
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.jpg "),
            Claim::Safe
        );
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.jpg\0"),
            Claim::Safe
        );
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.jp\0g"),
            Claim::Safe
        );
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.php"),
            Claim::ExplicitDangerous
        );
        assert_eq!(
            claim_for(Some("application/octet-stream"), "a.unknown"),
            Claim::Generic
        );
    }
}
