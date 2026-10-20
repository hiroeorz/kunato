//! Bounded inspection of `multipart/form-data` uploads.
//!
//! A part that carries a `filename` is treated as a file upload. Its declared
//! `Content-Type` (or, when that is generic or absent, its filename extension)
//! is compared with the bytes of the part: executable, server-side script, or
//! markup content behind an image, PDF, office, media, or font claim is
//! rejected. This closes the MIME-spoofing class where an upload filter trusts
//! the declared type while the upstream stores an executable or HTML file.
//!
//! The check shares the multipart boundary, part, and body limits with rule
//! inspection and never copies the body. It runs before rule evaluation, so an
//! `ALLOW` rule cannot bypass it. It is deliberately a heuristic: a valid image
//! header followed by a deeper polyglot, an unsupported boundary
//! interpretation, or an upload larger than `max_body_bytes` without
//! `body_inspection: stream` is not fully inspected.

use http::header::{CONTENT_TYPE, HeaderMap};

use crate::config::UploadInspection;
use crate::decoding::{
    MAX_MULTIPART_BOUNDARIES, MultipartPart, multipart_boundaries, multipart_parts,
};

/// Bytes searched for embedded server-side script markers. The leading bytes
/// are checked separately; the scan catches polyglots such as `GIF89a<?php`.
const SCRIPT_SCAN_BYTES: usize = 1024;

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
    "wsf", "hta", "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "jsp", "jspx",
    "asp", "aspx", "ashx", "asmx", "cgi", "pl", "py", "rb", "war", "jar",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DangerousKind {
    Executable,
    Script,
    ActiveWeb,
}

impl DangerousKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Script => "script",
            Self::ActiveWeb => "active-web",
        }
    }
}

#[derive(Debug)]
pub(crate) struct Rejection {
    pub(crate) filename: String,
    pub(crate) declared: Option<String>,
    pub(crate) kind: DangerousKind,
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
) -> Option<Rejection> {
    if mode == UploadInspection::Off || body.is_empty() {
        return None;
    }
    let content_type = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    if !is_multipart_media_type(content_type) {
        return None;
    }
    let boundaries = multipart_boundaries(content_type);
    if boundaries.is_empty() || boundaries.len() > MAX_MULTIPART_BOUNDARIES {
        return None;
    }

    for boundary in &boundaries {
        let Some(parts) = multipart_parts(body, boundary) else {
            continue;
        };
        for part in parts {
            let Some(rejection) = inspect_part(part, mode) else {
                continue;
            };
            return Some(rejection);
        }
    }
    None
}

fn inspect_part(part: MultipartPart<'_>, mode: UploadInspection) -> Option<Rejection> {
    let filename = part.filename()?;
    if part.value.is_empty() {
        return None;
    }
    let declared = part.declared_content_type();
    let claim = claim_for(declared.as_deref(), &filename);
    let kind = dangerous_content(part.value)?;
    blocks(mode, claim, kind).then_some(Rejection {
        filename,
        declared,
        kind,
    })
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
        if is_explicit_dangerous_media_type(media_type) {
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

fn blocks(mode: UploadInspection, claim: Claim, kind: DangerousKind) -> bool {
    match mode {
        UploadInspection::Off => false,
        UploadInspection::Mismatch => match claim {
            Claim::Safe => true,
            Claim::ActiveWeb => kind == DangerousKind::Executable,
            Claim::ExplicitDangerous | Claim::Generic => false,
        },
        UploadInspection::Strict => match kind {
            DangerousKind::Executable | DangerousKind::Script => true,
            DangerousKind::ActiveWeb => claim != Claim::ActiveWeb,
        },
    }
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
    {
        return Some(DangerousKind::Script);
    }
    if leading.starts_with(b"<") {
        return Some(DangerousKind::ActiveWeb);
    }
    if contains_script_marker(&value[..value.len().min(SCRIPT_SCAN_BYTES)]) {
        return Some(DangerousKind::Script);
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
    const MARKERS: &[&[u8]] = &[b"<?php", b"<?=", b"<%"];
    MARKERS.iter().copied().any(|marker| {
        bytes.len() >= marker.len()
            && bytes
                .windows(marker.len())
                .any(|window| window.eq_ignore_ascii_case(marker))
    })
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;

    use super::*;

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
