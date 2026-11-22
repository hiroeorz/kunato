//! Embedded browser-facing error pages.
//!
//! Pages are generic: they never include the rejection reason, rule, country,
//! or host policy that produced them. Automated clients keep receiving the
//! existing plain-text response because HTML is selected only for an explicit
//! `text/html` Accept value.

use bytes::Bytes;
use http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderMap, HeaderValue,
};
use http::{Method, Response, StatusCode};

use crate::proxy::{ProxyBody, full_body};

/// Reserved path for the mascot used by the generated error pages.
pub const IMAGE_PATH: &str = "/__kunato/error.png";

const IMAGE: &[u8] = include_bytes!("../kunato-chan-200x200.png");

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{STATUS}} {{TITLE}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 2rem 1rem;
    background: #f5f7fb;
    color: #1f2937;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main {
    width: min(100%, 34rem);
    padding: 2rem 1.5rem;
    border: 1px solid #e0e6ef;
    border-radius: 1.25rem;
    background: #ffffff;
    box-shadow: 0 1.5rem 4rem rgba(31, 41, 55, 0.12);
    text-align: center;
  }
  img {
    display: block;
    width: 200px;
    height: 200px;
    margin: 0 auto 1rem;
    border-radius: 1rem;
    object-fit: cover;
  }
  .status {
    margin: 0;
    color: #d96b2b;
    font-size: clamp(4.5rem, 18vw, 8rem);
    font-weight: 800;
    letter-spacing: -0.06em;
    line-height: 0.9;
  }
  h1 {
    margin: 1rem 0 0.5rem;
    font-size: clamp(1.25rem, 4vw, 1.6rem);
  }
  .message {
    margin: 0;
    color: #5b6675;
    font-size: 1rem;
    line-height: 1.6;
  }
  .brand {
    margin: 1.75rem 0 0;
    padding-top: 1rem;
    border-top: 1px solid #edf0f4;
    color: #7b8794;
    font-size: 0.85rem;
    line-height: 1.5;
  }
  .brand a {
    color: #c65f25;
    font-weight: 700;
    text-decoration: none;
  }
  .brand a:hover { text-decoration: underline; }
  .brand span {
    display: block;
    margin-top: 0.2rem;
    font-size: 0.7rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #0f172a; color: #e2e8f0; }
    main { background: #111c2e; border-color: #243247; box-shadow: none; }
    .status { color: #f0a35a; }
    .message { color: #9aa8ba; }
    .brand { border-color: #243247; color: #8d9aab; }
    .brand a { color: #f0a35a; }
  }
</style>
</head>
<body>
<main>
  <img src="{{IMAGE_PATH}}" alt="Kunato-chan, the Kunato mascot">
  <p class="status">{{STATUS}}</p>
  <h1>{{TITLE}}</h1>
  <p class="message">{{MESSAGE}}</p>
  <p class="brand">
    Protected by <a href="https://github.com/hiroeorz/kunato" rel="noopener noreferrer">Kunato</a>
    <span>Personal WAF</span>
  </p>
</main>
</body>
</html>
"#;

/// Return true when the request is explicitly asking for an HTML page.
pub fn accepts_html(headers: &HeaderMap) -> bool {
    headers.get_all(ACCEPT).iter().any(|value| {
        let Ok(value) = value.to_str() else {
            return false;
        };
        value.split(',').any(|part| {
            let media = part.split(';').next().unwrap_or_default().trim();
            media.eq_ignore_ascii_case("text/html")
                || media.eq_ignore_ascii_case("application/xhtml+xml")
        })
    })
}

/// Whether a request targets the reserved mascot image.
pub fn is_image_request(method: &Method, path: &str) -> bool {
    (*method == Method::GET || *method == Method::HEAD) && path == IMAGE_PATH
}

/// Serve the embedded mascot image.
pub fn image_response() -> Response<ProxyBody> {
    let mut response = Response::new(full_body(Bytes::from_static(IMAGE)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

/// Build a generic HTML page for a status, or `None` when this status does not
/// have a themed WAF error page.
pub fn page(status: StatusCode) -> Option<Response<ProxyBody>> {
    let (title, message) = message(status)?;
    let body = PAGE
        .replace("{{IMAGE_PATH}}", IMAGE_PATH)
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{TITLE}}", title)
        .replace("{{MESSAGE}}", message);
    let mut response = Response::new(full_body(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Some(response)
}

fn message(status: StatusCode) -> Option<(&'static str, &'static str)> {
    match status {
        StatusCode::BAD_REQUEST => Some((
            "Bad request",
            "The request could not be understood. Please check the request and try again.",
        )),
        StatusCode::FORBIDDEN => Some((
            "Access denied",
            "You do not have permission to access this page.",
        )),
        StatusCode::NOT_FOUND => Some((
            "Page not found",
            "The page you requested could not be found.",
        )),
        StatusCode::PAYLOAD_TOO_LARGE => Some((
            "Request too large",
            "The request exceeds the size this site accepts.",
        )),
        StatusCode::MISDIRECTED_REQUEST => Some((
            "Misdirected request",
            "This request was sent to the wrong destination.",
        )),
        StatusCode::TOO_MANY_REQUESTS => {
            Some(("Too many requests", "Please wait a moment and try again."))
        }
        StatusCode::INTERNAL_SERVER_ERROR => Some((
            "Internal server error",
            "Something went wrong while handling this request.",
        )),
        StatusCode::BAD_GATEWAY => Some((
            "Bad gateway",
            "The upstream service did not return a valid response.",
        )),
        StatusCode::SERVICE_UNAVAILABLE => Some((
            "Service unavailable",
            "This service is temporarily unavailable. Please try again later.",
        )),
        StatusCode::GATEWAY_TIMEOUT => Some((
            "Gateway timeout",
            "The upstream service took too long to respond.",
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::BodyExt;
    use http::HeaderMap;
    use http::header::HeaderValue;

    #[test]
    fn accepts_only_explicit_html() {
        let mut headers = HeaderMap::new();
        assert!(!accepts_html(&headers));
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        assert!(!accepts_html(&headers));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml"),
        );
        assert!(accepts_html(&headers));
    }

    #[test]
    fn image_path_is_reserved_for_get_and_head() {
        assert!(is_image_request(&Method::GET, IMAGE_PATH));
        assert!(is_image_request(&Method::HEAD, IMAGE_PATH));
        assert!(!is_image_request(&Method::POST, IMAGE_PATH));
        assert!(!is_image_request(&Method::GET, "/other"));
    }

    #[tokio::test]
    async fn page_has_status_artwork_and_brand() {
        let response = page(StatusCode::NOT_FOUND).expect("page");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/html; charset=utf-8"
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("utf-8");
        assert!(body.contains(">404<"));
        assert!(body.contains(IMAGE_PATH));
        assert!(body.contains("Kunato"));
        assert!(body.contains("Personal WAF"));
        assert!(body.contains("Page not found"));
    }

    #[tokio::test]
    async fn image_is_an_embedded_png() {
        let response = image_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "image/png"
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n");
    }
}
