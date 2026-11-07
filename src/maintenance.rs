//! Maintenance mode: an in-memory switch that replaces proxied traffic with a
//! static maintenance page while the origin is unavailable or being upgraded.
//!
//! The switch is controlled through the loopback admin listener by
//! `kunato maintenance on` / `kunato maintenance off`, and it is independent of
//! the hot-reloaded configuration. It resets to off when the process restarts.

use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use http::{Response, StatusCode};

use crate::proxy::{ProxyBody, full_body};

/// Path of the artwork referenced by the maintenance page.
pub const IMAGE_PATH: &str = "/maintenance_in_progress.png";

const IMAGE: &[u8] = include_bytes!("../maintenance_in_progress.png");
const RETRY_AFTER_SECONDS: &str = "3600";

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Maintenance in progress</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1rem;
    background: #f5f7fb;
    color: #1f2937;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { width: min(100%, 56rem); text-align: center; }
  img {
    display: block;
    width: 100%;
    height: auto;
    border-radius: 1rem;
    box-shadow: 0 1rem 3rem rgba(15, 23, 42, 0.15);
  }
  h1 { margin: 2rem 0 0.75rem; font-size: clamp(1.5rem, 4vw, 2.25rem); }
  p { margin: 0; font-size: 1.05rem; line-height: 1.6; color: #4b5563; }
  @media (prefers-color-scheme: dark) {
    body { background: #0f172a; color: #e2e8f0; }
    p { color: #94a3b8; }
  }
</style>
</head>
<body>
<main>
<img src="/maintenance_in_progress.png" alt="Maintenance in progress">
<h1>Maintenance in progress</h1>
<p>This site is temporarily unavailable while it is being maintained. Please try again later.</p>
</main>
</body>
</html>
"#;

/// Process-wide maintenance switch.
#[derive(Debug, Default)]
pub struct MaintenanceState {
    enabled: AtomicBool,
}

impl MaintenanceState {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Set the switch and return the previous value.
    pub fn set(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::Relaxed)
    }
}

/// Build the maintenance response for `path`: the embedded artwork for its
/// reserved path, and the page for every other request.
pub fn response(path: &str) -> Response<ProxyBody> {
    if path == IMAGE_PATH {
        image_response()
    } else {
        page_response()
    }
}

fn page_response() -> Response<ProxyBody> {
    let mut response = Response::new(full_body(PAGE));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    response
}

fn image_response() -> Response<ProxyBody> {
    let mut response = Response::new(full_body(Bytes::from_static(IMAGE)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proxy::BodyExt;

    #[test]
    fn switch_starts_off_and_toggles() {
        let state = MaintenanceState::new();
        assert!(!state.enabled());
        assert!(!state.set(true));
        assert!(state.enabled());
        assert!(state.set(false));
        assert!(!state.enabled());
    }

    #[test]
    fn page_points_at_the_embedded_artwork() {
        assert!(PAGE.contains("src=\"/maintenance_in_progress.png\""));
    }

    #[tokio::test]
    async fn page_is_a_service_unavailable_html_response() {
        let response = response("/some/page");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(RETRY_AFTER).expect("retry after"),
            RETRY_AFTER_SECONDS
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert!(body.starts_with(b"<!doctype html>"));
        assert!(
            std::str::from_utf8(&body)
                .expect("utf-8")
                .contains(IMAGE_PATH)
        );
    }

    #[tokio::test]
    async fn artwork_path_serves_the_embedded_png() {
        let response = response(IMAGE_PATH);
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
        assert_eq!(body.len(), IMAGE.len());
    }
}
