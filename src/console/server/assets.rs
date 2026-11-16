//! Embedded console web assets.
//!
//! The console ships the UI in the binary: no Node.js, build step, external
//! font, or network request is required at runtime.

pub const INDEX: &str = include_str!("../../../ui/console-web/index.html");
pub const LOGIN: &str = include_str!("../../../ui/console-web/login.html");
pub const APP_JS: &str = include_str!("../../../ui/console-web/app.js");
pub const LOGIN_JS: &str = include_str!("../../../ui/console-web/login.js");
pub const STYLES: &str = include_str!("../../../ui/console-web/styles.css");
pub const FAVICON: &str = include_str!("../../../ui/console-web/favicon.svg");
