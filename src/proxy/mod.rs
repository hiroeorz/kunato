pub mod client;
pub mod forward;
pub mod server;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;
