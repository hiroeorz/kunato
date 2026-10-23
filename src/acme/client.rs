//! Minimal ACME (RFC 8555) client.
//!
//! The client speaks HTTPS through hyper-rustls, signs every state-changing
//! request with ES256, and only implements the pieces Kunato needs: account
//! registration, DNS identifier orders, TLS-ALPN-01 challenges, finalization,
//! and certificate download.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, warn};

use super::AcmeError;
use super::base64;
use super::jose::AccountKey;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INLINE_RETRY_AFTER: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RETRY_AFTER_SECS: u64 = 60;
const MAX_PROBLEM_CHARS: usize = 512;
const USER_AGENT_VALUE: &str = concat!("kunato/", env!("CARGO_PKG_VERSION"));

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin {
    host: String,
    port: u16,
}

impl Origin {
    fn parse(value: &str) -> Result<Self, AcmeError> {
        let uri: http::Uri = value
            .parse()
            .map_err(|_| AcmeError::Protocol("invalid ACME URL".to_owned()))?;
        Self::from_uri(&uri)
            .ok_or_else(|| AcmeError::Protocol("ACME URLs must use an https origin".to_owned()))
    }

    fn from_uri(uri: &http::Uri) -> Option<Self> {
        if uri.scheme_str() != Some("https") {
            return None;
        }
        let authority = uri.authority()?;
        if authority.as_str().contains('@') {
            return None;
        }
        Some(Self {
            host: uri.host()?.to_ascii_lowercase(),
            port: uri.port_u16().unwrap_or(443),
        })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            443 => write!(formatter, "https://{}", self.host),
            port => write!(formatter, "https://{}:{port}", self.host),
        }
    }
}

pub(crate) struct AcmeClient {
    http: HttpsClient,
    directory_url: String,
    directory_origin: Origin,
    allowed_origins: Vec<Origin>,
    directory: Option<Directory>,
    account_key: Arc<AccountKey>,
    kid: Option<String>,
    nonce: Option<String>,
    retry_after: Option<Duration>,
}

impl AcmeClient {
    pub(crate) fn new(
        directory_url: String,
        allowed_origins: &[String],
        account_key: Arc<AccountKey>,
    ) -> Result<Self, AcmeError> {
        let directory_origin = Origin::parse(&directory_url)?;
        let allowed_origins = allowed_origins
            .iter()
            .map(|origin| Origin::parse(origin))
            .collect::<Result<Vec<_>, _>>()?;
        let roots = native_roots();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| {
                AcmeError::Protocol(format!("failed to initialize ACME TLS client: {err}"))
            })?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            http,
            directory_url,
            directory_origin,
            allowed_origins,
            directory: None,
            account_key,
            kid: None,
            nonce: None,
            retry_after: None,
        })
    }

    pub(crate) fn account_key(&self) -> &AccountKey {
        &self.account_key
    }

    /// Return the delay requested by the most recent successful response.
    pub(crate) fn retry_after(&mut self) -> Option<Duration> {
        self.retry_after.take()
    }

    fn check_url(&self, url: &str) -> Result<(), AcmeError> {
        let uri: http::Uri = url
            .parse()
            .map_err(|_| AcmeError::Protocol("ACME response contains an invalid URL".to_owned()))?;
        let origin = Origin::from_uri(&uri).ok_or_else(|| {
            AcmeError::Protocol("ACME response URL is not an https origin".to_owned())
        })?;
        if origin == self.directory_origin || self.allowed_origins.contains(&origin) {
            return Ok(());
        }
        Err(AcmeError::Protocol(format!(
            "ACME response URL uses an unconfigured origin: {}",
            bounded_text(&origin.to_string())
        )))
    }

    pub(crate) async fn register_account(
        &mut self,
        contact: Option<&str>,
    ) -> Result<(), AcmeError> {
        let directory = self.directory().await?;
        let contact = contact.map(|contact| {
            if contact.starts_with("mailto:") {
                contact.to_owned()
            } else {
                format!("mailto:{contact}")
            }
        });
        let payload = match contact {
            Some(contact) => json!({
                "termsOfServiceAgreed": true,
                "contact": [contact],
            }),
            None => json!({
                "termsOfServiceAgreed": true,
            }),
        };
        let response = self
            .post_signed(&directory.new_account, Some(&payload), true, false)
            .await?;
        let location = response
            .location()
            .ok_or(AcmeError::MissingHeader("Location"))?;
        self.kid = Some(location);
        Ok(())
    }

    pub(crate) async fn new_order(
        &mut self,
        domains: &[String],
    ) -> Result<(String, Order), AcmeError> {
        let directory = self.directory().await?;
        let identifiers: Vec<Value> = domains
            .iter()
            .map(|domain| json!({ "type": "dns", "value": domain }))
            .collect();
        let payload = json!({ "identifiers": identifiers });
        let response = self
            .post_signed(&directory.new_order, Some(&payload), false, false)
            .await?;
        let location = response
            .location()
            .ok_or(AcmeError::MissingHeader("Location"))?;
        let order = serde_json::from_slice(&response.body).map_err(AcmeError::Json)?;
        Ok((location, order))
    }

    pub(crate) async fn authorization(&mut self, url: &str) -> Result<Auth, AcmeError> {
        let response = self.post_signed(url, None, false, true).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn trigger_challenge(&mut self, url: &str) -> Result<(), AcmeError> {
        self.post_signed(url, Some(&json!({})), false, true).await?;
        Ok(())
    }

    pub(crate) async fn order(&mut self, url: &str) -> Result<Order, AcmeError> {
        let response = self.post_signed(url, None, false, true).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn finalize(&mut self, url: &str, csr_der: &[u8]) -> Result<Order, AcmeError> {
        let payload = json!({ "csr": base64::encode_url(csr_der) });
        let response = self.post_signed(url, Some(&payload), false, false).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn certificate(&mut self, url: &str) -> Result<String, AcmeError> {
        let response = self.post_signed(url, None, false, true).await?;
        let text = String::from_utf8(response.body)
            .map_err(|_| AcmeError::Protocol("certificate response is not UTF-8".to_owned()))?;
        if !text.contains("-----BEGIN CERTIFICATE-----") {
            return Err(AcmeError::Protocol(
                "certificate response does not contain a PEM chain".to_owned(),
            ));
        }
        Ok(text)
    }

    async fn directory(&mut self) -> Result<Directory, AcmeError> {
        if let Some(directory) = &self.directory {
            return Ok(directory.clone());
        }
        let response = self
            .request(Method::GET, &self.directory_url, None, None)
            .await?;
        if !response.status.is_success() {
            return Err(response.into_api_error());
        }
        let directory: Directory =
            serde_json::from_slice(&response.body).map_err(AcmeError::Json)?;
        self.directory = Some(directory.clone());
        Ok(directory)
    }

    async fn post_signed(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        use_jwk: bool,
        retry_transient: bool,
    ) -> Result<Response, AcmeError> {
        let payload = match payload {
            Some(payload) => serde_json::to_string(payload).map_err(AcmeError::Json)?,
            None => String::new(),
        };
        let kid =
            match use_jwk {
                true => None,
                false => Some(self.kid.clone().ok_or_else(|| {
                    AcmeError::Protocol("ACME account is not registered".to_owned())
                })?),
            };

        let mut bad_nonce_retried = false;
        let mut transient_retries = if retry_transient { 2 } else { 0 };

        loop {
            let nonce = self.take_nonce().await?;
            let body = self
                .account_key
                .sign_request(kid.as_deref(), &nonce, url, &payload)?;
            let response = match self
                .request(
                    Method::POST,
                    url,
                    Some(&body),
                    Some("application/jose+json"),
                )
                .await
            {
                Ok(response) => response,
                Err(err) if transient_retries > 0 && err.is_transient() => {
                    transient_retries -= 1;
                    let delay = err
                        .retry_after()
                        .unwrap_or(Duration::from_millis(500))
                        .min(MAX_INLINE_RETRY_AFTER);
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(err) => return Err(err),
            };

            if let Some(nonce) = response.replay_nonce() {
                self.nonce = Some(nonce);
            }
            if response.status.is_success() {
                self.retry_after = response.retry_after();
                return Ok(response);
            }

            let bad_nonce = !bad_nonce_retried && response.is_bad_nonce();
            let error = response.into_api_error();
            if bad_nonce {
                bad_nonce_retried = true;
                debug!("ACME server rejected a nonce; retrying once");
                continue;
            }
            if transient_retries > 0 && error.is_transient() {
                transient_retries -= 1;
                let delay = error
                    .retry_after()
                    .unwrap_or(Duration::from_millis(500))
                    .min(MAX_INLINE_RETRY_AFTER);
                tokio::time::sleep(delay).await;
                continue;
            }
            self.retry_after = None;
            return Err(error);
        }
    }

    async fn take_nonce(&mut self) -> Result<String, AcmeError> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let directory = self.directory().await?;
        let response = self
            .request(Method::HEAD, &directory.new_nonce, None, None)
            .await?;
        if !response.status.is_success() {
            return Err(response.into_api_error());
        }
        response
            .replay_nonce()
            .ok_or(AcmeError::MissingHeader("Replay-Nonce"))
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<Response, AcmeError> {
        self.check_url(url)?;
        let mut builder = Request::builder()
            .method(method)
            .uri(url)
            .header(USER_AGENT, USER_AGENT_VALUE);
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        let body = Full::new(Bytes::from(body.unwrap_or_default().to_owned()));
        let request = builder
            .body(body)
            .map_err(|err| AcmeError::Http(err.to_string()))?;

        let response = tokio::time::timeout(HTTP_TIMEOUT, self.http.request(request))
            .await
            .map_err(|_| AcmeError::Timeout)?
            .map_err(|err| AcmeError::Http(err.to_string()))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = tokio::time::timeout(
            HTTP_TIMEOUT,
            read_body(response.into_body(), MAX_RESPONSE_BYTES),
        )
        .await
        .map_err(|_| AcmeError::Timeout)??;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

async fn read_body(mut body: Incoming, limit: usize) -> Result<Vec<u8>, AcmeError> {
    let mut output = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| AcmeError::Http(err.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if output.len() + data.len() > limit {
                return Err(AcmeError::Protocol("ACME response is too large".to_owned()));
            }
            output.extend_from_slice(data);
        }
    }
    Ok(output)
}

fn native_roots() -> rustls::RootCertStore {
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        debug!(
            errors = native.errors.len(),
            "failed to load some native CA certificates"
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        warn!(
            "no native CA certificates found; ACME directory requests will fail until a trust store is available"
        );
    }
    roots
}

struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Response {
    fn location(&self) -> Option<String> {
        self.header("location")
    }

    fn replay_nonce(&self) -> Option<String> {
        self.header("replay-nonce")
    }

    fn retry_after(&self) -> Option<Duration> {
        let value = self.header("retry-after")?;
        let seconds: u64 = value.trim().parse().ok()?;
        Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECS)))
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name)?.to_str().ok().map(str::to_owned)
    }

    fn is_bad_nonce(&self) -> bool {
        serde_json::from_slice::<Problem>(&self.body)
            .map(|problem| problem.is_bad_nonce())
            .unwrap_or(false)
    }

    fn into_api_error(self) -> AcmeError {
        let retry_after = self.retry_after();
        let detail = match serde_json::from_slice::<Problem>(&self.body) {
            Ok(problem) => problem.to_string(),
            Err(_) => {
                let text = bounded_text(&String::from_utf8_lossy(&self.body));
                let text: String = text.chars().take(256).collect();
                if text.is_empty() {
                    self.status
                        .canonical_reason()
                        .unwrap_or("ACME error")
                        .to_owned()
                } else {
                    text
                }
            }
        };
        AcmeError::Api {
            status: self.status.as_u16(),
            detail,
            retry_after,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Order {
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
    pub error: Option<Problem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Auth {
    pub status: AuthStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    pub error: Option<Problem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AuthStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Challenge {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub token: String,
    pub error: Option<Problem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Problem {
    #[serde(rename = "type")]
    kind: Option<String>,
    detail: Option<String>,
}

impl Problem {
    fn is_bad_nonce(&self) -> bool {
        self.kind.as_deref() == Some("urn:ietf:params:acme:error:badNonce")
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (
            self.kind.as_deref().map(bounded_text),
            self.detail.as_deref().map(bounded_text),
        ) {
            (Some(kind), Some(detail)) => write!(formatter, "{detail} ({kind})"),
            (Some(kind), None) => formatter.write_str(&kind),
            (None, Some(detail)) => formatter.write_str(&detail),
            (None, None) => formatter.write_str("ACME problem document"),
        }
    }
}

/// Bound and sanitize strings that come from the ACME server before they are
/// used in errors or logs.
pub(crate) fn bounded_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .take(MAX_PROBLEM_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn test_client(directory: &str, allowed: &[&str]) -> AcmeClient {
        let key = Arc::new(AccountKey::generate().expect("account key").0);
        let allowed: Vec<String> = allowed.iter().map(|origin| (*origin).to_owned()).collect();
        AcmeClient::new(directory.to_owned(), &allowed, key).expect("client")
    }

    #[test]
    fn constrains_acme_response_urls_to_configured_origins() {
        let client = test_client("https://ca.example/directory", &[]);
        assert!(client.check_url("https://ca.example/acme/order").is_ok());
        assert!(client.check_url("https://CA.EXAMPLE:443/order?x=1").is_ok());
        assert!(client.check_url("http://ca.example/order").is_err());
        assert!(client.check_url("https://evil.example/order").is_err());
        assert!(client.check_url("https://ca.example.evil/order").is_err());
        assert!(client.check_url("https://ca.example:8443/order").is_err());
        assert!(client.check_url("https://user@ca.example/order").is_err());
        let client = test_client(
            "https://ca.example/directory",
            &["https://cdn.example:8443"],
        );
        assert!(client.check_url("https://cdn.example:8443/cert").is_ok());
        assert!(client.check_url("https://cdn.example/cert").is_err());
    }

    fn response(headers: HeaderMap) -> Response {
        Response {
            status: http::StatusCode::OK,
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn detects_bad_nonce_problems() {
        let problem = Problem {
            kind: Some("urn:ietf:params:acme:error:badNonce".to_owned()),
            detail: None,
        };
        assert!(problem.is_bad_nonce());
        let other = Problem {
            kind: Some("urn:ietf:params:acme:error:malformed".to_owned()),
            detail: None,
        };
        assert!(!other.is_bad_nonce());
    }

    #[test]
    fn parses_retry_after_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", "30".parse().expect("header"));
        assert_eq!(
            response(headers).retry_after(),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn ignores_http_date_retry_after() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "retry-after",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().expect("header"),
        );
        assert_eq!(response(headers).retry_after(), None);
    }

    #[test]
    fn bounds_and_sanitizes_problem_text() {
        let problem = Problem {
            kind: Some("kind\nwith-newline".to_owned()),
            detail: Some("x".repeat(2_000)),
        };
        let text = problem.to_string();
        assert!(!text.contains('\n'));
        assert!(text.chars().count() < 1_100);
        assert_eq!(bounded_text("a\u{1b}[31m\tb"), "a[31m\tb");
    }
}
