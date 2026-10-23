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
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const USER_AGENT_VALUE: &str = concat!("kunato/", env!("CARGO_PKG_VERSION"));

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

pub(crate) struct AcmeClient {
    http: HttpsClient,
    directory_url: String,
    directory: Option<Directory>,
    account_key: Arc<AccountKey>,
    kid: Option<String>,
    nonce: Option<String>,
}

impl AcmeClient {
    pub(crate) fn new(
        directory_url: String,
        account_key: Arc<AccountKey>,
    ) -> Result<Self, AcmeError> {
        let roots = native_roots()?;
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
            directory: None,
            account_key,
            kid: None,
            nonce: None,
        })
    }

    pub(crate) fn account_key(&self) -> &AccountKey {
        &self.account_key
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
            .post_signed(&directory.new_account, Some(&payload), true)
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
            .post_signed(&directory.new_order, Some(&payload), false)
            .await?;
        let location = response
            .location()
            .ok_or(AcmeError::MissingHeader("Location"))?;
        let order = serde_json::from_slice(&response.body).map_err(AcmeError::Json)?;
        Ok((location, order))
    }

    pub(crate) async fn authorization(&mut self, url: &str) -> Result<Auth, AcmeError> {
        let response = self.post_signed(url, None, false).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn trigger_challenge(&mut self, url: &str) -> Result<(), AcmeError> {
        self.post_signed(url, Some(&json!({})), false).await?;
        Ok(())
    }

    pub(crate) async fn order(&mut self, url: &str) -> Result<Order, AcmeError> {
        let response = self.post_signed(url, None, false).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn finalize(&mut self, url: &str, csr_der: &[u8]) -> Result<Order, AcmeError> {
        let payload = json!({ "csr": base64::encode_url(csr_der) });
        let response = self.post_signed(url, Some(&payload), false).await?;
        serde_json::from_slice(&response.body).map_err(AcmeError::Json)
    }

    pub(crate) async fn certificate(&mut self, url: &str) -> Result<String, AcmeError> {
        let response = self.post_signed(url, None, false).await?;
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

        for attempt in 0..2 {
            let nonce = self.take_nonce().await?;
            let body = self
                .account_key
                .sign_request(kid.as_deref(), &nonce, url, &payload)?;
            let response = self
                .request(
                    Method::POST,
                    url,
                    Some(&body),
                    Some("application/jose+json"),
                )
                .await?;
            if let Some(nonce) = response.replay_nonce() {
                self.nonce = Some(nonce);
            }
            if response.status.is_success() {
                return Ok(response);
            }
            let retry = attempt == 0 && response.is_bad_nonce();
            let error = response.into_api_error();
            if !retry {
                return Err(error);
            }
            debug!("ACME server rejected a nonce; retrying once");
        }

        Err(AcmeError::Protocol("ACME nonce retry exhausted".to_owned()))
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
        let body = read_body(response.into_body(), MAX_RESPONSE_BYTES).await?;
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

fn native_roots() -> Result<rustls::RootCertStore, AcmeError> {
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
    Ok(roots)
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

    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name)?.to_str().ok().map(str::to_owned)
    }

    fn is_bad_nonce(&self) -> bool {
        serde_json::from_slice::<Problem>(&self.body)
            .map(|problem| problem.is_bad_nonce())
            .unwrap_or(false)
    }

    fn into_api_error(self) -> AcmeError {
        let detail = match serde_json::from_slice::<Problem>(&self.body) {
            Ok(problem) => problem.to_string(),
            Err(_) => {
                let text = String::from_utf8_lossy(&self.body);
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
        match (&self.kind, &self.detail) {
            (Some(kind), Some(detail)) => write!(formatter, "{detail} ({kind})"),
            (Some(kind), None) => formatter.write_str(kind),
            (None, Some(detail)) => formatter.write_str(detail),
            (None, None) => formatter.write_str("ACME problem document"),
        }
    }
}
