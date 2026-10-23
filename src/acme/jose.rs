//! Minimal JOSE support for ACME: ES256 JWS, JWK thumbprints, and account keys.

use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Serialize;

use super::AcmeError;
use super::base64;

const ALGORITHM: &ring::signature::EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

/// An ACME account key. ACME account keys are P-256 ECDSA keys and every
/// request is signed with ES256.
pub(crate) struct AccountKey {
    pair: EcdsaKeyPair,
}

impl AccountKey {
    pub(crate) fn generate() -> Result<(Self, Vec<u8>), AcmeError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(ALGORITHM, &rng).map_err(crypto)?;
        let key = Self::from_pkcs8(pkcs8.as_ref())?;
        Ok((key, pkcs8.as_ref().to_vec()))
    }

    pub(crate) fn from_pkcs8(der: &[u8]) -> Result<Self, AcmeError> {
        let pair = EcdsaKeyPair::from_pkcs8(ALGORITHM, der, &SystemRandom::new())
            .map_err(|err| AcmeError::Crypto(format!("{err:?}")))?;
        Ok(Self { pair })
    }

    /// Encode a JWS for an ACME request. `kid` is omitted for the new-account
    /// request, which uses the embedded JWK instead.
    pub(crate) fn sign_request(
        &self,
        kid: Option<&str>,
        nonce: &str,
        url: &str,
        payload: &str,
    ) -> Result<String, AcmeError> {
        let jwk = self.jwk();
        let protected = Protected {
            alg: "ES256",
            jwk: kid.is_none().then_some(&jwk),
            kid,
            nonce,
            url,
        };
        let protected =
            base64::encode_url(&serde_json::to_vec(&protected).map_err(AcmeError::Json)?);
        let encoded_payload = base64::encode_url(payload.as_bytes());
        let signing_input = format!("{protected}.{encoded_payload}");
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(crypto)?;
        let body = JwsBody {
            protected,
            payload: encoded_payload,
            signature: base64::encode_url(signature.as_ref()),
        };
        serde_json::to_string(&body).map_err(AcmeError::Json)
    }

    pub(crate) fn thumbprint(&self) -> Result<String, AcmeError> {
        let jwk = self.jwk();
        let thumbprint = JwkThumbprint {
            crv: "P-256",
            kty: "EC",
            x: &jwk.x,
            y: &jwk.y,
        };
        let encoded = serde_json::to_vec(&thumbprint).map_err(AcmeError::Json)?;
        Ok(base64::encode_url(digest(&SHA256, &encoded).as_ref()))
    }

    pub(crate) fn key_authorization_digest(&self, token: &str) -> Result<[u8; 32], AcmeError> {
        let key_authorization = format!("{token}.{}", self.thumbprint()?);
        let digest = digest(&SHA256, key_authorization.as_bytes());
        let mut output = [0u8; 32];
        output.copy_from_slice(digest.as_ref());
        Ok(output)
    }

    fn jwk(&self) -> Jwk {
        let (x, y) = public_coordinates(self.pair.public_key().as_ref());
        Jwk {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            use_: "sig",
            x: base64::encode_url(x),
            y: base64::encode_url(y),
        }
    }
}

fn public_coordinates(public_key: &[u8]) -> (&[u8], &[u8]) {
    // P-256 public keys are the uncompressed point 0x04 || x || y.
    let coordinates = public_key.get(1..).unwrap_or(&[]);
    coordinates.split_at(coordinates.len().min(32))
}

fn crypto(err: ring::error::Unspecified) -> AcmeError {
    AcmeError::Crypto(format!("{err:?}"))
}

#[derive(Serialize)]
struct JwsBody {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<&'a Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    x: String,
    y: String,
}

#[derive(Serialize)]
struct JwkThumbprint<'a> {
    crv: &'static str,
    kty: &'static str,
    x: &'a str,
    y: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn ec_jwk_thumbprint_vector() {
        let jwk = JwkThumbprint {
            crv: "P-256",
            kty: "EC",
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        };
        let encoded = serde_json::to_vec(&jwk).expect("json");
        assert_eq!(
            base64::encode_url(digest(&SHA256, &encoded).as_ref()),
            "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
        );
    }

    #[test]
    fn new_account_jws_embeds_the_jwk() {
        let (key, _) = AccountKey::generate().expect("key");
        let body = key
            .sign_request(None, "nonce", "https://example.com/new-account", "{}")
            .expect("jws");
        let body: Value = serde_json::from_str(&body).expect("json");
        let protected =
            base64::decode_url(body["protected"].as_str().expect("protected")).expect("base64");
        let protected: Value = serde_json::from_slice(&protected).expect("protected json");
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce");
        assert_eq!(protected["url"], "https://example.com/new-account");
        assert!(protected.get("kid").is_none());
        assert_eq!(protected["jwk"]["crv"], "P-256");
        assert_eq!(protected["jwk"]["kty"], "EC");
        assert_eq!(body["payload"], "e30");
        let signature =
            base64::decode_url(body["signature"].as_str().expect("signature")).expect("base64");
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn account_requests_use_kid_instead_of_jwk() {
        let (key, _) = AccountKey::generate().expect("key");
        let body = key
            .sign_request(
                Some("https://example.com/acct/1"),
                "nonce",
                "https://example.com/order",
                "",
            )
            .expect("jws");
        let body: Value = serde_json::from_str(&body).expect("json");
        let protected =
            base64::decode_url(body["protected"].as_str().expect("protected")).expect("base64");
        let protected: Value = serde_json::from_slice(&protected).expect("protected json");
        assert_eq!(protected["kid"], "https://example.com/acct/1");
        assert!(protected.get("jwk").is_none());
        assert_eq!(body["payload"], "");
    }

    #[test]
    fn key_authorization_matches_the_thumbprint() {
        let (key, _) = AccountKey::generate().expect("key");
        let key_authorization_digest = key.key_authorization_digest("token").expect("digest");
        let expected = digest(
            &SHA256,
            format!("token.{}", key.thumbprint().expect("thumbprint")).as_bytes(),
        );
        assert_eq!(key_authorization_digest.as_slice(), expected.as_ref());
    }
}
