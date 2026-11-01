//! Trusted signing keys embedded in the binary.
//!
//! Release assets and the managed rule set are verified with detached minisign
//! signatures (see [`crate::signing`]). Keeping the keys in the binary rather
//! than next to the configuration means a local file cannot swap them.
//!
//! The lists are empty until signing keys have been generated and published;
//! an empty list makes verification *skip* with a warning so a build without
//! keys keeps updating rules. Once a key is listed, a missing or invalid
//! signature is a hard failure.

use crate::error::Error;
use crate::signing::{self, PublicKey};

/// Minisign public keys trusted for release assets (`install.sh`,
/// `SHA256SUMS`). Paste the full public key file text or its base64 payload.
pub const RELEASE_KEYS: &[&str] = &[];

/// Minisign public keys trusted for `dist/rules.yaml`.
pub const RULES_KEYS: &[&str] = &[];

/// Outcome of a signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// A trusted key signed the bytes.
    Verified,
    /// No key is configured for this purpose; the caller should warn once.
    NoTrustedKeys,
}

pub fn verify_release(message: &[u8], signature: &str) -> Result<Verification, Error> {
    verify(RELEASE_KEYS, message, signature)
}

pub fn verify_rules(message: &[u8], signature: &str) -> Result<Verification, Error> {
    verify(RULES_KEYS, message, signature)
}

/// Verify `message` against the keys in `keys`.
pub fn verify(keys: &[&str], message: &[u8], signature: &str) -> Result<Verification, Error> {
    if keys.is_empty() {
        return Ok(Verification::NoTrustedKeys);
    }
    let signature = signing::parse_signature(signature)?;
    for key in keys {
        let key = PublicKey::parse(key)?;
        if key.key_id() != signature.key_id() {
            continue;
        }
        if key.verify(message, &signature) {
            return Ok(Verification::Verified);
        }
        return Err(Error::Message(format!(
            "signature from key {} does not match the artifact",
            key.key_id_hex()
        )));
    }
    Err(Error::Message(format!(
        "artifact is signed by untrusted key {}",
        signature.key_id_hex()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64(bytes: &[u8]) -> String {
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(BASE64[((value >> (18 - index * 6)) & 0x3f) as usize] as char);
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key pair")
    }

    fn public_key_text(pair: &Ed25519KeyPair, key_id: [u8; 8]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"Ed");
        payload.extend_from_slice(&key_id);
        payload.extend_from_slice(pair.public_key().as_ref());
        base64(&payload)
    }

    fn signature_text(pair: &Ed25519KeyPair, key_id: [u8; 8], message: &[u8]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"Ed");
        payload.extend_from_slice(&key_id);
        payload.extend_from_slice(pair.sign(message).as_ref());
        format!("untrusted comment: signature\n{}\n", base64(&payload))
    }

    #[test]
    fn verifies_with_a_listed_key() {
        let pair = keypair();
        let id = [7u8; 8];
        let message = b"rules";
        let public_key = public_key_text(&pair, id);
        let signature = signature_text(&pair, id, message);
        assert_eq!(
            verify(&[public_key.as_str()], message, &signature).expect("verify"),
            Verification::Verified
        );
    }

    #[test]
    fn skips_when_no_key_is_configured() {
        assert_eq!(
            verify(&[], b"rules", "untrusted comment: none").expect("skip"),
            Verification::NoTrustedKeys
        );
    }

    #[test]
    fn rejects_an_untrusted_key_id_and_a_bad_signature() {
        let pair = keypair();
        let trusted = public_key_text(&pair, [1u8; 8]);
        let other = keypair();
        let untrusted_signature = signature_text(&other, [2u8; 8], b"rules");
        let error =
            verify(&[trusted.as_str()], b"rules", &untrusted_signature).expect_err("untrusted key");
        assert!(error.to_string().contains("untrusted key"), "{error}");

        let tampered = signature_text(&pair, [1u8; 8], b"other");
        let error = verify(&[trusted.as_str()], b"rules", &tampered).expect_err("bad signature");
        assert!(error.to_string().contains("does not match"), "{error}");
    }
}
