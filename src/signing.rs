//! Detached minisign signatures for managed rules and release assets.
//!
//! Both variants minisign produces are accepted: plain Ed25519 over the file
//! (`Ed`) and the prehashed form (`ED`) that hashes the artifact with
//! BLAKE2b-512 first. `minisign -S` uses the prehashed form by default; the
//! digest is implemented in [`crate::blake2b`] because `ring` does not expose
//! it. The parser understands the textual `minisign` formats:

//! ```text
//! untrusted comment: minisign public key <id>
//! RWQ...base64(Ed || key id || 32-byte key)
//! ```
//!
//! ```text
//! untrusted comment: signature from minisign secret key
//! RWQ...base64(Ed || key id || 64-byte signature)
//! trusted comment: timestamp:... file:...
//! <base64(global signature)>
//! ```
//!
//! The trusted comment's global signature is not checked: it authenticates a
//! comment this module never consumes, while the file signature above is what
//! the caller relies on.

use ring::signature::{ED25519, UnparsedPublicKey};

use crate::error::Error;

/// Algorithm bytes of an Ed25519 signature over the whole file.
const ED25519_ALGORITHM: &[u8; 2] = b"Ed";
/// Algorithm bytes of an Ed25519 signature over the BLAKE2b-512 digest.
const ED25519_PREHASHED_ALGORITHM: &[u8; 2] = b"ED";
const PUBLIC_KEY_BYTES: usize = 2 + 8 + 32;
const SIGNATURE_BYTES: usize = 2 + 8 + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    key_id: [u8; 8],
    key: [u8; 32],
}

impl PublicKey {
    /// Parse a minisign public key file, or its bare base64 payload.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let payload = decode_payload(text, PUBLIC_KEY_BYTES).ok_or_else(|| {
            Error::Message("signing public key is not a minisign public key".to_owned())
        })?;
        if &payload[..2] != ED25519_ALGORITHM {
            return Err(Error::Message(
                "signing public key uses an algorithm this build does not verify".to_owned(),
            ));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&payload[2..10]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&payload[10..]);
        Ok(Self { key_id, key })
    }

    pub fn key_id(&self) -> [u8; 8] {
        self.key_id
    }

    /// The key id in the lowercase hex form minisign prints, for log messages.
    pub fn key_id_hex(&self) -> String {
        let mut id = String::with_capacity(16);
        for byte in self.key_id {
            id.push_str(&format!("{byte:02X}"));
        }
        id
    }

    /// Verify a signature over `message` produced by this key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if signature.key_id != self.key_id {
            return false;
        }
        let digest = signature
            .prehashed
            .then(|| crate::blake2b::blake2b_512(message));
        let signed = digest.as_ref().map_or(message, |digest| &digest[..]);
        UnparsedPublicKey::new(&ED25519, &self.key[..])
            .verify(signed, &signature.signature[..])
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    key_id: [u8; 8],
    signature: [u8; 64],
    /// The signature covers the BLAKE2b-512 digest instead of the bytes.
    prehashed: bool,
}

impl Signature {
    pub fn key_id(&self) -> [u8; 8] {
        self.key_id
    }

    pub fn key_id_hex(&self) -> String {
        let mut id = String::with_capacity(16);
        for byte in self.key_id {
            id.push_str(&format!("{byte:02X}"));
        }
        id
    }
}

/// Parse a detached minisign signature file.
pub fn parse_signature(text: &str) -> Result<Signature, Error> {
    let payload = decode_payload(text, SIGNATURE_BYTES)
        .ok_or_else(|| Error::Message("signature is not a minisign signature".to_owned()))?;
    let prehashed = if payload[..2] == *ED25519_ALGORITHM {
        false
    } else if payload[..2] == *ED25519_PREHASHED_ALGORITHM {
        true
    } else {
        return Err(Error::Message(
            "signature uses an algorithm this build does not verify".to_owned(),
        ));
    };
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&payload[2..10]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload[10..]);
    Ok(Signature {
        key_id,
        signature,
        prehashed,
    })
}

/// The first line that decodes to exactly `expected` bytes, skipping the
/// comment lines of the minisign text formats.
fn decode_payload(text: &str, expected: usize) -> Option<Vec<u8>> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("untrusted comment:")
            || line.starts_with("trusted comment:")
        {
            continue;
        }
        if let Some(decoded) = decode_base64(line)
            && decoded.len() == expected
        {
            return Some(decoded);
        }
    }
    None
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len().saturating_mul(3) / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const BASE64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64(bytes: &[u8]) -> String {
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    output.push(
                        BASE64_ALPHABET[((value >> (18 - index * 6)) & 0x3f) as usize] as char,
                    );
                } else {
                    output.push('=');
                }
            }
        }
        output
    }

    struct TestKey {
        pair: Ed25519KeyPair,
        key_id: [u8; 8],
    }

    fn test_key() -> TestKey {
        let pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map(|pkcs8| Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key pair"))
            .expect("generate key");
        TestKey {
            pair,
            key_id: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    fn public_key_text(key: &TestKey) -> String {
        let mut payload = Vec::with_capacity(PUBLIC_KEY_BYTES);
        payload.extend_from_slice(ED25519_ALGORITHM);
        payload.extend_from_slice(&key.key_id);
        payload.extend_from_slice(key.pair.public_key().as_ref());
        format!(
            "untrusted comment: minisign public key 0807060504030201\n{}\n",
            base64(&payload)
        )
    }

    fn signature_text(key: &TestKey, message: &[u8]) -> String {
        let mut payload = Vec::with_capacity(SIGNATURE_BYTES);
        payload.extend_from_slice(ED25519_ALGORITHM);
        payload.extend_from_slice(&key.key_id);
        payload.extend_from_slice(key.pair.sign(message).as_ref());
        format!(
            "untrusted comment: signature from minisign secret key\n{}\ntrusted comment: timestamp:0\n{}\n",
            base64(&payload),
            base64(&[0u8; 64])
        )
    }

    #[test]
    fn verifies_a_minisign_signature() {
        let key = test_key();
        let message = b"dist/rules.yaml";
        let public_key = PublicKey::parse(&public_key_text(&key)).expect("public key");
        let signature = parse_signature(&signature_text(&key, message)).expect("signature");
        assert_eq!(public_key.key_id(), key.key_id);
        assert_eq!(signature.key_id(), key.key_id);
        assert!(public_key.verify(message, &signature));
    }

    #[test]
    fn rejects_a_tampered_message_or_signature() {
        let key = test_key();
        let public_key = PublicKey::parse(&public_key_text(&key)).expect("public key");
        let signature = parse_signature(&signature_text(&key, b"rules")).expect("signature");
        assert!(!public_key.verify(b"rules ", &signature));

        let other = test_key();
        let other_key = PublicKey::parse(&public_key_text(&other)).expect("public key");
        assert!(!other_key.verify(b"rules", &signature));
    }

    #[test]
    fn accepts_prehashed_signatures_and_rejects_unknown_algorithms() {
        let key = test_key();
        let message = b"rules";
        let digest = crate::blake2b::blake2b_512(message);
        let mut payload = Vec::new();
        payload.extend_from_slice(b"ED");
        payload.extend_from_slice(&key.key_id);
        payload.extend_from_slice(key.pair.sign(&digest).as_ref());
        let text = format!("untrusted comment: x\n{}\n", base64(&payload));

        let public_key = PublicKey::parse(&public_key_text(&key)).expect("public key");
        let signature = parse_signature(&text).expect("prehashed signature");
        assert!(public_key.verify(message, &signature));
        assert!(!public_key.verify(b"other", &signature));

        let mut unknown = Vec::new();
        unknown.extend_from_slice(b"XX");
        unknown.extend_from_slice(&key.key_id);
        unknown.extend_from_slice(&[0u8; 64]);
        let text = format!("untrusted comment: x\n{}\n", base64(&unknown));
        assert!(parse_signature(&text).is_err());
    }

    #[test]
    fn verifies_a_real_minisign_signature() {
        // Produced by `minisign -G -W` and `minisign -S -W` (0.11) over
        // b"hello\n"; minisign signs the BLAKE2b-512 digest by default.
        let public_key = "untrusted comment: minisign public key 7CEB65AF8CBD8130\n\
                          RWQwgb2Mr2XrfDq1JYiM1C+oxuA1a5Qk1q368hPqDLJFUFPk/9e2ddMH";
        let signature = "untrusted comment: signature from minisign secret key\n\
                         RUQwgb2Mr2XrfMRPSR3kFI1dBAj87rJ2DoUvZk9BDYqki7krFPX2QpFwOybnl74br57PQl7opVVDRhgNyQxreWSPmVolFlN5uAs=";

        let key = PublicKey::parse(public_key).expect("public key");
        let signature = parse_signature(signature).expect("signature");
        assert!(key.verify(b"hello\n", &signature));
        assert!(!key.verify(b"hello", &signature));
        assert!(
            key.verify(b"hello\n", &signature),
            "verification is repeatable"
        );
    }

    #[test]
    fn rejects_garbage_and_mismatched_key_ids() {
        assert!(parse_signature("not a signature").is_err());
        assert!(PublicKey::parse("not a key").is_err());

        let key = test_key();
        let message = b"payload";
        let signature = parse_signature(&signature_text(&key, message)).expect("signature");

        let mut other = test_key();
        other.key_id = [9; 8];
        let public_key = PublicKey::parse(&public_key_text(&other)).expect("public key");
        assert!(!public_key.verify(message, &signature));
    }
}
