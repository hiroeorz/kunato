//! PEM encoding and decoding for certificate caches and ACME responses.

use super::base64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Block {
    pub label: String,
    pub der: Vec<u8>,
}

pub(crate) fn encode(label: &str, der: &[u8]) -> String {
    let encoded = base64::encode_standard(der);
    let mut out = String::with_capacity(encoded.len() + label.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

pub(crate) fn decode_blocks(input: &[u8]) -> Option<Vec<Block>> {
    let text = std::str::from_utf8(input).ok()?;
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|line| line.strip_suffix("-----"))
        {
            if current.is_some() {
                return None;
            }
            current = Some((label.to_owned(), String::new()));
        } else if let Some(label) = line
            .strip_prefix("-----END ")
            .and_then(|line| line.strip_suffix("-----"))
        {
            let (begin_label, encoded) = current.take()?;
            if begin_label != label {
                return None;
            }
            blocks.push(Block {
                label: begin_label,
                der: base64::decode_standard(&encoded)?,
            });
        } else if let Some((_, encoded)) = current.as_mut() {
            encoded.push_str(line);
        }
    }

    if current.is_some() {
        return None;
    }
    Some(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_block() {
        let encoded = encode("CERTIFICATE", &[0x30, 0x03, 0x02, 0x01, 0x01]);
        let blocks = decode_blocks(encoded.as_bytes()).expect("decode");
        assert_eq!(
            blocks,
            vec![Block {
                label: "CERTIFICATE".to_owned(),
                der: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            }]
        );
    }

    #[test]
    fn decodes_multiple_blocks_and_crlf() {
        let input = [
            encode("PRIVATE KEY", &[1, 2, 3]),
            encode("CERTIFICATE", &[4, 5, 6]),
        ]
        .concat()
        .replace('\n', "\r\n");
        let blocks = decode_blocks(input.as_bytes()).expect("decode");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "PRIVATE KEY");
        assert_eq!(blocks[0].der, vec![1, 2, 3]);
        assert_eq!(blocks[1].label, "CERTIFICATE");
        assert_eq!(blocks[1].der, vec![4, 5, 6]);
    }

    #[test]
    fn random_input_does_not_panic() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let bytes = state.to_le_bytes();
            let _ = decode_blocks(&bytes);
        }
    }

    #[test]
    fn rejects_malformed_blocks() {
        assert!(decode_blocks(b"-----BEGIN CERTIFICATE-----\nAA==\n").is_none());
        assert!(
            decode_blocks(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n")
                .is_none()
        );
        assert!(
            decode_blocks(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
                .is_none()
        );
    }
}
