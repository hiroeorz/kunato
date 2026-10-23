//! Small base64 codec for ACME JWS (URL-safe, unpadded) and PEM (standard).

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode_url(input: &[u8]) -> String {
    encode(input, URL_ALPHABET, false)
}

pub(crate) fn encode_standard(input: &[u8]) -> String {
    encode(input, STANDARD_ALPHABET, true)
}

#[cfg(test)]
pub(crate) fn decode_url(input: &str) -> Option<Vec<u8>> {
    decode(input, URL_ALPHABET, false)
}

pub(crate) fn decode_standard(input: &str) -> Option<Vec<u8>> {
    decode(input, STANDARD_ALPHABET, true)
}

fn encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        out.push(alphabet[(first >> 2) as usize] as char);
        out.push(alphabet[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(third & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

fn decode(input: &str, alphabet: &[u8; 64], pad: bool) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }

    let mut padding = 0usize;
    let mut end = bytes.len();
    if pad {
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        while end > 0 && bytes[end - 1] == b'=' {
            padding += 1;
            end -= 1;
            if padding > 2 {
                return None;
            }
        }
        if padding > 0 && bytes.len() < 4 {
            return None;
        }
    } else if bytes.contains(&b'=') {
        return None;
    }

    let mut out = Vec::with_capacity(end * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &byte in &bytes[..end] {
        let value = decode_char(byte, alphabet)? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }

    if pad {
        let expected_padding = match end % 4 {
            2 => 2,
            3 => 1,
            _ => 0,
        };
        if padding != expected_padding {
            return None;
        }
    } else if accumulator != 0 {
        return None;
    }

    Some(out)
}

fn decode_char(byte: u8, alphabet: &[u8; 64]) -> Option<u8> {
    alphabet
        .iter()
        .position(|&candidate| candidate == byte)
        .map(|index| index as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_standard_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, encoded) in vectors {
            assert_eq!(encode_standard(input), *encoded);
            assert_eq!(decode_standard(encoded).as_deref(), Some(*input));
        }
    }

    #[test]
    fn url_safe_alphabet_has_no_padding() {
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode_url("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(decode_url("Zg=="), None);
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(decode_url("A"), None);
        assert_eq!(decode_url("A!"), None);
        assert_eq!(decode_url("AA"), Some(vec![0]));
        assert_eq!(decode_url("AB"), None);
        assert_eq!(decode_standard("Zg"), None);
        assert_eq!(decode_standard("Zg="), None);
        assert_eq!(decode_standard("Zg==="), None);
    }

    #[test]
    fn random_input_does_not_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let bytes = state.to_le_bytes();
            let input: String = bytes.iter().map(|byte| char::from(byte % 128)).collect();
            let _ = decode_standard(&input);
            let _ = decode_url(&input);
        }
    }

    #[test]
    fn round_trips_every_length() {
        for length in 0..64 {
            let input: Vec<u8> = (0..length).map(|index| (index * 37 + 11) as u8).collect();
            let encoded = encode_url(&input);
            assert_eq!(decode_url(&encoded).as_deref(), Some(input.as_slice()));
            let encoded = encode_standard(&input);
            assert_eq!(decode_standard(&encoded).as_deref(), Some(input.as_slice()));
        }
    }
}
