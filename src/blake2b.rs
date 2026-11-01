//! BLAKE2b-512 for minisign's prehashed signature variant.
//!
//! `minisign -S` hashes the artifact with BLAKE2b-512 before signing (the `ED`
//! algorithm bytes), and `ring` does not expose that hash, so the small amount
//! needed here is implemented in-tree. It is only used to reconstruct the
//! digest that the signature covers; it is not a general-purpose hash API.
//!
//! The implementation follows RFC 7693 and is checked against the published
//! vectors in the tests below.

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const BLOCK_BYTES: usize = 128;

pub(crate) fn blake2b_512(input: &[u8]) -> [u8; 64] {
    let mut state = IV;
    // Parameter block for an unkeyed 64-byte digest: digest length, fanout 1,
    // depth 1.
    state[0] ^= 0x0101_0000 ^ 64;

    let mut counter: u128 = 0;
    let mut offset = 0;
    // Every block but the last is compressed as non-final; the last block
    // (which may be empty) carries the finalization flag.
    while input.len() - offset > BLOCK_BYTES {
        counter += BLOCK_BYTES as u128;
        compress(
            &mut state,
            input[offset..offset + BLOCK_BYTES]
                .try_into()
                .expect("block size"),
            counter,
            false,
        );
        offset += BLOCK_BYTES;
    }
    let rest = &input[offset..];
    let mut last = [0u8; BLOCK_BYTES];
    last[..rest.len()].copy_from_slice(rest);
    counter += rest.len() as u128;
    compress(&mut state, &last, counter, true);

    let mut digest = [0u8; 64];
    for (index, word) in state.iter().enumerate() {
        digest[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_BYTES], counter: u128, last: bool) {
    let mut message = [0u64; 16];
    for (index, word) in message.iter_mut().enumerate() {
        *word = u64::from_le_bytes(
            block[index * 8..index * 8 + 8]
                .try_into()
                .expect("word size"),
        );
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(state);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for round in &SIGMA {
        mix(&mut v, 0, 4, 8, 12, message[round[0]], message[round[1]]);
        mix(&mut v, 1, 5, 9, 13, message[round[2]], message[round[3]]);
        mix(&mut v, 2, 6, 10, 14, message[round[4]], message[round[5]]);
        mix(&mut v, 3, 7, 11, 15, message[round[6]], message[round[7]]);
        mix(&mut v, 0, 5, 10, 15, message[round[8]], message[round[9]]);
        mix(&mut v, 1, 6, 11, 12, message[round[10]], message[round[11]]);
        mix(&mut v, 2, 7, 8, 13, message[round[12]], message[round[13]]);
        mix(&mut v, 3, 4, 9, 14, message[round[14]], message[round[15]]);
    }

    for index in 0..8 {
        state[index] ^= v[index] ^ v[index + 8];
    }
}

#[allow(clippy::too_many_arguments)]
fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: [u8; 64]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn matches_published_vectors() {
        assert_eq!(
            hex(blake2b_512(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        assert_eq!(
            hex(blake2b_512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn hashes_block_boundaries_correctly() {
        let block: Vec<u8> = (0..128).map(|value| value as u8).collect();
        assert_eq!(
            hex(blake2b_512(&block)),
            "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e\
             8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115"
        );

        let mut longer = block.clone();
        longer.push(128);
        assert_eq!(
            hex(blake2b_512(&longer)),
            "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e\
             4418be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f"
        );

        assert_eq!(
            hex(blake2b_512(&[0u8; 1000])),
            "1ee4e51ecab5210a518f26150e882627ec839967f19d763e1508b12cfefed148\
             58f6a1c9d1f969bc224dc9440f5a6955277e755b9c513f9ba4421c5e50c8d787"
        );
    }
}
