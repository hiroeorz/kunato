use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};

pub const TOKEN_BYTES: usize = 169;
const DOMAIN: &[u8] = b"kunato/decoy/credential/v1\0";

pub struct Key(hmac::Key);

impl Key {
    pub fn generate() -> Result<Self, &'static str> {
        hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map(Self)
            .map_err(|_| "token entropy unavailable")
    }

    pub fn mint(&self, site: [u8; 16], now: u64, ttl: u64) -> Result<String, &'static str> {
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "nonce entropy unavailable")?;
        self.mint_with_nonce(site, now, ttl, nonce)
    }

    fn mint_with_nonce(
        &self,
        site: [u8; 16],
        now: u64,
        ttl: u64,
        nonce: [u8; 16],
    ) -> Result<String, &'static str> {
        let exp = now.checked_add(ttl).ok_or("token time overflow")?;
        let message = message(now, exp, &site, &nonce);
        let mac = hmac::sign(&self.0, &message);
        Ok(format!(
            "kdt1.{now:016x}.{exp:016x}.{}.{}.{}",
            hex(&site),
            hex(&nonce),
            hex(mac.as_ref())
        ))
    }

    pub fn verify(&self, token: &Parsed, site: [u8; 16], now: u64) -> Result<u64, Invalid> {
        if token.site != site {
            return Err(Invalid::Scope);
        }
        hmac::verify(
            &self.0,
            &message(token.iat, token.exp, &token.site, &token.nonce),
            &token.mac,
        )
        .map_err(|_| Invalid::Mac)?;
        if token.iat > now
            || token.exp <= token.iat
            || token.exp - token.iat > 86400
            || now >= token.exp
        {
            return Err(Invalid::Expired);
        }
        Ok(now - token.iat)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    Syntax,
    Mac,
    Expired,
    Scope,
}

pub struct Parsed {
    iat: u64,
    exp: u64,
    site: [u8; 16],
    nonce: [u8; 16],
    mac: [u8; 32],
}

impl Parsed {
    pub fn parse(raw: &[u8]) -> Result<Self, Invalid> {
        if raw.len() != TOKEN_BYTES
            || !raw.starts_with(b"kdt1.")
            || [21, 38, 71, 104].iter().any(|&i| raw[i] != b'.')
        {
            return Err(Invalid::Syntax);
        }
        Ok(Self {
            iat: u64::from_be_bytes(unhex(&raw[5..21])?),
            exp: u64::from_be_bytes(unhex(&raw[22..38])?),
            site: unhex(&raw[39..71])?,
            nonce: unhex(&raw[72..104])?,
            mac: unhex(&raw[105..169])?,
        })
    }
}

fn message(iat: u64, exp: u64, site: &[u8; 16], nonce: &[u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 48);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&iat.to_be_bytes());
    bytes.extend_from_slice(&exp.to_be_bytes());
    bytes.extend_from_slice(site);
    bytes.extend_from_slice(nonce);
    bytes
}

pub fn site_id(name: &str, origin: &str) -> [u8; 16] {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"kunato/decoy/site/v1\0");
    for value in [name, origin] {
        hash.update(&(value.len() as u16).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let hash = hash.finish();
    let mut id = [0; 16];
    id.copy_from_slice(&hash.as_ref()[..16]);
    id
}

pub fn id(raw: &[u8]) -> String {
    hex(&digest::digest(&digest::SHA256, raw).as_ref()[..16])
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn unhex<const N: usize>(raw: &[u8]) -> Result<[u8; N], Invalid> {
    if raw.len() != N * 2 {
        return Err(Invalid::Syntax);
    }
    let digit = |c| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Invalid::Syntax),
    };
    let mut out = [0; N];
    for (dest, pair) in out.iter_mut().zip(raw.as_chunks::<2>().0) {
        *dest = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_token_authenticates_all_fields_and_expires_at_boundary() {
        let key = Key(hmac::Key::new(hmac::HMAC_SHA256, &[42; 32]));
        let site = site_id("blog", "https://example.test");
        let raw = key.mint_with_nonce(site, 10, 60, [7; 16]).unwrap();
        assert_eq!(hex(&site), "c6643fdfd90d5540ab9c38eb95ee7f2a");
        assert_eq!(
            raw,
            concat!(
                "kdt1.000000000000000a.0000000000000046.",
                "c6643fdfd90d5540ab9c38eb95ee7f2a.07070707070707070707070707070707.",
                "55e22e7cbbeaf2ebecf62554ee4da28975e25bd2626bb9c5fef6ece780e40358"
            )
        );
        assert_eq!(raw.len(), TOKEN_BYTES);
        assert_eq!(
            key.verify(&Parsed::parse(raw.as_bytes()).unwrap(), site, 69),
            Ok(59)
        );
        assert_eq!(
            key.verify(&Parsed::parse(raw.as_bytes()).unwrap(), site, 70),
            Err(Invalid::Expired)
        );
        assert_eq!(
            key.verify(&Parsed::parse(raw.as_bytes()).unwrap(), [0; 16], 11),
            Err(Invalid::Scope)
        );
        assert_eq!(
            key.verify(&Parsed::parse(raw.as_bytes()).unwrap(), site, 9),
            Err(Invalid::Expired)
        );
        for index in 0..TOKEN_BYTES {
            let mut changed = raw.as_bytes().to_vec();
            changed[index] = if changed[index] == b'0' { b'1' } else { b'0' };
            if let Ok(parsed) = Parsed::parse(&changed) {
                assert!(key.verify(&parsed, site, 11).is_err(), "offset {index}");
            }
        }
    }

    #[test]
    fn minting_is_unique_and_process_keys_are_isolated() {
        let key = Key::generate().unwrap();
        let other = Key::generate().unwrap();
        let first = key.mint([1; 16], 0, 60).unwrap();
        assert_ne!(first, key.mint([1; 16], 0, 60).unwrap());
        assert_eq!(
            other.verify(&Parsed::parse(first.as_bytes()).unwrap(), [1; 16], 0),
            Err(Invalid::Mac)
        );
        for ttl in [0, 86401] {
            let raw = key.mint([1; 16], 0, ttl).unwrap();
            assert!(
                key.verify(&Parsed::parse(raw.as_bytes()).unwrap(), [1; 16], 0)
                    .is_err()
            );
        }
    }
}
