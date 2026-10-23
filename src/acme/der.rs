//! Minimal DER encoding for ACME certificates and CSRs.
//!
//! Only the structures needed by RFC 8555 / RFC 8737 are encoded: a PKCS#10
//! certification request with a subjectAltName extension and a self-signed
//! TLS-ALPN-01 certificate. The decoder is deliberately narrow and only reads
//! the validity window from a certificate issued by the CA.

use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

use super::AcmeError;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0_CONSTRUCTED: u8 = 0xa0;
const TAG_CONTEXT_2_PRIMITIVE: u8 = 0x82;
const TAG_CONTEXT_3_CONSTRUCTED: u8 = 0xa3;

const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];
const OID_SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
const OID_EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_ACME_IDENTIFIER: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

pub(crate) struct CsrMaterial {
    pub der: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
}

pub(crate) struct ChallengeCert {
    pub cert_der: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Validity {
    pub not_before: u64,
    pub not_after: u64,
}

pub(crate) fn generate_csr(domains: &[String]) -> Result<CsrMaterial, AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::Protocol(
            "a certificate order needs at least one domain".to_owned(),
        ));
    }

    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(crypto)?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|err| AcmeError::Crypto(format!("{err:?}")))?;

    let public_key = key.public_key().as_ref();
    let spki = subject_public_key_info(public_key);
    let san = subject_alt_name_extension(domains);
    let attributes = extension_request(&[san]);
    let request_info = seq(&[integer_u64(0), seq(&[]), spki, attributes]);
    let signature = key.sign(&rng, &request_info).map_err(crypto)?;
    let der = seq(&[
        request_info,
        ecdsa_with_sha256(),
        bit_string(signature.as_ref(), 0),
    ]);

    Ok(CsrMaterial {
        der,
        key_pkcs8: pkcs8.as_ref().to_vec(),
    })
}

pub(crate) fn generate_challenge_cert(
    domain: &str,
    key_authorization_digest: &[u8; 32],
) -> Result<ChallengeCert, AcmeError> {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(crypto)?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|err| AcmeError::Crypto(format!("{err:?}")))?;

    let now = unix_now();
    let name = name(domain);
    let validity = seq(&[
        utc_time(now.saturating_sub(3600)),
        utc_time(now.saturating_add(86_400)),
    ]);
    let san = subject_alt_name_extension(&[domain.to_owned()]);
    let acme_identifier = seq(&[
        oid(OID_ACME_IDENTIFIER),
        boolean(true),
        octet_string(&octet_string(key_authorization_digest)),
    ]);
    let extensions = tlv(TAG_CONTEXT_3_CONSTRUCTED, &seq(&[san, acme_identifier]));

    let tbs = seq(&[
        tlv(TAG_CONTEXT_0_CONSTRUCTED, &integer_u64(2)),
        integer(&random_serial(&rng)?),
        ecdsa_with_sha256(),
        name.clone(),
        validity,
        name,
        subject_public_key_info(key.public_key().as_ref()),
        extensions,
    ]);
    let signature = key.sign(&rng, &tbs).map_err(crypto)?;
    let cert_der = seq(&[tbs, ecdsa_with_sha256(), bit_string(signature.as_ref(), 0)]);

    Ok(ChallengeCert {
        cert_der,
        key_pkcs8: pkcs8.as_ref().to_vec(),
    })
}

pub(crate) fn certificate_validity(cert_der: &[u8]) -> Result<Validity, AcmeError> {
    let mut input = cert_der;
    let (tag, certificate) = take(&mut input)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("certificate is not a SEQUENCE"));
    }

    let mut input = certificate;
    let (tag, tbs) = take(&mut input)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("tbsCertificate is not a SEQUENCE"));
    }

    let mut tbs = tbs;
    if tbs.first() == Some(&TAG_CONTEXT_0_CONSTRUCTED) {
        let _version = take(&mut tbs)?;
    }
    let _serial = take(&mut tbs)?;
    let _signature = take(&mut tbs)?;
    let _issuer = take(&mut tbs)?;
    let (tag, validity) = take(&mut tbs)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("validity is not a SEQUENCE"));
    }

    let mut validity = validity;
    let (tag, not_before) = take(&mut validity)?;
    let not_before = parse_time(tag, not_before)?;
    let (tag, not_after) = take(&mut validity)?;
    let not_after = parse_time(tag, not_after)?;
    if not_after < not_before {
        return Err(invalid("certificate validity is inverted"));
    }

    Ok(Validity {
        not_before,
        not_after,
    })
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn subject_public_key_info(public_key: &[u8]) -> Vec<u8> {
    let algorithm = seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_PRIME256V1)]);
    seq(&[algorithm, bit_string(public_key, 0)])
}

fn subject_alt_name_extension(domains: &[String]) -> Vec<u8> {
    let names: Vec<Vec<u8>> = domains
        .iter()
        .map(|domain| tlv(TAG_CONTEXT_2_PRIMITIVE, domain.as_bytes()))
        .collect();
    seq(&[oid(OID_SUBJECT_ALT_NAME), octet_string(&seq(&names))])
}

fn extension_request(extensions: &[Vec<u8>]) -> Vec<u8> {
    let extensions = seq(extensions);
    let attribute = seq(&[oid(OID_EXTENSION_REQUEST), set(&[extensions])]);
    tlv(TAG_CONTEXT_0_CONSTRUCTED, &attribute)
}

fn name(domain: &str) -> Vec<u8> {
    let attribute = seq(&[oid(OID_COMMON_NAME), utf8_string(domain)]);
    seq(&[set(&[attribute])])
}

fn ecdsa_with_sha256() -> Vec<u8> {
    seq(&[oid(OID_ECDSA_WITH_SHA256)])
}

fn random_serial(rng: &SystemRandom) -> Result<Vec<u8>, AcmeError> {
    let mut serial = [0u8; 16];
    rng.fill(&mut serial).map_err(crypto)?;
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[15] = 1;
    }
    Ok(serial.to_vec())
}

fn crypto(err: ring::error::Unspecified) -> AcmeError {
    AcmeError::Crypto(format!("{err:?}"))
}

fn invalid(message: &'static str) -> AcmeError {
    AcmeError::Protocol(message.to_owned())
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    tlv(TAG_SEQUENCE, &content)
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for part in parts {
        content.extend_from_slice(part);
    }
    tlv(TAG_SET, &content)
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    if let [first, second, rest @ ..] = arcs {
        encode_base128(&mut content, first * 40 + second);
        for arc in rest {
            encode_base128(&mut content, *arc);
        }
    }
    tlv(TAG_OID, &content)
}

fn encode_base128(out: &mut Vec<u8>, mut value: u64) {
    let mut buffer = [0u8; 10];
    let mut index = buffer.len() - 1;
    buffer[index] = (value & 0x7f) as u8;
    value >>= 7;
    while value > 0 {
        index -= 1;
        buffer[index] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }
    out.extend_from_slice(&buffer[index..]);
}

fn integer(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let value = &value[first..];
    if value.is_empty() {
        return tlv(TAG_INTEGER, &[0]);
    }
    if value[0] & 0x80 != 0 {
        let mut content = Vec::with_capacity(value.len() + 1);
        content.push(0);
        content.extend_from_slice(value);
        tlv(TAG_INTEGER, &content)
    } else {
        tlv(TAG_INTEGER, value)
    }
}

fn integer_u64(value: u64) -> Vec<u8> {
    integer(&value.to_be_bytes())
}

fn boolean(value: bool) -> Vec<u8> {
    // DER requires TRUE to be 0xFF, not 0x01.
    tlv(TAG_BOOLEAN, &[if value { 0xff } else { 0x00 }])
}

fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, value)
}

fn bit_string(value: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut content = Vec::with_capacity(value.len() + 1);
    content.push(unused_bits);
    content.extend_from_slice(value);
    tlv(TAG_BIT_STRING, &content)
}

fn utf8_string(value: &str) -> Vec<u8> {
    tlv(TAG_UTF8_STRING, value.as_bytes())
}

fn utc_time(timestamp: u64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = utc_parts(timestamp);
    if (1950..=2049).contains(&year) {
        let text = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year % 100,
            month,
            day,
            hour,
            minute,
            second
        );
        tlv(TAG_UTC_TIME, text.as_bytes())
    } else {
        let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        tlv(TAG_GENERALIZED_TIME, text.as_bytes())
    }
}

fn utc_parts(timestamp: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (timestamp / 86_400) as i64;
    let seconds = (timestamp % 86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60,
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month_prime = if month > 2 { month - 3 } else { month + 9 } as u64;
    let day_of_year = (153 * month_prime + 2) / 5 + day as u64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

fn parse_time(tag: u8, content: &[u8]) -> Result<u64, AcmeError> {
    let (year, rest) = match tag {
        TAG_UTC_TIME if content.len() == 13 => {
            let year = digits(&content[0..2])? as i64;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            (year, &content[2..])
        }
        TAG_GENERALIZED_TIME if content.len() == 15 => {
            (digits(&content[0..4])? as i64, &content[4..])
        }
        TAG_UTC_TIME | TAG_GENERALIZED_TIME => {
            return Err(invalid("unsupported certificate time encoding"));
        }
        _ => return Err(invalid("certificate validity is not a time")),
    };

    if rest.last() != Some(&b'Z') {
        return Err(invalid("certificate time is not UTC"));
    }
    let rest = &rest[..rest.len() - 1];
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let minute = digits(&rest[6..8])?;
    let second = digits(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(invalid("certificate time is out of range"));
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(hour as i64 * 3_600))
        .and_then(|seconds| seconds.checked_add(minute as i64 * 60))
        .and_then(|seconds| seconds.checked_add(second as i64))
        .ok_or_else(|| invalid("certificate time is out of range"))?;
    u64::try_from(seconds).map_err(|_| invalid("certificate time is negative"))
}

fn digits(bytes: &[u8]) -> Result<u32, AcmeError> {
    let mut value = 0u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(invalid("certificate time contains a non-digit"));
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Ok(value)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    write_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn write_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let bytes = &bytes[first..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn take<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8]), AcmeError> {
    if input.len() < 2 {
        return Err(invalid("truncated DER value"));
    }
    let tag = input[0];
    let (length, header) = read_length(&input[1..])?;
    let start = 1 + header;
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("DER length overflow"))?;
    if end > input.len() {
        return Err(invalid("truncated DER value"));
    }
    let content = &input[start..end];
    *input = &input[end..];
    Ok((tag, content))
}

fn read_length(input: &[u8]) -> Result<(usize, usize), AcmeError> {
    let first = *input
        .first()
        .ok_or_else(|| invalid("truncated DER length"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    if first == 0x80 {
        return Err(invalid("indefinite DER length is not allowed"));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || input.len() < 1 + count {
        return Err(invalid("invalid DER length"));
    }
    let mut length = 0usize;
    for byte in &input[1..=count] {
        length = length
            .checked_shl(8)
            .and_then(|length| length.checked_add(*byte as usize))
            .ok_or_else(|| invalid("DER length overflow"))?;
    }
    Ok((length, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_encoding_matches_rfc_vectors() {
        assert_eq!(
            oid(&[1, 3, 6, 1, 5, 5, 7, 1, 31]),
            vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f]
        );
        assert_eq!(oid(&[2, 5, 29, 17]), vec![0x06, 0x03, 0x55, 0x1d, 0x11]);
    }

    #[test]
    fn time_round_trips() {
        let timestamp = 1_792_713_600;
        let encoded = utc_time(timestamp);
        assert_eq!(encoded[0], TAG_UTC_TIME);
        assert_eq!(
            parse_time(TAG_UTC_TIME, &encoded[2..]).expect("parse"),
            timestamp
        );
    }

    #[test]
    fn length_encoding_handles_long_forms() {
        assert_eq!(tlv(0x04, &[0; 127])[1], 127);
        assert_eq!(&tlv(0x04, &[0; 128])[1..3], &[0x81, 0x80]);
        assert_eq!(&tlv(0x04, &[0; 256])[1..4], &[0x82, 0x01, 0x00]);
    }

    #[test]
    fn csr_parses_with_rcgen() {
        let csr = generate_csr(&["example.com".to_owned(), "www.example.com".to_owned()])
            .expect("generate CSR");
        let der = rustls::pki_types::CertificateSigningRequestDer::from(csr.der.clone());
        let parsed = rcgen::CertificateSigningRequestParams::from_der(&der).expect("parse CSR");
        assert_eq!(parsed.params.subject_alt_names.len(), 2);
    }

    #[test]
    fn acme_extension_uses_der_true_for_critical() {
        let challenge = generate_challenge_cert("example.com", &[7u8; 32]).expect("challenge cert");
        let acme_oid = oid(OID_ACME_IDENTIFIER);
        let position = challenge
            .cert_der
            .windows(acme_oid.len())
            .position(|window| window == acme_oid.as_slice())
            .expect("acmeIdentifier OID");
        let after = &challenge.cert_der[position + acme_oid.len()..];
        assert_eq!(&after[..3], &[TAG_BOOLEAN, 0x01, 0xff]);
    }

    #[test]
    fn generalized_time_round_trips() {
        let timestamp = 2_524_608_000;
        let encoded = utc_time(timestamp);
        assert_eq!(encoded[0], TAG_GENERALIZED_TIME);
        assert_eq!(
            parse_time(TAG_GENERALIZED_TIME, &encoded[2..]).expect("parse"),
            timestamp
        );
    }

    #[test]
    fn challenge_cert_parses_as_x509() {
        let challenge = generate_challenge_cert("example.com", &[7u8; 32]).expect("challenge cert");
        let (tag, _) = take(&mut challenge.cert_der.as_slice()).expect("certificate");
        assert_eq!(tag, TAG_SEQUENCE);
    }

    #[test]
    fn parses_rcgen_certificate_validity() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let validity = certificate_validity(certified.cert.der()).expect("validity");
        assert!(validity.not_after > validity.not_before);
        assert!(validity.not_after > unix_now());
    }
}
