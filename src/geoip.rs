use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use flate2::read::GzDecoder;
use maxminddb::{Reader, path};
use serde::Deserialize;

use crate::cidr::IpNet;

/// The release build always carries a country database. The database is
/// compressed in the repository and expanded once at runtime; the MMDB reader
/// remains immutable after construction.
const EMBEDDED_DATABASE: &[u8] = include_bytes!("../data/dbip-country-lite.mmdb.gz");
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXTERNAL_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_BUILD_EPOCH: u64 = 946_684_800;
// Keep implausible future timestamps from wrapping the human-readable label.
const MAX_BUILD_EPOCH: u64 = 4_102_444_800; // 2100-01-01
const MAX_NODE_COUNT: u32 = 10_000_000;

static EMBEDDED: OnceLock<Result<Arc<GeoIp>, String>> = OnceLock::new();

/// Two-letter ISO 3166-1 alpha-2 country code plus the `ZZ` unknown marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Parse a two-letter country code. Lowercase input is normalized so
    /// configuration files stay forgiving, but the stored value is uppercase.
    pub fn parse(raw: &str) -> Option<Self> {
        let bytes = raw.as_bytes();
        if bytes.len() != 2 {
            return None;
        }
        let first = bytes[0].to_ascii_uppercase();
        let second = bytes[1].to_ascii_uppercase();
        if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
            return None;
        }
        Some(Self([first, second]))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("ZZ")
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnknownCountryAction {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CountryPolicyAction {
    Block,
    Log,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountryPolicyDecision {
    Continue,
    Reject,
    Log,
}

#[derive(Debug)]
pub enum CountryPolicyMode {
    Only(Vec<CountryCode>),
    Block(Vec<CountryCode>),
}

/// A country admission filter. Unlike an ALLOW rule, a matching policy only
/// decides whether the request is rejected before inspection; an admitted
/// request still passes through every rule, log, and behavioral check.
#[derive(Debug)]
pub struct CountryPolicy {
    mode: CountryPolicyMode,
    unknown: UnknownCountryAction,
    action: CountryPolicyAction,
    exempt: Vec<IpNet>,
}

impl CountryPolicy {
    pub fn new(
        mode: CountryPolicyMode,
        unknown: UnknownCountryAction,
        action: CountryPolicyAction,
        exempt: Vec<IpNet>,
    ) -> Self {
        Self {
            mode,
            unknown,
            action,
            exempt,
        }
    }

    pub fn check(&self, address: IpAddr, country: Option<CountryCode>) -> CountryPolicyDecision {
        if self.exempt.iter().any(|network| network.contains(address)) {
            return CountryPolicyDecision::Continue;
        }
        let country = country.filter(|country| country.as_str() != "ZZ");
        let rejected = match (&self.mode, country) {
            (_, None) => self.unknown == UnknownCountryAction::Block,
            (CountryPolicyMode::Only(countries), Some(country)) => !countries.contains(&country),
            (CountryPolicyMode::Block(countries), Some(country)) => countries.contains(&country),
        };
        if !rejected {
            return CountryPolicyDecision::Continue;
        }
        match self.action {
            CountryPolicyAction::Block => CountryPolicyDecision::Reject,
            CountryPolicyAction::Log => CountryPolicyDecision::Log,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoIpSource {
    Embedded,
    External(PathBuf),
}

impl fmt::Display for GeoIpSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Embedded => formatter.write_str("embedded"),
            Self::External(path) => write!(formatter, "external:{}", path.display()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GeoIpInfo {
    pub source: GeoIpSource,
    pub database_type: String,
    pub build_epoch: u64,
    pub ip_version: u16,
    pub node_count: u32,
}

impl GeoIpInfo {
    /// Human-readable database age label used by startup logging.
    pub fn build_time_label(&self) -> String {
        let seconds = self.build_epoch;
        let days = seconds / 86_400;
        let (year, month, day) = civil_from_days(days as i64);
        format!("{year:04}-{month:02}-{day:02}")
    }
}

/// Read-only country lookup backed by a MaxMind DB file.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
    info: GeoIpInfo,
}

impl fmt::Debug for GeoIp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeoIp")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl GeoIp {
    /// Load the database embedded in the binary. The compressed database is
    /// expanded once per process and shared by every request.
    pub fn embedded() -> Result<Arc<Self>, String> {
        EMBEDDED
            .get_or_init(|| load_embedded().map(Arc::new))
            .clone()
    }

    /// Load an external MMDB, accepting either a raw MMDB file or a gzip
    /// compressed one. The file is bounded before it is read or expanded.
    pub fn open(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("cannot open `{}`: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!("`{}` is not a regular file", path.display()));
        }
        if metadata.len() > MAX_EXTERNAL_DATABASE_BYTES {
            return Err(format!(
                "`{}` is larger than the {} byte database limit",
                path.display(),
                MAX_EXTERNAL_DATABASE_BYTES
            ));
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
        let bytes = if is_gzip(&bytes) {
            expand_gzip(&bytes).map_err(|error| format!("`{}`: {error}", path.display()))?
        } else {
            bytes
        };
        Self::from_bytes(bytes, GeoIpSource::External(path.to_path_buf()))
    }

    pub fn lookup(&self, address: IpAddr) -> Option<CountryCode> {
        let result = self.reader.lookup(address).ok()?;
        let code: Option<&str> = result.decode_path(&path!["country", "iso_code"]).ok()?;
        CountryCode::parse(code?)
    }

    pub fn info(&self) -> &GeoIpInfo {
        &self.info
    }

    fn from_bytes(bytes: Vec<u8>, source: GeoIpSource) -> Result<Self, String> {
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(format!(
                "expanded database is larger than the {} byte limit",
                MAX_DATABASE_BYTES
            ));
        }
        let reader = Reader::from_source(bytes)
            .map_err(|error| format!("invalid MaxMind DB database: {error}"))?;
        let metadata = reader.metadata();
        if metadata.binary_format_major_version != 2 {
            return Err(format!(
                "unsupported MaxMind DB binary format version {}",
                metadata.binary_format_major_version
            ));
        }
        if metadata.ip_version != 4 && metadata.ip_version != 6 {
            return Err(format!(
                "unsupported IP version {} in country database",
                metadata.ip_version
            ));
        }
        if metadata.node_count == 0 || metadata.node_count > MAX_NODE_COUNT {
            return Err(format!(
                "country database node count {} is outside the accepted range",
                metadata.node_count
            ));
        }
        if !matches!(metadata.record_size, 24 | 28 | 32) {
            return Err(format!(
                "unsupported MaxMind DB record size {}",
                metadata.record_size
            ));
        }
        if metadata.database_type.trim().is_empty() {
            return Err("country database has no database_type".to_owned());
        }
        if metadata.build_epoch < MIN_BUILD_EPOCH || metadata.build_epoch > MAX_BUILD_EPOCH {
            return Err(format!(
                "country database build time {} is implausible",
                metadata.build_epoch
            ));
        }
        if matches!(source, GeoIpSource::Embedded)
            && !metadata.database_type.starts_with("DBIP-Country")
        {
            return Err(format!(
                "embedded database has unexpected type `{}`",
                metadata.database_type
            ));
        }

        let sample_v4: IpAddr = "8.8.8.8".parse().map_err(|_| "invalid IPv4 sample")?;
        if country_code(&reader, sample_v4).is_none() {
            return Err("country database does not expose country.iso_code".to_owned());
        }
        if metadata.ip_version == 6 {
            let sample_v6: IpAddr = "2001:4860:4860::8888"
                .parse()
                .map_err(|_| "invalid IPv6 sample")?;
            if country_code(&reader, sample_v6).is_none() {
                return Err("country database does not resolve IPv6 addresses".to_owned());
            }
        }

        let info = GeoIpInfo {
            source,
            database_type: metadata.database_type.clone(),
            build_epoch: metadata.build_epoch,
            ip_version: metadata.ip_version,
            node_count: metadata.node_count,
        };
        Ok(Self { reader, info })
    }
}

fn load_embedded() -> Result<GeoIp, String> {
    let bytes = expand_gzip(EMBEDDED_DATABASE)?;
    GeoIp::from_bytes(bytes, GeoIpSource::Embedded)
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

fn expand_gzip(compressed: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = GzDecoder::new(compressed);
    let mut expanded = Vec::new();
    decoder
        .take(MAX_DATABASE_BYTES as u64 + 1)
        .read_to_end(&mut expanded)
        .map_err(|error| format!("cannot decompress country database: {error}"))?;
    if expanded.len() > MAX_DATABASE_BYTES {
        return Err(format!(
            "expanded country database is larger than the {} byte limit",
            MAX_DATABASE_BYTES
        ));
    }
    Ok(expanded)
}

fn country_code(reader: &Reader<Vec<u8>>, address: IpAddr) -> Option<CountryCode> {
    let result = reader.lookup(address).ok()?;
    let code: Option<&str> = result.decode_path(&path!["country", "iso_code"]).ok()?;
    CountryCode::parse(code?)
}

/// Convert a Unix day count to a proleptic Gregorian date. This is only used
/// for human-readable build labels; it avoids pulling in a date dependency.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = y + i64::from(m <= 2);
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_codes_normalize_and_validate() {
        assert_eq!(CountryCode::parse("jp").expect("JP").as_str(), "JP");
        assert_eq!(CountryCode::parse("NO").expect("NO").as_str(), "NO");
        assert_eq!(CountryCode::parse("ZZ").expect("ZZ").as_str(), "ZZ");
        assert!(CountryCode::parse("").is_none());
        assert!(CountryCode::parse("J").is_none());
        assert!(CountryCode::parse("JPN").is_none());
        assert!(CountryCode::parse("1P").is_none());
        assert!(CountryCode::parse("J ").is_none());
    }

    #[test]
    fn embedded_database_loads_and_answers_ipv4_and_ipv6() {
        let database = GeoIp::embedded().expect("embedded database");
        assert_eq!(database.info().database_type, "DBIP-Country-Lite");
        assert_eq!(database.info().source, GeoIpSource::Embedded);
        assert!(!database.info().build_time_label().is_empty());

        let ipv4 = database
            .lookup("8.8.8.8".parse().expect("IPv4"))
            .expect("IPv4 country");
        assert_eq!(ipv4.as_str().len(), 2);

        let ipv6 = database
            .lookup("2001:4860:4860::8888".parse().expect("IPv6"))
            .expect("IPv6 country");
        assert_eq!(ipv6.as_str().len(), 2);

        assert!(
            database
                .lookup("10.0.0.1".parse().expect("private IPv4"))
                .is_none()
        );
    }

    #[test]
    fn external_gzip_database_is_accepted() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("country.mmdb.gz");
        std::fs::write(&path, EMBEDDED_DATABASE).expect("write database");
        let database = GeoIp::open(&path).expect("gzip database");
        assert_eq!(database.info().source, GeoIpSource::External(path.clone()));
        assert!(database.lookup("8.8.8.8".parse().expect("IPv4")).is_some());
    }

    #[test]
    fn malformed_external_database_is_rejected() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("country.mmdb");
        std::fs::write(&path, b"not a MaxMind database").expect("write database");
        let error = GeoIp::open(&path).expect_err("malformed database");
        assert!(error.contains("invalid MaxMind DB"), "{error}");
    }

    #[test]
    fn country_policy_allowlist_blocks_without_short_circuiting_rules() {
        let japan = CountryCode::parse("JP").expect("JP");
        let policy = CountryPolicy::new(
            CountryPolicyMode::Only(vec![japan]),
            UnknownCountryAction::Block,
            CountryPolicyAction::Block,
            vec!["203.0.113.10/32".parse().expect("CIDR")],
        );
        assert_eq!(
            policy.check("133.11.0.1".parse().expect("IP"), Some(japan)),
            CountryPolicyDecision::Continue
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), CountryCode::parse("US")),
            CountryPolicyDecision::Reject
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), None),
            CountryPolicyDecision::Reject
        );
        assert_eq!(
            policy.check(
                "203.0.113.10".parse().expect("IP"),
                CountryCode::parse("US")
            ),
            CountryPolicyDecision::Continue
        );
    }

    #[test]
    fn country_policy_blocklist_and_unknown_policy_are_explicit() {
        let north_korea = CountryCode::parse("KP").expect("KP");
        let policy = CountryPolicy::new(
            CountryPolicyMode::Block(vec![north_korea]),
            UnknownCountryAction::Allow,
            CountryPolicyAction::Block,
            Vec::new(),
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), CountryCode::parse("US")),
            CountryPolicyDecision::Continue
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), Some(north_korea)),
            CountryPolicyDecision::Reject
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), None),
            CountryPolicyDecision::Continue
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), CountryCode::parse("ZZ")),
            CountryPolicyDecision::Continue
        );
    }

    #[test]
    fn country_policy_log_mode_keeps_admitted_traffic_in_inspection() {
        let policy = CountryPolicy::new(
            CountryPolicyMode::Only(vec![CountryCode::parse("JP").expect("JP")]),
            UnknownCountryAction::Block,
            CountryPolicyAction::Log,
            Vec::new(),
        );
        assert_eq!(
            policy.check("8.8.8.8".parse().expect("IP"), CountryCode::parse("US")),
            CountryPolicyDecision::Log
        );
    }

    #[test]
    fn civil_date_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_727), (2026, 10, 1));
        assert_eq!(civil_from_days(20_758), (2026, 11, 1));
    }
}
