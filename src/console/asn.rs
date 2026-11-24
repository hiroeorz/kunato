//! Offline ASN lookup for the monitoring console.
//!
//! The embedded DB-IP ASN Lite database gives the BGP operator recorded for an
//! address. It is not a WHOIS replacement: it has no registrant, allocation
//! range, registration date, or abuse contact. An optional external MMDB (raw
//! or gzip) overrides the embedded copy so the data can be refreshed without a
//! new binary.

use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use flate2::read::GzDecoder;
use maxminddb::Reader;
use serde::Serialize;
use tracing::{info, warn};

const EMBEDDED_DATABASE: &[u8] = include_bytes!("../../data/dbip-asn-lite-2026-11.mmdb.gz");
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXTERNAL_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_BUILD_EPOCH: u64 = 946_684_800;
const MAX_BUILD_EPOCH: u64 = 4_102_444_800; // 2100-01-01
const MAX_NODE_COUNT: u32 = 10_000_000;
const MAX_ORGANIZATION_CHARS: usize = 160;

static EMBEDDED: OnceLock<Result<Arc<AsnDatabase>, String>> = OnceLock::new();

/// Where the loaded ASN database came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsnSource {
    Embedded,
    External,
}

impl AsnSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::External => "external",
        }
    }
}

impl fmt::Display for AsnSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The lookup outcome. `Unavailable` means the database itself could not be
/// loaded or read; `NoData` means the database is healthy but has no record for
/// this globally routable address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnState {
    Ok,
    NoData,
    NotGlobal,
    Unavailable,
}

/// A bounded, serializable ASN result for the console API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnLookup {
    pub state: AsnState,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub database: Option<String>,
    pub source: Option<&'static str>,
    pub built_at_ms: Option<u64>,
}

impl AsnLookup {
    fn bare(state: AsnState) -> Self {
        Self {
            state,
            asn: None,
            organization: None,
            database: None,
            source: None,
            built_at_ms: None,
        }
    }

    fn with_database(state: AsnState, database: &AsnDatabase) -> Self {
        Self {
            state,
            asn: None,
            organization: None,
            database: Some(database.database.clone()),
            source: Some(database.source.as_str()),
            built_at_ms: Some(database.build_epoch.saturating_mul(1000)),
        }
    }
}

struct AsnDatabase {
    reader: Reader<Vec<u8>>,
    source: AsnSource,
    database: String,
    build_epoch: u64,
    ip_version: u16,
}

/// Shared, read-only ASN lookup used by the console HTTP server.
#[derive(Clone)]
pub struct AsnDb {
    database: Option<Arc<AsnDatabase>>,
}

impl fmt::Debug for AsnDb {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsnDb")
            .field(
                "source",
                &self.database.as_ref().map(|db| db.source.as_str()),
            )
            .field(
                "database",
                &self.database.as_ref().map(|db| db.database.as_str()),
            )
            .finish()
    }
}

impl AsnDb {
    /// Load the configured external database, falling back to the embedded
    /// copy when it is absent or invalid. A broken ASN database must not stop
    /// the console: the endpoint reports `unavailable` instead.
    pub fn load(external: Option<&Path>) -> Self {
        if let Some(path) = external {
            match AsnDatabase::open_external(path) {
                Ok(database) => {
                    info!(
                        source = "external",
                        database = %database.database,
                        path = %path.display(),
                        "ASN database loaded"
                    );
                    return Self {
                        database: Some(Arc::new(database)),
                    };
                }
                Err(error) => warn!(
                    path = %path.display(),
                    error = %error,
                    "cannot load the external ASN database; using the embedded database"
                ),
            }
        }
        Self::embedded()
    }

    pub fn embedded() -> Self {
        match EMBEDDED.get_or_init(load_embedded) {
            Ok(database) => Self {
                database: Some(database.clone()),
            },
            Err(error) => {
                warn!(error = %error, "cannot load the embedded ASN database");
                Self { database: None }
            }
        }
    }

    pub fn available(&self) -> bool {
        self.database.is_some()
    }

    pub fn lookup(&self, address: IpAddr) -> AsnLookup {
        let address = canonical(address);
        if !is_global(address) {
            return AsnLookup::bare(AsnState::NotGlobal);
        }
        let Some(database) = &self.database else {
            return AsnLookup::bare(AsnState::Unavailable);
        };
        if matches!(address, IpAddr::V6(_)) && database.ip_version == 4 {
            return AsnLookup::with_database(AsnState::NoData, database);
        }
        let Ok(result) = database.reader.lookup(address) else {
            return AsnLookup::bare(AsnState::Unavailable);
        };
        let Ok(Some(asn)) = result.decode::<maxminddb::geoip2::Asn>() else {
            return AsnLookup::with_database(AsnState::NoData, database);
        };
        let Some(number) = asn.autonomous_system_number else {
            return AsnLookup::with_database(AsnState::NoData, database);
        };
        let organization = asn
            .autonomous_system_organization
            .and_then(clean_organization);
        AsnLookup {
            state: AsnState::Ok,
            asn: Some(number),
            organization,
            database: Some(database.database.clone()),
            source: Some(database.source.as_str()),
            built_at_ms: Some(database.build_epoch.saturating_mul(1000)),
        }
    }
}

impl AsnDatabase {
    fn open_external(path: &Path) -> Result<Self, String> {
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
            expand_gzip(&bytes)?
        } else {
            bytes
        };
        Self::from_bytes(bytes, AsnSource::External)
    }

    fn from_bytes(bytes: Vec<u8>, source: AsnSource) -> Result<Self, String> {
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(format!(
                "expanded ASN database is larger than the {} byte limit",
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
                "unsupported IP version {} in ASN database",
                metadata.ip_version
            ));
        }
        if metadata.node_count == 0 || metadata.node_count > MAX_NODE_COUNT {
            return Err(format!(
                "ASN database node count {} is outside the accepted range",
                metadata.node_count
            ));
        }
        if !matches!(metadata.record_size, 24 | 28 | 32) {
            return Err(format!(
                "unsupported MaxMind DB record size {}",
                metadata.record_size
            ));
        }
        if metadata.build_epoch < MIN_BUILD_EPOCH || metadata.build_epoch > MAX_BUILD_EPOCH {
            return Err(format!(
                "ASN database build time {} is implausible",
                metadata.build_epoch
            ));
        }
        let database_type = metadata.database_type.trim().to_ascii_lowercase();
        let is_dbip = database_type.starts_with("dbip-asn");
        let is_geolite = database_type.starts_with("geolite2-asn");
        if !(is_dbip || is_geolite) {
            return Err(format!(
                "unexpected ASN database type `{}`",
                metadata.database_type
            ));
        }
        if matches!(source, AsnSource::Embedded) && !is_dbip {
            return Err(format!(
                "embedded database has unexpected type `{}`",
                metadata.database_type
            ));
        }
        let sample_v4: IpAddr = "8.8.8.8".parse().map_err(|_| "invalid IPv4 sample")?;
        if asn_number(&reader, sample_v4).is_none() {
            return Err("ASN database does not expose autonomous_system_number".to_owned());
        }
        if metadata.ip_version == 6 {
            let sample_v6: IpAddr = "2606:4700:4700::1111"
                .parse()
                .map_err(|_| "invalid IPv6 sample")?;
            if asn_number(&reader, sample_v6).is_none() {
                return Err("ASN database does not resolve IPv6 addresses".to_owned());
            }
        }
        let build_epoch = metadata.build_epoch;
        let ip_version = metadata.ip_version;
        let database = if is_dbip {
            "DB-IP ASN Lite".to_owned()
        } else {
            "GeoLite2 ASN".to_owned()
        };
        Ok(Self {
            reader,
            source,
            database,
            build_epoch,
            ip_version,
        })
    }
}

fn load_embedded() -> Result<Arc<AsnDatabase>, String> {
    let bytes = expand_gzip(EMBEDDED_DATABASE)?;
    AsnDatabase::from_bytes(bytes, AsnSource::Embedded).map(Arc::new)
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
        .map_err(|error| format!("cannot decompress ASN database: {error}"))?;
    if expanded.len() > MAX_DATABASE_BYTES {
        return Err(format!(
            "expanded ASN database is larger than the {} byte limit",
            MAX_DATABASE_BYTES
        ));
    }
    Ok(expanded)
}

fn asn_number(reader: &Reader<Vec<u8>>, address: IpAddr) -> Option<u32> {
    reader
        .lookup(address)
        .ok()?
        .decode::<maxminddb::geoip2::Asn>()
        .ok()??
        .autonomous_system_number
}

fn clean_organization(value: &str) -> Option<String> {
    let flattened: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_ORGANIZATION_CHARS)
        .collect();
    let cleaned = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    (!cleaned.is_empty()).then_some(cleaned)
}

pub(crate) fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

pub(crate) fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_global_v4(value),
        IpAddr::V6(value) => is_global_v6(value),
    }
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(octets[0] == 0
        || octets[0] == 10
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..32).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224)
}

fn is_global_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xff00) == 0xff00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010)
        || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("IP")
    }

    #[test]
    fn embedded_database_resolves_known_sources() {
        let database = AsnDb::embedded();
        assert!(database.available());
        let google = database.lookup(ip("8.8.8.8"));
        assert_eq!(google.state, AsnState::Ok);
        assert_eq!(google.asn, Some(15169));
        assert!(
            google
                .organization
                .as_deref()
                .is_some_and(|value| value.contains("Google")),
            "{google:?}"
        );
        assert_eq!(google.source, Some("embedded"));
        assert_eq!(google.database.as_deref(), Some("DB-IP ASN Lite"));
        assert!(google.built_at_ms.is_some());

        let cloudflare = database.lookup(ip("2606:4700:4700::1111"));
        assert_eq!(cloudflare.state, AsnState::Ok);
        assert_eq!(cloudflare.asn, Some(13335));
    }

    #[test]
    fn non_global_addresses_are_not_looked_up() {
        let database = AsnDb::embedded();
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "203.0.113.9",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "::1",
        ] {
            assert_eq!(database.lookup(ip(raw)).state, AsnState::NotGlobal, "{raw}");
        }
        assert_eq!(database.lookup(ip("::ffff:8.8.8.8")).state, AsnState::Ok);
    }

    #[test]
    fn global_address_without_record_is_no_data() {
        let database = AsnDb::embedded();
        let lookup = database.lookup(ip("54.141.204.116"));
        assert_eq!(lookup.state, AsnState::NoData);
        assert_eq!(lookup.database.as_deref(), Some("DB-IP ASN Lite"));
        assert!(lookup.asn.is_none());
    }

    #[test]
    fn missing_database_reports_unavailable() {
        let database = AsnDb { database: None };
        assert_eq!(database.lookup(ip("8.8.8.8")).state, AsnState::Unavailable);
    }

    #[test]
    fn external_database_overrides_the_embedded_copy() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/dbip-asn-lite-2026-11.mmdb.gz");
        let database = AsnDb::load(Some(&path));
        assert!(database.available());
        let lookup = database.lookup(ip("8.8.8.8"));
        assert_eq!(lookup.state, AsnState::Ok);
        assert_eq!(lookup.source, Some("external"));
    }

    #[test]
    fn missing_or_invalid_external_database_falls_back() {
        let missing = AsnDb::load(Some(Path::new("/nonexistent/kunato-asn.mmdb")));
        assert!(missing.available());
        assert_eq!(missing.lookup(ip("8.8.8.8")).source, Some("embedded"));

        let temp = tempfile::tempdir().expect("tempdir");
        let invalid = temp.path().join("invalid.mmdb");
        std::fs::write(&invalid, b"not a database").expect("write");
        let fallback = AsnDb::load(Some(&invalid));
        assert_eq!(fallback.lookup(ip("8.8.8.8")).source, Some("embedded"));
    }

    #[test]
    fn asn_database_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AsnDb>();
    }

    #[test]
    fn organization_names_are_bounded_and_clean() {
        assert_eq!(
            clean_organization("  Google\nLLC  "),
            Some("Google LLC".to_owned())
        );
        assert_eq!(clean_organization(" \t\n "), None);
        assert_eq!(
            clean_organization(&"a".repeat(200)).map(|value| value.len()),
            Some(MAX_ORGANIZATION_CHARS)
        );
    }
}
