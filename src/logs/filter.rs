use std::net::{IpAddr, SocketAddr};

use regex::Regex;

use crate::cidr::IpNet;
use crate::cli::LogArgs;
use crate::error::Error;

use super::attack::AttackFilter;
use super::parse::LogEntry;

#[derive(Debug, Clone)]
enum IpMatcher {
    Exact(IpAddr),
    Network(IpNet),
}

impl IpMatcher {
    fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("address must not be empty".to_owned());
        }
        if value.contains('/') {
            value
                .parse::<IpNet>()
                .map(Self::Network)
                .map_err(|_| "invalid CIDR range".to_owned())
        } else {
            value
                .parse::<IpAddr>()
                .map(Self::Exact)
                .map_err(|_| "invalid IP address".to_owned())
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        let address = normalize_ip(address);
        match self {
            Self::Exact(expected) => normalize_ip(*expected) == address,
            Self::Network(network) => network.contains(address),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Filters {
    ips: Vec<IpMatcher>,
    peer_ips: Vec<IpMatcher>,
    attacks: Vec<AttackFilter>,
    categories: Vec<String>,
    rules: Vec<String>,
    actions: Vec<String>,
    methods: Vec<String>,
    statuses: Vec<u16>,
    path: Option<Regex>,
}

impl Filters {
    pub(crate) fn from_args(args: &LogArgs) -> Result<Self, Error> {
        let mut filters = Self::default();
        for value in &args.ips {
            filters.ips.push(
                IpMatcher::parse(value)
                    .map_err(|err| Error::Message(format!("invalid --ip `{value}`: {err}")))?,
            );
        }
        for value in &args.peer_ips {
            filters
                .peer_ips
                .push(IpMatcher::parse(value).map_err(|err| {
                    Error::Message(format!("invalid --peer-ip `{value}`: {err}"))
                })?);
        }
        for value in &args.attacks {
            filters
                .attacks
                .push(AttackFilter::parse(value).map_err(Error::Message)?);
        }
        filters.categories = args
            .categories
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        filters.rules = args
            .rules
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();
        for value in &args.actions {
            let action = value.trim().to_ascii_uppercase();
            match action.as_str() {
                "BLOCK" | "LOG" => filters.actions.push(action),
                _ => {
                    return Err(Error::Message(format!(
                        "invalid --action `{value}`: use BLOCK or LOG (ALLOW matches are not logged)"
                    )));
                }
            }
        }
        filters.methods = args
            .methods
            .iter()
            .map(|value| value.trim().to_ascii_uppercase())
            .filter(|value| !value.is_empty())
            .collect();
        filters.statuses = args.statuses.clone();
        if let Some(path) = &args.path {
            filters.path = Some(Regex::new(path).map_err(|err| {
                Error::Message(format!("invalid --path regular expression: {err}"))
            })?);
        }
        Ok(filters)
    }

    pub(crate) fn active(&self) -> bool {
        !self.ips.is_empty()
            || !self.peer_ips.is_empty()
            || !self.attacks.is_empty()
            || !self.categories.is_empty()
            || !self.rules.is_empty()
            || !self.actions.is_empty()
            || !self.methods.is_empty()
            || !self.statuses.is_empty()
            || self.path.is_some()
    }

    pub(crate) fn matches(&self, entry: &LogEntry) -> bool {
        if !self.ips.is_empty() {
            let Some(address) = client_address(entry) else {
                return false;
            };
            if !self.ips.iter().any(|matcher| matcher.contains(address)) {
                return false;
            }
        }
        if !self.peer_ips.is_empty() {
            let Some(address) = entry.peer().and_then(parse_ip_value) else {
                return false;
            };
            if !self
                .peer_ips
                .iter()
                .any(|matcher| matcher.contains(address))
            {
                return false;
            }
        }
        if !self.attacks.is_empty() {
            let Some(category) = entry.category() else {
                return false;
            };
            if !self
                .attacks
                .iter()
                .any(|attack| attack.matches_category(category))
            {
                return false;
            }
        }
        if !self.categories.is_empty()
            && !entry.category().is_some_and(|category| {
                self.categories
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(category))
            })
        {
            return false;
        }
        if !self.rules.is_empty()
            && !entry.field("rule").is_some_and(|rule| {
                self.rules
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(rule))
            })
        {
            return false;
        }
        if !self.actions.is_empty()
            && !entry.action().is_some_and(|action| {
                self.actions
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(action))
            })
        {
            return false;
        }
        if !self.methods.is_empty()
            && !entry.field("method").is_some_and(|method| {
                self.methods
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(method))
            })
        {
            return false;
        }
        if !self.statuses.is_empty()
            && !entry
                .field("status")
                .and_then(|status| status.parse::<u16>().ok())
                .is_some_and(|status| self.statuses.contains(&status))
        {
            return false;
        }
        if let Some(path) = &self.path
            && !entry
                .field("path")
                .is_some_and(|value| path.is_match(value))
        {
            return false;
        }
        true
    }
}

fn client_address(entry: &LogEntry) -> Option<IpAddr> {
    entry
        .client()
        .and_then(parse_ip_value)
        .or_else(|| entry.peer().and_then(parse_ip_value))
}

fn parse_ip_value(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(normalize_ip(address));
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(normalize_ip(address.ip()));
    }
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    inner.parse::<IpAddr>().ok().map(normalize_ip)
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(address),
        },
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn entry(fields: &[(&str, &str)]) -> LogEntry {
        LogEntry {
            raw: String::new(),
            journal_timestamp: None,
            timestamp: None,
            level: None,
            target: None,
            message: String::new(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn filters(args: LogArgs) -> Filters {
        Filters::from_args(&args).expect("valid filters")
    }

    fn base_args() -> LogArgs {
        LogArgs {
            follow: false,
            lines: None,
            since: None,
            until: None,
            ips: Vec::new(),
            peer_ips: Vec::new(),
            attacks: Vec::new(),
            categories: Vec::new(),
            rules: Vec::new(),
            actions: Vec::new(),
            methods: Vec::new(),
            statuses: Vec::new(),
            path: None,
            format: crate::cli::LogOutputFormat::Raw,
            no_color: false,
            unit: "kunato".to_owned(),
            journalctl: "journalctl".to_owned(),
            list_attacks: false,
        }
    }

    #[test]
    fn ip_filters_match_client_and_cidr() {
        let mut args = base_args();
        args.ips = vec!["203.0.113.9".to_owned(), "10.0.0.0/8".to_owned()];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[("client", "203.0.113.9")])));
        assert!(filters.matches(&entry(&[("client", "10.1.2.3")])));
        assert!(!filters.matches(&entry(&[("client", "198.51.100.1")])));
        assert!(!filters.matches(&entry(&[("path", "/")])));
    }

    #[test]
    fn ip_filter_falls_back_to_peer() {
        let mut args = base_args();
        args.ips = vec!["2001:db8::1".to_owned()];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[("peer", "[2001:db8::1]:443")])));
        assert!(!filters.matches(&entry(&[("peer", "[2001:db8::2]:443")])));
    }

    #[test]
    fn peer_filter_matches_only_the_transport_peer() {
        let mut args = base_args();
        args.peer_ips = vec!["203.0.113.9".to_owned()];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[
            ("client", "198.51.100.7"),
            ("peer", "203.0.113.9:443"),
        ])));
        assert!(!filters.matches(&entry(&[
            ("client", "203.0.113.9"),
            ("peer", "198.51.100.7:443"),
        ])));
    }

    #[test]
    fn path_and_status_filters_use_recorded_fields() {
        let mut args = base_args();
        args.path = Some("^/search$".to_owned());
        args.statuses = vec![403];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[("path", "/search"), ("status", "403"),])));
        assert!(!filters.matches(&entry(&[("path", "/search"), ("status", "404"),])));
        assert!(!filters.matches(&entry(&[("path", "/search/other"), ("status", "403"),])));
    }

    #[test]
    fn filters_combine_with_and_semantics() {
        let mut args = base_args();
        args.attacks = vec!["sqli".to_owned()];
        args.actions = vec!["BLOCK".to_owned()];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[
            ("category", "sql-injection"),
            ("action", "BLOCK"),
        ])));
        assert!(!filters.matches(&entry(&[("category", "sql-injection"), ("action", "LOG"),])));
        assert!(!filters.matches(&entry(&[("category", "xss"), ("action", "BLOCK"),])));
    }

    #[test]
    fn cve_year_filter_matches_both_cve_category_shapes() {
        let mut args = base_args();
        args.attacks = vec!["cve-2026".to_owned()];
        let filters = filters(args);
        assert!(filters.matches(&entry(&[("category", "cve-2026-04-signatures")])));
        assert!(filters.matches(&entry(&[("category", "cve-2026-10-signatures")])));
        assert!(!filters.matches(&entry(&[("category", "cve-2025-signatures")])));
    }

    #[test]
    fn rejects_invalid_inputs() {
        let mut args = base_args();
        args.ips = vec!["not-an-ip".to_owned()];
        assert!(Filters::from_args(&args).is_err());

        let mut args = base_args();
        args.actions = vec!["ALLOW".to_owned()];
        assert!(Filters::from_args(&args).is_err());

        let mut args = base_args();
        args.path = Some("(".to_owned());
        assert!(Filters::from_args(&args).is_err());
    }
}
