use std::net::{IpAddr, SocketAddr};

use http::header::{HeaderMap, HeaderName};
use ipnet::IpNet;

use crate::protection::normalize_ip;

const MAX_HEADER_BYTES: usize = 4096;
const MAX_HOPS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct ClientSource {
    pub peer: SocketAddr,
    pub client_ip: IpAddr,
}

impl ClientSource {
    pub fn direct(peer: SocketAddr) -> Self {
        Self {
            peer,
            client_ip: normalize_ip(peer.ip()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientIp {
    trusted_proxies: Vec<IpNet>,
    header: HeaderName,
}

impl Default for ClientIp {
    fn default() -> Self {
        Self::new(Vec::new(), HeaderName::from_static("x-forwarded-for"))
    }
}

impl ClientIp {
    pub(crate) fn new(trusted_proxies: Vec<IpNet>, header: HeaderName) -> Self {
        Self {
            trusted_proxies,
            header,
        }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|net| net.contains(&ip))
    }

    /// Validate the bounded list, then walk trusted hops from the direct peer
    /// outward. Assertions from an untrusted peer never affect the identity.
    pub fn resolve(
        &self,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<ClientSource, &'static str> {
        let mut source = ClientSource::direct(peer);
        if !self.is_trusted(source.client_ip) {
            return Ok(source);
        }
        let mut bytes = 0usize;
        let mut hops = Vec::new();
        for value in headers.get_all(&self.header) {
            bytes = bytes
                .saturating_add(value.as_bytes().len())
                .saturating_add(usize::from(!hops.is_empty()));
            if bytes > MAX_HEADER_BYTES {
                return Err("client IP header too large");
            }
            let value = value.to_str().map_err(|_| "invalid client IP header")?;
            for token in value.split(',') {
                if hops.len() >= MAX_HOPS {
                    return Err("too many client IP hops");
                }
                let ip = token
                    .trim_matches([' ', '\t'])
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid client IP header")?;
                hops.push(normalize_ip(ip));
            }
        }
        if hops.is_empty() {
            return Err("missing client IP header");
        }
        if self.header != "x-forwarded-for" && hops.len() != 1 {
            return Err("client IP header requires a single address");
        }
        for hop in hops.into_iter().rev() {
            if !self.is_trusted(source.client_ip) {
                break;
            }
            source.client_ip = hop;
        }
        if self.is_trusted(source.client_ip) {
            return Err("client IP chain contains only trusted proxies");
        }
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn policy(header: &'static str) -> ClientIp {
        ClientIp::new(
            vec!["10.0.0.0/24".parse().expect("CIDR")],
            HeaderName::from_static(header),
        )
    }

    #[test]
    fn direct_and_untrusted_peers_ignore_forged_headers() {
        let peer = "203.0.113.7:1234".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("garbage"));
        for config in [ClientIp::default(), policy("x-forwarded-for")] {
            assert_eq!(
                config.resolve(peer, &headers).expect("direct").client_ip,
                peer.ip()
            );
        }
    }

    #[test]
    fn walks_trusted_hops_and_stops_at_the_first_untrusted_address() {
        let peer = "10.0.0.1:443".parse().expect("peer");
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.99, 203.0.113.7"),
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("10.0.0.2"));
        let source = policy("x-forwarded-for")
            .resolve(peer, &headers)
            .expect("client");
        assert_eq!(source.peer, peer);
        assert_eq!(
            source.client_ip,
            "203.0.113.7".parse::<IpAddr>().expect("IP")
        );
    }

    #[test]
    fn rejects_missing_malformed_and_unattributable_chains() {
        let config = policy("x-forwarded-for");
        let peer = "10.0.0.1:443".parse().expect("peer");
        assert!(config.resolve(peer, &HeaderMap::new()).is_err());
        for value in [
            "",
            "unknown",
            "203.0.113.7:80",
            "[2001:db8::1]",
            "203.0.113.7,",
            "bad, 203.0.113.7",
            "10.0.0.2",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("header"),
            );
            assert!(config.resolve(peer, &headers).is_err(), "{value}");
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xff").expect("header"),
        );
        assert!(config.resolve(peer, &headers).is_err());
    }

    #[test]
    fn bounds_combined_header_bytes_and_hops() {
        let peer = "10.0.0.1:443".parse().expect("peer");
        let config = policy("x-forwarded-for");
        let at_limit = format!(
            "{}203.0.113.7",
            " ".repeat(MAX_HEADER_BYTES - "203.0.113.7".len())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&at_limit).expect("header"),
        );
        assert!(config.resolve(peer, &headers).is_ok());
        headers.append("x-forwarded-for", HeaderValue::from_static("10.0.0.2"));
        assert!(config.resolve(peer, &headers).is_err());
        for count in [MAX_HOPS, MAX_HOPS + 1] {
            let mut headers = HeaderMap::new();
            let value = vec!["203.0.113.7"; count].join(",");
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&value).expect("header"),
            );
            assert_eq!(config.resolve(peer, &headers).is_ok(), count == MAX_HOPS);
        }
    }

    #[test]
    fn single_address_headers_reject_duplicates_and_lists() {
        let peer = "10.0.0.1:443".parse().expect("peer");
        for header in ["x-real-ip", "cf-connecting-ip", "true-client-ip"] {
            let mut headers = HeaderMap::new();
            headers.append(header, HeaderValue::from_static("203.0.113.7"));
            assert!(policy(header).resolve(peer, &headers).is_ok());
            headers.append(header, HeaderValue::from_static("203.0.113.8"));
            assert!(policy(header).resolve(peer, &headers).is_err());
            headers.insert(header, HeaderValue::from_static("203.0.113.7, 203.0.113.8"));
            assert!(policy(header).resolve(peer, &headers).is_err());
        }
    }

    #[test]
    fn normalizes_mapped_ipv4_and_accepts_bare_ipv6() {
        let peer = "[::ffff:10.0.0.1]:443".parse().expect("peer");
        for value in ["::ffff:203.0.113.7", "2001:db8::7"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(value).expect("header"),
            );
            let source = policy("x-forwarded-for")
                .resolve(peer, &headers)
                .expect("client");
            assert_eq!(source.client_ip, normalize_ip(value.parse().expect("IP")));
        }
        let config = ClientIp::new(
            vec!["2001:db8:1::/64".parse().expect("CIDR")],
            HeaderName::from_static("x-forwarded-for"),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        assert_eq!(
            config
                .resolve("[2001:db8:1::1]:443".parse().expect("peer"), &headers)
                .expect("client")
                .client_ip,
            "203.0.113.7".parse::<IpAddr>().expect("IP")
        );
    }
}
