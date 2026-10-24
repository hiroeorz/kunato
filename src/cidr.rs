//! IPv4/IPv6 CIDR parsing and matching.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 network with a prefix length.
///
/// Host bits are cleared during construction, so `10.0.0.7/24` and
/// `10.0.0.0/24` are the same network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!("prefix length {prefix} exceeds {max}"));
        }
        Ok(Self {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix
    }

    pub fn addr(self) -> IpAddr {
        self.addr
    }

    /// Convert an IPv4-mapped IPv6 network (`::ffff:a.b.c.d/96..128`) to its
    /// IPv4 equivalent. Other networks return `None`.
    pub fn to_ipv4_mapped(self) -> Option<Self> {
        let IpAddr::V6(addr) = self.addr else {
            return None;
        };
        if self.prefix < 96 {
            return None;
        }
        let v4 = addr.to_ipv4_mapped()?;
        Self::new(IpAddr::V4(v4), self.prefix - 96).ok()
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.addr, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = ipv4_mask(self.prefix);
                u32::from(address) & mask == u32::from(network) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = ipv6_mask(self.prefix);
                u128::from(address) & mask == u128::from(network) & mask
            }
            _ => false,
        }
    }
}

impl From<IpAddr> for IpNet {
    fn from(addr: IpAddr) -> Self {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Self { addr, prefix }
    }
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("missing prefix length in `{value}`"))?;
        if prefix.contains('/') {
            return Err(format!("invalid CIDR `{value}`"));
        }
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("invalid IP address in `{value}`"))?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!("invalid prefix length in `{value}`"));
        }
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid prefix length in `{value}`"))?;
        Self::new(address, prefix).map_err(|error| format!("{error} in `{value}`"))
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(Ipv4Addr::from(u32::from(addr) & ipv4_mask(prefix))),
        IpAddr::V6(addr) => IpAddr::V6(Ipv6Addr::from(u128::from(addr) & ipv6_mask(prefix))),
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::IpNet;
    use std::net::IpAddr;

    #[test]
    fn parses_and_normalizes_ipv4_networks() {
        let network = "10.0.0.7/24".parse::<IpNet>().expect("network");
        assert_eq!(network.addr().to_string(), "10.0.0.0");
        assert_eq!(network.prefix_len(), 24);
        assert_eq!(network.to_string(), "10.0.0.0/24");
        assert!(network.contains("10.0.0.1".parse().expect("ip")));
        assert!(!network.contains("10.0.1.1".parse().expect("ip")));
        assert!(!network.contains("::1".parse().expect("ip")));
    }

    #[test]
    fn parses_ipv6_and_boundary_prefixes() {
        let network = "2001:db8::1/32".parse::<IpNet>().expect("network");
        assert_eq!(network.addr().to_string(), "2001:db8::");
        assert!(network.contains("2001:db8::1".parse().expect("ip")));
        assert!(!network.contains("2001:db9::1".parse().expect("ip")));

        let any = "0.0.0.0/0".parse::<IpNet>().expect("network");
        assert!(any.contains("203.0.113.7".parse().expect("ip")));
        let host = "203.0.113.7/32".parse::<IpNet>().expect("network");
        assert!(host.contains("203.0.113.7".parse().expect("ip")));
        assert!(!host.contains("203.0.113.8".parse().expect("ip")));
        let any6 = "::/0".parse::<IpNet>().expect("network");
        assert!(any6.contains("2001:db8::1".parse().expect("ip")));
        let host6 = "2001:db8::1/128".parse::<IpNet>().expect("network");
        assert!(host6.contains("2001:db8::1".parse().expect("ip")));
        assert!(!host6.contains("2001:db8::2".parse().expect("ip")));
    }

    #[test]
    fn rejects_invalid_networks() {
        for value in [
            "10.0.0.0",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/",
            "/24",
            "10.0.0.0/24/8",
            "10.0.0.0/+24",
            " 10.0.0.0/24",
        ] {
            assert!(value.parse::<IpNet>().is_err(), "{value}");
        }
    }

    #[test]
    fn converts_ipv4_mapped_networks() {
        let network = "::ffff:10.0.0.0/120".parse::<IpNet>().expect("network");
        let mapped = network.to_ipv4_mapped().expect("mapped");
        assert_eq!(mapped.to_string(), "10.0.0.0/24");
        assert!(mapped.contains("10.0.0.7".parse().expect("ip")));
        assert!(
            "2001:db8::/32"
                .parse::<IpNet>()
                .expect("network")
                .to_ipv4_mapped()
                .is_none()
        );
        assert!(
            "::ffff:10.0.0.0/95"
                .parse::<IpNet>()
                .expect("network")
                .to_ipv4_mapped()
                .is_none()
        );
    }

    #[test]
    fn host_conversion_uses_the_full_prefix() {
        let v4 = IpNet::from("192.0.2.1".parse::<IpAddr>().expect("ip"));
        assert_eq!(v4.prefix_len(), 32);
        let v6 = IpNet::from("2001:db8::1".parse::<IpAddr>().expect("ip"));
        assert_eq!(v6.prefix_len(), 128);
    }
}
