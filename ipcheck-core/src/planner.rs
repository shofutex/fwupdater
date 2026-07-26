use std::net::Ipv6Addr;

use crate::ip_detect::DetectedIps;
use crate::vultr::models::{FirewallRuleReq, IpType, Protocol};

/// Ports commonly opened for a management IP: SSH, HTTP, HTTPS.
pub const DEFAULT_PORTS: [u16; 3] = [22, 80, 443];

/// Default IPv6 prefix length used for generated rules. Many hosts rotate
/// their IPv6 host address via privacy extensions while keeping the same
/// ISP-assigned prefix, so opening the whole /64 prefix (rather than a
/// single /128 host address) avoids needing a new rule on every rotation.
pub const DEFAULT_IPV6_PREFIX_LEN: u8 = 64;

/// A port (or port range) and protocol to open, e.g. `22/tcp` or
/// `"8000:9000"/tcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub port: String,
    pub protocol: Protocol,
}

impl PortSpec {
    /// A single TCP port, e.g. `PortSpec::tcp(22)`.
    pub fn tcp(port: u16) -> Self {
        Self { port: port.to_string(), protocol: Protocol::Tcp }
    }
}

/// Builds the firewall rule requests needed to open `ports` for whichever of
/// `ips.ipv4` / `ips.ipv6` are present, tagged with `note`. One rule is
/// produced per (address family, port) pair.
///
/// The IPv4 rule always targets a single /32 host. The IPv6 rule targets the
/// `ipv6_prefix_len`-bit network prefix containing the detected address
/// (see [`DEFAULT_IPV6_PREFIX_LEN`]) rather than a single /128 host, since
/// the host portion commonly rotates while the prefix stays stable.
pub fn plan_add_rules(
    ips: &DetectedIps,
    ports: &[PortSpec],
    note: &str,
    ipv6_prefix_len: u8,
) -> Vec<FirewallRuleReq> {
    let mut planned = Vec::with_capacity(ports.len() * 2);

    if let Some(v4) = ips.ipv4 {
        for spec in ports {
            planned.push(FirewallRuleReq {
                ip_type: IpType::V4,
                protocol: spec.protocol,
                subnet: v4.to_string(),
                subnet_size: 32,
                port: spec.port.clone(),
                source: String::new(),
                notes: note.to_string(),
            });
        }
    }

    if let Some(v6) = ips.ipv6 {
        let network = ipv6_network_prefix(v6, ipv6_prefix_len);
        for spec in ports {
            planned.push(FirewallRuleReq {
                ip_type: IpType::V6,
                protocol: spec.protocol,
                subnet: network.to_string(),
                subnet_size: ipv6_prefix_len as i64,
                port: spec.port.clone(),
                source: String::new(),
                notes: note.to_string(),
            });
        }
    }

    planned
}

/// Masks off the host bits of `addr`, leaving only the `prefix_len`-bit
/// network prefix.
fn ipv6_network_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let mask = if prefix_len >= 128 { u128::MAX } else { !0u128 << (128 - prefix_len as u32) };
    Ipv6Addr::from_bits(addr.to_bits() & mask)
}
