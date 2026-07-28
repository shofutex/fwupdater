use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ip_detect::DetectedIps;
use crate::vultr::models::{FirewallRule, FirewallRuleReq, IpType, Protocol};

/// Ports commonly opened for a management IP: SSH, HTTP, HTTPS.
pub const DEFAULT_PORTS: [u16; 3] = [22, 80, 443];

/// Default IPv6 prefix length used for generated rules. Many hosts rotate
/// their IPv6 host address via privacy extensions while keeping the same
/// ISP-assigned prefix, so opening the whole /64 prefix (rather than a
/// single /128 host address) avoids needing a new rule on every rotation.
pub const DEFAULT_IPV6_PREFIX_LEN: u8 = 64;

/// Default IPv4 prefix length used for generated rules: a single host.
pub const DEFAULT_IPV4_PREFIX_LEN: u8 = 32;

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
/// The IPv4 rule targets the `ipv4_prefix_len`-bit network prefix containing
/// the address (see [`DEFAULT_IPV4_PREFIX_LEN`] for the usual single-host
/// default). The IPv6 rule targets the `ipv6_prefix_len`-bit network prefix
/// containing the detected address (see [`DEFAULT_IPV6_PREFIX_LEN`]) rather
/// than a single /128 host, since the host portion commonly rotates while
/// the prefix stays stable.
pub fn plan_add_rules(
    ips: &DetectedIps,
    ports: &[PortSpec],
    note: &str,
    ipv4_prefix_len: u8,
    ipv6_prefix_len: u8,
) -> Vec<FirewallRuleReq> {
    let mut planned = Vec::with_capacity(ports.len() * 2);

    if let Some(v4) = ips.ipv4 {
        let network = ipv4_network_prefix(v4, ipv4_prefix_len);
        for spec in ports {
            planned.push(FirewallRuleReq {
                ip_type: IpType::V4,
                protocol: spec.protocol,
                subnet: network.to_string(),
                subnet_size: ipv4_prefix_len as i64,
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
pub fn ipv6_network_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let mask = if prefix_len >= 128 { u128::MAX } else { !0u128 << (128 - prefix_len as u32) };
    Ipv6Addr::from_bits(addr.to_bits() & mask)
}

/// Masks off the host bits of `addr`, leaving only the `prefix_len`-bit
/// network prefix.
pub fn ipv4_network_prefix(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len >= 32 { u32::MAX } else { !0u32 << (32 - prefix_len as u32) };
    Ipv4Addr::from_bits(addr.to_bits() & mask)
}

/// Finds rules tagged with `notes` whose subnet no longer matches either of
/// `ips`' currently-detected addresses (v4 as a /32, v6 as the
/// `ipv6_prefix_len`-bit network prefix — mirroring [`plan_add_rules`]).
/// These are the rules a caller should offer to delete: they were created
/// for an IP address this machine no longer has.
pub fn find_stale_rules(
    rules: &[FirewallRule],
    ips: &DetectedIps,
    notes: &str,
    ipv6_prefix_len: u8,
) -> Vec<FirewallRule> {
    let current_v4 = ips.ipv4.map(|v4| format!("{v4}/32"));
    let current_v6 = ips
        .ipv6
        .map(|v6| format!("{}/{}", ipv6_network_prefix(v6, ipv6_prefix_len), ipv6_prefix_len));

    rules
        .iter()
        .filter(|r| r.notes == notes)
        .filter(|r| {
            let subnet = format!("{}/{}", r.subnet, r.subnet_size);
            Some(&subnet) != current_v4.as_ref() && Some(&subnet) != current_v6.as_ref()
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rule(id: u64, ip_type: IpType, subnet: &str, subnet_size: i64, notes: &str) -> FirewallRule {
        FirewallRule {
            id,
            action: "accept".to_string(),
            ip_type,
            protocol: Protocol::Tcp,
            port: "22".to_string(),
            subnet: subnet.to_string(),
            subnet_size,
            source: String::new(),
            notes: notes.to_string(),
        }
    }

    #[test]
    fn find_stale_rules_keeps_current_ignores_other_notes_flags_the_rest() {
        let ips = DetectedIps {
            ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ipv6: Some("2607:fb91:4b0c:c2d4::1".parse().unwrap()),
        };

        let current_v4 = rule(1, IpType::V4, "1.2.3.4", 32, "framework");
        let current_v6 = rule(2, IpType::V6, "2607:fb91:4b0c:c2d4::", 64, "framework");
        let stale_v4 = rule(3, IpType::V4, "9.9.9.9", 32, "framework");
        let other_notes = rule(4, IpType::V4, "9.9.9.9", 32, "manual-rule");

        let rules = vec![current_v4, current_v6, stale_v4.clone(), other_notes];
        let stale = find_stale_rules(&rules, &ips, "framework", 64);

        assert_eq!(stale, vec![stale_v4]);
    }
}
