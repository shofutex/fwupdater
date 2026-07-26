use crate::ip_detect::DetectedIps;
use crate::vultr::models::{FirewallRuleReq, IpType, Protocol};

/// Ports commonly opened for a management IP: SSH, HTTP, HTTPS.
pub const DEFAULT_PORTS: [u16; 3] = [22, 80, 443];

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
pub fn plan_add_rules(ips: &DetectedIps, ports: &[PortSpec], note: &str) -> Vec<FirewallRuleReq> {
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
        for spec in ports {
            planned.push(FirewallRuleReq {
                ip_type: IpType::V6,
                protocol: spec.protocol,
                subnet: v6.to_string(),
                subnet_size: 128,
                port: spec.port.clone(),
                source: String::new(),
                notes: note.to_string(),
            });
        }
    }

    planned
}
