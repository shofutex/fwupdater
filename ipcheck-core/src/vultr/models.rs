use serde::{Deserialize, Serialize};
use std::fmt;

/// Address family for a firewall rule, as accepted by the Vultr API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpType {
    V4,
    V6,
}

impl fmt::Display for IpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpType::V4 => write!(f, "v4"),
            IpType::V6 => write!(f, "v6"),
        }
    }
}

/// Protocol for a firewall rule, as accepted by the Vultr API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Gre,
    Esp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Gre => "gre",
            Protocol::Esp => "esp",
        };
        write!(f, "{s}")
    }
}

/// A firewall group, as returned by the Vultr API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallGroup {
    pub id: String,
    pub description: String,
    pub date_created: String,
    pub date_modified: String,
    pub instance_count: i64,
    pub rule_count: i64,
    pub max_rule_count: i64,
}

/// A single rule within a firewall group, as returned by the Vultr API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u64,
    pub action: String,
    pub ip_type: IpType,
    pub protocol: Protocol,
    pub port: String,
    pub subnet: String,
    pub subnet_size: i64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub notes: String,
}

/// Request body used to create a new firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirewallRuleReq {
    pub ip_type: IpType,
    pub protocol: Protocol,
    pub subnet: String,
    pub subnet_size: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub port: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub total: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallGroupsResponse {
    pub firewall_groups: Vec<FirewallGroup>,
    #[serde(default)]
    pub meta: Option<Meta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallGroupResponse {
    pub firewall_group: FirewallGroup,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallRulesResponse {
    pub firewall_rules: Vec<FirewallRule>,
    #[serde(default)]
    pub meta: Option<Meta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallRuleResponse {
    pub firewall_rule: FirewallRule,
}
