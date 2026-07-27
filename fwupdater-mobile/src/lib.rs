//! UniFFI bindings exposing `fwupdater-core` to Kotlin (Android) and Swift
//! (iOS). Mirrors the CLI's workflow: detect IP -> pick a firewall group
//! (via `list_groups`, backing a picker) -> list its rules -> plan/preview
//! rules to add -> send them -> later, find and remove stale ones.
//!
//! Every method here is synchronous (it makes blocking HTTP calls under the
//! hood, same as `fwupdater-core`/`fwupdater-cli`). Callers must invoke these
//! off their main/UI thread (e.g. `Dispatchers.IO` in Kotlin, a detached
//! `Task` in Swift), exactly as with any blocking network SDK call.

use std::sync::Arc;

use fwupdater_core::planner::{self, PortSpec};
use fwupdater_core::vultr::models::{FirewallRule as CoreFirewallRule, FirewallRuleReq, IpType as CoreIpType, Protocol as CoreProtocol};
use fwupdater_core::vultr::{FirewallGroup as CoreFirewallGroup, VultrClient};
use fwupdater_core::DetectedIps as CoreDetectedIps;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------
// Records / enums
// ---------------------------------------------------------------------

/// The public IPv4/IPv6 addresses detected for this device. `ipv6` is
/// `None` when the device has no IPv6 connectivity - a normal condition,
/// not an error.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DetectedIps {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

impl From<CoreDetectedIps> for DetectedIps {
    fn from(ips: CoreDetectedIps) -> Self {
        Self { ipv4: ips.ipv4.map(|ip| ip.to_string()), ipv6: ips.ipv6.map(|ip| ip.to_string()) }
    }
}

impl DetectedIps {
    fn to_core(&self) -> Result<CoreDetectedIps, MobileError> {
        let ipv4 = self
            .ipv4
            .as_deref()
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| MobileError::IpDetect(format!("invalid IPv4 address: {e}")))?;
        let ipv6 = self
            .ipv6
            .as_deref()
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| MobileError::IpDetect(format!("invalid IPv6 address: {e}")))?;
        Ok(CoreDetectedIps { ipv4, ipv6 })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IpType {
    V4,
    V6,
}

impl From<CoreIpType> for IpType {
    fn from(t: CoreIpType) -> Self {
        match t {
            CoreIpType::V4 => IpType::V4,
            CoreIpType::V6 => IpType::V6,
        }
    }
}

impl From<IpType> for CoreIpType {
    fn from(t: IpType) -> Self {
        match t {
            IpType::V4 => CoreIpType::V4,
            IpType::V6 => CoreIpType::V6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Gre,
    Esp,
}

impl From<CoreProtocol> for Protocol {
    fn from(p: CoreProtocol) -> Self {
        match p {
            CoreProtocol::Tcp => Protocol::Tcp,
            CoreProtocol::Udp => Protocol::Udp,
            CoreProtocol::Icmp => Protocol::Icmp,
            CoreProtocol::Gre => Protocol::Gre,
            CoreProtocol::Esp => Protocol::Esp,
        }
    }
}

impl From<Protocol> for CoreProtocol {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Tcp => CoreProtocol::Tcp,
            Protocol::Udp => CoreProtocol::Udp,
            Protocol::Icmp => CoreProtocol::Icmp,
            Protocol::Gre => CoreProtocol::Gre,
            Protocol::Esp => CoreProtocol::Esp,
        }
    }
}

/// A Vultr firewall group, as shown by `MobileClient::list_groups` - back a
/// picker with these so the user can tap the group they mean instead of
/// typing an opaque ID.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FirewallGroup {
    pub id: String,
    pub description: String,
    pub date_created: String,
    pub date_modified: String,
    pub instance_count: i64,
    pub rule_count: i64,
    pub max_rule_count: i64,
}

impl From<CoreFirewallGroup> for FirewallGroup {
    fn from(g: CoreFirewallGroup) -> Self {
        Self {
            id: g.id,
            description: g.description,
            date_created: g.date_created,
            date_modified: g.date_modified,
            instance_count: g.instance_count,
            rule_count: g.rule_count,
            max_rule_count: g.max_rule_count,
        }
    }
}

/// An existing rule within a firewall group.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FirewallRule {
    pub id: u64,
    pub action: String,
    pub ip_type: IpType,
    pub protocol: Protocol,
    pub port: String,
    pub subnet: String,
    pub subnet_size: i64,
    pub source: String,
    pub notes: String,
}

impl From<CoreFirewallRule> for FirewallRule {
    fn from(r: CoreFirewallRule) -> Self {
        Self {
            id: r.id,
            action: r.action,
            ip_type: r.ip_type.into(),
            protocol: r.protocol.into(),
            port: r.port,
            subnet: r.subnet,
            subnet_size: r.subnet_size,
            source: r.source,
            notes: r.notes,
        }
    }
}

impl From<FirewallRule> for CoreFirewallRule {
    fn from(r: FirewallRule) -> Self {
        Self {
            id: r.id,
            action: r.action,
            ip_type: r.ip_type.into(),
            protocol: r.protocol.into(),
            port: r.port,
            subnet: r.subnet,
            subnet_size: r.subnet_size,
            source: r.source,
            notes: r.notes,
        }
    }
}

/// A rule that would be created if sent - the mobile equivalent of the
/// CLI's "print the request before sending it" step. Show these to the
/// user for confirmation, then hand the (possibly user-edited) list to
/// `MobileClient::add_rules`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PlannedRule {
    pub ip_type: IpType,
    pub protocol: Protocol,
    pub subnet: String,
    pub subnet_size: i64,
    pub port: String,
    pub notes: String,
}

impl From<FirewallRuleReq> for PlannedRule {
    fn from(r: FirewallRuleReq) -> Self {
        Self {
            ip_type: r.ip_type.into(),
            protocol: r.protocol.into(),
            subnet: r.subnet,
            subnet_size: r.subnet_size,
            port: r.port,
            notes: r.notes,
        }
    }
}

impl From<PlannedRule> for FirewallRuleReq {
    fn from(r: PlannedRule) -> Self {
        Self {
            ip_type: r.ip_type.into(),
            protocol: r.protocol.into(),
            subnet: r.subnet,
            subnet_size: r.subnet_size,
            port: r.port,
            source: String::new(),
            notes: r.notes,
        }
    }
}

/// Outcome of attempting to create one planned rule. `rule` is populated
/// only on success; `error_message` only on failure - one failing rule
/// never hides the others that succeeded.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AddRuleResult {
    pub planned: PlannedRule,
    pub rule: Option<FirewallRule>,
    pub error_message: Option<String>,
}

/// Outcome of attempting to delete one rule by ID.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RemoveRuleResult {
    pub rule_id: u64,
    pub error_message: Option<String>,
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("network error: {0}")]
    Network(String),
    #[error("Vultr API error (HTTP {status}): {message}")]
    Api { status: u16, message: String },
    #[error("could not determine public IP address: {0}")]
    IpDetect(String),
}

impl From<fwupdater_core::Error> for MobileError {
    fn from(e: fwupdater_core::Error) -> Self {
        match e {
            fwupdater_core::Error::Http(err) => MobileError::Network(err.to_string()),
            fwupdater_core::Error::Json(err) => MobileError::Network(err.to_string()),
            fwupdater_core::Error::Api { status, message } => MobileError::Api { status, message },
            fwupdater_core::Error::IpDetect(msg) => MobileError::IpDetect(msg),
        }
    }
}

// ---------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------

/// Detects this device's public IPv4/IPv6 addresses. Blocking - call off
/// the main thread.
#[uniffi::export]
pub fn detect_ips() -> DetectedIps {
    fwupdater_core::detect_all().into()
}

/// Ports opened by default if the caller doesn't specify its own: 22, 80, 443.
#[uniffi::export]
pub fn default_ports() -> Vec<u16> {
    planner::DEFAULT_PORTS.to_vec()
}

/// Default IPv6 network prefix length used for generated rules (64):
/// see [`plan_add_rules`] for why a whole prefix rather than a single host
/// address is opened by default.
#[uniffi::export]
pub fn default_ipv6_prefix_len() -> u8 {
    planner::DEFAULT_IPV6_PREFIX_LEN
}

/// Builds the list of rules that *would* be created for `ports` at the
/// given `ips`, tagged with `note` - pure, no network access. Show this to
/// the user for confirmation before calling `MobileClient::add_rules` with
/// it (or a user-edited subset of it).
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn plan_add_rules(
    ips: DetectedIps,
    ports: Vec<u16>,
    note: String,
    ipv6_prefix_len: u8,
    ipv4_only: bool,
    ipv6_only: bool,
) -> Result<Vec<PlannedRule>, MobileError> {
    let mut core_ips = ips.to_core()?;
    if ipv4_only {
        core_ips.ipv6 = None;
    }
    if ipv6_only {
        core_ips.ipv4 = None;
    }
    let specs: Vec<PortSpec> = ports.into_iter().map(PortSpec::tcp).collect();
    let planned = planner::plan_add_rules(&core_ips, &specs, &note, ipv6_prefix_len);
    Ok(planned.into_iter().map(Into::into).collect())
}

/// Finds rules among `rules` tagged with `notes` whose subnet no longer
/// matches either of `ips`' currently-detected addresses - i.e. rules
/// created for an IP this device no longer has. Pure, no network access;
/// feed the result to `MobileClient::remove_rules`.
#[uniffi::export]
pub fn find_stale_rules(
    rules: Vec<FirewallRule>,
    ips: DetectedIps,
    notes: String,
    ipv6_prefix_len: u8,
) -> Result<Vec<FirewallRule>, MobileError> {
    let core_ips = ips.to_core()?;
    let core_rules: Vec<CoreFirewallRule> = rules.into_iter().map(Into::into).collect();
    let stale = planner::find_stale_rules(&core_rules, &core_ips, &notes, ipv6_prefix_len);
    Ok(stale.into_iter().map(Into::into).collect())
}

// ---------------------------------------------------------------------
// MobileClient
// ---------------------------------------------------------------------

/// A Vultr API client. Every method makes a blocking HTTP call - invoke
/// off the main/UI thread.
#[derive(uniffi::Object)]
pub struct MobileClient {
    inner: VultrClient,
}

#[uniffi::export]
impl MobileClient {
    /// Creates a client using the default Vultr API base URL.
    #[uniffi::constructor]
    pub fn new(api_key: String) -> Result<Arc<Self>, MobileError> {
        Ok(Arc::new(Self { inner: VultrClient::new(api_key)? }))
    }

    /// Creates a client pointed at a custom base URL (e.g. a test/mock
    /// server).
    #[uniffi::constructor]
    pub fn with_base_url(api_key: String, base_url: String) -> Result<Arc<Self>, MobileError> {
        Ok(Arc::new(Self { inner: VultrClient::with_base_url(api_key, base_url)? }))
    }

    /// Lists firewall groups on the account - back a group picker with
    /// these.
    pub fn list_groups(&self) -> Result<Vec<FirewallGroup>, MobileError> {
        Ok(self.inner.list_firewall_groups()?.into_iter().map(Into::into).collect())
    }

    /// Lists the rules inside a firewall group.
    pub fn list_rules(&self, group_id: String) -> Result<Vec<FirewallRule>, MobileError> {
        Ok(self.inner.list_firewall_rules(&group_id)?.into_iter().map(Into::into).collect())
    }

    /// Sends previously-planned (and, ideally, user-confirmed) rules to
    /// Vultr. Returns one result per input rule so a single failure
    /// doesn't hide the others that succeeded.
    pub fn add_rules(&self, group_id: String, planned: Vec<PlannedRule>) -> Vec<AddRuleResult> {
        planned
            .into_iter()
            .map(|p| {
                let req: FirewallRuleReq = p.clone().into();
                match self.inner.create_firewall_rule(&group_id, &req) {
                    Ok(rule) => AddRuleResult { planned: p, rule: Some(rule.into()), error_message: None },
                    Err(e) => AddRuleResult { planned: p, rule: None, error_message: Some(e.to_string()) },
                }
            })
            .collect()
    }

    /// Deletes rules by ID. Returns one result per input ID so a single
    /// failure (e.g. a rule already deleted elsewhere) doesn't stop the
    /// rest from being attempted.
    pub fn remove_rules(&self, group_id: String, rule_ids: Vec<u64>) -> Vec<RemoveRuleResult> {
        rule_ids
            .into_iter()
            .map(|id| match self.inner.delete_firewall_rule(&group_id, id) {
                Ok(()) => RemoveRuleResult { rule_id: id, error_message: None },
                Err(e) => RemoveRuleResult { rule_id: id, error_message: Some(e.to_string()) },
            })
            .collect()
    }
}
