use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::error::{Error, Result};

const IPV4_ENDPOINT: &str = "https://ipv4.icanhazip.com";
const IPV6_ENDPOINT: &str = "https://ipv6.icanhazip.com";
const TIMEOUT: Duration = Duration::from_secs(5);

/// The public IPv4/IPv6 addresses detected for this machine.
///
/// `ipv6` is `None` when the host has no IPv6 connectivity, which is a normal
/// condition rather than an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectedIps {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// Detects this machine's public IPv4 address by asking an external echo service.
pub fn detect_ipv4() -> Result<Ipv4Addr> {
    let text = fetch(IPV4_ENDPOINT)?;
    text.parse::<Ipv4Addr>()
        .map_err(|e| Error::IpDetect(format!("could not parse IPv4 response '{text}': {e}")))
}

/// Detects this machine's public IPv6 address, if it has one.
pub fn detect_ipv6() -> Result<Option<Ipv6Addr>> {
    match fetch(IPV6_ENDPOINT) {
        Ok(text) => text
            .parse::<Ipv6Addr>()
            .map(Some)
            .map_err(|e| Error::IpDetect(format!("could not parse IPv6 response '{text}': {e}"))),
        Err(_) => Ok(None),
    }
}

/// Detects both address families, treating a missing IPv6 address as absence
/// rather than failure.
pub fn detect_all() -> DetectedIps {
    DetectedIps {
        ipv4: detect_ipv4().ok(),
        ipv6: detect_ipv6().ok().flatten(),
    }
}

fn fetch(url: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()?;
    let resp = client.get(url).send()?.error_for_status()?;
    Ok(resp.text()?.trim().to_string())
}
