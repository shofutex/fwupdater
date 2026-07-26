use std::time::Duration;

use reqwest::Method;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

use super::models::{
    FirewallGroupsResponse, FirewallRule, FirewallRuleReq, FirewallRuleResponse,
    FirewallRulesResponse,
};

/// A fully-described Vultr API call: method, path, and (optionally) a JSON
/// body. Building one of these never touches the network — it exists so a
/// caller (e.g. the CLI harness) can inspect or print exactly what would be
/// sent before [`VultrClient::send`] actually sends it.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<serde_json::Value>,
}

impl ApiRequest {
    fn get(path: impl Into<String>) -> Self {
        Self { method: Method::GET, path: path.into(), body: None }
    }

    fn post(path: impl Into<String>, body: serde_json::Value) -> Self {
        Self { method: Method::POST, path: path.into(), body: Some(body) }
    }

    fn delete(path: impl Into<String>) -> Self {
        Self { method: Method::DELETE, path: path.into(), body: None }
    }

    /// The full URL this request would be sent to, given an API base URL.
    pub fn url(&self, base_url: &str) -> String {
        format!("{base_url}{}", self.path)
    }

    /// Renders this request as an equivalent `curl` command, matching the
    /// style of Vultr's own API documentation. The API key is never
    /// embedded — it's referenced via `$VULTR_API_KEY` so the rendered
    /// command is safe to print or log.
    pub fn to_curl(&self, base_url: &str) -> String {
        let mut cmd = format!(
            "curl \"{}\" \\\n  -X {} \\\n  -H \"Authorization: Bearer $VULTR_API_KEY\"",
            self.url(base_url),
            self.method
        );
        if let Some(body) = &self.body {
            cmd.push_str(" \\\n  -H \"Content-Type: application/json\"");
            let pretty = serde_json::to_string_pretty(body).unwrap_or_default();
            cmd.push_str(&format!(" \\\n  --data '{pretty}'"));
        }
        cmd
    }
}

/// Request builders. These are pure functions — no client or network access
/// required — so a caller can build, print, and inspect a request before
/// deciding whether to actually send it.
pub mod requests {
    use super::*;

    pub fn list_firewall_groups() -> ApiRequest {
        ApiRequest::get("/v2/firewalls")
    }

    pub fn list_firewall_rules(group_id: &str) -> ApiRequest {
        ApiRequest::get(format!("/v2/firewalls/{group_id}/rules"))
    }

    pub fn create_firewall_rule(group_id: &str, rule: &FirewallRuleReq) -> ApiRequest {
        let body = serde_json::to_value(rule).expect("FirewallRuleReq is always serializable");
        ApiRequest::post(format!("/v2/firewalls/{group_id}/rules"), body)
    }

    pub fn delete_firewall_rule(group_id: &str, rule_id: u64) -> ApiRequest {
        ApiRequest::delete(format!("/v2/firewalls/{group_id}/rules/{rule_id}"))
    }
}

/// A thin client for the Vultr firewall API. Every mutating call is a
/// two-step process: build an [`ApiRequest`] with a function from
/// [`requests`], then hand it to [`VultrClient::send`] (or
/// [`VultrClient::send_no_content`]) to actually dispatch it.
pub struct VultrClient {
    api_key: String,
    base_url: String,
    http: reqwest::blocking::Client,
}

impl VultrClient {
    pub const DEFAULT_BASE_URL: &'static str = "https://api.vultr.com";

    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, Self::DEFAULT_BASE_URL)
    }

    pub fn with_base_url(api_key: impl Into<String>, base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Sends a request and decodes the JSON response body.
    pub fn send<T: DeserializeOwned>(&self, req: &ApiRequest) -> Result<T> {
        let resp = self.dispatch(req)?;
        Ok(resp.json::<T>()?)
    }

    /// Sends a request that returns no body (e.g. a delete).
    pub fn send_no_content(&self, req: &ApiRequest) -> Result<()> {
        self.dispatch(req)?;
        Ok(())
    }

    fn dispatch(&self, req: &ApiRequest) -> Result<reqwest::blocking::Response> {
        let url = req.url(&self.base_url);
        let mut builder = self.http.request(req.method.clone(), url).bearer_auth(&self.api_key);
        if let Some(body) = &req.body {
            builder = builder.json(body);
        }
        let resp = builder.send()?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let message = resp.text().unwrap_or_default();
            Err(Error::Api { status, message })
        }
    }

    // Convenience wrappers for callers (e.g. a future mobile FFI layer) that
    // just want the result and don't need to inspect the request first.

    pub fn list_firewall_groups(&self) -> Result<Vec<super::models::FirewallGroup>> {
        let resp: FirewallGroupsResponse = self.send(&requests::list_firewall_groups())?;
        Ok(resp.firewall_groups)
    }

    pub fn list_firewall_rules(&self, group_id: &str) -> Result<Vec<FirewallRule>> {
        let resp: FirewallRulesResponse = self.send(&requests::list_firewall_rules(group_id))?;
        Ok(resp.firewall_rules)
    }

    pub fn create_firewall_rule(
        &self,
        group_id: &str,
        rule: &FirewallRuleReq,
    ) -> Result<FirewallRule> {
        let resp: FirewallRuleResponse = self.send(&requests::create_firewall_rule(group_id, rule))?;
        Ok(resp.firewall_rule)
    }

    pub fn delete_firewall_rule(&self, group_id: &str, rule_id: u64) -> Result<()> {
        self.send_no_content(&requests::delete_firewall_rule(group_id, rule_id))
    }
}
