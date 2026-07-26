mod display;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ipcheck_core::planner::{plan_add_rules, PortSpec, DEFAULT_PORTS};
use ipcheck_core::vultr::{requests, FirewallRuleResponse, VultrClient};
use ipcheck_core::{detect_all, DetectedIps};

/// Test harness for validating the exact Vultr API calls the ipcheck app
/// would make, before wiring them into the mobile UI. Every mutating command
/// prints the request (and an equivalent curl command) and asks for
/// confirmation before sending it.
#[derive(Parser)]
#[command(name = "ipcheck", version, about)]
struct Cli {
    /// Vultr API key. Can also be set via VULTR_API_KEY.
    #[arg(long, env = "VULTR_API_KEY", global = true)]
    api_key: Option<String>,

    /// Override the Vultr API base URL (e.g. to point at a local mock server).
    #[arg(long, default_value = VultrClient::DEFAULT_BASE_URL, global = true)]
    base_url: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Detect this machine's public IPv4/IPv6 addresses.
    Detect,
    /// List firewall groups on the Vultr account.
    Groups,
    /// List the rules inside a firewall group.
    Rules { group_id: String },
    /// Add rules for the given ports at this machine's current IP address(es).
    Add {
        group_id: String,
        /// Comma-separated TCP ports to open.
        #[arg(long, value_delimiter = ',', default_values_t = DEFAULT_PORTS)]
        ports: Vec<u16>,
        /// Note/label to attach to each created rule.
        #[arg(long)]
        note: String,
        #[arg(long, conflicts_with = "ipv6_only")]
        ipv4_only: bool,
        #[arg(long, conflicts_with = "ipv4_only")]
        ipv6_only: bool,
        /// Only print the requests that would be sent; never contact Vultr.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Remove one or more existing rules by ID (see `rules` for IDs).
    Remove {
        group_id: String,
        #[arg(required = true)]
        rule_ids: Vec<u64>,
        /// Only print the requests that would be sent; never contact Vultr.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Detect => cmd_detect(),
        Command::Groups => cmd_groups(&cli),
        Command::Rules { group_id } => cmd_rules(&cli, group_id),
        Command::Add { group_id, ports, note, ipv4_only, ipv6_only, dry_run, yes } => {
            cmd_add(&cli, group_id, ports, note, *ipv4_only, *ipv6_only, *dry_run, *yes)
        }
        Command::Remove { group_id, rule_ids, dry_run, yes } => {
            cmd_remove(&cli, group_id, rule_ids, *dry_run, *yes)
        }
    }
}

fn client_for(cli: &Cli) -> Result<VultrClient> {
    let api_key = cli
        .api_key
        .clone()
        .context("a Vultr API key is required: pass --api-key or set VULTR_API_KEY")?;
    Ok(VultrClient::with_base_url(api_key, &cli.base_url)?)
}

fn print_detected(ips: &DetectedIps) {
    match ips.ipv4 {
        Some(ip) => println!("IPv4: {ip}"),
        None => println!("IPv4: (not detected)"),
    }
    match ips.ipv6 {
        Some(ip) => println!("IPv6: {ip}"),
        None => println!("IPv6: (none / not detected)"),
    }
}

fn cmd_detect() -> Result<()> {
    print_detected(&detect_all());
    Ok(())
}

fn cmd_groups(cli: &Cli) -> Result<()> {
    let client = client_for(cli)?;
    let req = requests::list_firewall_groups();
    display::print_request(&req, &cli.base_url);

    let groups = client.list_firewall_groups()?;
    if groups.is_empty() {
        println!("No firewall groups found.");
    }
    for g in &groups {
        display::print_group(g);
    }
    Ok(())
}

fn cmd_rules(cli: &Cli, group_id: &str) -> Result<()> {
    let client = client_for(cli)?;
    let req = requests::list_firewall_rules(group_id);
    display::print_request(&req, &cli.base_url);

    let rules = client.list_firewall_rules(group_id)?;
    if rules.is_empty() {
        println!("No rules found in group {group_id}.");
    }
    for r in &rules {
        display::print_rule(r);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_add(
    cli: &Cli,
    group_id: &str,
    ports: &[u16],
    note: &str,
    ipv4_only: bool,
    ipv6_only: bool,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    println!("Detecting public IP address(es)...");
    let mut ips = detect_all();
    if ipv4_only {
        ips.ipv6 = None;
    }
    if ipv6_only {
        ips.ipv4 = None;
    }
    print_detected(&ips);

    if ips.ipv4.is_none() && ips.ipv6.is_none() {
        bail!("no usable IP address detected; nothing to do");
    }

    let port_specs: Vec<PortSpec> = ports.iter().copied().map(PortSpec::tcp).collect();
    let planned_rules = plan_add_rules(&ips, &port_specs, note);
    let api_requests: Vec<_> = planned_rules
        .iter()
        .map(|rule| requests::create_firewall_rule(group_id, rule))
        .collect();

    println!("\n{} rule(s) would be created:\n", api_requests.len());
    for req in &api_requests {
        display::print_request(req, &cli.base_url);
    }

    if dry_run {
        println!("(dry run: no requests were sent)");
        return Ok(());
    }

    if !yes && !display::confirm(&format!("Send {} request(s) to Vultr?", api_requests.len())) {
        println!("Aborted; nothing sent.");
        return Ok(());
    }

    let client = client_for(cli)?;
    for req in &api_requests {
        match client.send::<FirewallRuleResponse>(req) {
            Ok(resp) => println!("Created rule id={}", resp.firewall_rule.id),
            Err(e) => println!("Failed: {e}"),
        }
    }

    Ok(())
}

fn cmd_remove(cli: &Cli, group_id: &str, rule_ids: &[u64], dry_run: bool, yes: bool) -> Result<()> {
    let api_requests: Vec<_> = rule_ids
        .iter()
        .map(|id| requests::delete_firewall_rule(group_id, *id))
        .collect();

    println!("{} rule(s) would be deleted:\n", api_requests.len());
    for req in &api_requests {
        display::print_request(req, &cli.base_url);
    }

    if dry_run {
        println!("(dry run: no requests were sent)");
        return Ok(());
    }

    if !yes && !display::confirm(&format!("Send {} delete request(s) to Vultr?", api_requests.len()))
    {
        println!("Aborted; nothing sent.");
        return Ok(());
    }

    let client = client_for(cli)?;
    for (id, req) in rule_ids.iter().zip(&api_requests) {
        match client.send_no_content(req) {
            Ok(()) => println!("Deleted rule id={id}"),
            Err(e) => println!("Failed to delete rule id={id}: {e}"),
        }
    }

    Ok(())
}
