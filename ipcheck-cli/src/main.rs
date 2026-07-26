mod display;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ipcheck_core::planner::{plan_add_rules, PortSpec, DEFAULT_IPV6_PREFIX_LEN, DEFAULT_PORTS};
use ipcheck_core::vultr::{requests, FirewallRuleResponse, VultrClient};
use ipcheck_core::{detect_all, DetectedIps};

/// Command-line tool for communicating Vultr firewall API calls
/// Every mutating command prints the request (and an equivalent 
/// curl command) and asks for confirmation before sending it
#[derive(Parser)]
#[command(name = "ipcheck", version, about)]
struct Cli {
    /// Vultr API key. Can also be set via VULTR_API_KEY.
    #[arg(long, env = "VULTR_API_KEY", global = true)]
    api_key: Option<String>,

    /// Override the Vultr API base URL (e.g. to point at a local mock server).
    #[arg(long, default_value = VultrClient::DEFAULT_BASE_URL, global = true)]
    base_url: String,

    /// Don't print the request (JSON body + equivalent curl) before sending it.
    #[arg(short = 's', long, global = true)]
    silent: bool,

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
    Rules {
        /// Firewall group ID (from `groups`). Omit if using --group-description.
        group_id: Option<String>,
        /// Look up the group by its description (from `groups`) instead of
        /// its ID. Resolves to a group ID and pauses for confirmation
        /// before listing its rules.
        #[arg(long, conflicts_with = "group_id")]
        group_description: Option<String>,
    },
    /// Add rules for the given ports at this machine's current IP address(es).
    Add {
        /// Firewall group ID (from `groups`). Omit if using --group-description.
        group_id: Option<String>,
        /// Look up the group by its description (from `groups`) instead of
        /// its ID. Resolves to a group ID and pauses for confirmation
        /// before creating any rules.
        #[arg(long, conflicts_with = "group_id")]
        group_description: Option<String>,
        /// Comma-separated TCP ports to open.
        #[arg(long, value_delimiter = ',', default_values_t = DEFAULT_PORTS)]
        ports: Vec<u16>,
        /// Note/label to attach to each created rule.
        #[arg(long)]
        note: String,
        /// IPv6 network prefix length to open (rather than a single /128
        /// host), since the host portion commonly rotates via privacy
        /// extensions while the prefix stays stable.
        #[arg(long, default_value_t = DEFAULT_IPV6_PREFIX_LEN)]
        ipv6_prefix_len: u8,
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
    ///
    /// The group is selected with --group-id or --group-description (rather
    /// than a positional GROUP_ID like `add`/`rules` use) since a positional
    /// group ID here would be ambiguous with the trailing rule ID list.
    Remove {
        /// Firewall group ID (from `groups`). Omit if using --group-description.
        #[arg(long, conflicts_with = "group_description")]
        group_id: Option<String>,
        /// Look up the group by its description (from `groups`) instead of
        /// its ID. Resolves to a group ID and pauses for confirmation
        /// before deleting any rules.
        #[arg(long)]
        group_description: Option<String>,
        /// Rule IDs to delete (see `rules` for IDs); at least one is required.
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
        Command::Rules { group_id, group_description } => {
            cmd_rules(&cli, group_id.as_deref(), group_description.as_deref())
        }
        Command::Add {
            group_id,
            group_description,
            ports,
            note,
            ipv6_prefix_len,
            ipv4_only,
            ipv6_only,
            dry_run,
            yes,
        } => cmd_add(
            &cli,
            group_id.as_deref(),
            group_description.as_deref(),
            ports,
            note,
            *ipv6_prefix_len,
            *ipv4_only,
            *ipv6_only,
            *dry_run,
            *yes,
        ),
        Command::Remove { group_id, group_description, rule_ids, dry_run, yes } => cmd_remove(
            &cli,
            group_id.as_deref(),
            group_description.as_deref(),
            rule_ids,
            *dry_run,
            *yes,
        ),
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
    if !cli.silent {
        display::print_request(&req, &cli.base_url);
    }

    let groups = client.list_firewall_groups()?;
    if groups.is_empty() {
        println!("No firewall groups found.");
    }
    for g in &groups {
        display::print_group(g);
    }
    Ok(())
}

fn cmd_rules(cli: &Cli, group_id: Option<&str>, group_description: Option<&str>) -> Result<()> {
    let client = client_for(cli)?;
    let resolved_group_id = resolve_group(&client, cli, group_id, group_description)?;

    let req = requests::list_firewall_rules(&resolved_group_id);
    if !cli.silent {
        display::print_request(&req, &cli.base_url);
    }

    let rules = client.list_firewall_rules(&resolved_group_id)?;
    if rules.is_empty() {
        println!("No rules found in group {resolved_group_id}.");
    }
    for r in &rules {
        display::print_rule(r);
    }
    Ok(())
}

/// Resolves the group to operate on: an explicit `group_id` is used as-is;
/// otherwise `group_description` is looked up via [`resolve_group_id`].
/// Exactly one of the two must be given (enforced by the CLI's
/// `conflicts_with`), so the `(None, None)` case only happens when both were
/// omitted entirely.
fn resolve_group(
    client: &VultrClient,
    cli: &Cli,
    group_id: Option<&str>,
    group_description: Option<&str>,
) -> Result<String> {
    match (group_id, group_description) {
        (Some(id), _) => Ok(id.to_string()),
        (None, Some(desc)) => resolve_group_id(client, cli, desc),
        (None, None) => bail!("a firewall group is required: pass a group ID or --group-description"),
    }
}

/// Resolves a firewall group's description (as shown by `groups`) to its ID.
/// Since a description isn't guaranteed unique or exact the way an ID is,
/// this always pauses for explicit confirmation of the resolved id/description
/// pair before handing the ID back to the caller.
fn resolve_group_id(client: &VultrClient, cli: &Cli, group_description: &str) -> Result<String> {
    let req = requests::list_firewall_groups();
    if !cli.silent {
        display::print_request(&req, &cli.base_url);
    }

    let groups = client.list_firewall_groups()?;
    let matches: Vec<_> =
        groups.iter().filter(|g| g.description.eq_ignore_ascii_case(group_description)).collect();

    match matches.as_slice() {
        [] => bail!(
            "no firewall group found with description '{group_description}'; run `ipcheck groups` to see available descriptions"
        ),
        [group] => {
            println!("Found group id={} description={}", group.id, group.description);
            if display::confirm("Is this the group you meant?") {
                Ok(group.id.clone())
            } else {
                bail!("aborted; group not confirmed")
            }
        }
        multiple => {
            println!("Multiple groups match description '{group_description}':");
            for g in multiple {
                display::print_group(g);
            }
            bail!("ambiguous description; re-run with an explicit GROUP_ID")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_add(
    cli: &Cli,
    group_id: Option<&str>,
    group_description: Option<&str>,
    ports: &[u16],
    note: &str,
    ipv6_prefix_len: u8,
    ipv4_only: bool,
    ipv6_only: bool,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let client = client_for(cli)?;
    let resolved_group_id = resolve_group(&client, cli, group_id, group_description)?;

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
    let planned_rules = plan_add_rules(&ips, &port_specs, note, ipv6_prefix_len);
    let api_requests: Vec<_> = planned_rules
        .iter()
        .map(|rule| requests::create_firewall_rule(&resolved_group_id, rule))
        .collect();

    println!("\n{} rule(s) would be created:\n", api_requests.len());
    if !cli.silent {
        for req in &api_requests {
            display::print_request(req, &cli.base_url);
        }
    }

    if dry_run {
        println!("(dry run: no requests were sent)");
        return Ok(());
    }

    if !yes && !display::confirm(&format!("Send {} request(s) to Vultr?", api_requests.len())) {
        println!("Aborted; nothing sent.");
        return Ok(());
    }

    for req in &api_requests {
        match client.send::<FirewallRuleResponse>(req) {
            Ok(resp) => println!("Created rule id={}", resp.firewall_rule.id),
            Err(e) => println!("Failed: {e}"),
        }
    }

    Ok(())
}

fn cmd_remove(
    cli: &Cli,
    group_id: Option<&str>,
    group_description: Option<&str>,
    rule_ids: &[u64],
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let client = client_for(cli)?;
    let resolved_group_id = resolve_group(&client, cli, group_id, group_description)?;

    let api_requests: Vec<_> = rule_ids
        .iter()
        .map(|id| requests::delete_firewall_rule(&resolved_group_id, *id))
        .collect();

    println!("{} rule(s) would be deleted:\n", api_requests.len());
    if !cli.silent {
        for req in &api_requests {
            display::print_request(req, &cli.base_url);
        }
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

    for (id, req) in rule_ids.iter().zip(&api_requests) {
        match client.send_no_content(req) {
            Ok(()) => println!("Deleted rule id={id}"),
            Err(e) => println!("Failed to delete rule id={id}: {e}"),
        }
    }

    Ok(())
}
