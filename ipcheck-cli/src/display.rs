use ipcheck_core::vultr::{ApiRequest, FirewallGroup, FirewallRule};

/// Prints everything about a request that a human needs to visually verify
/// it before it goes out: method, URL, JSON body, and an equivalent curl
/// command that can be copy-pasted and run by hand.
pub fn print_request(req: &ApiRequest, base_url: &str) {
    println!("---");
    println!("{} {}", req.method, req.url(base_url));
    if let Some(body) = &req.body {
        println!("Body:");
        println!("{}", serde_json::to_string_pretty(body).unwrap_or_default());
    }
    println!();
    println!("Equivalent curl:");
    println!("{}", req.to_curl(base_url));
    println!("---\n");
}

pub fn print_group(g: &FirewallGroup) {
    println!(
        "id={:<10} description={:<30} instances={:<4} rules={}/{} created={}",
        g.id, g.description, g.instance_count, g.rule_count, g.max_rule_count, g.date_created
    );
}

pub fn print_rule(r: &FirewallRule) {
    let source = if r.source.is_empty() { "-" } else { &r.source };
    println!(
        "id={:<8} action={:<8} type={:<3} proto={:<5} port={:<10} subnet={}/{:<3} source={:<10} notes={}",
        r.id, r.action, r.ip_type, r.protocol, r.port, r.subnet, r.subnet_size, source, r.notes
    );
}

/// Prompts the user with a yes/no question on stdin; anything other than an
/// explicit "y"/"yes" is treated as "no".
pub fn confirm(prompt: &str) -> bool {
    use std::io::{self, Write};
    print!("{prompt} [y/N] ");
    let _ = io::stdout().flush();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
