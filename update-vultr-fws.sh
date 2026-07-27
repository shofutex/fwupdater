#!/bin/bash
# Adds/refreshes "framework" firewall rules for the current public IP across
# every Vultr firewall group on the account, and removes stale ones.
#
# This is a thin wrapper around the `ipcheck` CLI (see ipcheck-cli/): all
# Vultr API traffic, IP detection, and request confirmation is handled by
# the binary, not this script.
set -euo pipefail

verbose=0
confirm=0
dry_run=0
ipcheck_bin="${IPCHECK_BIN:-}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-v] [-c] [-n] [-b PATH]
  -v  verbose: print each Vultr API request before sending it
  -c  confirm: ask for approval before each add/delete request is sent
  -n  dry-run: only print the requests that would be sent; never send them
  -b  path to the ipcheck binary (or set IPCHECK_BIN); default: search PATH,
      then <script_dir>/target/release/ipcheck, then .../target/debug/ipcheck
  -h  show this help
EOF
}

while getopts "vcnb:h" opt; do
    case "$opt" in
        v) verbose=1 ;;
        c) confirm=1 ;;
        n) dry_run=1 ;;
        b) ipcheck_bin="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${script_dir}/.env" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "${script_dir}/.env"
    set +a
fi

: "${VULTR_API_KEY:?VULTR_API_KEY must be set (Vultr API key, firewall-edit scope only)}"
if [[ "$VULTR_API_KEY" == REPLACE_ME* ]]; then
    echo "VULTR_API_KEY is still a placeholder — set the real key in ${script_dir}/.env" >&2
    exit 1
fi

# Resolve the ipcheck binary: -b flag, then IPCHECK_BIN (already applied
# above as the default), then PATH, then the usual cargo build output dirs.
if [[ -z "$ipcheck_bin" ]]; then
    if command -v ipcheck >/dev/null 2>&1; then
        ipcheck_bin="ipcheck"
    elif [[ -x "${script_dir}/target/release/ipcheck" ]]; then
        ipcheck_bin="${script_dir}/target/release/ipcheck"
    elif [[ -x "${script_dir}/target/debug/ipcheck" ]]; then
        ipcheck_bin="${script_dir}/target/debug/ipcheck"
    else
        echo "Could not locate the ipcheck binary; build it (cargo build --release)," \
            "or pass -b PATH, or set IPCHECK_BIN" >&2
        exit 1
    fi
fi
if ! command -v "$ipcheck_bin" >/dev/null 2>&1 && [[ ! -x "$ipcheck_bin" ]]; then
    echo "ipcheck binary not found or not executable: ${ipcheck_bin}" >&2
    exit 1
fi

NO_MATCH="__no-ipv6__" # sentinel so an empty mysubnet6 never accidentally matches a rule's subnet

# Global flags applied to every ipcheck invocation.
common_flags=()
[[ "$verbose" -eq 0 ]] && common_flags+=(-s)

# Flags applied only to mutating subcommands (add/remove).
mutate_flags=()
[[ "$confirm" -eq 0 ]] && mutate_flags+=(--yes)
[[ "$dry_run" -eq 1 ]] && mutate_flags+=(--dry-run)

run_ipcheck() {
    "$ipcheck_bin" "${common_flags[@]}" "$@"
}

# Runs add/remove, echoes their output (so -v/-c prompts and Created/Deleted
# lines are visible), and reports via $mutate_changed whether anything was
# actually sent (as opposed to skipped by --dry-run or declined at a -c
# prompt).
mutate_changed=0

run_mutation() {
    local output
    output=$(run_ipcheck "$@")
    echo "$output"
    if grep -qE '^(Created|Deleted) rule id=' <<<"$output"; then
        mutate_changed=1
    fi
}

detect_output=$(run_ipcheck detect)
myipv4=$(sed -n 's/^IPv4: //p' <<<"$detect_output")
myipv6=$(sed -n 's/^IPv6: //p' <<<"$detect_output")

if [[ "$myipv4" == "(not detected)" || -z "$myipv4" ]]; then
    echo "Could not detect a public IPv4 address" >&2
    exit 1
fi
if [[ "$myipv6" == "(none / not detected)" ]]; then
    myipv6=""
fi

mysubnet6="$NO_MATCH"
if [[ -n "$myipv6" ]]; then
    mysubnet6="$(awk -F: '{print $1":"$2":"$3":"$4}' <<<"$myipv6")::"
fi

mapfile -t firewall_ids < <(run_ipcheck groups | grep -oP 'id=\K\S+')

changed=0
attempted=0

for fw_id in "${firewall_ids[@]}"; do
    rules_output=$(run_ipcheck rules "$fw_id")
    framework_lines=$(grep 'notes=framework$' <<<"$rules_output" || true)

    has_current_rule=0
    extra_rule_ids=()
    if [[ -n "$framework_lines" ]]; then
        while IFS= read -r line; do
            subnet=$(grep -oP 'subnet=\K\S+' <<<"$line")
            id=$(grep -oP 'id=\K[0-9]+' <<<"$line")
            if [[ "$subnet" == "${myipv4}/32" ]] \
                || { [[ "$mysubnet6" != "$NO_MATCH" ]] && [[ "$subnet" == "${mysubnet6}/64" ]]; }; then
                has_current_rule=1
            else
                extra_rule_ids+=("$id")
            fi
        done <<<"$framework_lines"
    fi

    if [[ "$has_current_rule" -eq 0 ]]; then
        echo "[$fw_id] rules missing for current IP (${myipv4}${myipv6:+, $myipv6})"
        attempted=1
        run_mutation add "$fw_id" --ports 22,443 --note framework "${mutate_flags[@]}"
        [[ "$mutate_changed" -eq 1 ]] && changed=1
    fi

    if [[ "${#extra_rule_ids[@]}" -gt 0 ]]; then
        echo "[$fw_id] ${#extra_rule_ids[@]} stale rule(s) to delete"
        attempted=1
        run_mutation remove --group-id "$fw_id" "${mutate_flags[@]}" "${extra_rule_ids[@]}"
        [[ "$mutate_changed" -eq 1 ]] && changed=1
    fi
done

if [[ "$changed" -eq 1 ]]; then
    echo "Waiting for Vultr to apply firewall changes..."
    sleep 120
elif [[ "$attempted" -eq 1 ]]; then
    echo "Changes were pending but not sent (dry-run or declined)."
else
    echo "No changes needed — all firewall groups already have the current IP and no stale rules."
fi

echo "Complete"
