#!/bin/bash
# Adds/refreshes "framework" firewall rules for the current public IP across
# every Vultr firewall group on the account, and removes stale ones.
#
# This is a thin wrapper around the `fwupdater` CLI (see fwupdater-cli/): all
# Vultr API traffic, IP detection, and request confirmation is handled by
# the binary, not this script.
set -euo pipefail

verbose=0
confirm=0
dry_run=0
fwupdater_bin="${FWUPDATER_BIN:-}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-v] [-c] [-n] [-b PATH]
  -v  verbose: print each Vultr API request before sending it
  -c  confirm: ask for approval before each add/delete request is sent
  -n  dry-run: only print the requests that would be sent; never send them
  -b  path to the fwupdater binary (or set FWUPDATER_BIN); default: search PATH,
      then <script_dir>/target/release/fwupdater, then .../target/debug/fwupdater
  -h  show this help
EOF
}

while getopts "vcnb:h" opt; do
    case "$opt" in
        v) verbose=1 ;;
        c) confirm=1 ;;
        n) dry_run=1 ;;
        b) fwupdater_bin="$OPTARG" ;;
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

# Resolve the fwupdater binary: -b flag, then FWUPDATER_BIN (already applied
# above as the default), then PATH, then the usual cargo build output dirs.
if [[ -z "$fwupdater_bin" ]]; then
    if command -v fwupdater >/dev/null 2>&1; then
        fwupdater_bin="fwupdater"
    elif [[ -x "${script_dir}/target/release/fwupdater" ]]; then
        fwupdater_bin="${script_dir}/target/release/fwupdater"
    elif [[ -x "${script_dir}/target/debug/fwupdater" ]]; then
        fwupdater_bin="${script_dir}/target/debug/fwupdater"
    else
        echo "Could not locate the fwupdater binary; build it (cargo build --release)," \
            "or pass -b PATH, or set FWUPDATER_BIN" >&2
        exit 1
    fi
fi
if ! command -v "$fwupdater_bin" >/dev/null 2>&1 && [[ ! -x "$fwupdater_bin" ]]; then
    echo "fwupdater binary not found or not executable: ${fwupdater_bin}" >&2
    exit 1
fi

NO_MATCH="__no-ipv6__" # sentinel so an empty mysubnet6 never accidentally matches a rule's subnet

# Global flags applied to every fwupdater invocation.
common_flags=()
[[ "$verbose" -eq 1 ]] && common_flags+=(-c)

# Flags applied only to mutating subcommands (add/remove).
mutate_flags=()
[[ "$confirm" -eq 0 ]] && mutate_flags+=(--yes)
[[ "$dry_run" -eq 1 ]] && mutate_flags+=(--dry-run)

run_fwupdater() {
    "$fwupdater_bin" "${common_flags[@]}" "$@"
}

# Runs add/remove, echoes their output (so -v/-c prompts and Created/Deleted
# lines are visible), and reports via $mutate_changed whether anything was
# actually sent (as opposed to skipped by --dry-run or declined at a -c
# prompt).
mutate_changed=0

run_mutation() {
    local output
    output=$(run_fwupdater "$@")
    echo "$output"
    if grep -qE '^(Created|Deleted) rule id=' <<<"$output"; then
        mutate_changed=1
    fi
}

detect_output=$(run_fwupdater detect)
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

mapfile -t firewall_ids < <(run_fwupdater groups | grep -oP 'id=\K\S+')

changed=0
attempted=0

for fw_id in "${firewall_ids[@]}"; do
    rules_output=$(run_fwupdater rules "$fw_id")
    framework_lines=$(grep 'notes=framework$' <<<"$rules_output" || true)

    have_v4=0
    have_v6=0
    extra_rule_ids=()
    if [[ -n "$framework_lines" ]]; then
        while IFS= read -r line; do
            subnet=$(grep -oP 'subnet=\K\S+' <<<"$line")
            id=$(grep -oP 'id=\K[0-9]+' <<<"$line")
            if [[ "$subnet" == "${myipv4}/32" ]]; then
                have_v4=1
            elif [[ "$mysubnet6" != "$NO_MATCH" ]] && [[ "$subnet" == "${mysubnet6}/64" ]]; then
                have_v6=1
            else
                extra_rule_ids+=("$id")
            fi
        done <<<"$framework_lines"
    fi

    # Track v4/v6 independently: an existing rule for one family must not
    # suppress creating the missing rule for the other. IPv6 is only "needed"
    # when this machine actually has one.
    need_v4=$(( have_v4 == 0 ? 1 : 0 ))
    need_v6=0
    [[ "$have_v6" -eq 0 && "$mysubnet6" != "$NO_MATCH" ]] && need_v6=1

    if [[ "$need_v4" -eq 1 && "$need_v6" -eq 1 ]]; then
        echo "[$fw_id] rules missing for current IP (${myipv4}, ${myipv6})"
        attempted=1
        run_mutation add "$fw_id" --ports 22,443 --note framework "${mutate_flags[@]}"
        [[ "$mutate_changed" -eq 1 ]] && changed=1
    elif [[ "$need_v4" -eq 1 ]]; then
        echo "[$fw_id] IPv4 rule missing for current IP (${myipv4})"
        attempted=1
        run_mutation add "$fw_id" --ports 22,443 --note framework --ipv4-only "${mutate_flags[@]}"
        [[ "$mutate_changed" -eq 1 ]] && changed=1
    elif [[ "$need_v6" -eq 1 ]]; then
        echo "[$fw_id] IPv6 rule missing for current IP (${myipv6})"
        attempted=1
        run_mutation add "$fw_id" --ports 22,443 --note framework --ipv6-only "${mutate_flags[@]}"
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
