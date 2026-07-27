// Reference usage of the generated Swift bindings (module name set by
// fwupdater-mobile/uniffi.toml - "Fwupdater" below matches that config). Not
// part of the build; illustrates the workflow against the actual generated
// API (verified by generating real bindings and reading their signatures,
// not guessed).
//
// Every MobileClient call is a blocking network request - always invoke
// from a detached Task or a background actor, never from the main actor.

import Foundation
import Fwupdater

final class FirewallUpdateWorkflow {
    // One client per workflow instance (e.g. per screen) - it holds the
    // underlying HTTP client, so it's created once and reused rather than
    // per call.
    private let client: MobileClient

    init(apiKey: String) throws {
        client = try MobileClient(apiKey: apiKey)
    }

    // 1. Detect this device's current public IP address(es).
    func detect() async -> DetectedIps {
        await Task.detached { detectIps() }.value
    }

    // 2. List firewall groups to back a picker ("select the group to add").
    func listGroups() async throws -> [FirewallGroup] {
        try await Task.detached { try self.client.listGroups() }.value
    }

    // 3. List the rules already in the group the user picked.
    func listRules(groupId: String) async throws -> [FirewallRule] {
        try await Task.detached { try self.client.listRules(groupId: groupId) }.value
    }

    // 4. Build the rules that *would* be created (pure, no network) so the
    //    UI can show a confirmation screen before anything is sent - `note`
    //    is the custom label the user typed in.
    func planAdd(ips: DetectedIps, ports: [UInt16] = defaultPorts(), note: String) throws -> [PlannedRule] {
        try planAddRules(
            ips: ips,
            ports: ports,
            note: note,
            ipv6PrefixLen: defaultIpv6PrefixLen(),
            ipv4Only: false,
            ipv6Only: false
        )
    }

    // 5. After the user confirms the plan from step 4, actually send it.
    //    One result per planned rule, so a single failure doesn't hide the
    //    others that succeeded.
    func confirmAdd(groupId: String, planned: [PlannedRule]) async -> [AddRuleResult] {
        await Task.detached { self.client.addRules(groupId: groupId, planned: planned) }.value
    }

    // 6. Find rules tagged with this app's note that no longer match the
    //    device's current IP - i.e. stale rules left over from a previous
    //    address - so the UI can offer to delete them.
    func findStale(rules: [FirewallRule], ips: DetectedIps, note: String) throws -> [FirewallRule] {
        try findStaleRules(rules: rules, ips: ips, notes: note, ipv6PrefixLen: defaultIpv6PrefixLen())
    }

    // 7. Delete the stale rules the user selected.
    func removeStale(groupId: String, staleRuleIds: [UInt64]) async -> [RemoveRuleResult] {
        await Task.detached { self.client.removeRules(groupId: groupId, ruleIds: staleRuleIds) }.value
    }
}

// Example end-to-end call sequence (e.g. from a view model):
//
//   let workflow = try FirewallUpdateWorkflow(apiKey: apiKey)
//   let ips = await workflow.detect()
//   let groups = try await workflow.listGroups()             // show a picker
//   let group = groups.first { $0.description == "mycloud" }!
//   let existingRules = try await workflow.listRules(groupId: group.id)
//   let planned = try workflow.planAdd(ips: ips, note: "my-phone")
//   // ... show `planned` to the user for confirmation ...
//   let addResults = await workflow.confirmAdd(groupId: group.id, planned: planned)
//   let stale = try workflow.findStale(rules: existingRules, ips: ips, note: "my-phone")
//   // ... show `stale` to the user, they pick which to delete ...
//   let removeResults = await workflow.removeStale(groupId: group.id, staleRuleIds: stale.map { $0.id })
