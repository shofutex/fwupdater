// Reference usage of the generated Kotlin bindings (package name set by
// fwupdater-mobile/uniffi.toml - rename it there to match your app, then this
// import changes to match). Not part of the build; illustrates the workflow
// against the actual generated API (verified by generating real bindings
// and reading their signatures, not guessed).
//
// Every MobileClient call is a blocking network request - always invoke
// from a coroutine on Dispatchers.IO, never on the main thread.

package com.example.fwupdater.example

import com.example.fwupdater.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class FirewallUpdateWorkflow(apiKey: String) : AutoCloseable {
    // One client per workflow instance (e.g. per screen/ViewModel) - it
    // holds the underlying HTTP client, so it's created once and reused
    // rather than per call.
    private val client = MobileClient(apiKey)

    override fun close() = client.close()

    // 1. Detect this device's current public IP address(es).
    suspend fun detect(): DetectedIps = withContext(Dispatchers.IO) {
        detectIps()
    }

    // 2. List firewall groups to back a picker ("select the group to add").
    suspend fun listGroups(): List<FirewallGroup> = withContext(Dispatchers.IO) {
        client.listGroups()
    }

    // 3. List the rules already in the group the user picked.
    suspend fun listRules(groupId: String): List<FirewallRule> = withContext(Dispatchers.IO) {
        client.listRules(groupId)
    }

    // 4. Build the rules that *would* be created (pure, no network) so the
    //    UI can show a confirmation screen before anything is sent -
    //    `note` is the custom label the user typed in.
    fun planAdd(ips: DetectedIps, ports: List<UShort> = defaultPorts(), note: String): List<PlannedRule> =
        planAddRules(
            ips = ips,
            ports = ports,
            note = note,
            ipv6PrefixLen = defaultIpv6PrefixLen(),
            ipv4Only = false,
            ipv6Only = false,
        )

    // 5. After the user confirms the plan from step 4, actually send it.
    //    One result per planned rule, so a single failure doesn't hide the
    //    others that succeeded.
    suspend fun confirmAdd(groupId: String, planned: List<PlannedRule>): List<AddRuleResult> =
        withContext(Dispatchers.IO) {
            client.addRules(groupId, planned)
        }

    // 6. Find rules tagged with this app's note that no longer match the
    //    device's current IP - i.e. stale rules left over from a previous
    //    address - so the UI can offer to delete them.
    fun findStale(rules: List<FirewallRule>, ips: DetectedIps, note: String): List<FirewallRule> =
        findStaleRules(rules, ips, note, defaultIpv6PrefixLen())

    // 7. Delete the stale rules the user selected.
    suspend fun removeStale(groupId: String, staleRuleIds: List<ULong>): List<RemoveRuleResult> =
        withContext(Dispatchers.IO) {
            client.removeRules(groupId, staleRuleIds)
        }
}

// Example end-to-end call sequence (e.g. from a ViewModel that owns the
// workflow and closes it in onCleared()):
//
//   val workflow = FirewallUpdateWorkflow(apiKey)
//   val ips = workflow.detect()
//   val groups = workflow.listGroups()                 // show a picker
//   val group = groups.first { it.description == "mycloud" }
//   val existingRules = workflow.listRules(group.id)
//   val planned = workflow.planAdd(ips, note = "my-phone")
//   // ... show `planned` to the user for confirmation ...
//   val addResults = workflow.confirmAdd(group.id, planned)
//   val stale = workflow.findStale(existingRules, ips, note = "my-phone")
//   // ... show `stale` to the user, they pick which to delete ...
//   val removeResults = workflow.removeStale(group.id, stale.map { it.id })
//   workflow.close()
