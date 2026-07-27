# fwupdater-mobile

UniFFI bindings exposing `fwupdater-core` to Kotlin (Android) and Swift (iOS),
mirroring the CLI's workflow:

```
detect_ips()  ->  list_groups() [picker]  ->  list_rules(group)
             ->  plan_add_rules(... note ...) [show for confirmation]
             ->  add_rules(...)
             ->  find_stale_rules(...)  ->  remove_rules(...)
```

Every `MobileClient` method makes a **blocking** HTTP call (same underlying
`reqwest::blocking` client as the CLI) - callers must invoke off their
main/UI thread, exactly like any blocking network SDK
(`Dispatchers.IO` in Kotlin, a detached `Task` in Swift).

## API surface

- `detectIps()` - this device's public IPv4/IPv6.
- `MobileClient(apiKey)` / `.withBaseUrl(apiKey, baseUrl)` - construct a client.
- `client.listGroups()` - back a group picker with these (no separate
  "resolve by description" call like the CLI has - on mobile, a picker list
  *is* the description-lookup UI).
- `client.listRules(groupId)` - existing rules in a group.
- `planAddRules(ips, ports, note, ipv6PrefixLen, ipv4Only, ipv6Only)` - pure,
  no network; builds the rules that *would* be created, for a confirmation
  screen (mirrors the CLI's print-before-send step). `defaultPorts()`
  (22/80/443) and `defaultIpv6PrefixLen()` (64) give the same defaults the
  CLI uses.
- `client.addRules(groupId, planned)` - sends the (user-confirmed) planned
  rules; returns one `AddRuleResult` per rule so a single failure doesn't
  hide the others that succeeded.
- `findStaleRules(rules, ips, notes, ipv6PrefixLen)` - pure, no network;
  finds rules tagged with your app's note whose subnet no longer matches
  this device's current IP (i.e. left over from a previous address).
- `client.removeRules(groupId, ruleIds)` - deletes rules by ID; one
  `RemoveRuleResult` per ID.

See `examples/android/ExampleUsage.kt` / `examples/ios/ExampleUsage.swift`
for a full call sequence, written against the actual generated bindings.

## Pipeline

1. **Build the Rust library for your target** - `scripts/build-android.sh`
   (needs the Android NDK + `cargo-ndk`) or `scripts/build-ios.sh` (macOS +
   Xcode only). Both also invoke step 2 for you.
2. **Generate bindings** - `cargo run --bin uniffi-bindgen --features
   uniffi/cli -- generate --config uniffi.toml --library <path-to-lib>
   --language kotlin|swift --out-dir <dir>`. This step doesn't need a
   mobile toolchain: it reads metadata embedded in the compiled library by
   the `uniffi::export` macros, so it can run against a native build on any
   OS - only the *cross-compiling* in step 1 needs the real toolchains.
3. **Wire into your app** - Android: copy the generated `.so`s into
   `app/src/main/jniLibs/<abi>/` and the generated Kotlin source into your
   module. iOS: add the generated `.xcframework` and Swift source to your
   Xcode project (or a local Swift Package).

Rename the placeholder Kotlin package (`com.example.fwupdater`) in
`uniffi.toml` to match your app before generating bindings for real use.

## What's been verified vs. not

Verified in this repo's dev environment (no Android/iOS toolchain
available here):
- `cargo build -p fwupdater-mobile` / `cargo test` / `cargo clippy` all pass.
- `uniffi-bindgen` was actually run (`--language kotlin` and `--language
  swift`, against a native Linux build) and produced real, inspected
  binding source - the example usage files above were written by reading
  those generated signatures, not guessed.

Not runnable/verified here, and left for you to run:
- Cross-compiling for Android ABIs or iOS device/simulator targets
  (`scripts/build-android.sh` / `scripts/build-ios.sh`).
- Compiling the generated Kotlin/Swift in a real Gradle/Xcode project.
- Running on a device or simulator.
