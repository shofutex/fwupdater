#!/bin/bash
# Cross-compiles fwupdater-mobile for Android and generates the Kotlin
# bindings alongside the .so files, ready to drop into an Android Studio
# project's jniLibs/ directory.
#
# NOT runnable on a plain Linux box: requires the Android NDK and
# cargo-ndk. Install (one-time):
#   rustup target add aarch64-linux-android armv7-linux-androideabi \
#       x86_64-linux-android i686-linux-android
#   cargo install cargo-ndk
#   # ANDROID_NDK_HOME must point at an installed NDK (via Android Studio's
#   # SDK Manager, or `sdkmanager --install "ndk;27.0.12077973"`).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "${script_dir}/.." && pwd)"
out_dir="${1:-${crate_dir}/dist/android}"

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point at an installed Android NDK}"
command -v cargo-ndk >/dev/null || { echo "cargo-ndk not found; run: cargo install cargo-ndk" >&2; exit 1; }

echo "Building fwupdater_mobile for Android ABIs..."
cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
    -o "${out_dir}/jniLibs" \
    build --release --manifest-path "${crate_dir}/Cargo.toml"

echo "Generating Kotlin bindings..."
lib="${out_dir}/jniLibs/arm64-v8a/libfwupdater_mobile.so"
# uniffi.toml is picked up automatically since it sits next to Cargo.toml in
# the crate this library was built from; no --config flag needed (uniffi
# 0.32+ repurposed --config for a different, global-config-file format).
cargo run --manifest-path "${crate_dir}/Cargo.toml" --bin uniffi-bindgen --features uniffi/cli -- \
    generate --library "$lib" --language kotlin \
    --out-dir "${out_dir}/kotlin"

echo "Done. jniLibs: ${out_dir}/jniLibs, Kotlin sources: ${out_dir}/kotlin"
echo "Copy jniLibs/* into app/src/main/jniLibs/ and the generated .kt package into your sources."
