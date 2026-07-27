#!/bin/bash
# Cross-compiles fwupdater-mobile for iOS (device + simulator), assembles an
# .xcframework, and generates the Swift bindings, ready to add to an Xcode
# project.
#
# Mac-only (needs Xcode's toolchain: xcodebuild, lipo). Install (one-time):
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "${script_dir}/.." && pwd)"
out_dir="${1:-${crate_dir}/dist/ios}"
lib_name="libfwupdater_mobile.a"

command -v xcodebuild >/dev/null || { echo "xcodebuild not found; this script must run on macOS with Xcode installed" >&2; exit 1; }

echo "Building fwupdater_mobile for iOS device + simulator..."
cargo build --release --manifest-path "${crate_dir}/Cargo.toml" --target aarch64-apple-ios
cargo build --release --manifest-path "${crate_dir}/Cargo.toml" --target aarch64-apple-ios-sim

echo "Generating Swift bindings..."
bindings_dir="${out_dir}/bindings"
mkdir -p "$bindings_dir"
cargo run --manifest-path "${crate_dir}/Cargo.toml" --bin uniffi-bindgen --features uniffi/cli -- \
    generate --config "${crate_dir}/uniffi.toml" \
    --library "${crate_dir}/../target/aarch64-apple-ios/release/${lib_name}" \
    --language swift --out-dir "$bindings_dir"

# uniffi names the header/modulemap after the configured Swift module name.
header_dir="${out_dir}/headers"
mkdir -p "$header_dir"
mv "$bindings_dir"/*.h "$header_dir"/
mv "$bindings_dir"/*.modulemap "$header_dir"/module.modulemap

echo "Assembling .xcframework..."
rm -rf "${out_dir}/FwupdaterMobile.xcframework"
xcodebuild -create-xcframework \
    -library "${crate_dir}/../target/aarch64-apple-ios/release/${lib_name}" -headers "$header_dir" \
    -library "${crate_dir}/../target/aarch64-apple-ios-sim/release/${lib_name}" -headers "$header_dir" \
    -output "${out_dir}/FwupdaterMobile.xcframework"

echo "Done. Swift sources: ${bindings_dir}, xcframework: ${out_dir}/FwupdaterMobile.xcframework"
echo "Add both to your Xcode project (or a local Swift Package) to use them."
