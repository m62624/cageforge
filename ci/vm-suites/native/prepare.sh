#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# rustup installs the toolchain for the guest user rather than system-wide.
# The SSH command used by the VM driver does not inherit the bootstrap shell's
# PATH, so make Cargo available explicitly during dependency preparation.
export PATH=/home/ubuntu/.cargo/bin:$PATH

root_dir=${CAGEFORGE_SOURCE_ROOT:?CAGEFORGE_SOURCE_ROOT is required}
fetch_dir=$(mktemp -d /tmp/cageforge-cargo-fetch.XXXXXX)
trap 'rm -rf "$fetch_dir"' EXIT
cd "$fetch_dir"
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
cargo fetch --locked --manifest-path "$root_dir/Cargo.toml"
