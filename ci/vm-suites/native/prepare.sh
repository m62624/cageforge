#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root_dir=${CAGEFORGE_SOURCE_ROOT:?CAGEFORGE_SOURCE_ROOT is required}
fetch_dir=$(mktemp -d /tmp/cageforge-cargo-fetch.XXXXXX)
trap 'rm -rf "$fetch_dir"' EXIT
cd "$fetch_dir"
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
cargo fetch --locked --manifest-path "$root_dir/Cargo.toml"
