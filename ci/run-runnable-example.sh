#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root_dir=$(git rev-parse --show-toplevel)
cd "$root_dir"

case "${CAGEFORGE_RUNNABLE_OS:-}" in
  linux)
    echo 'Running the Linux runnable configuration example.'
    output=$(cargo run --locked --release -p cageforge-cli \
      --no-default-features --features linux-bundled-bubblewrap -- \
      run --approve \
      --config crates/cageforge-config/examples/runnable/linux/smoke.toml)
    grep -Fx 'cageforge-linux-smoke' <<<"$output"
    ;;
  macos)
    echo 'Running the macOS runnable configuration example.'
    output=$(cargo run --locked --release -p cageforge-cli \
      --no-default-features --features config -- \
      run --approve \
      --config crates/cageforge-config/examples/runnable/macos/smoke.toml)
    grep -Fx 'cageforge-macos-smoke' <<<"$output"
    ;;
  windows)
    echo 'Building the Windows runnable example and native helpers.'
    cargo build --locked --release -p cageforge-cli \
      --no-default-features --features config
    cargo build --locked --release -p cageforge-windows --bins \
      --features bundled-helpers
    echo 'Installing the Windows native setup for the runnable example.'
    target/release/cageforge-cli.exe setup install
    echo 'Running the Windows runnable configuration example.'
    output=$(target/release/cageforge-cli.exe run --approve \
      --config crates/cageforge-config/examples/runnable/windows/smoke.toml)
    grep -Fx 'cageforge-windows-smoke' <<<"$output"
    ;;
  *)
    echo 'CAGEFORGE_RUNNABLE_OS must be linux, macos, or windows' >&2
    exit 64
    ;;
esac
