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
    # This is a configuration smoke, not a release-artifact test. The native
    # Windows job has already compiled and tested the same sources; rebuilding
    # both packages with --release here needlessly starts a second cold build
    # and can make the runnable check look hung on hosted runners.
    echo 'Building the Windows runnable example and native helpers (debug profile).'
    cargo build --locked -p cageforge-cli \
      --no-default-features --features config
    cargo build --locked -p cageforge-windows --bins \
      --features bundled-helpers
    echo 'Installing the Windows native setup for the runnable example.'
    target/debug/cageforge-cli.exe setup install
    echo 'Running the Windows runnable configuration example.'
    output=$(target/debug/cageforge-cli.exe run --approve \
      --config crates/cageforge-config/examples/runnable/windows/smoke.toml)
    grep -Fx 'cageforge-windows-smoke' <<<"$output"
    ;;
  *)
    echo 'CAGEFORGE_RUNNABLE_OS must be linux, macos, or windows' >&2
    exit 64
    ;;
esac
