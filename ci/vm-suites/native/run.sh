#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root_dir=${CAGEFORGE_SOURCE_ROOT:?CAGEFORGE_SOURCE_ROOT is required}
cd "$root_dir"
export PATH=/home/ubuntu/.cargo/bin:$PATH
export RUST_BACKTRACE=1

cargo fmt --all -- --check
cargo clippy -p cageforge-bwrap --all-targets --locked -- -D warnings

echo 'Running the unified facade Clippy with automatic target backend selection.'
cargo clippy -p cageforge --no-default-features --all-targets --locked -- -D warnings

echo 'Running cageforge-linux Clippy without optional features.'
cargo clippy -p cageforge-linux --no-default-features --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests without optional features.'
cargo test -p cageforge-linux --no-default-features --locked

echo 'Running cageforge-linux Clippy with bundled-bubblewrap.'
cargo clippy -p cageforge-linux --features bundled-bubblewrap --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests with bundled-bubblewrap.'
cargo test -p cageforge-linux --features bundled-bubblewrap --locked

echo 'Running cageforge-linux Clippy with all features.'
cargo clippy -p cageforge-linux --all-features --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests with all features.'
cargo test -p cageforge-linux --all-features --locked

cargo test -p cageforge --no-default-features --locked

echo 'Running the CLI checks with the config feature.'
cargo clippy -p cageforge-cli --no-default-features --features config --all-targets --locked -- -D warnings
cargo test -p cageforge-cli --no-default-features --features config --locked
cargo doc -p cageforge-cli --no-default-features --features config --no-deps --locked

echo 'Running the CLI checks with the bundled Bubblewrap feature.'
cargo clippy -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --all-targets --locked -- -D warnings
cargo test -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --locked
cargo doc -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --no-deps --locked

echo 'Running the runnable configuration example after native checks.'
CAGEFORGE_RUNNABLE_OS=linux ci/run-runnable-example.sh
