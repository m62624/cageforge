#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

root_dir=${CAGEFORGE_SOURCE_ROOT:?CAGEFORGE_SOURCE_ROOT is required}
cd "$root_dir"
export PATH=/home/ubuntu/.cargo/bin:$PATH
export RUST_BACKTRACE=1

cargo fmt --all -- --check
cargo clippy -p cageforge-bwrap --all-targets --locked -- -D warnings

# Keep the trusted suite runnable while the target-backend refactor moves
# through the PR boundary. The old main branch exposes a `linux` selector;
# the refactored facade selects its backend from target_os and only needs the
# config feature for the CLI.
workspace_metadata=$(cargo metadata --no-deps --format-version 1)
if grep -Eq '"features":\{[^}]*"linux"' <<<"$workspace_metadata"; then
    facade_features=(--features linux)
    cli_features=(--features linux)
    echo 'Running the unified facade Clippy with the legacy Linux feature.'
else
    facade_features=()
    cli_features=(--features config)
    echo 'Running the unified facade Clippy with automatic target backend selection.'
fi
cargo clippy -p cageforge --no-default-features "${facade_features[@]}" --all-targets --locked -- -D warnings

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

if ((${#facade_features[@]})); then
    echo 'Running the unified facade tests with the legacy Linux feature.'
else
    echo 'Running the unified facade tests with automatic target backend selection.'
fi
cargo test -p cageforge --no-default-features "${facade_features[@]}" --locked

echo 'Running the CLI checks with the selected facade feature set.'
cargo clippy -p cageforge-cli --no-default-features "${cli_features[@]}" --all-targets --locked -- -D warnings
cargo test -p cageforge-cli --no-default-features "${cli_features[@]}" --locked
cargo doc -p cageforge-cli --no-default-features "${cli_features[@]}" --no-deps --locked

echo 'Running the CLI checks with the bundled Bubblewrap feature.'
cargo clippy -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --all-targets --locked -- -D warnings
cargo test -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --locked
cargo doc -p cageforge-cli --no-default-features --features linux-bundled-bubblewrap --no-deps --locked
