#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

echo '[cageforge] suite native: installing Rust toolchain'
runuser -u ubuntu -- env HOME=/home/ubuntu bash -c \
    "curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
runuser -u ubuntu -- env HOME=/home/ubuntu PATH=/home/ubuntu/.cargo/bin:$PATH \
    rustup component add clippy rustfmt
