#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if (($# == 0)); then
    java_output=$(cat)
elif (($# == 1)); then
    java_output=$(<"$1")
else
    echo "Usage: verify-output.sh [SMOKE_LOG]" >&2
    exit 64
fi

expected_target=${CAGEFORGE_JVM_EXPECTED_TARGET:-linux-x86_64}
expected_markers=(
    "native-target=$expected_target"
    'toml-validation=ok'
    'typed-errors=ok'
    'concurrent-instances=ok'
    'consumer-smoke=ok'
    'closed-handles=ok'
    'wait-kill=ok'
    'stream-kill=ok'
    'write-kill=ok'
    'close-kill=ok'
    'async-cancel=ok'
    'stdin-eof=ok'
    'stdio-routing=ok'
)

for marker in "${expected_markers[@]}"; do
    grep -F "$marker" <<<"$java_output"
done
