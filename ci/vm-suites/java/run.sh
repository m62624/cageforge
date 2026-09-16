#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

java_mount=${CAGEFORGE_PAYLOAD_JAVA_SMOKE_MOUNT:?java-smoke payload is required}
java_dir=/home/ubuntu/cageforge-java-consumer-smoke

rm -rf "$java_dir"
mkdir -p "$java_dir"
tar --extract --file="$java_mount/payload" --directory="$java_dir" --no-same-owner

java_cache=$(mktemp -d /tmp/cageforge-java-native-cache.XXXXXX)
java_output=$(JAVA_OPTS="-Dcageforge.native.cache=$java_cache" \
    "$java_dir/cageforge-java-consumer-smoke/bin/cageforge-java-consumer-smoke")
printf '%s\n' "$java_output"

expected_markers=(
    'native-target=linux-x86_64'
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
