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

"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/verify-output.sh" <<<"$java_output"
