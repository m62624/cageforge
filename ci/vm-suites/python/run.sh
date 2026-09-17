#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

python_mount=${CAGEFORGE_PAYLOAD_PYTHON_WHEEL_MOUNT:?python-wheel payload is required}
python_dir=$(mktemp -d /tmp/cageforge-python-consumer.XXXXXX)
python_venv=$(mktemp -d /tmp/cageforge-python-venv.XXXXXX)
trap 'rm -rf "$python_dir" "$python_venv"' EXIT

tar --extract --file="$python_mount/payload" --directory="$python_dir" --no-same-owner
python3 -m venv "$python_venv"
shopt -s nullglob
wheels=("$python_dir"/*.whl)
if (( ${#wheels[@]} != 1 )); then
    echo "expected exactly one Python wheel, found ${#wheels[@]}" >&2
    exit 1
fi
"$python_venv/bin/python" -m pip install --no-index --no-deps "${wheels[0]}"
"$python_venv/bin/python" "$python_dir/run.py"
