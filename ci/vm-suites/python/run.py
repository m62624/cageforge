#!/usr/bin/env python3
"""Python wheel consumer executed inside the native QEMU guest."""

import atexit
import json
import shutil
import tempfile
import threading
import time
from pathlib import Path

from cageforge import Cageforge, RuntimeContext


smoke_directory = Path(tempfile.mkdtemp(prefix="cageforge-python-smoke-")).resolve()
atexit.register(shutil.rmtree, smoke_directory, ignore_errors=True)
minimal_path = smoke_directory / ".cageforge-test-runtime"
minimal_path.mkdir()
workspace_root = json.dumps(str(smoke_directory))

config = f"""
default_profile = "smoke"

[profiles.smoke]
workspace_roots = {{{workspace_root} = true}}

[profiles.smoke.filesystem]
mode = "restricted"
rules = [
  {{ target = "minimal", access = "read" }},
  {{ target = "workspace-root", access = "write" }},
]

[profiles.smoke.network]
mode = "disabled"
"""

Cageforge.check_toml(
    config, context=RuntimeContext(smoke_directory, minimal_path)
)
runtime = Cageforge.from_toml(
    config, context=RuntimeContext(smoke_directory, minimal_path)
)
try:
    process = runtime.launch(["/bin/echo", "cageforge-python-smoke"])
    try:
        result = process.wait()
        assert result.exit_code == 0
        assert b"cageforge-python-smoke" in process.read_stdout(4096)
    finally:
        process.close()
finally:
    runtime.close()

runtime = Cageforge.from_toml(
    config, context=RuntimeContext(smoke_directory, minimal_path)
)
try:
    process = runtime.launch(["/bin/sh", "-c", "sleep 1"])
    completed = threading.Event()

    def waiter() -> None:
        process.wait()
        completed.set()

    thread = threading.Thread(target=waiter)
    thread.start()
    counter = 0
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        counter += 1
    assert counter > 1_000
    process.kill()
    thread.join(timeout=5)
    assert completed.is_set()
    process.close()
finally:
    runtime.close()

print("python-consumer-smoke=ok")
