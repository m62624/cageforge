"""Native Python consumer smoke tests run on the same target matrix as Java."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest
from cageforge import Cageforge, CageforgeProcessError

ROOT = Path(__file__).resolve().parents[4]


def smoke_config() -> Path:
    if sys.platform == "win32":
        return ROOT / "crates/cageforge-config/examples/runnable/windows/smoke.toml"
    if sys.platform == "darwin":
        return ROOT / "crates/cageforge-config/examples/runnable/macos/smoke.toml"
    return ROOT / "crates/cageforge-config/examples/runnable/linux/smoke.toml"


def require_linux_guest() -> None:
    if sys.platform == "linux" and not os.environ.get("CAGEFORGE_PYTHON_NATIVE_SMOKE"):
        pytest.skip("Linux native consumer runs in the dedicated QEMU guest")


def test_native_profile_launch_and_streams() -> None:
    require_linux_guest()
    runtime = Cageforge.from_toml_file(smoke_config())
    try:
        process = runtime.launch()
        try:
            result = process.wait()
            assert result.exit_code == 0
            assert process.has_stdout()
            assert process.read_stdout(4096)
        finally:
            process.close()
            process.close()
        with pytest.raises(CageforgeProcessError):
            process.id()
    finally:
        runtime.close()


def test_wait_releases_the_gil() -> None:
    require_linux_guest()
    runtime = Cageforge.from_toml_file(smoke_config())
    try:
        if sys.platform == "win32":
            argv = [
                r"C:\Windows\System32\cmd.exe",
                "/d",
                "/c",
                "ping",
                "127.0.0.1",
                "-n",
                "3",
                ">nul",
            ]
        else:
            argv = ["/bin/sh", "-c", "sleep 1"]
        process = runtime.launch(argv)
        completed = threading.Event()

        def waiter() -> None:
            try:
                assert process.wait().exit_code == 0
            finally:
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
