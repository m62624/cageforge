"""Native Python consumer smoke tests run on the same target matrix as Java."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from cageforge import (
    Cageforge,
    CageforgeProcessError,
    PermissionApprover,
    PermissionGrant,
    PermissionStore,
    RuntimeContext,
    WindowsSetup,
    wait_for_async,
)

ROOT = Path(__file__).resolve().parents[4]


def smoke_config() -> Path:
    if sys.platform == "win32":
        return ROOT / "crates/cageforge-config/examples/runnable/windows/smoke.toml"
    if sys.platform == "darwin":
        return ROOT / "crates/cageforge-config/examples/runnable/macos/smoke.toml"
    return ROOT / "crates/cageforge-config/examples/runnable/linux/smoke.toml"


def smoke_toml() -> str:
    """Read TOML bytes without newline normalization on Windows."""
    return smoke_config().read_bytes().decode("utf-8")


def toml_for_argv(argv: list[str]) -> str:
    source = smoke_toml()
    prefix, separator, _command = source.partition("[profiles.smoke.command]")
    assert separator
    return (
        prefix
        + separator
        + "\nprogram = "
        + json.dumps(argv[0])
        + "\nargs = "
        + json.dumps(argv[1:])
        + "\n"
    )


def require_linux_guest() -> None:
    if sys.platform == "linux" and not os.environ.get("CAGEFORGE_PYTHON_NATIVE_SMOKE"):
        pytest.skip("Linux native consumer runs in the dedicated QEMU guest")


def ensure_windows_setup() -> None:
    if sys.platform == "win32":
        if WindowsSetup.status() != "ready":
            WindowsSetup.install()
        WindowsSetup.verify()


def runtime_context(tmp_path: Path) -> RuntimeContext:
    minimal_path = tmp_path / "minimal"
    minimal_path.mkdir()
    return RuntimeContext(tmp_path, minimal_path)


def smoke_argv() -> list[str]:
    if sys.platform == "win32":
        return [
            "C:/Windows/System32/cmd.exe",
            "/d",
            "/c",
            "echo",
            "cageforge-python-native",
        ]
    return ["/bin/echo", "cageforge-python-native"]


def smoke_grant(toml: str, context: RuntimeContext) -> PermissionGrant:
    request = Cageforge.permission_request(toml, context=context)
    return PermissionApprover().approve(request)


def long_running_argv() -> list[str]:
    if sys.platform == "win32":
        return [
            "C:/Windows/System32/cmd.exe",
            "/d",
            "/c",
            "ping",
            "127.0.0.1",
            "-n",
            "30",
            ">nul",
        ]
    return ["/bin/sh", "-c", "sleep 30"]


def test_persistent_grant_store_uses_the_explicit_path(tmp_path: Path) -> None:
    context = runtime_context(tmp_path)
    request = Cageforge.permission_request(smoke_toml(), context=context)
    grant = PermissionApprover().approve(request, scope="persistent")
    path = tmp_path / "host-state" / "permissions.json"
    store = PermissionStore(path)
    assert store.path() == str(path)
    store.put(grant, request)
    cached = store.get(request)
    assert cached is not None
    assert cached.request_digest() == request.digest()


def test_native_profile_launch_and_streams(tmp_path: Path) -> None:
    require_linux_guest()
    ensure_windows_setup()
    context = runtime_context(tmp_path)
    toml = smoke_toml()
    runtime = Cageforge.from_toml_file(
        smoke_config(), context=context, grant=smoke_grant(toml, context)
    )
    try:
        process = runtime.launch(smoke_argv())
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


def test_wait_releases_the_gil(tmp_path: Path) -> None:
    require_linux_guest()
    ensure_windows_setup()
    context = runtime_context(tmp_path)
    argv = (
        [
            "C:/Windows/System32/cmd.exe",
            "/d",
            "/c",
            "ping",
            "127.0.0.1",
            "-n",
            "3",
            ">nul",
        ]
        if sys.platform == "win32"
        else ["/bin/sh", "-c", "sleep 1"]
    )
    toml = toml_for_argv(argv)
    runtime = Cageforge.from_toml(
        toml, context=context, grant=smoke_grant(toml, context)
    )
    try:
        process = runtime.launch(argv)
        completed = threading.Event()
        wait_result: list[int | None] = []

        def waiter() -> None:
            try:
                wait_result.append(process.wait().exit_code)
            finally:
                completed.set()

        thread = threading.Thread(target=waiter)
        thread.start()
        counter = 0
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline:
            counter += 1
        assert counter > 1_000
        thread.join(timeout=5)
        if not completed.is_set():
            process.kill()
            thread.join(timeout=5)
        assert completed.is_set()
        assert wait_result and wait_result[0] in (0, None)
        process.close()
    finally:
        runtime.close()


def test_async_wait_cancellation_terminates_the_process(tmp_path: Path) -> None:
    require_linux_guest()
    ensure_windows_setup()
    context = runtime_context(tmp_path)
    argv = long_running_argv()
    toml = toml_for_argv(argv)
    runtime = Cageforge.from_toml(
        toml, context=context, grant=smoke_grant(toml, context)
    )
    process = runtime.launch(argv)
    try:
        async def cancel_wait() -> None:
            task = asyncio.create_task(wait_for_async(process))
            await asyncio.sleep(0.1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(cancel_wait())
        deadline = time.monotonic() + 5
        while process.try_wait() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        result = process.try_wait()
        assert result is not None
        assert result.exit_code is None
    finally:
        process.close()
        runtime.close()
