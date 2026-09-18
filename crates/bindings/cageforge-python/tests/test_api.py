"""The Python facade mirrors the public Java binding contract."""

from __future__ import annotations

import cageforge
import pytest

JAVA_TO_PYTHON = {
    "Cageforge": {
        "profileNames": "profile_names",
        "checkToml": "check_toml",
        "permissionRequest": "permission_request",
        "fromToml": "from_toml",
        "fromTomlFile": "from_toml_file",
        "nativeTarget": "native_target",
        "launch": "launch",
        "close": "close",
    },
    "SandboxProcess": {
        "id": "id",
        "hasStdin": "has_stdin",
        "hasStdout": "has_stdout",
        "hasStderr": "has_stderr",
        "readStdout": "read_stdout",
        "readStderr": "read_stderr",
        "writeStdin": "write_stdin",
        "closeStdin": "close_stdin",
        "tryWait": "try_wait",
        "waitFor": "wait_for",
        "kill": "kill",
        "close": "close",
    },
    "WindowsSetup": {
        "isSupported": "is_supported",
        "install": "install",
        "status": "status",
        "verify": "verify",
        "uninstall": "uninstall",
    },
    "PermissionApprover": {
        "approve": "approve",
    },
    "PermissionRequest": {
        "getJson": "json",
        "getToolId": "tool_id",
        "getToolVersion": "tool_version",
        "getPlatform": "platform",
        "getDigest": "digest",
        "getFilesystem": "filesystem",
        "getNetwork": "network",
        "close": "close",
    },
    "PermissionGrant": {
        "getRequestDigest": "request_digest",
        "getScope": "scope",
        "getExpiresAt": "expires_at",
        "close": "close",
    },
    "PermissionStore": {
        "open": "open",
        "get": "get",
        "put": "put",
        "path": "path",
        "close": "close",
    },
    "ProcessResult": {
        "getExitCode": "exit_code",
    },
    "RuntimeContext": {
        "getCurrentDirectory": "current_directory",
        "getMinimalPath": "minimal_path",
    },
}


def test_java_surface_has_a_python_spelling() -> None:
    for java_type, methods in JAVA_TO_PYTHON.items():
        python_type = getattr(cageforge, java_type)
        for java_name, python_name in methods.items():
            assert hasattr(python_type, python_name), (
                f"{java_type}.{java_name} is missing as {python_type.__name__}.{python_name}"
            )
    assert hasattr(cageforge, "wait_for_async")


def test_structured_errors_are_a_single_exported_hierarchy() -> None:
    concrete = (
        cageforge.CageforgeConfigurationError,
        cageforge.CageforgeInitializationError,
        cageforge.CageforgeLaunchError,
        cageforge.CageforgePermissionError,
        cageforge.CageforgeProcessError,
        cageforge.CageforgeStreamError,
        cageforge.CageforgeWindowsSetupError,
        cageforge.UnsupportedPlatformError,
    )
    assert all(issubclass(error, cageforge.CageforgeError) for error in concrete)
    assert all(error.__module__ == "cageforge._cageforge" for error in concrete)


def test_native_target_is_a_platform_architecture_pair() -> None:
    target = cageforge.native_target()
    assert target == cageforge.Cageforge.native_target()
    assert target.count("-") == 1


def test_windows_setup_matches_java_platform_behavior() -> None:
    if cageforge.WindowsSetup.is_supported():
        return
    with pytest.raises(cageforge.UnsupportedPlatformError):
        cageforge.WindowsSetup.status()
