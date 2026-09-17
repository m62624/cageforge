"""Python facade for the Cageforge cross-platform sandbox."""

import asyncio

from ._cageforge import (
    Cageforge,
    CageforgeConfigurationError,
    CageforgeError,
    CageforgeInitializationError,
    CageforgeLaunchError,
    CageforgePermissionError,
    CageforgeProcessError,
    CageforgeStreamError,
    CageforgeWindowsSetupError,
    PermissionApprover,
    PermissionGrant,
    PermissionRequest,
    ProcessResult,
    RuntimeContext,
    SandboxProcess,
    UnsupportedPlatformError,
    WindowsSetup,
    native_target,
)

__all__ = [
    "Cageforge",
    "CageforgeConfigurationError",
    "CageforgeError",
    "CageforgeInitializationError",
    "CageforgeLaunchError",
    "CageforgePermissionError",
    "CageforgeProcessError",
    "CageforgeStreamError",
    "CageforgeWindowsSetupError",
    "PermissionApprover",
    "PermissionGrant",
    "PermissionRequest",
    "ProcessResult",
    "RuntimeContext",
    "SandboxProcess",
    "UnsupportedPlatformError",
    "WindowsSetup",
    "native_target",
    "wait_for_async",
]


async def wait_for_async(process: SandboxProcess) -> ProcessResult:
    """Wait for a process without blocking the current asyncio event loop."""

    wait_task = asyncio.create_task(asyncio.to_thread(process.wait))
    try:
        return await wait_task
    except asyncio.CancelledError:
        try:
            await asyncio.to_thread(process.kill)
        except CageforgeError:
            pass
        raise
