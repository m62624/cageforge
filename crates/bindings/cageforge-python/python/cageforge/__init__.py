"""Python facade for the Cageforge cross-platform sandbox."""

import asyncio

from ._cageforge import (
    Cageforge,
    CageforgeConfigurationError,
    CageforgeError,
    CageforgeGrantNotFoundError,
    CageforgeInitializationError,
    CageforgeInvalidCursorError,
    CageforgeInvalidGrantIdError,
    CageforgeInvalidPageSizeError,
    CageforgeLaunchError,
    CageforgeListingSnapshotExpiredError,
    CageforgePermissionError,
    CageforgeProcessError,
    CageforgeStoreError,
    CageforgeStoreFormatError,
    CageforgeStoreLockedError,
    CageforgeStorePathError,
    CageforgeStoreReadError,
    CageforgeStoreWriteError,
    CageforgeStreamError,
    CageforgeWindowsSetupError,
    GrantId,
    GrantPage,
    GrantPageCursor,
    GrantSummary,
    PermissionApprover,
    PermissionGrant,
    PermissionRequest,
    PermissionStore,
    ProcessResult,
    RevokeResult,
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
    "CageforgeGrantNotFoundError",
    "CageforgeInitializationError",
    "CageforgeInvalidCursorError",
    "CageforgeInvalidGrantIdError",
    "CageforgeInvalidPageSizeError",
    "CageforgeLaunchError",
    "CageforgeListingSnapshotExpiredError",
    "CageforgePermissionError",
    "CageforgeProcessError",
    "CageforgeStoreError",
    "CageforgeStoreFormatError",
    "CageforgeStoreLockedError",
    "CageforgeStorePathError",
    "CageforgeStoreReadError",
    "CageforgeStoreWriteError",
    "CageforgeStreamError",
    "CageforgeWindowsSetupError",
    "GrantId",
    "GrantPage",
    "GrantPageCursor",
    "GrantSummary",
    "PermissionApprover",
    "PermissionGrant",
    "PermissionRequest",
    "PermissionStore",
    "ProcessResult",
    "RevokeResult",
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
