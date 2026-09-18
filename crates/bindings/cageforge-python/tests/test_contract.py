"""Binding-level contract checks that do not compare language surfaces."""

from __future__ import annotations

import cageforge
import pytest


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


def test_windows_setup_matches_native_platform_behavior() -> None:
    if cageforge.WindowsSetup.is_supported():
        return
    with pytest.raises(cageforge.UnsupportedPlatformError):
        cageforge.WindowsSetup.status()
