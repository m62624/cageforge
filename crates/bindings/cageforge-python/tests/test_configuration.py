"""Pure configuration checks shared by every native target."""

from __future__ import annotations

from pathlib import Path

import pytest
from cageforge import Cageforge, CageforgeConfigurationError, RuntimeContext

CONFIG = """
default_profile = "read-only"

[profiles.read-only]

[profiles.read-only.filesystem]
mode = "restricted"
rules = [{ target = "minimal", access = "read" }]

[profiles.read-only.network]
mode = "disabled"
"""


def test_profile_resolution_and_composition() -> None:
    assert Cageforge.profile_names(CONFIG) == ["read-only"]
    Cageforge.check_toml(CONFIG, context=RuntimeContext(Path.cwd()))


def test_configuration_failures_are_structured() -> None:
    with pytest.raises(CageforgeConfigurationError):
        Cageforge.profile_names("not valid = [")
    with pytest.raises(CageforgeConfigurationError):
        RuntimeContext(Path("relative"))
