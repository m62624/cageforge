// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use crate::CommandError;
use crate::command::contains_nul;

/// Selects the base environment from which a command is launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentBase {
    /// Inherit the launching process environment.
    Inherit,
    /// Start with no inherited variables.
    Empty,
}

/// An explicit change to one environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentOverride {
    /// Set the variable to the given value.
    Set(OsString),
    /// Remove the variable from the final environment.
    Remove,
}

/// Environment construction rules for a command.
///
/// Overrides are kept in a sorted map for deterministic inspection and are
/// applied by a backend after selecting the requested base environment. A
/// value of [`EnvironmentOverride::Remove`] is distinct from setting an empty
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSpec {
    base: EnvironmentBase,
    overrides: BTreeMap<OsString, EnvironmentOverride>,
}

impl EnvironmentSpec {
    /// Creates an environment that inherits all parent variables.
    pub fn inherit_all() -> Self {
        Self {
            base: EnvironmentBase::Inherit,
            overrides: BTreeMap::new(),
        }
    }

    /// Creates an environment that starts empty.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::Empty,
            overrides: BTreeMap::new(),
        }
    }

    /// Returns the selected base environment behavior.
    pub fn base(&self) -> EnvironmentBase {
        self.base
    }

    /// Returns all explicit variable overrides in deterministic key order.
    pub fn overrides(&self) -> &BTreeMap<OsString, EnvironmentOverride> {
        &self.overrides
    }

    /// Returns the override for one variable, if present.
    pub fn override_for(&self, name: &OsStr) -> Option<&EnvironmentOverride> {
        self.overrides.get(name)
    }

    /// Adds a variable assignment and returns the updated environment.
    pub fn with_var(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Result<Self, CommandError> {
        let name = name.into();
        let value = value.into();
        validate_name(&name)?;
        if contains_nul(&value) {
            return Err(CommandError::EnvironmentValueContainsNul);
        }
        self.overrides.insert(name, EnvironmentOverride::Set(value));
        Ok(self)
    }

    /// Adds a variable removal and returns the updated environment.
    pub fn without_var(mut self, name: impl Into<OsString>) -> Result<Self, CommandError> {
        let name = name.into();
        validate_name(&name)?;
        self.overrides.insert(name, EnvironmentOverride::Remove);
        Ok(self)
    }
}

impl Default for EnvironmentSpec {
    fn default() -> Self {
        Self::inherit_all()
    }
}

fn validate_name(name: &OsStr) -> Result<(), CommandError> {
    if name.is_empty() {
        return Err(CommandError::EmptyEnvironmentName);
    }
    if contains_nul(name) {
        return Err(CommandError::EnvironmentNameContainsNul);
    }
    if name.to_string_lossy().contains('=') {
        return Err(CommandError::EnvironmentNameContainsEquals);
    }
    Ok(())
}
