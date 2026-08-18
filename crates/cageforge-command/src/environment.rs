// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use crate::CommandError;
use crate::command::contains_nul;

/// Selects the base environment from which a command is launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentBase {
    /// Inherit every variable from the launching process.
    All,
    /// Inherit the platform's conservative set of core variables.
    Core,
    /// Start with no inherited variables.
    None,
}

/// A wildcard pattern matched against an environment variable name.
///
/// The pattern language is deliberately small and portable: `*` matches zero
/// or more Unicode scalar values and `?` matches one. Backends apply the
/// include and exclude lists to the environment they actually construct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvironmentPattern(String);

impl EnvironmentPattern {
    /// Creates a validated environment-variable pattern.
    pub fn new(pattern: impl Into<String>) -> Result<Self, CommandError> {
        let pattern = pattern.into();
        if pattern.is_empty() {
            return Err(CommandError::EmptyEnvironmentPattern);
        }
        if contains_nul(OsStr::new(&pattern)) {
            return Err(CommandError::EnvironmentPatternContainsNul);
        }
        if pattern.contains('=') {
            return Err(CommandError::EnvironmentPatternContainsEquals);
        }
        Ok(Self(pattern))
    }

    /// Returns the pattern text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this pattern matches an environment variable name.
    pub fn matches(&self, name: &str) -> bool {
        wildcard_matches(self.as_str(), name)
    }
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
    include_patterns: Vec<EnvironmentPattern>,
    exclude_patterns: Vec<EnvironmentPattern>,
}

impl EnvironmentSpec {
    /// Creates an environment that inherits all parent variables.
    pub fn inherit_all() -> Self {
        Self {
            base: EnvironmentBase::All,
            overrides: BTreeMap::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }

    /// Creates an environment that starts empty.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::None,
            overrides: BTreeMap::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }

    /// Creates an environment that inherits the platform's core variables.
    pub fn inherit_core() -> Self {
        Self {
            base: EnvironmentBase::Core,
            overrides: BTreeMap::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
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

    /// Returns patterns that retain matching variables after exclusion.
    pub fn include_patterns(&self) -> &[EnvironmentPattern] {
        &self.include_patterns
    }

    /// Returns patterns that remove matching variables before inclusion.
    pub fn exclude_patterns(&self) -> &[EnvironmentPattern] {
        &self.exclude_patterns
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

    /// Adds an include-only pattern.
    pub fn with_include_pattern(
        mut self,
        pattern: impl Into<String>,
    ) -> Result<Self, CommandError> {
        let pattern = EnvironmentPattern::new(pattern)?;
        if !self.include_patterns.contains(&pattern) {
            self.include_patterns.push(pattern);
        }
        Ok(self)
    }

    /// Adds an exclude pattern.
    pub fn with_exclude_pattern(
        mut self,
        pattern: impl Into<String>,
    ) -> Result<Self, CommandError> {
        let pattern = EnvironmentPattern::new(pattern)?;
        if !self.exclude_patterns.contains(&pattern) {
            self.exclude_patterns.push(pattern);
        }
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

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    let mut matches = vec![false; value.len() + 1];
    matches[0] = true;

    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            '*' => {
                next[0] = matches[0];
                for index in 1..=value.len() {
                    next[index] = next[index - 1] || matches[index];
                }
            }
            '?' => {
                next[1..].copy_from_slice(&matches[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = matches[index - 1] && value[index - 1] == literal;
                }
            }
        }
        matches = next;
    }

    matches[value.len()]
}
