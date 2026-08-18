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

/// The action applied to a matching environment-variable pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvironmentFilterAction {
    /// Retain matching variables when the include allowlist is active.
    Include,
    /// Remove matching variables with deny precedence over inclusion.
    Exclude,
}

/// A wildcard pattern matched against an environment variable name.
///
/// The pattern language is deliberately small and portable: `*` matches zero
/// or more Unicode scalar values and `?` matches one. Matching is
/// case-insensitive so the same policy is safe on POSIX and Windows hosts.
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
        wildcard_matches(&self.as_str().to_lowercase(), &name.to_lowercase())
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
/// string. Variable names are one logical, case-insensitive namespace, so a
/// later case variant replaces an earlier override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSpec {
    base: EnvironmentBase,
    overrides: BTreeMap<OsString, EnvironmentOverride>,
    filters: BTreeMap<EnvironmentPattern, EnvironmentFilterAction>,
}

impl EnvironmentSpec {
    /// Creates an environment that inherits all parent variables.
    pub fn inherit_all() -> Self {
        Self {
            base: EnvironmentBase::All,
            overrides: BTreeMap::new(),
            filters: BTreeMap::new(),
        }
    }

    /// Creates an environment that starts empty.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::None,
            overrides: BTreeMap::new(),
            filters: BTreeMap::new(),
        }
    }

    /// Creates an environment that inherits the platform's core variables.
    pub fn inherit_core() -> Self {
        Self {
            base: EnvironmentBase::Core,
            overrides: BTreeMap::new(),
            filters: BTreeMap::new(),
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

    /// Returns canonical environment filters in deterministic pattern order.
    pub fn filters(&self) -> &BTreeMap<EnvironmentPattern, EnvironmentFilterAction> {
        &self.filters
    }

    /// Returns the override for one variable, if present.
    pub fn override_for(&self, name: &OsStr) -> Option<&EnvironmentOverride> {
        self.overrides
            .iter()
            .find(|(existing, _)| environment_names_equal(existing, name))
            .map(|(_, override_value)| override_value)
    }

    /// Returns the filter action for a variable name, if a filter matches.
    ///
    /// Exclude always wins when both actions match. A backend can use the
    /// presence of any include filter together with this result to implement
    /// the complete inherited-environment decision without reimplementing
    /// wildcard precedence.
    pub fn filter_action_for(&self, name: &str) -> Option<EnvironmentFilterAction> {
        let mut include_matches = false;
        for (pattern, action) in &self.filters {
            if pattern.matches(name) {
                match action {
                    EnvironmentFilterAction::Include => include_matches = true,
                    EnvironmentFilterAction::Exclude => {
                        return Some(EnvironmentFilterAction::Exclude);
                    }
                }
            }
        }
        include_matches.then_some(EnvironmentFilterAction::Include)
    }

    /// Applies filters and explicit overrides to an already selected base
    /// environment.
    ///
    /// The caller selects the `All`, `Core`, or `None` base at the backend
    /// boundary. This method then applies the portable sequence
    /// `exclude -> set/remove -> include`. A variable removed by an exclude is
    /// not restored by an include; an explicit set is applied after exclusion
    /// and can intentionally reintroduce that named variable.
    pub fn apply_to<I>(&self, variables: I) -> BTreeMap<OsString, OsString>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut environment = BTreeMap::new();
        for (name, value) in variables {
            remove_environment_name(&mut environment, &name);
            environment.insert(name, value);
        }
        let has_include_filter = self
            .filters
            .values()
            .any(|action| *action == EnvironmentFilterAction::Include);

        environment.retain(|name, _| {
            !self.filters.iter().any(|(pattern, action)| {
                *action == EnvironmentFilterAction::Exclude
                    && pattern.matches(&name.to_string_lossy())
            })
        });

        for (name, value) in &self.overrides {
            match value {
                EnvironmentOverride::Set(value) => {
                    remove_environment_name(&mut environment, name);
                    environment.insert(name.clone(), value.clone());
                }
                EnvironmentOverride::Remove => {
                    remove_environment_name(&mut environment, name);
                }
            }
        }

        if has_include_filter {
            environment.retain(|name, _| {
                self.filters.iter().any(|(pattern, action)| {
                    *action == EnvironmentFilterAction::Include
                        && pattern.matches(&name.to_string_lossy())
                })
            });
        }

        environment
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
        remove_environment_name(&mut self.overrides, &name);
        self.overrides.insert(name, EnvironmentOverride::Set(value));
        Ok(self)
    }

    /// Adds a variable removal and returns the updated environment.
    pub fn without_var(mut self, name: impl Into<OsString>) -> Result<Self, CommandError> {
        let name = name.into();
        validate_name(&name)?;
        remove_environment_name(&mut self.overrides, &name);
        self.overrides.insert(name, EnvironmentOverride::Remove);
        Ok(self)
    }

    /// Adds or replaces a canonical environment filter.
    pub fn with_filter(
        mut self,
        pattern: impl Into<String>,
        action: EnvironmentFilterAction,
    ) -> Result<Self, CommandError> {
        let pattern = EnvironmentPattern::new(pattern)?;
        if let Some(existing) = self
            .filters
            .keys()
            .find(|existing| environment_patterns_equal(existing, &pattern))
            .cloned()
        {
            self.filters.remove(&existing);
        }
        self.filters.insert(pattern, action);
        Ok(self)
    }

    /// Adds an include filter.
    pub fn with_include_pattern(self, pattern: impl Into<String>) -> Result<Self, CommandError> {
        self.with_filter(pattern, EnvironmentFilterAction::Include)
    }

    /// Adds an exclude filter.
    pub fn with_exclude_pattern(self, pattern: impl Into<String>) -> Result<Self, CommandError> {
        self.with_filter(pattern, EnvironmentFilterAction::Exclude)
    }
}

impl Default for EnvironmentSpec {
    fn default() -> Self {
        Self::inherit_core()
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

fn remove_environment_name<V>(values: &mut BTreeMap<OsString, V>, name: &OsStr) {
    if let Some(existing) = values
        .keys()
        .find(|existing| environment_names_equal(existing, name))
        .cloned()
    {
        values.remove(&existing);
    }
}

fn environment_names_equal(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
}

fn environment_patterns_equal(left: &EnvironmentPattern, right: &EnvironmentPattern) -> bool {
    left.as_str().to_lowercase() == right.as_str().to_lowercase()
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
