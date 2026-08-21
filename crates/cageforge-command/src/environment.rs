// SPDX-License-Identifier: Apache-2.0

//! Environment bases, filters, and overrides for [`crate::EnvironmentSpec`].
//!
//! This module describes transformations but does not discover the operating
//! system's core variables. A backend supplies that base when it applies the
//! [`crate::EnvironmentBase::Core`] request.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::hash::{Hash, Hasher};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use wildmatch::WildMatch;

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
#[derive(Debug, Clone)]
pub struct EnvironmentPattern {
    original: String,
    canonical: String,
    matcher: WildMatch,
}

impl PartialEq for EnvironmentPattern {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for EnvironmentPattern {}

impl Hash for EnvironmentPattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl PartialOrd for EnvironmentPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EnvironmentPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

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
        Ok(Self {
            canonical: pattern.to_lowercase(),
            matcher: WildMatch::new_case_insensitive(&pattern),
            original: pattern,
        })
    }

    /// Returns the original pattern text.
    ///
    /// Trait identity is based on the same case-insensitive canonical form as
    /// [`Self::matches`], while this accessor preserves the caller's spelling
    /// for diagnostics and serialization.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns whether this pattern matches an environment variable name.
    pub fn matches(&self, name: &str) -> bool {
        self.matcher.matches(name)
    }
}

/// A case-insensitive identity key for an operating-system environment name.
///
/// Valid Unicode names use the portable case-insensitive Cageforge policy.
/// Malformed native strings retain their exact code units or bytes so distinct
/// names can never collide through lossy conversion. Backends and composition
/// layers can use this key to deduplicate names consistently with
/// [`EnvironmentSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvironmentNameKey(EnvironmentNameIdentity);

impl EnvironmentNameKey {
    /// Creates the policy identity for one native environment-variable name.
    pub fn new(name: &OsStr) -> Self {
        Self(environment_name_identity(name))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum EnvironmentNameIdentity {
    Folded(String),
    #[cfg(unix)]
    NativeBytes(Vec<u8>),
    #[cfg(windows)]
    NativeWide(Vec<u16>),
}

/// An explicit change to one environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentOverride {
    /// Set the variable to the given value.
    Set(OsString),
    /// Remove the variable from the final environment.
    Remove,
}

/// A base environment selected by the process adapter.
///
/// The constructors encode the base that the variables represent. This keeps
/// an [`EnvironmentSpec`] from being applied to an arbitrarily broad map while
/// claiming that the map is empty or platform-core input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInput {
    base: EnvironmentBase,
    variables: BTreeMap<OsString, OsString>,
}

/// A platform-selected snapshot used to construct a core environment input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreEnvironment {
    variables: BTreeMap<OsString, OsString>,
}

impl CoreEnvironment {
    /// Creates a core snapshot from variables selected by the process adapter.
    pub fn from_selected<I>(variables: I) -> Self
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        Self {
            variables: variables.into_iter().collect(),
        }
    }

    /// Returns the selected core variables.
    pub fn variables(&self) -> &BTreeMap<OsString, OsString> {
        &self.variables
    }
}

impl EnvironmentInput {
    /// Creates an input containing all inherited variables.
    pub fn all<I>(variables: I) -> Self
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        Self {
            base: EnvironmentBase::All,
            variables: variables.into_iter().collect(),
        }
    }

    /// Creates an input containing a process adapter's selected core set.
    pub fn core(environment: CoreEnvironment) -> Self {
        Self {
            base: EnvironmentBase::Core,
            variables: environment.variables,
        }
    }

    /// Creates an input with no inherited variables.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::None,
            variables: BTreeMap::new(),
        }
    }

    /// Returns the declared base represented by this input.
    pub const fn base(&self) -> EnvironmentBase {
        self.base
    }

    /// Returns the variables represented by this input.
    pub fn variables(&self) -> &BTreeMap<OsString, OsString> {
        &self.variables
    }

    /// Consumes the input and returns its selected variables.
    pub fn into_variables(self) -> BTreeMap<OsString, OsString> {
        self.variables
    }
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
    override_names: HashMap<EnvironmentNameKey, OsString>,
    filters: BTreeMap<EnvironmentPattern, EnvironmentFilterAction>,
}

impl EnvironmentSpec {
    /// Creates an environment that inherits all parent variables.
    pub fn inherit_all() -> Self {
        Self {
            base: EnvironmentBase::All,
            overrides: BTreeMap::new(),
            override_names: HashMap::new(),
            filters: BTreeMap::new(),
        }
    }

    /// Creates an environment that starts empty.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::None,
            overrides: BTreeMap::new(),
            override_names: HashMap::new(),
            filters: BTreeMap::new(),
        }
    }

    /// Creates an environment that inherits the platform's core variables.
    pub fn inherit_core() -> Self {
        Self {
            base: EnvironmentBase::Core,
            overrides: BTreeMap::new(),
            override_names: HashMap::new(),
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
        self.override_names
            .get(&EnvironmentNameKey::new(name))
            .and_then(|name| self.overrides.get(name))
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
    /// boundary. A broader input is rejected before transformation. This
    /// method then applies the portable sequence `exclude -> set/remove ->
    /// include` and keeps the validated base tag on the returned snapshot. A
    /// variable removed by an exclude is not restored by an include; an
    /// explicit set is applied after exclusion and can intentionally
    /// reintroduce that named variable.
    pub fn apply_to(&self, input: EnvironmentInput) -> Result<EnvironmentInput, CommandError> {
        if !base_is_at_most(input.base, self.base) {
            return Err(CommandError::EnvironmentBaseTooPermissive {
                required: self.base,
                supplied: input.base,
            });
        }
        let base = input.base;
        let variables = input.variables;
        let mut environment = BTreeMap::new();
        let mut environment_names = HashMap::new();
        for (name, value) in variables {
            remove_environment_name(&mut environment, &mut environment_names, &name);
            environment_names.insert(EnvironmentNameKey::new(&name), name.clone());
            environment.insert(name, value);
        }
        let has_include_filter = self
            .filters
            .values()
            .any(|action| *action == EnvironmentFilterAction::Include);

        environment.retain(|name, _| {
            self.filters.is_empty()
                || name.to_str().is_some_and(|name| {
                    !self.filters.iter().any(|(pattern, action)| {
                        *action == EnvironmentFilterAction::Exclude && pattern.matches(name)
                    })
                })
        });

        for (name, value) in &self.overrides {
            match value {
                EnvironmentOverride::Set(value) => {
                    remove_environment_name(&mut environment, &mut environment_names, name);
                    environment_names.insert(EnvironmentNameKey::new(name), name.clone());
                    environment.insert(name.clone(), value.clone());
                }
                EnvironmentOverride::Remove => {
                    remove_environment_name(&mut environment, &mut environment_names, name);
                }
            }
        }

        if has_include_filter {
            environment.retain(|name, _| {
                name.to_str().is_some_and(|name| {
                    self.filters.iter().any(|(pattern, action)| {
                        *action == EnvironmentFilterAction::Include && pattern.matches(name)
                    })
                })
            });
        } else if !self.filters.is_empty() {
            environment.retain(|name, _| name.to_str().is_some());
        }

        Ok(EnvironmentInput {
            base,
            variables: environment,
        })
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
        remove_environment_name(&mut self.overrides, &mut self.override_names, &name);
        self.override_names
            .insert(EnvironmentNameKey::new(&name), name.clone());
        self.overrides.insert(name, EnvironmentOverride::Set(value));
        Ok(self)
    }

    /// Adds a variable removal and returns the updated environment.
    pub fn without_var(mut self, name: impl Into<OsString>) -> Result<Self, CommandError> {
        let name = name.into();
        validate_name(&name)?;
        remove_environment_name(&mut self.overrides, &mut self.override_names, &name);
        self.override_names
            .insert(EnvironmentNameKey::new(&name), name.clone());
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
        self.filters.remove(&pattern);
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

fn remove_environment_name<V>(
    values: &mut BTreeMap<OsString, V>,
    names: &mut HashMap<EnvironmentNameKey, OsString>,
    name: &OsStr,
) {
    if let Some(existing) = names.remove(&EnvironmentNameKey::new(name)) {
        values.remove(&existing);
    }
}

fn environment_name_identity(name: &OsStr) -> EnvironmentNameIdentity {
    if let Some(name) = name.to_str() {
        return EnvironmentNameIdentity::Folded(name.to_lowercase());
    }
    #[cfg(unix)]
    {
        EnvironmentNameIdentity::NativeBytes(name.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        EnvironmentNameIdentity::NativeWide(name.encode_wide().collect())
    }
}

fn base_is_at_most(supplied: EnvironmentBase, required: EnvironmentBase) -> bool {
    match required {
        EnvironmentBase::None => supplied == EnvironmentBase::None,
        EnvironmentBase::Core => supplied != EnvironmentBase::All,
        EnvironmentBase::All => true,
    }
}
