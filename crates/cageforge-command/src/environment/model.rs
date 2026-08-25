// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;

use wildmatch::WildMatch;

/// Environment construction rules for a command.
///
/// Overrides are kept in a sorted map for deterministic inspection and are
/// applied by a backend after selecting the requested base environment. A
/// value of [`EnvironmentOverride::Remove`] is distinct from setting an empty
/// string. Variable names are one logical, case-insensitive namespace, so a
/// later case variant replaces an earlier override.
#[derive(Debug, Clone)]
pub struct EnvironmentSpec {
    pub(super) base: EnvironmentBase,
    pub(super) overrides: BTreeMap<OsString, EnvironmentOverride>,
    pub(super) override_names: HashMap<EnvironmentNameKey, OsString>,
    pub(super) filters: BTreeMap<EnvironmentPattern, EnvironmentFilterAction>,
}

/// A base environment selected by the process adapter.
///
/// The constructors encode the base that the variables represent. This keeps
/// an [`EnvironmentSpec`] from being applied to an arbitrarily broad map while
/// claiming that the map is empty or platform-core input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInput {
    pub(super) base: EnvironmentBase,
    pub(super) variables: BTreeMap<OsString, OsString>,
}

/// A platform-selected snapshot used to construct a core environment input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreEnvironment {
    pub(super) variables: BTreeMap<OsString, OsString>,
}

/// An explicit change to one environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentOverride {
    /// Set the variable to the given value.
    Set(OsString),
    /// Remove the variable from the final environment.
    Remove,
}

/// A wildcard pattern matched against an environment variable name.
///
/// The pattern language is deliberately small and portable: `*` matches zero
/// or more Unicode scalar values and `?` matches one. Matching is
/// case-insensitive so the same policy is safe on POSIX and Windows hosts.
#[derive(Debug, Clone)]
pub struct EnvironmentPattern {
    pub(super) original: String,
    pub(super) canonical: String,
    pub(super) matcher: WildMatch,
}

/// A case-insensitive identity key for an operating-system environment name.
///
/// Valid Unicode names use the portable case-insensitive Cageforge policy.
/// Malformed native strings retain their exact code units or bytes so distinct
/// names can never collide through lossy conversion. Backends and composition
/// layers can use this key to deduplicate names consistently with
/// [`EnvironmentSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvironmentNameKey(pub(super) EnvironmentNameIdentity);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum EnvironmentNameIdentity {
    Folded(String),
    #[cfg(unix)]
    NativeBytes(Vec<u8>),
    #[cfg(windows)]
    NativeWide(Vec<u16>),
}

/// The action applied to a matching environment-variable pattern.
///
/// Include and exclude are evaluated with named precedence rules; their enum
/// declaration order is not an environment authorization order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvironmentFilterAction {
    /// Retain matching variables when the include allowlist is active.
    Include,
    /// Remove matching variables with deny precedence over inclusion.
    Exclude,
}

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
