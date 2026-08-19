// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use cageforge_command::{EnvironmentBase, EnvironmentSpec};

use crate::CompositionError;

/// An environment transformation constrained by two portable specifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEnvironment {
    requested: EnvironmentSpec,
    ceiling: EnvironmentSpec,
}

impl EffectiveEnvironment {
    pub(crate) fn new(requested: EnvironmentSpec, ceiling: EnvironmentSpec) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the least permissive inherited-environment base.
    pub fn base(&self) -> EnvironmentBase {
        least_permissive_base(self.requested.base(), self.ceiling.base())
    }

    /// Returns the requested environment specification.
    pub fn requested(&self) -> &EnvironmentSpec {
        &self.requested
    }

    /// Returns the ceiling environment specification.
    pub fn ceiling(&self) -> &EnvironmentSpec {
        &self.ceiling
    }

    /// Applies both environment transformations without allowing the ceiling
    /// to introduce a variable absent from the requested result.
    ///
    /// The input carries the base selected by the backend. A broader base is
    /// rejected instead of being silently accepted.
    pub fn apply_to(
        &self,
        input: EnvironmentInput,
    ) -> Result<BTreeMap<OsString, OsString>, CompositionError> {
        if !base_is_at_most(input.base, self.base()) {
            return Err(CompositionError::EnvironmentBaseTooPermissive {
                required: self.base(),
                supplied: input.base,
            });
        }
        let requested = self.requested.apply_to(input.variables);
        let requested_names: Vec<OsString> = requested.keys().cloned().collect();
        let mut effective = self.ceiling.apply_to(requested);
        effective.retain(|name, _| {
            requested_names
                .iter()
                .any(|requested_name| environment_names_equal(requested_name, name))
        });
        Ok(effective)
    }
}

/// A backend-selected environment snapshot for effective policy application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInput {
    base: EnvironmentBase,
    variables: BTreeMap<OsString, OsString>,
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

    /// Creates an input containing the backend's selected core variables.
    ///
    /// This constructor does not verify the contents. The caller must build
    /// the map from the platform-specific core allowlist, not from the full
    /// parent environment, before handing it to composition.
    pub fn core<I>(variables: I) -> Self
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        Self {
            base: EnvironmentBase::Core,
            variables: variables.into_iter().collect(),
        }
    }

    /// Creates an input with no inherited variables.
    pub fn empty() -> Self {
        Self {
            base: EnvironmentBase::None,
            variables: BTreeMap::new(),
        }
    }

    /// Returns the base selected by the backend.
    pub const fn base(&self) -> EnvironmentBase {
        self.base
    }
}

fn least_permissive_base(left: EnvironmentBase, right: EnvironmentBase) -> EnvironmentBase {
    match (left, right) {
        (EnvironmentBase::None, _) | (_, EnvironmentBase::None) => EnvironmentBase::None,
        (EnvironmentBase::Core, _) | (_, EnvironmentBase::Core) => EnvironmentBase::Core,
        (EnvironmentBase::All, EnvironmentBase::All) => EnvironmentBase::All,
    }
}

fn base_is_at_most(supplied: EnvironmentBase, required: EnvironmentBase) -> bool {
    match required {
        EnvironmentBase::None => supplied == EnvironmentBase::None,
        EnvironmentBase::Core => supplied != EnvironmentBase::All,
        EnvironmentBase::All => true,
    }
}

fn environment_names_equal(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}
