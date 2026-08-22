// SPDX-License-Identifier: Apache-2.0

//! Monotonic environment composition and backend-selected core variables.
//!
//! [`crate::EffectiveEnvironment`] applies requested and ceiling transforms,
//! while [`crate::CoreEnvironment`] marks a variable set selected by the
//! backend. The module never invents a platform's core-variable list.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;

use cageforge_command::{
    CommandError, EnvironmentBase, EnvironmentInput, EnvironmentNameKey, EnvironmentSpec,
};

use crate::CompositionError;

/// An environment transformation constrained by two portable specifications.
/// The component specifications remain private so a backend can apply only
/// the composed transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEnvironment {
    requested: EnvironmentSpec,
    ceiling: EnvironmentSpec,
}

/// The environment features a backend must be able to enforce for one
/// effective composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveEnvironmentRequirements {
    base: EnvironmentBase,
    filters: bool,
    overrides: bool,
}

impl EffectiveEnvironmentRequirements {
    /// Returns the least-permissive effective environment base.
    pub const fn base(self) -> EnvironmentBase {
        self.base
    }

    /// Returns whether include/exclude filters are present.
    pub const fn filters(self) -> bool {
        self.filters
    }

    /// Returns whether set/remove overrides are present.
    pub const fn overrides(self) -> bool {
        self.overrides
    }
}

impl EffectiveEnvironment {
    pub(crate) fn new(requested: EnvironmentSpec, ceiling: EnvironmentSpec) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the least permissive inherited-environment base.
    pub fn base(&self) -> EnvironmentBase {
        least_permissive_base(self.requested.base(), self.ceiling.base())
    }

    /// Returns the aggregate environment requirements for backend preflight.
    pub fn requirements(&self) -> EffectiveEnvironmentRequirements {
        EffectiveEnvironmentRequirements {
            base: self.base(),
            filters: !self.requested.filters().is_empty() || !self.ceiling.filters().is_empty(),
            overrides: !self.requested.overrides().is_empty()
                || !self.ceiling.overrides().is_empty(),
        }
    }

    /// Returns whether a command environment is the requested input used for
    /// this composition.
    pub fn requested_matches(&self, environment: &EnvironmentSpec) -> bool {
        self.requested == *environment
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
        if !base_is_at_most(input.base(), self.base()) {
            return Err(CompositionError::EnvironmentBaseTooPermissive {
                required: self.base(),
                supplied: input.base(),
            });
        }
        let requested = self
            .requested
            .apply_to(input)
            .map_err(environment_application_error)?;
        let requested_names: HashSet<_> = requested
            .variables()
            .keys()
            .map(|name| EnvironmentNameKey::new(name))
            .collect();
        let mut effective = self
            .ceiling
            .apply_to(requested)
            .map_err(environment_application_error)?
            .into_variables();
        effective.retain(|name, _| requested_names.contains(&EnvironmentNameKey::new(name)));
        Ok(effective)
    }
}

fn environment_application_error(error: CommandError) -> CompositionError {
    match error {
        CommandError::EnvironmentBaseTooPermissive { required, supplied } => {
            CompositionError::EnvironmentBaseTooPermissive { required, supplied }
        }
        other => CompositionError::EnvironmentApplication { source: other },
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
