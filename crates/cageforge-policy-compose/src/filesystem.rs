// SPDX-License-Identifier: Apache-2.0

//! Effective filesystem constraints retained for backend lowering.
//!
//! [`crate::EffectiveFilesystemPolicy`] keeps both the requested and ceiling
//! policies so a backend can inspect the complete narrowed contract.

use std::num::NonZeroUsize;

use cageforge_policy::{AccessMode, FilesystemPolicy};

use crate::context::{ContextIdentity, EffectivePathContext};

/// A filesystem decision constrained by both input policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveFilesystemPolicy {
    requested: FilesystemPolicy,
    ceiling: FilesystemPolicy,
    context_identity: ContextIdentity,
}

impl EffectiveFilesystemPolicy {
    pub(crate) fn new(
        requested: FilesystemPolicy,
        ceiling: FilesystemPolicy,
        context_identity: ContextIdentity,
    ) -> Self {
        Self {
            requested,
            ceiling,
            context_identity,
        }
    }

    /// Returns the requested filesystem policy retained for backend lowering.
    pub fn requested(&self) -> &FilesystemPolicy {
        &self.requested
    }

    /// Returns the ceiling filesystem policy retained for backend lowering.
    pub fn ceiling(&self) -> &FilesystemPolicy {
        &self.ceiling
    }

    pub(crate) fn context_identity(&self) -> ContextIdentity {
        self.context_identity.clone()
    }

    pub(crate) fn owns_context(&self, context: &EffectivePathContext) -> bool {
        context.belongs_to(&self.context_identity)
    }

    /// Returns the scan depth required to preserve all deny-glob rules.
    ///
    /// A bounded depth is widened to the larger bound. If a relevant deny
    /// glob is unbounded on either side, the effective result is unbounded.
    pub fn glob_scan_max_depth(&self) -> Option<NonZeroUsize> {
        merge_glob_scan_depth(
            effective_glob_scan_depth(&self.requested),
            effective_glob_scan_depth(&self.ceiling),
        )
    }
}

fn effective_glob_scan_depth(policy: &FilesystemPolicy) -> Option<Option<NonZeroUsize>> {
    policy
        .entries()
        .iter()
        .any(|entry| {
            matches!(entry.target(), cageforge_policy::FilesystemTarget::Glob(_))
                && entry.access() == AccessMode::Deny
        })
        .then_some(policy.glob_scan_max_depth())
}

fn merge_glob_scan_depth(
    left: Option<Option<NonZeroUsize>>,
    right: Option<Option<NonZeroUsize>>,
) -> Option<NonZeroUsize> {
    match (left, right) {
        (Some(None), _) | (_, Some(None)) => None,
        (Some(Some(left)), Some(Some(right))) => Some(left.max(right)),
        (Some(Some(depth)), None) | (None, Some(Some(depth))) => Some(depth),
        (None, None) => None,
    }
}
