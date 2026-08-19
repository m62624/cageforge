// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use cageforge_policy::{AccessMode, FilesystemPolicy};

/// A filesystem decision constrained by both input policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveFilesystemPolicy {
    requested: FilesystemPolicy,
    ceiling: FilesystemPolicy,
}

impl EffectiveFilesystemPolicy {
    pub(crate) fn new(requested: FilesystemPolicy, ceiling: FilesystemPolicy) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the requested filesystem policy retained for backend lowering.
    pub fn requested(&self) -> &FilesystemPolicy {
        &self.requested
    }

    /// Returns the ceiling filesystem policy retained for backend lowering.
    pub fn ceiling(&self) -> &FilesystemPolicy {
        &self.ceiling
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
