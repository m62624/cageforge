// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use cageforge_policy::PathResolutionContext;

/// A runtime path context created by [`crate::EffectiveSandbox::path_context`].
///
/// The constructor is intentionally private so a filesystem decision cannot
/// accidentally use a context with workspace roots broader than the composed
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePathContext {
    context: PathResolutionContext,
}

impl EffectivePathContext {
    pub(crate) fn new(context: PathResolutionContext) -> Self {
        Self { context }
    }

    /// Returns the validated context for backend inspection.
    pub fn context(&self) -> &PathResolutionContext {
        &self.context
    }

    /// Returns the workspace roots permitted by the composed result.
    pub fn workspace_roots(&self) -> &[PathBuf] {
        self.context.workspace_roots()
    }
}

impl AsRef<PathResolutionContext> for EffectivePathContext {
    fn as_ref(&self) -> &PathResolutionContext {
        &self.context
    }
}
