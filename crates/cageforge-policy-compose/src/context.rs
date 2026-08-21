// SPDX-License-Identifier: Apache-2.0

//! Narrowed runtime path context produced by [`crate::EffectiveSandbox`].
//!
//! The private constructor is intentional: callers should obtain this context
//! from the effective result rather than rebuilding a broader context by hand.

use std::path::PathBuf;
use std::sync::Arc;

use cageforge_policy::PathResolutionContext;

/// Identity shared by one effective sandbox and the contexts it creates.
///
/// The value is intentionally opaque. Pointer identity, rather than the
/// value stored in the token, binds a context to its originating composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextIdentity(Arc<()>);

impl ContextIdentity {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// A runtime path context created by [`crate::EffectiveSandbox::path_context`].
///
/// The constructor is intentionally private so a filesystem decision cannot
/// accidentally use a context with workspace roots broader than the composed
/// result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePathContext {
    context: PathResolutionContext,
    identity: ContextIdentity,
}

impl EffectivePathContext {
    pub(crate) fn new(context: PathResolutionContext, identity: ContextIdentity) -> Self {
        Self { context, identity }
    }

    /// Returns the validated context for backend inspection.
    pub fn context(&self) -> &PathResolutionContext {
        &self.context
    }

    /// Returns the workspace roots permitted by the composed result.
    pub fn workspace_roots(&self) -> &[PathBuf] {
        self.context.workspace_roots()
    }

    pub(crate) fn belongs_to(&self, identity: &ContextIdentity) -> bool {
        self.identity.matches(identity)
    }
}

impl AsRef<PathResolutionContext> for EffectivePathContext {
    fn as_ref(&self) -> &PathResolutionContext {
        &self.context
    }
}
