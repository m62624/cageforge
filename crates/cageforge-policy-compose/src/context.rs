// SPDX-License-Identifier: Apache-2.0

//! Narrowed runtime path context produced by [`crate::EffectiveSandbox`].
//!
//! The private constructor is intentional: callers should obtain this context
//! from the effective result rather than rebuilding a broader context by hand.

use std::path::PathBuf;
use std::sync::Arc;

use cageforge_policy::{PathResolutionContext, PathSelector};

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

    /// Returns the workspace roots permitted by the composed result.
    pub fn workspace_roots(&self) -> &[PathBuf] {
        self.context.workspace_roots()
    }

    /// Returns the system roots retained by the composed runtime context.
    pub fn root_paths(&self) -> &[PathBuf] {
        self.context.root_paths()
    }

    /// Returns the platform-minimal paths retained by the composed context.
    pub fn minimal_paths(&self) -> &[PathBuf] {
        self.context.minimal_paths()
    }

    /// Returns the platform temporary directory, if one was supplied.
    pub fn tmpdir(&self) -> Option<&std::path::Path> {
        self.context.tmpdir()
    }

    /// Returns the conventional `/tmp` directory, if one was supplied.
    pub fn slash_tmp(&self) -> Option<&std::path::Path> {
        self.context.slash_tmp()
    }

    /// Returns the runtime current directory, if one was supplied.
    pub fn current_directory(&self) -> Option<&std::path::Path> {
        self.context.current_directory()
    }

    /// Resolves a symbolic selector through this bound effective context.
    pub fn resolve(&self, selector: &PathSelector) -> Vec<PathBuf> {
        selector.resolve(&self.context)
    }

    pub(crate) fn belongs_to(&self, identity: &ContextIdentity) -> bool {
        self.identity.matches(identity)
    }

    pub(crate) fn raw(&self) -> &PathResolutionContext {
        &self.context
    }
}
