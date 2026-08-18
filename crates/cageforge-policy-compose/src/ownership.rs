// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

/// An opaque proof that two external-enforcement declarations share one owner.
///
/// Cloning an owner preserves its identity. Independent owners do not compare
/// equal, so unrelated external boundaries cannot be composed accidentally.
/// The `Arc<()>` payload stores no platform or harness data: the allocation's
/// identity is the proof, and `Arc::ptr_eq` is the comparison. This keeps the
/// type reusable wherever one trusted enforcement boundary owns both sides.
#[derive(Clone)]
pub struct ExternalOwner(Arc<()>);

impl ExternalOwner {
    /// Creates a new external-enforcement owner identity.
    pub fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl Default for ExternalOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ExternalOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalOwner")
            .finish_non_exhaustive()
    }
}

impl PartialEq for ExternalOwner {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ExternalOwner {}
