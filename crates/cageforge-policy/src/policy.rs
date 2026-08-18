// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::AccessMode;
use crate::FilesystemPolicy;
use crate::FilesystemRule;
use crate::NetworkPolicy;
use crate::PathSelector;
use crate::PolicyError;

/// The complete platform-independent sandbox request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    filesystem: FilesystemPolicy,
    network: NetworkPolicy,
}

impl SandboxPolicy {
    /// Creates a policy from explicit filesystem and network boundaries.
    pub const fn new(filesystem: FilesystemPolicy, network: NetworkPolicy) -> Self {
        Self {
            filesystem,
            network,
        }
    }

    /// Creates a read-only policy for ordinary workspace inspection.
    pub fn read_only() -> Self {
        Self::new(
            FilesystemPolicy::restricted([
                FilesystemRule::new(PathSelector::root(), AccessMode::Read),
                FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
                FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Read),
                FilesystemRule::new(PathSelector::tmpdir(), AccessMode::Read),
                FilesystemRule::new(PathSelector::slash_tmp(), AccessMode::Read),
            ]),
            NetworkPolicy::disabled(),
        )
    }

    /// Creates a workspace-editing policy with no outbound network access.
    pub fn workspace() -> Self {
        Self::new(
            FilesystemPolicy::restricted([
                FilesystemRule::new(PathSelector::root(), AccessMode::Read),
                FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
                FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
                FilesystemRule::new(PathSelector::tmpdir(), AccessMode::Write),
                FilesystemRule::new(PathSelector::slash_tmp(), AccessMode::Write),
            ]),
            NetworkPolicy::disabled(),
        )
    }

    /// Creates a fully unrestricted policy.
    pub const fn full_access() -> Self {
        Self::new(FilesystemPolicy::unrestricted(), NetworkPolicy::enabled())
    }

    /// Returns the filesystem boundary.
    pub const fn filesystem(&self) -> &FilesystemPolicy {
        &self.filesystem
    }

    /// Returns the network boundary.
    pub const fn network(&self) -> &NetworkPolicy {
        &self.network
    }

    /// Validates both policy boundaries before backend selection.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.filesystem.validate()?;
        self.network.validate()?;
        Ok(())
    }
}
