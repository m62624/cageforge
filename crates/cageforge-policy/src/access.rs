// SPDX-License-Identifier: Apache-2.0

//! Shared access results for the filesystem and network policy modules.
//!
//! [`crate::AccessMode`] expresses a filesystem rule, while
//! [`crate::FilesystemDecision`] preserves whether a result is local or
//! externally enforced. The network module has its own [`crate::NetworkDecision`]
//! because connection authorization also carries an exact socket address.

/// Filesystem access requested or granted for a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccessMode {
    /// Permit reads but not modifications.
    Read,
    /// Permit reads and modifications.
    Write,
    /// Permit neither reads nor modifications.
    Deny,
}

impl AccessMode {
    /// Returns whether this mode permits a read.
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    /// Returns whether this mode permits a modification.
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write)
    }

    /// Returns the more restrictive capability for two conflicting grants.
    ///
    /// The order is `Deny` over `Read` over `Write`. Explicit profile
    /// replacement is a separate operation owned by the config resolver.
    pub const fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Self::Deny, _) | (_, Self::Deny) => Self::Deny,
            (Self::Read, _) | (_, Self::Read) => Self::Read,
            (Self::Write, Self::Write) => Self::Write,
        }
    }

    /// Returns whether this grant satisfies a requested access mode.
    pub const fn permits(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::Write, Self::Read | Self::Write)
                | (Self::Read, Self::Read)
                | (Self::Deny, Self::Deny)
        )
    }
}

/// The result of evaluating a filesystem request against a policy.
///
/// `ExternallyEnforced` is intentionally distinct from [`AccessMode::Deny`].
/// It tells a backend that Cageforge does not make the local decision because
/// another trusted sandbox owns the filesystem boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FilesystemDecision {
    /// Permit reads but not modifications.
    Read,
    /// Permit reads and modifications.
    Write,
    /// Permit neither reads nor modifications.
    Deny,
    /// Defer enforcement to the trusted external sandbox.
    ExternallyEnforced,
}

impl FilesystemDecision {
    /// Returns the local access mode, or `None` when another sandbox enforces it.
    pub const fn as_access_mode(self) -> Option<AccessMode> {
        match self {
            Self::Read => Some(AccessMode::Read),
            Self::Write => Some(AccessMode::Write),
            Self::Deny => Some(AccessMode::Deny),
            Self::ExternallyEnforced => None,
        }
    }

    /// Returns whether local filesystem enforcement is delegated elsewhere.
    pub const fn is_externally_enforced(self) -> bool {
        matches!(self, Self::ExternallyEnforced)
    }
}

impl From<AccessMode> for FilesystemDecision {
    fn from(access: AccessMode) -> Self {
        match access {
            AccessMode::Read => Self::Read,
            AccessMode::Write => Self::Write,
            AccessMode::Deny => Self::Deny,
        }
    }
}
