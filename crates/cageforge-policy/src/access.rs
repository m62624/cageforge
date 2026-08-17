// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

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

    /// Returns the more restrictive of two modes.
    pub const fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (Self::Deny, _) | (_, Self::Deny) => Self::Deny,
            (Self::Write, _) | (_, Self::Write) => Self::Write,
            (Self::Read, Self::Read) => Self::Read,
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
