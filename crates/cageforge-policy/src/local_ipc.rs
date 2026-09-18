// SPDX-License-Identifier: Apache-2.0

//! Typed local-IPC endpoints shared by policy and platform backends.

use std::path::{Path, PathBuf};

use cageforge_path::contains_parent_traversal;

use crate::{PathSelector, PolicyError};

/// A validated absolute filesystem path used as a local-IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AbsolutePath(PathBuf);

/// A validated name in the Windows local named-pipe namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamedPipeName(String);

/// A platform-neutral local-IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LocalIpcEndpoint {
    /// A Unix-domain socket pathname.
    UnixSocket(AbsolutePath),
    /// A Windows named pipe in the local `\\.\pipe\` namespace.
    WindowsNamedPipe(NamedPipeName),
}

impl AbsolutePath {
    /// Creates a validated absolute path.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        let path = path.into();
        PathSelector::absolute(path.clone())?;
        Ok(Self(path))
    }

    /// Returns the validated path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consumes the wrapper and returns its path.
    pub fn into_path(self) -> PathBuf {
        self.0
    }
}

impl NamedPipeName {
    /// Creates a validated local Windows named-pipe name.
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        const PREFIX: &str = "\\\\.\\pipe\\";
        if !value
            .get(..PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        {
            return Err(PolicyError::InvalidLocalIpcEndpoint {
                endpoint: value,
                reason: "named pipe must use the local \\\\.\\pipe\\ namespace",
            });
        }
        let name = &value[PREFIX.len()..];
        if name.is_empty()
            || name.contains('\0')
            || name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
            || name.contains(':')
            || !name.is_ascii()
        {
            return Err(PolicyError::InvalidLocalIpcEndpoint {
                endpoint: value,
                reason: "named pipe name is empty or contains an unsafe component",
            });
        }
        if value.encode_utf16().count() > 256 {
            return Err(PolicyError::InvalidLocalIpcEndpoint {
                endpoint: value,
                reason: "named pipe name exceeds the supported length",
            });
        }
        Ok(Self(format!("{PREFIX}{}", name.to_ascii_lowercase())))
    }

    /// Returns the canonical native name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl LocalIpcEndpoint {
    /// Creates a Unix-socket endpoint.
    pub fn unix_socket(path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        Ok(Self::UnixSocket(AbsolutePath::new(path)?))
    }

    /// Creates a Windows named-pipe endpoint.
    pub fn windows_named_pipe(name: impl Into<String>) -> Result<Self, PolicyError> {
        Ok(Self::WindowsNamedPipe(NamedPipeName::new(name)?))
    }

    /// Returns the Unix path, if this is a Unix-socket endpoint.
    pub fn unix_path(&self) -> Option<&Path> {
        match self {
            Self::UnixSocket(path) => Some(path.as_path()),
            Self::WindowsNamedPipe(_) => None,
        }
    }

    /// Returns the Windows pipe name, if this is a named-pipe endpoint.
    pub fn named_pipe(&self) -> Option<&str> {
        match self {
            Self::UnixSocket(_) => None,
            Self::WindowsNamedPipe(name) => Some(name.as_str()),
        }
    }

    /// Validates endpoint-specific invariants again at a policy boundary.
    pub fn validate(&self) -> Result<(), PolicyError> {
        match self {
            Self::UnixSocket(path) => {
                if contains_parent_traversal(path.as_path()) {
                    return Err(PolicyError::InvalidLocalIpcEndpoint {
                        endpoint: path.as_path().display().to_string(),
                        reason: "parent traversal is not allowed",
                    });
                }
                Ok(())
            }
            Self::WindowsNamedPipe(name) => NamedPipeName::new(name.as_str()).map(|_| ()),
        }
    }
}
