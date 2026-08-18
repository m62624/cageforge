// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::PathSelector;
use crate::PolicyError;
use std::path::Path;
use std::path::PathBuf;

/// Runtime paths needed to resolve platform-independent policy selectors.
///
/// The context is supplied by a harness or a platform backend. Constructing it
/// never reads the filesystem, follows symlinks, or infers a workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathResolutionContext {
    root_paths: Vec<PathBuf>,
    workspace_roots: Vec<PathBuf>,
    minimal_paths: Vec<PathBuf>,
    tmpdir: Option<PathBuf>,
    slash_tmp: Option<PathBuf>,
}

impl PathResolutionContext {
    /// Creates an empty context.
    pub const fn new() -> Self {
        Self {
            root_paths: Vec::new(),
            workspace_roots: Vec::new(),
            minimal_paths: Vec::new(),
            tmpdir: None,
            slash_tmp: None,
        }
    }

    /// Adds one absolute system root represented by the runtime environment.
    ///
    /// POSIX backends normally provide `/`. Windows backends may provide more
    /// than one drive or UNC root. The context never discovers these paths on
    /// its own.
    pub fn with_root(mut self, path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        self.root_paths.push(validated_absolute(path.into())?);
        Ok(self)
    }

    /// Adds one absolute workspace root.
    pub fn with_workspace_root(mut self, path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        self.workspace_roots.push(validated_absolute(path.into())?);
        Ok(self)
    }

    /// Adds one absolute path required by ordinary process execution.
    pub fn with_minimal_path(mut self, path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        self.minimal_paths.push(validated_absolute(path.into())?);
        Ok(self)
    }

    /// Sets the platform temporary directory.
    pub fn with_tmpdir(mut self, path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        self.tmpdir = Some(validated_absolute(path.into())?);
        Ok(self)
    }

    /// Sets the conventional `/tmp` directory when the platform provides it.
    pub fn with_slash_tmp(mut self, path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        self.slash_tmp = Some(validated_absolute(path.into())?);
        Ok(self)
    }

    /// Returns the configured workspace roots.
    pub fn workspace_roots(&self) -> &[PathBuf] {
        &self.workspace_roots
    }

    /// Returns the absolute system roots supplied by the runtime.
    pub fn root_paths(&self) -> &[PathBuf] {
        &self.root_paths
    }

    /// Returns the configured minimal runtime paths.
    pub fn minimal_paths(&self) -> &[PathBuf] {
        &self.minimal_paths
    }

    /// Returns the configured platform temporary directory.
    pub fn tmpdir(&self) -> Option<&Path> {
        self.tmpdir.as_deref()
    }

    /// Returns the configured conventional `/tmp` directory.
    pub fn slash_tmp(&self) -> Option<&Path> {
        self.slash_tmp.as_deref()
    }
}

fn validated_absolute(path: PathBuf) -> Result<PathBuf, PolicyError> {
    PathSelector::absolute(path)?
        .path()
        .map(Path::to_path_buf)
        .ok_or_else(|| PolicyError::InvalidContext {
            message: "absolute path validation returned a non-absolute selector".to_string(),
        })
}
