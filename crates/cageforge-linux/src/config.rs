// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend construction settings.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How the backend obtains Bubblewrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BubblewrapSource {
    /// Discover `bwrap` on the construction process's `PATH`.
    System,
    /// Use this explicitly selected executable after validation and probing.
    Explicit(PathBuf),
}

/// How the backend obtains the in-sandbox hardening helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningHelperSource {
    /// Discover `cageforge-linux-helper` on `PATH`.
    System,
    /// Use this explicitly selected helper executable.
    Explicit(PathBuf),
}

/// Whether Bubblewrap must create a fresh `/proc` mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcMountPolicy {
    /// Require a fresh process namespace and `/proc` mount.
    Required,
    /// Do not request a fresh `/proc` mount.
    Disabled,
}

/// Configuration for one Linux enforcement instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBackendConfig {
    bubblewrap: BubblewrapSource,
    hardening_helper: HardeningHelperSource,
    proc_mount: ProcMountPolicy,
    default_timeout: Duration,
}

impl Default for LinuxBackendConfig {
    fn default() -> Self {
        Self {
            bubblewrap: BubblewrapSource::System,
            hardening_helper: HardeningHelperSource::System,
            proc_mount: ProcMountPolicy::Required,
            default_timeout: Duration::from_secs(300),
        }
    }
}

impl LinuxBackendConfig {
    /// Creates the secure default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses system Bubblewrap discovered from `PATH`.
    pub fn with_system_bubblewrap(mut self) -> Self {
        self.bubblewrap = BubblewrapSource::System;
        self
    }

    /// Uses an explicitly selected Bubblewrap executable.
    pub fn with_bubblewrap_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.bubblewrap = BubblewrapSource::Explicit(path.into());
        self
    }

    /// Uses an explicitly selected in-sandbox hardening helper.
    pub fn with_hardening_helper_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.hardening_helper = HardeningHelperSource::Explicit(path.into());
        self
    }

    /// Sets the proc-mount policy.
    pub fn with_proc_mount(mut self, policy: ProcMountPolicy) -> Self {
        self.proc_mount = policy;
        self
    }

    /// Sets the timeout used by `TimeoutPolicy::BackendDefault`.
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Returns the Bubblewrap source.
    pub(crate) fn bubblewrap(&self) -> &BubblewrapSource {
        &self.bubblewrap
    }

    pub(crate) fn hardening_helper(&self) -> &HardeningHelperSource {
        &self.hardening_helper
    }

    /// Returns the proc-mount policy.
    pub(crate) const fn proc_mount(&self) -> ProcMountPolicy {
        self.proc_mount
    }

    /// Returns the configured backend timeout.
    pub(crate) const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Returns an explicit Bubblewrap path, if configured.
    pub fn bubblewrap_path(&self) -> Option<&Path> {
        match &self.bubblewrap {
            BubblewrapSource::System => None,
            BubblewrapSource::Explicit(path) => Some(path),
        }
    }

    /// Returns an explicit hardening-helper path, if configured.
    pub fn hardening_helper_path(&self) -> Option<&Path> {
        match &self.hardening_helper {
            HardeningHelperSource::System => None,
            HardeningHelperSource::Explicit(path) => Some(path),
        }
    }
}
