// SPDX-License-Identifier: Apache-2.0

//! Typed failures at the CLI adapter boundary.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Failure while parsing, preparing, or running a CLI request.
#[derive(Debug, Error)]
pub enum CliError {
    /// The selected native backend could not be initialized.
    #[error(transparent)]
    NativeSandbox(#[from] cageforge::NativeSandboxError),
    /// Preparation, launch, or lifecycle failed through the shared execution API.
    #[error(transparent)]
    Execution(#[from] cageforge::SandboxExecutionError),
    /// The config feature is required for `run`.
    #[error("the CLI was built without the `config` feature; rebuild with one matching OS feature")]
    ConfigFeatureRequired,
    /// No native backend feature matches the current target.
    #[error(
        "no matching native backend feature is enabled for this target; rebuild with `linux`, `windows`, or `macos`"
    )]
    NativeFeatureRequired,
    /// The selected profile did not contain a command and argv was empty.
    #[error(
        "no command was supplied; provide a program after `--` or configure one in the profile"
    )]
    MissingCommand,
    /// The command cannot be safely assembled from the supplied argv.
    #[error("command arguments must contain a program")]
    InvalidCommand,
    /// A workspace root contains lexical parent traversal.
    #[error("workspace root contains parent traversal: {path:?}")]
    InvalidWorkspaceRoot {
        /// Rejected workspace-root declaration.
        path: PathBuf,
    },
    /// The public config resolver rejected the document or profile.
    #[cfg(feature = "config")]
    #[error("configuration: {0}")]
    Config(#[from] cageforge::ConfigError),
    /// The portable command model rejected a value.
    #[error("command: {0}")]
    Command(#[from] cageforge::CommandError),
    /// The portable policy context rejected a runtime path.
    #[error("policy context: {0}")]
    Policy(#[from] cageforge::PolicyError),
    /// Policy composition rejected the requested and outer values.
    #[error("policy composition: {0}")]
    Composition(#[from] cageforge::CompositionError),
    /// Reading the current directory or schema failed.
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    /// The configuration schema could not be serialized.
    #[error("schema: {0}")]
    Schema(#[from] serde_json::Error),
    /// Linux native setup or execution failed.
    #[cfg(all(feature = "linux", target_os = "linux"))]
    #[error("Linux backend: {0}")]
    Linux(#[from] cageforge::LinuxBackendError),
    /// Windows native setup or execution failed.
    #[cfg(all(feature = "windows", target_os = "windows"))]
    #[error("Windows backend: {0}")]
    Windows(#[from] cageforge::WindowsBackendError),
    /// Windows persistent setup provisioning or removal failed.
    #[cfg(all(feature = "windows", target_os = "windows"))]
    #[error("Windows setup: {0}")]
    WindowsSetup(#[from] cageforge::WindowsSetupError),
    /// macOS native setup or execution failed.
    #[cfg(all(feature = "macos", target_os = "macos"))]
    #[error("macOS backend: {0}")]
    Macos(#[from] cageforge::MacosBackendError),
}

impl CliError {
    pub(crate) const fn exit_code(&self) -> u8 {
        2
    }
}
