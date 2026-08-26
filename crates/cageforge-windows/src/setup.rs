// SPDX-License-Identifier: Apache-2.0

//! Versioned elevated-setup discovery and read-back.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::config::{
    CommandRunnerSource, SetupHelperSource, WindowsSetupConfig, WindowsStateDirectorySource,
};
use crate::error::WindowsSetupError;
use crate::setup_protocol::{
    SETUP_PROTOCOL_VERSION, SetupOperation, SetupOutcome, SetupRequest, SetupResponse,
};
use crate::setup_state::{SETUP_STATE_VERSION, SetupMarker};

/// Current on-disk Windows setup contract version.
pub const WINDOWS_SETUP_VERSION: u32 = SETUP_STATE_VERSION;
const STATE_PARENT: &str = "Cageforge";
const STATE_COMPONENT: &str = "windows-sandbox";
const MARKER_NAME: &str = "setup.json";
const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";
const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";

/// Current state of elevated Windows provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsSetupStatus {
    /// No setup marker exists at the selected location.
    Missing {
        /// Expected marker path.
        marker_path: PathBuf,
    },
    /// A marker exists but is not valid for this crate or signed-in user.
    Stale {
        /// Existing marker path.
        marker_path: PathBuf,
        /// Exact mismatch.
        reason: WindowsSetupStaleReason,
    },
    /// Marker and native account state passed read-back.
    Ready(Box<WindowsSetupDetails>),
}

/// Read-back details for one current elevated Windows installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSetupDetails {
    version: u32,
    owner_sid: String,
    state_directory: PathBuf,
    accounts: WindowsSandboxAccounts,
    proxy_ports: Vec<u16>,
    firewall_policy_id: String,
    wfp_provider_id: String,
    setup_helper_sha256: String,
    command_runner_sha256: String,
    credential_sha256: String,
}

/// Dedicated local identities used by the elevated Windows boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSandboxAccounts {
    offline_name: String,
    offline_sid: String,
    online_name: String,
    online_sid: String,
    group_name: String,
    group_sid: String,
}

/// Why an existing Windows setup marker is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsSetupStaleReason {
    /// The helper/state schema changed.
    Version {
        /// Required version.
        expected: u32,
        /// Stored version.
        actual: u32,
    },
    /// State belongs to another signed-in user.
    Owner {
        /// Current user SID.
        expected: String,
        /// Stored owner SID.
        actual: String,
    },
    /// Stored deterministic account names do not match the owner SID.
    AccountIdentity,
}

/// Read-only setup inspector and explicit provisioning entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSetup {
    config: WindowsSetupConfig,
}

impl WindowsSetupDetails {
    /// Returns the setup schema version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the real-user SID that owns this setup.
    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    /// Returns the protected per-user state directory.
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    /// Returns the dedicated sandbox identities.
    pub const fn accounts(&self) -> &WindowsSandboxAccounts {
        &self.accounts
    }

    /// Returns the fixed IPv4 loopback ingress ports opened for this owner.
    pub fn proxy_ports(&self) -> &[u16] {
        &self.proxy_ports
    }

    /// Returns the stable identifier of the installed offline firewall policy.
    pub fn firewall_policy_id(&self) -> &str {
        &self.firewall_policy_id
    }

    /// Returns the stable identifier of the installed WFP provider.
    pub fn wfp_provider_id(&self) -> &str {
        &self.wfp_provider_id
    }

    /// Returns the SHA-256 digest recorded for the installed setup helper.
    pub fn setup_helper_sha256(&self) -> &str {
        &self.setup_helper_sha256
    }

    /// Returns the SHA-256 digest recorded for the installed command runner.
    pub fn command_runner_sha256(&self) -> &str {
        &self.command_runner_sha256
    }

    /// Returns the SHA-256 digest of the protected credential record.
    pub fn credential_sha256(&self) -> &str {
        &self.credential_sha256
    }
}

impl WindowsSandboxAccounts {
    /// Returns the account used for disabled and proxy-routed networking.
    pub fn offline_name(&self) -> &str {
        &self.offline_name
    }

    /// Returns the offline account SID captured during setup.
    pub fn offline_sid(&self) -> &str {
        &self.offline_sid
    }

    /// Returns the account used for unrestricted direct networking.
    pub fn online_name(&self) -> &str {
        &self.online_name
    }

    /// Returns the online account SID captured during setup.
    pub fn online_sid(&self) -> &str {
        &self.online_sid
    }

    /// Returns the Cageforge-managed local group name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the managed group SID captured during setup.
    pub fn group_sid(&self) -> &str {
        &self.group_sid
    }
}

impl WindowsSetup {
    /// Creates an inspector for one setup configuration.
    pub const fn new(config: WindowsSetupConfig) -> Self {
        Self { config }
    }

    /// Returns the immutable setup configuration.
    pub const fn config(&self) -> &WindowsSetupConfig {
        &self.config
    }

    /// Resolves the protected state directory for the current signed-in user.
    pub fn state_directory(&self) -> Result<PathBuf, WindowsSetupError> {
        let owner_sid = crate::win::current_user_sid()
            .map_err(|source| WindowsSetupError::CurrentUserSid { source })?;
        self.state_directory_for(&owner_sid)
    }

    /// Reads the marker and verifies current account identities and membership.
    pub fn status(&self) -> Result<WindowsSetupStatus, WindowsSetupError> {
        let owner_sid = crate::win::current_user_sid()
            .map_err(|source| WindowsSetupError::CurrentUserSid { source })?;
        let state_directory = self.state_directory_for(&owner_sid)?;
        let marker_path = state_directory.join(MARKER_NAME);
        let marker_bytes = match fs::read(&marker_path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(WindowsSetupStatus::Missing { marker_path });
            }
            Err(source) => {
                return Err(WindowsSetupError::StateRead {
                    path: marker_path,
                    source,
                });
            }
        };
        let marker: SetupMarker = serde_json::from_slice(&marker_bytes).map_err(|source| {
            WindowsSetupError::StateDecode {
                path: marker_path.clone(),
                source,
            }
        })?;
        if marker.version != WINDOWS_SETUP_VERSION {
            return Ok(WindowsSetupStatus::Stale {
                marker_path,
                reason: WindowsSetupStaleReason::Version {
                    expected: WINDOWS_SETUP_VERSION,
                    actual: marker.version,
                },
            });
        }
        if !marker.owner_sid.eq_ignore_ascii_case(&owner_sid) {
            return Ok(WindowsSetupStatus::Stale {
                marker_path,
                reason: WindowsSetupStaleReason::Owner {
                    expected: owner_sid,
                    actual: marker.owner_sid,
                },
            });
        }
        let expected = account_names(&owner_sid);
        if marker.accounts.offline_name != expected.offline_name
            || marker.accounts.online_name != expected.online_name
            || marker.accounts.group_name != expected.group_name
        {
            return Ok(WindowsSetupStatus::Stale {
                marker_path,
                reason: WindowsSetupStaleReason::AccountIdentity,
            });
        }
        let details = marker.into_details(state_directory);
        verify_accounts(&details)?;
        crate::setup_verification::verify(&details)?;
        Ok(WindowsSetupStatus::Ready(Box::new(details)))
    }

    /// Requires a current setup and returns its verified details.
    pub fn verify(&self) -> Result<WindowsSetupDetails, WindowsSetupError> {
        match self.status()? {
            WindowsSetupStatus::Missing { marker_path } => {
                Err(WindowsSetupError::Missing { path: marker_path })
            }
            WindowsSetupStatus::Stale { reason, .. } => Err(stale_error(reason)),
            WindowsSetupStatus::Ready(details) => Ok(*details),
        }
    }

    /// Runs the administrator-approved helper and verifies the completed setup.
    ///
    /// The helper is elevated through the Windows `runas` shell verb. Cancelling
    /// the UAC prompt is returned as [`WindowsSetupError::ElevationCanceled`].
    pub fn install(&self) -> Result<WindowsSetupDetails, WindowsSetupError> {
        self.run_helper(SetupOperation::Install)?;
        self.verify()
    }

    /// Explicitly removes only the owner-scoped Cageforge setup objects.
    ///
    /// Cleanup refuses to recursively delete unknown state. Unexpected files
    /// therefore produce a typed helper failure instead of widening deletion.
    pub fn uninstall(&self) -> Result<(), WindowsSetupError> {
        self.run_helper(SetupOperation::Uninstall)?;
        match self.status()? {
            WindowsSetupStatus::Missing { .. } => Ok(()),
            WindowsSetupStatus::Stale { .. } | WindowsSetupStatus::Ready(_) => {
                Err(WindowsSetupError::HelperExitMismatch { exit_code: 0 })
            }
        }
    }

    fn run_helper(&self, operation: SetupOperation) -> Result<(), WindowsSetupError> {
        let owner_sid = crate::win::current_user_sid()
            .map_err(|source| WindowsSetupError::CurrentUserSid { source })?;
        let state_directory = self.state_directory_for(&owner_sid)?;
        let helper_path = self.resolve_setup_helper()?;
        let runner_path = self.resolve_command_runner()?;
        let helper_sha256 = file_digest(&helper_path)?;
        let runner_sha256 = file_digest(&runner_path)?;
        let proxy_ports = proxy_ports_for_current_owner(&state_directory);
        let request = SetupRequest {
            version: SETUP_PROTOCOL_VERSION,
            operation,
            owner_sid,
            state_directory,
            setup_helper_sha256: helper_sha256,
            command_runner_source: runner_path,
            command_runner_sha256: runner_sha256,
            proxy_ports,
        };
        let transport = tempfile::Builder::new()
            .prefix("cageforge-windows-setup-")
            .tempdir()
            .map_err(|error| WindowsSetupError::RequestWrite {
                path: std::env::temp_dir(),
                detail: error.to_string(),
            })?;
        let request_path = transport.path().join("request.json");
        let response_path = transport.path().join("response.json");
        let encoded =
            serde_json::to_vec(&request).map_err(|error| WindowsSetupError::RequestWrite {
                path: request_path.clone(),
                detail: error.to_string(),
            })?;
        fs::write(&request_path, encoded).map_err(|error| WindowsSetupError::RequestWrite {
            path: request_path.clone(),
            detail: error.to_string(),
        })?;
        let arguments = [
            "--request".to_string(),
            request_path.to_string_lossy().into_owned(),
            "--response".to_string(),
            response_path.to_string_lossy().into_owned(),
        ];
        let elevated = crate::win::current_process_is_elevated().map_err(|source| {
            WindowsSetupError::HelperLaunch {
                path: helper_path.clone(),
                source,
            }
        })?;
        let launched = if elevated {
            std::process::Command::new(&helper_path)
                .args(&arguments)
                .status()
                .map(|status| status.code().map_or(125, |code| code as u32))
        } else {
            crate::win::run_elevated(&helper_path, &arguments)
        };
        let exit_code = match launched {
            Ok(code) => code,
            Err(source) if source.raw_os_error() == Some(1223) => {
                return Err(WindowsSetupError::ElevationCanceled);
            }
            Err(source) => {
                return Err(WindowsSetupError::HelperLaunch {
                    path: helper_path,
                    source,
                });
            }
        };
        let response_bytes =
            fs::read(&response_path).map_err(|source| WindowsSetupError::ResponseRead {
                path: response_path.clone(),
                source,
            })?;
        let response: SetupResponse =
            serde_json::from_slice(&response_bytes).map_err(|source| {
                WindowsSetupError::ResponseDecode {
                    path: response_path,
                    source,
                }
            })?;
        if response.version != SETUP_PROTOCOL_VERSION {
            return Err(WindowsSetupError::ResponseVersionMismatch {
                expected: SETUP_PROTOCOL_VERSION,
                actual: response.version,
            });
        }
        match response.outcome {
            SetupOutcome::Complete if exit_code == 0 => Ok(()),
            SetupOutcome::Complete => Err(WindowsSetupError::HelperExitMismatch { exit_code }),
            SetupOutcome::Failed {
                stage,
                code,
                native_code,
                detail,
            } => Err(WindowsSetupError::HelperFailed {
                stage,
                code,
                native_code,
                detail,
            }),
        }
    }

    fn state_directory_for(&self, owner_sid: &str) -> Result<PathBuf, WindowsSetupError> {
        let base = match self.config.state_directory_source() {
            WindowsStateDirectorySource::ProgramData => crate::win::program_data_directory()
                .map_err(|code| WindowsSetupError::ProgramDataUnavailable { code })?
                .join(STATE_PARENT)
                .join(STATE_COMPONENT),
            WindowsStateDirectorySource::Explicit(path) => path.clone(),
        };
        Ok(base.join(owner_key(owner_sid)))
    }

    fn resolve_setup_helper(&self) -> Result<PathBuf, WindowsSetupError> {
        resolve_resource(
            self.config.setup_helper_source(),
            SETUP_HELPER_NAME,
            "bundled Windows setup helper is not staged in this build",
        )
    }

    fn resolve_command_runner(&self) -> Result<PathBuf, WindowsSetupError> {
        match self.config.command_runner_source() {
            CommandRunnerSource::Bundled => Err(WindowsSetupError::HelperUnavailable {
                detail: "bundled Windows command runner is not staged in this build".to_string(),
            }),
            CommandRunnerSource::Sibling => sibling_resource(COMMAND_RUNNER_NAME),
            CommandRunnerSource::Explicit(path) => Ok(path.clone()),
        }
    }
}

impl SetupMarker {
    fn into_details(self, state_directory: PathBuf) -> WindowsSetupDetails {
        WindowsSetupDetails {
            version: self.version,
            owner_sid: self.owner_sid,
            state_directory,
            accounts: WindowsSandboxAccounts {
                offline_name: self.accounts.offline_name,
                offline_sid: self.accounts.offline_sid,
                online_name: self.accounts.online_name,
                online_sid: self.accounts.online_sid,
                group_name: self.accounts.group_name,
                group_sid: self.accounts.group_sid,
            },
            proxy_ports: self.proxy_ports,
            firewall_policy_id: self.firewall_policy_id,
            wfp_provider_id: self.wfp_provider_id,
            setup_helper_sha256: self.setup_helper_sha256,
            command_runner_sha256: self.command_runner_sha256,
            credential_sha256: self.credential_sha256,
        }
    }
}

fn account_names(owner_sid: &str) -> WindowsSandboxAccounts {
    let key = owner_key(owner_sid);
    WindowsSandboxAccounts {
        offline_name: format!("CgfOff_{}", &key[..12]),
        offline_sid: String::new(),
        online_name: format!("CgfOn_{}", &key[..12]),
        online_sid: String::new(),
        group_name: format!("CgfGrp_{}", &key[..12]),
        group_sid: String::new(),
    }
}

fn owner_key(owner_sid: &str) -> String {
    let digest = Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify_accounts(details: &WindowsSetupDetails) -> Result<(), WindowsSetupError> {
    let accounts = details.accounts();
    for (label, name, expected_sid) in [
        (
            "offline account",
            accounts.offline_name(),
            accounts.offline_sid(),
        ),
        (
            "online account",
            accounts.online_name(),
            accounts.online_sid(),
        ),
        ("sandbox group", accounts.group_name(), accounts.group_sid()),
    ] {
        let actual_sid =
            crate::win::account_sid(name).map_err(|source| WindowsSetupError::AccountLookup {
                component: label,
                source,
            })?;
        if !actual_sid.eq_ignore_ascii_case(expected_sid) {
            return Err(
                crate::error::WindowsSetupVerificationError::AccountSidMismatch {
                    component: label,
                    expected: expected_sid.to_string(),
                    actual: actual_sid,
                }
                .into(),
            );
        }
    }
    for account in [accounts.offline_name(), accounts.online_name()] {
        crate::win::verify_sandbox_account(account, accounts.group_name())?;
    }
    Ok(())
}

fn stale_error(reason: WindowsSetupStaleReason) -> WindowsSetupError {
    match reason {
        WindowsSetupStaleReason::Version { expected, actual } => {
            WindowsSetupError::VersionMismatch { expected, actual }
        }
        WindowsSetupStaleReason::Owner { expected, actual } => {
            WindowsSetupError::OwnerMismatch { expected, actual }
        }
        WindowsSetupStaleReason::AccountIdentity => WindowsSetupError::AccountIdentityMismatch,
    }
}

fn resolve_resource(
    source: &SetupHelperSource,
    sibling_name: &str,
    bundled_error: &str,
) -> Result<PathBuf, WindowsSetupError> {
    match source {
        SetupHelperSource::Bundled => Err(WindowsSetupError::HelperUnavailable {
            detail: bundled_error.to_string(),
        }),
        SetupHelperSource::Sibling => sibling_resource(sibling_name),
        SetupHelperSource::Explicit(path) => Ok(path.clone()),
    }
}

fn sibling_resource(name: &str) -> Result<PathBuf, WindowsSetupError> {
    let executable =
        std::env::current_exe().map_err(|error| WindowsSetupError::HelperUnavailable {
            detail: format!("failed to resolve current executable: {error}"),
        })?;
    let parent = executable
        .parent()
        .ok_or_else(|| WindowsSetupError::HelperUnavailable {
            detail: format!("current executable has no parent directory: {executable:?}"),
        })?;
    Ok(parent.join(name))
}

fn file_digest(path: &Path) -> Result<String, WindowsSetupError> {
    let bytes = fs::read(path).map_err(|source| WindowsSetupError::HelperResourceRead {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn proxy_ports_for_current_owner(state_directory: &Path) -> Vec<u16> {
    let digest = Sha256::digest(state_directory.as_os_str().to_string_lossy().as_bytes());
    let offset = u16::from_be_bytes([digest[0], digest[1]]) % 8_000;
    let first = 49_152 + offset * 2;
    vec![first, first + 1]
}
