// SPDX-License-Identifier: Apache-2.0

//! Versioned elevated-setup discovery and read-back.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{WindowsSetupConfig, WindowsStateDirectorySource};
use crate::error::WindowsSetupError;

/// Current on-disk Windows setup contract version.
pub const WINDOWS_SETUP_VERSION: u32 = 1;
const STATE_PARENT: &str = "Cageforge";
const STATE_COMPONENT: &str = "windows-sandbox";
const MARKER_NAME: &str = "setup.json";

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

/// Read-back details for one current elevated Windows installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSetupDetails {
    version: u32,
    owner_sid: String,
    state_directory: PathBuf,
    accounts: WindowsSandboxAccounts,
    firewall_policy_id: String,
    wfp_provider_id: String,
    setup_helper_sha256: String,
    command_runner_sha256: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SetupMarker {
    version: u32,
    owner_sid: String,
    accounts: SetupMarkerAccounts,
    firewall_policy_id: String,
    wfp_provider_id: String,
    setup_helper_sha256: String,
    command_runner_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SetupMarkerAccounts {
    offline_name: String,
    offline_sid: String,
    online_name: String,
    online_sid: String,
    group_name: String,
    group_sid: String,
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
            firewall_policy_id: self.firewall_policy_id,
            wfp_provider_id: self.wfp_provider_id,
            setup_helper_sha256: self.setup_helper_sha256,
            command_runner_sha256: self.command_runner_sha256,
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
            return Err(WindowsSetupError::NativeVerification {
                component: label,
                detail: format!("expected SID {expected_sid}, found {actual_sid}"),
            });
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
