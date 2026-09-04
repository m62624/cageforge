// SPDX-License-Identifier: Apache-2.0

//! Versioned elevated-setup discovery and read-back.

pub(crate) mod pinned;
pub(crate) mod protocol;
pub(crate) mod state;
pub(crate) mod state_path;
pub(crate) mod verification;

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::capability::store::{CapabilityStateStore, CapabilityStateStoreError};
use crate::config::{
    CommandRunnerSource, SetupHelperSource, WindowsSetupConfig, WindowsStateDirectorySource,
};
use crate::error::WindowsSetupError;
use crate::filesystem::acl::FilesystemAclEnforcement;
use crate::filesystem::path::ValidatedPath;
use crate::setup::protocol::{
    SETUP_PROTOCOL_VERSION, SetupOperation, SetupOutcome, SetupRequest, SetupResponse,
};
use crate::setup::state::{SETUP_STATE_VERSION, SetupMarker};

/// Current on-disk Windows setup contract version.
pub const WINDOWS_SETUP_VERSION: u32 = SETUP_STATE_VERSION;
const MARKER_NAME: &str = "setup.json";
const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";
const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";
const BIN_DIRNAME: &str = "bin";
const RESOURCES_DIRNAME: &str = "cageforge-resources";

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
    runner_manifest_sha256: String,
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

    /// Returns the SHA-256 digest of the protected command-runner manifest.
    pub fn runner_manifest_sha256(&self) -> &str {
        &self.runner_manifest_sha256
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
        match fs::symlink_metadata(&marker_path) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(WindowsSetupStatus::Missing { marker_path });
            }
            Err(source) => {
                return Err(WindowsSetupError::StateRead {
                    path: marker_path,
                    source,
                });
            }
            Ok(_) => {}
        }
        let mut marker_file = crate::setup::pinned::file::open_for_readback(&marker_path, true)
            .map_err(|error| WindowsSetupError::StatePathUnsafe {
                path: marker_path.clone(),
                detail: error.to_string(),
            })?;
        let mut marker_bytes = Vec::new();
        marker_file
            .read_to_end(&mut marker_bytes)
            .map_err(|source| WindowsSetupError::StateRead {
                path: marker_path.clone(),
                source,
            })?;
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
        crate::setup::verification::verify(&details, marker_file)?;
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
    /// Call this after dropping every [`crate::WindowsBackend`] created from
    /// this setup and waiting for or dropping every [`crate::WindowsChild`].
    /// Backends pin the installed runner and manifest handles for their whole
    /// lifetime, so Windows correctly refuses to remove those files while a
    /// backend remains alive.
    ///
    /// Cleanup refuses to recursively delete unknown state. Unexpected files
    /// therefore produce a typed helper failure instead of widening deletion.
    pub fn uninstall(&self) -> Result<(), WindowsSetupError> {
        let owner_sid = crate::win::current_user_sid()
            .map_err(|source| WindowsSetupError::CurrentUserSid { source })?;
        let state_directory = self.state_directory_for(&owner_sid)?;
        let uninstall_guard = match fs::symlink_metadata(&state_directory) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(WindowsSetupError::StateRead {
                    path: state_directory,
                    source,
                });
            }
            Ok(_) => {
                let store = CapabilityStateStore::new(&state_directory, &owner_sid);
                let guard = store
                    .acquire_uninstall_guard()
                    .map_err(|source| match source {
                        CapabilityStateStoreError::ActiveChildren => {
                            WindowsSetupError::ActiveSandboxes
                        }
                        source => WindowsSetupError::UninstallCoordination {
                            source: Box::new(source),
                        },
                    })?;
                FilesystemAclEnforcement::cleanup_persistent(&store).map_err(|source| {
                    WindowsSetupError::UninstallFilesystemCleanup {
                        source: Box::new(source),
                    }
                })?;
                guard
            }
        };
        uninstall_guard.release();
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
        let helper_source = self.resolve_setup_helper()?;
        let runner_source = self.resolve_command_runner()?;
        let helper = pin_setup_resource(&helper_source)?;
        let runner = pin_setup_resource(&runner_source)?;
        let helper_path = helper.final_path().to_path_buf();
        let runner_path = runner.final_path().to_path_buf();
        let helper_sha256 = file_digest(&helper, &helper_path)?;
        let runner_sha256 = file_digest(&runner, &runner_path)?;
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
        let _request_file = write_pinned_setup_request(&request_path, &encoded)?;
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
        let response_bytes = match fs::read(&response_path) {
            Ok(response) => response,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let last_checkpoint = fs::read_to_string(response_path.with_extension("progress"))
                    .ok()
                    .filter(|checkpoint| !checkpoint.is_empty());
                return Err(WindowsSetupError::HelperResponseMissing {
                    path: response_path,
                    exit_code,
                    last_checkpoint,
                    source,
                });
            }
            Err(source) => {
                return Err(WindowsSetupError::ResponseRead {
                    path: response_path.clone(),
                    source,
                });
            }
        };
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
                code: crate::setup::protocol::SetupFailureCode::ActiveSandboxes,
                ..
            } => Err(WindowsSetupError::ActiveSandboxes),
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
            WindowsStateDirectorySource::ProgramData => {
                return crate::setup::state_path::default_state_directory(owner_sid)
                    .map_err(|code| WindowsSetupError::ProgramDataUnavailable { code });
            }
            WindowsStateDirectorySource::Explicit(path) => path.clone(),
        };
        Ok(base.join(crate::owner_identity::owner_key(owner_sid)))
    }

    fn resolve_setup_helper(&self) -> Result<PathBuf, WindowsSetupError> {
        resolve_resource(
            self.config.setup_helper_source(),
            SETUP_HELPER_NAME,
            "bundled Windows setup helper is not present in the application resource layout",
        )
    }

    fn resolve_command_runner(&self) -> Result<PathBuf, WindowsSetupError> {
        match self.config.command_runner_source() {
            CommandRunnerSource::Bundled => bundled_resource(
                COMMAND_RUNNER_NAME,
                "bundled Windows command runner is not present in the application resource layout",
            ),
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
            runner_manifest_sha256: self.runner_manifest_sha256,
            credential_sha256: self.credential_sha256,
        }
    }
}

fn account_names(owner_sid: &str) -> WindowsSandboxAccounts {
    let names = crate::account_identity::ManagedAccountNames::for_owner(owner_sid);
    WindowsSandboxAccounts {
        offline_name: names.offline,
        offline_sid: String::new(),
        online_name: names.online,
        online_sid: String::new(),
        group_name: names.group,
        group_sid: String::new(),
    }
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
        SetupHelperSource::Bundled => bundled_resource(sibling_name, bundled_error),
        SetupHelperSource::Sibling => sibling_resource(sibling_name),
        SetupHelperSource::Explicit(path) => Ok(path.clone()),
    }
}

fn bundled_resource(name: &str, missing_detail: &str) -> Result<PathBuf, WindowsSetupError> {
    let executable =
        std::env::current_exe().map_err(|error| WindowsSetupError::HelperUnavailable {
            detail: format!("failed to resolve current executable: {error}"),
        })?;
    bundled_resource_path_for_exe(&executable, name).ok_or_else(|| {
        WindowsSetupError::HelperUnavailable {
            detail: format!(
                "{missing_detail}; searched beside {executable:?} and in {RESOURCES_DIRNAME}"
            ),
        }
    })
}

fn bundled_resource_path_for_exe(executable: &Path, name: &str) -> Option<PathBuf> {
    let directory = executable.parent()?;
    let direct = directory.join(name);
    if direct.is_file() {
        return Some(direct);
    }

    if directory
        .file_name()
        .is_some_and(|file_name| file_name == BIN_DIRNAME)
        && let Some(package_directory) = directory.parent()
    {
        let package_resource = package_directory.join(RESOURCES_DIRNAME).join(name);
        if package_resource.is_file() {
            return Some(package_resource);
        }
    }

    let resource = directory.join(RESOURCES_DIRNAME).join(name);
    resource.is_file().then_some(resource)
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

fn pin_setup_resource(path: &Path) -> Result<ValidatedPath, WindowsSetupError> {
    ValidatedPath::open_file_for_execution(path).map_err(|error| {
        WindowsSetupError::HelperResourceUnsafe {
            path: path.to_path_buf(),
            detail: error.to_string(),
        }
    })
}

fn write_pinned_setup_request(path: &Path, encoded: &[u8]) -> Result<fs::File, WindowsSetupError> {
    let mut request_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|error| WindowsSetupError::RequestWrite {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    request_file
        .write_all(encoded)
        .and_then(|()| request_file.sync_all())
        .map_err(|error| WindowsSetupError::RequestWrite {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    Ok(request_file)
}

fn file_digest(resource: &ValidatedPath, path: &Path) -> Result<String, WindowsSetupError> {
    let mut file =
        resource
            .try_clone_file()
            .map_err(|source| WindowsSetupError::HelperResourceRead {
                path: path.to_path_buf(),
                source,
            })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read =
            file.read(&mut buffer)
                .map_err(|source| WindowsSetupError::HelperResourceRead {
                    path: path.to_path_buf(),
                    source,
                })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
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

#[cfg(test)]
mod tests {
    use std::fs;

    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    use super::{bundled_resource_path_for_exe, pin_setup_resource, write_pinned_setup_request};

    #[test]
    fn pinned_setup_resource_cannot_be_rewritten_or_replaced() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("helper.exe");
        fs::write(&path, b"verified helper").expect("write helper fixture");

        let resource = pin_setup_resource(&path).expect("pin helper fixture");
        let write_error = fs::write(&path, b"replacement").expect_err("rewrite must be excluded");
        let delete_error = fs::remove_file(&path).expect_err("replacement must be excluded");

        assert_eq!(
            write_error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        assert_eq!(
            delete_error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        drop(resource);
        fs::remove_file(path).expect("pin release permits cleanup");
    }

    #[test]
    fn pinned_setup_request_cannot_be_rewritten_or_replaced() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("request.json");

        let request = write_pinned_setup_request(&path, b"request").expect("pin request fixture");
        let write_error = fs::write(&path, b"replacement").expect_err("rewrite must be excluded");
        let delete_error = fs::remove_file(&path).expect_err("replacement must be excluded");

        assert_eq!(
            write_error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        assert_eq!(
            delete_error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION as i32)
        );
        drop(request);
        fs::remove_file(path).expect("pin release permits cleanup");
    }

    #[test]
    fn bundled_resource_lookup_prefers_a_direct_sibling() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let resources = temporary.path().join(super::RESOURCES_DIRNAME);
        fs::create_dir_all(&resources).expect("resource directory");
        let executable = temporary.path().join("application.exe");
        let sibling = temporary.path().join(super::SETUP_HELPER_NAME);
        let resource = resources.join(super::SETUP_HELPER_NAME);
        fs::write(&executable, b"application").expect("application");
        fs::write(&sibling, b"sibling").expect("sibling");
        fs::write(&resource, b"resource").expect("resource");

        assert_eq!(
            bundled_resource_path_for_exe(&executable, super::SETUP_HELPER_NAME),
            Some(sibling)
        );
    }

    #[test]
    fn bundled_resource_lookup_checks_package_resources_for_bin_executables() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let bin = temporary.path().join(super::BIN_DIRNAME);
        let resources = temporary.path().join(super::RESOURCES_DIRNAME);
        fs::create_dir_all(&bin).expect("bin directory");
        fs::create_dir_all(&resources).expect("resource directory");
        let executable = bin.join("application.exe");
        let resource = resources.join(super::COMMAND_RUNNER_NAME);
        fs::write(&executable, b"application").expect("application");
        fs::write(&resource, b"runner").expect("runner");

        assert_eq!(
            bundled_resource_path_for_exe(&executable, super::COMMAND_RUNNER_NAME),
            Some(resource)
        );
    }

    #[test]
    fn bundled_resource_lookup_returns_none_for_missing_resources() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let executable = temporary.path().join("application.exe");
        fs::write(&executable, b"application").expect("application");

        assert_eq!(
            bundled_resource_path_for_exe(&executable, super::SETUP_HELPER_NAME),
            None
        );
    }
}
