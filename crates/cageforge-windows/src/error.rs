// SPDX-License-Identifier: Apache-2.0

//! Typed Windows backend and provisioning failures.

use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_policy::{FilesystemMode, NetworkMode};
use thiserror::Error;

/// Failure while resolving one Windows account or group SID.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsAccountLookupError {
    /// Windows rejected the initial SID buffer-size query.
    #[error("failed to query SID size for Windows account {account:?}: error {code}")]
    SidSizeQuery {
        /// Account or group name.
        account: String,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows failed to populate the account SID.
    #[error("failed to resolve SID for Windows account {account:?}: error {code}")]
    SidRead {
        /// Account or group name.
        account: String,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows failed to convert a resolved SID to its canonical string.
    #[error("failed to format SID for Windows account {account:?}: error {code}")]
    SidFormat {
        /// Account or group name.
        account: String,
        /// Native Windows error code.
        code: u32,
    },
}

/// Failure while proving that a provisioned sandbox account is unprivileged.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsAccountVerificationError {
    /// Windows could not read the local user record.
    #[error("failed to read local sandbox account {account:?}: error {code}")]
    UserRecordRead {
        /// Sandbox account name.
        account: String,
        /// Native NetAPI status.
        code: u32,
    },
    /// The account has a non-user privilege classification.
    #[error("sandbox account {account:?} is not a regular local user (privilege class {actual})")]
    NotRegularUser {
        /// Sandbox account name.
        account: String,
        /// Native `usri1_priv` value.
        actual: u32,
    },
    /// The account is disabled.
    #[error("sandbox account {account:?} is disabled")]
    Disabled {
        /// Sandbox account name.
        account: String,
    },
    /// The account is locked.
    #[error("sandbox account {account:?} is locked")]
    Locked {
        /// Sandbox account name.
        account: String,
    },
    /// Windows could not enumerate local group membership.
    #[error("failed to enumerate local groups for sandbox account {account:?}: error {code}")]
    GroupEnumeration {
        /// Sandbox account name.
        account: String,
        /// Native NetAPI status.
        code: u32,
    },
    /// NetAPI returned a null local-group name.
    #[error("Windows returned an invalid local-group entry for sandbox account {account:?}")]
    InvalidGroupEntry {
        /// Sandbox account name.
        account: String,
    },
    /// A returned local group could not be resolved to a SID.
    #[error("failed to resolve local group {group:?} for sandbox account {account:?}: {source}")]
    GroupSidLookup {
        /// Sandbox account name.
        account: String,
        /// Returned local-group name.
        group: String,
        /// SID lookup failure.
        #[source]
        source: WindowsAccountLookupError,
    },
    /// The account is not in the Cageforge-managed group.
    #[error("sandbox account {account:?} is not a member of managed group {group:?}")]
    MissingManagedGroup {
        /// Sandbox account name.
        account: String,
        /// Required Cageforge group.
        group: String,
    },
    /// The account is a direct or indirect administrator.
    #[error("sandbox account {account:?} is a member of Administrators")]
    AdministratorMembership {
        /// Sandbox account name.
        account: String,
    },
}

/// A Windows filesystem policy shape that cannot be enforced without widening.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsFilesystemShapeError {
    /// Another component claimed filesystem ownership.
    #[error("Windows backend does not accept external filesystem ownership")]
    ExternalOwnership,
    /// A restricted policy omitted every readable platform or root scope.
    #[error(
        "Windows elevated filesystem enforcement requires a readable root or platform-minimal scope"
    )]
    MissingReadablePlatformBase,
    /// Windows has no meaningful conventional Unix `/tmp` scope.
    #[error("Windows backend cannot enforce the conventional Unix /tmp selector")]
    SlashTmpScope,
    /// An unbounded root-level glob would require scanning the complete machine.
    #[error("Windows backend rejects an unbounded glob rooted at a complete system volume")]
    UnboundedRootGlob,
}

/// A Windows filesystem/network ownership combination that cannot be enforced.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsNetworkCombinationError {
    /// Another component claimed network ownership.
    #[error("Windows backend does not accept external network ownership")]
    ExternalOwnership,
    /// Windows pathname Unix socket rules are not a Windows sandbox primitive.
    #[error("Windows backend does not support pathname Unix socket policy")]
    UnixSocketPolicy,
    /// Current-identity filesystem access cannot be combined with an offline account.
    #[error("unrestricted filesystem access requires unrestricted direct networking on Windows")]
    UnrestrictedFilesystemWithRestrictedNetwork,
    /// Restricted filesystem enforcement cannot be performed under the current identity.
    #[error("restricted Windows filesystem enforcement requires a provisioned sandbox identity")]
    RestrictedFilesystemWithCurrentIdentity,
}

/// Provisioning, marker, account, firewall, or WFP verification failure.
#[derive(Debug, Error)]
pub enum WindowsSetupError {
    /// Windows could not resolve ProgramData.
    #[error("failed to resolve the Windows ProgramData directory (HRESULT {code:#x})")]
    ProgramDataUnavailable {
        /// Native HRESULT.
        code: i32,
    },
    /// The current process identity could not be read.
    #[error("failed to read the current Windows user SID: {source}")]
    CurrentUserSid {
        /// Native I/O failure.
        #[source]
        source: io::Error,
    },
    /// The protected setup marker is absent.
    #[error("Windows elevated setup is missing at {path:?}")]
    Missing {
        /// Expected marker path.
        path: PathBuf,
    },
    /// Setup state could not be read.
    #[error("failed to read Windows setup state {path:?}: {source}")]
    StateRead {
        /// State file path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// Setup state was not valid JSON.
    #[error("failed to decode Windows setup state {path:?}: {source}")]
    StateDecode {
        /// State file path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// The marker version does not match this crate.
    #[error("Windows setup version mismatch: expected {expected}, found {actual}")]
    VersionMismatch {
        /// Required version.
        expected: u32,
        /// Stored version.
        actual: u32,
    },
    /// Setup belongs to a different signed-in identity.
    #[error("Windows setup owner SID mismatch: expected {expected}, found {actual}")]
    OwnerMismatch {
        /// Current real-user SID.
        expected: String,
        /// Stored owner SID.
        actual: String,
    },
    /// Deterministic account names do not match the marker.
    #[error("Windows setup account identity does not match its owner SID")]
    AccountIdentityMismatch,
    /// Setup read-back found an ineffective native component.
    #[error("Windows setup verification failed for {component}: {detail}")]
    NativeVerification {
        /// Native component name.
        component: &'static str,
        /// Stable diagnostic.
        detail: String,
    },
    /// A setup account or group SID could not be resolved.
    #[error("Windows setup account lookup failed for {component}: {source}")]
    AccountLookup {
        /// Setup component being checked.
        component: &'static str,
        /// Typed lookup failure.
        #[source]
        source: WindowsAccountLookupError,
    },
    /// A setup account failed its unprivileged-membership contract.
    #[error(transparent)]
    AccountVerification(#[from] WindowsAccountVerificationError),
    /// A setup-helper source is unavailable.
    #[error("Windows setup helper is unavailable: {detail}")]
    HelperUnavailable {
        /// Resolution diagnostic.
        detail: String,
    },
    /// UAC elevation was cancelled.
    #[error("Windows elevated setup was cancelled by the user")]
    ElevationCanceled,
    /// The setup helper failed.
    #[error("Windows setup helper failed during {stage}: {detail}")]
    HelperFailed {
        /// Versioned helper stage.
        stage: String,
        /// Helper diagnostic.
        detail: String,
    },
}

/// Windows backend preparation, lowering, setup, and process failure.
#[derive(Debug, Error)]
pub enum WindowsBackendError {
    /// Portable capability or backend-identity validation failed.
    #[error(transparent)]
    BackendContract(#[from] BackendContractError),
    /// Elevated setup is missing, stale, or ineffective.
    #[error(transparent)]
    Setup(#[from] WindowsSetupError),
    /// The filesystem shape cannot be enforced safely.
    #[error(transparent)]
    FilesystemShape(#[from] WindowsFilesystemShapeError),
    /// The network/filesystem combination cannot be enforced safely.
    #[error(transparent)]
    NetworkCombination(#[from] WindowsNetworkCombinationError),
    /// A native capability was deliberately not advertised.
    #[error("Windows backend cannot safely enforce required capability: {capability}")]
    UnsupportedCapability {
        /// Unsupported portable capability.
        capability: BackendCapability,
    },
    /// A mode pair reached lowering after validation unexpectedly.
    #[error(
        "invalid Windows native lowering modes: filesystem={filesystem:?}, network={network:?}"
    )]
    InvalidLoweringModes {
        /// Effective filesystem ownership.
        filesystem: FilesystemMode,
        /// Effective network ownership.
        network: NetworkMode,
    },
    /// A native Windows operation failed.
    #[error("Windows sandbox operation {operation} failed: {source}")]
    Native {
        /// Stable operation label.
        operation: &'static str,
        /// Native failure.
        #[source]
        source: io::Error,
    },
}
