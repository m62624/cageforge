// SPDX-License-Identifier: Apache-2.0

//! Typed Windows backend and provisioning failures.

use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_policy::{FilesystemMode, NetworkMode};
use thiserror::Error;

use crate::setup_protocol::{SetupFailureCode, SetupStage};

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
    /// The account belongs directly or indirectly to a privileged local group.
    #[error("sandbox account {account:?} is a member of privileged local group {group_sid}")]
    PrivilegedGroupMembership {
        /// Sandbox account name.
        account: String,
        /// Well-known SID of the rejected privileged local group.
        group_sid: String,
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

/// Read-back failure for one mandatory elevated setup component.
#[derive(Debug, Error)]
pub enum WindowsSetupVerificationError {
    /// The marker does not contain exactly two usable ingress ports.
    #[error("Windows setup marker has invalid proxy ingress ports: {ports:?}")]
    InvalidProxyPorts {
        /// Rejected marker ports.
        ports: Vec<u16>,
    },
    /// A live account or group SID differs from the committed marker.
    #[error("Windows setup SID mismatch for {component}: expected {expected}, found {actual}")]
    AccountSidMismatch {
        /// Account or group role.
        component: &'static str,
        /// SID committed by setup.
        expected: String,
        /// SID resolved during read-back.
        actual: String,
    },
    /// Required LSA rights could not be enumerated.
    #[error("failed to enumerate Windows account rights for {account:?}: error {code}")]
    AccountRightsRead {
        /// Sandbox account SID.
        account: String,
        /// Native Win32 code mapped from NTSTATUS.
        code: u32,
    },
    /// A sandbox account lacks one mandatory logon right.
    #[error("Windows sandbox account {account:?} is missing required right {right}")]
    MissingAccountRight {
        /// Sandbox account SID.
        account: String,
        /// Required LSA right.
        right: &'static str,
    },
    /// A protected setup path DACL could not be read.
    #[error("failed to read protected Windows setup DACL {path:?}: error {code}")]
    ProtectedAclRead {
        /// State, credential, marker, or helper path.
        path: PathBuf,
        /// Native Win32 code.
        code: u32,
    },
    /// A protected setup path does not have the required owner/Admin/SYSTEM DACL.
    #[error("protected Windows setup DACL mismatch at {path:?}: {actual}")]
    ProtectedAclMismatch {
        /// State, credential, marker, or helper path.
        path: PathBuf,
        /// Read-back SDDL.
        actual: String,
    },
    /// The protected credential record could not be read.
    #[error("failed to read protected Windows credentials {path:?}: {source}")]
    CredentialRead {
        /// Credential record path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The protected credential record could not be decoded.
    #[error("failed to decode protected Windows credentials {path:?}: {source}")]
    CredentialDecode {
        /// Credential record path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// A staged resource or credential record digest differs from the marker.
    #[error("Windows setup digest mismatch for {component}: expected {expected}, found {actual}")]
    DigestMismatch {
        /// Credential, setup-helper, or command-runner role.
        component: &'static str,
        /// Digest committed by setup.
        expected: String,
        /// Digest computed during read-back.
        actual: String,
    },
    /// DPAPI could not decrypt a committed sandbox credential.
    #[error("failed to decrypt {component} Windows sandbox credential: error {code}")]
    CredentialDecrypt {
        /// Offline or online credential role.
        component: &'static str,
        /// Native Win32 code.
        code: u32,
    },
    /// A decrypted credential record names a different sandbox account.
    #[error("protected Windows credential identity does not match the setup marker")]
    CredentialIdentityMismatch,
    /// A staged helper resource could not be read.
    #[error("failed to read staged Windows setup resource {path:?}: {source}")]
    ResourceRead {
        /// Staged resource path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// Windows Firewall COM initialization failed.
    #[error("failed to initialize COM for Windows Firewall read-back: HRESULT {code:#x}")]
    FirewallComInitialization {
        /// Native HRESULT.
        code: i32,
    },
    /// Windows Firewall policy could not be queried.
    #[error("failed to query effective Windows Firewall policy: HRESULT {code:#x}")]
    FirewallPolicyRead {
        /// Native HRESULT or modify-state value.
        code: i32,
    },
    /// Group Policy prevents local firewall rules from being effective.
    #[error("local Windows Firewall policy is ineffective (state {state})")]
    FirewallPolicyIneffective {
        /// `NET_FW_MODIFY_STATE` value.
        state: i32,
    },
    /// One mandatory firewall rule is absent.
    #[error("mandatory Windows Firewall rule is missing: {name}")]
    FirewallRuleMissing {
        /// Stable owner-scoped rule name.
        name: String,
    },
    /// One property of a mandatory firewall rule differs from its expected state.
    #[error(
        "Windows Firewall rule {name:?} property {property:?} mismatch: expected {expected:?}, found {actual:?}"
    )]
    FirewallRulePropertyMismatch {
        /// Stable owner-scoped rule name.
        name: String,
        /// Exact COM property or semantic security scope that differs.
        property: &'static str,
        /// Canonical expected value or security invariant.
        expected: String,
        /// Value returned by Windows Firewall read-back.
        actual: String,
    },
    /// The WFP engine could not be opened for read-back.
    #[error("failed to open WFP for setup read-back: error {code:#x}")]
    WfpEngineOpen {
        /// Native WFP code.
        code: u32,
    },
    /// The persistent Cageforge WFP provider is absent or stale.
    #[error("Cageforge WFP provider failed read-back: error {code:#x}")]
    WfpProvider {
        /// Zero for a field mismatch, otherwise a native WFP code.
        code: u32,
    },
    /// The persistent Cageforge WFP sublayer is absent or stale.
    #[error("Cageforge WFP sublayer failed read-back: error {code:#x}")]
    WfpSublayer {
        /// Zero for a field mismatch, otherwise a native WFP code.
        code: u32,
    },
    /// One owner-scoped WFP filter is absent or stale.
    #[error("Cageforge WFP filter {name:?} failed read-back: error {code:#x}")]
    WfpFilter {
        /// Stable owner-scoped filter name.
        name: String,
        /// Zero for a field mismatch, otherwise a native WFP code.
        code: u32,
    },
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
    /// Mandatory native setup read-back failed.
    #[error(transparent)]
    Verification(#[from] WindowsSetupVerificationError),
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
    /// A helper resource could not be read for digest pinning.
    #[error("failed to read Windows setup resource {path:?}: {source}")]
    HelperResourceRead {
        /// Setup helper or command-runner path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The versioned setup request could not be written.
    #[error("failed to write Windows setup request {path:?}: {detail}")]
    RequestWrite {
        /// Request file path.
        path: PathBuf,
        /// Filesystem or serialization failure rendered as stable text.
        detail: String,
    },
    /// The elevated helper could not be launched or waited for.
    #[error("failed to run elevated Windows setup helper {path:?}: {source}")]
    HelperLaunch {
        /// Selected helper executable.
        path: PathBuf,
        /// Shell elevation or process wait failure.
        #[source]
        source: io::Error,
    },
    /// The helper exited before creating its mandatory structured response.
    #[error(
        "Windows setup helper exited with code {exit_code:#x} without creating response {path:?} after {last_checkpoint:?}: {source}"
    )]
    HelperResponseMissing {
        /// Expected response file path.
        path: PathBuf,
        /// Native helper process exit code, including NTSTATUS-style crash values.
        exit_code: u32,
        /// Last native setup checkpoint durably recorded by the helper.
        last_checkpoint: Option<String>,
        /// Filesystem error proving that the response is absent.
        #[source]
        source: io::Error,
    },
    /// The structured setup response could not be read.
    #[error("failed to read Windows setup response {path:?}: {source}")]
    ResponseRead {
        /// Response file path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The structured setup response was malformed.
    #[error("failed to decode Windows setup response {path:?}: {source}")]
    ResponseDecode {
        /// Response file path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// The setup response protocol version does not match the request.
    #[error("Windows setup response version mismatch: expected {expected}, found {actual}")]
    ResponseVersionMismatch {
        /// Required helper protocol version.
        expected: u32,
        /// Returned helper protocol version.
        actual: u32,
    },
    /// The helper returned a failing process status without a typed failure.
    #[error("Windows setup helper exited with code {exit_code} after reporting success")]
    HelperExitMismatch {
        /// Native process exit code.
        exit_code: u32,
    },
    /// UAC elevation was cancelled.
    #[error("Windows elevated setup was cancelled by the user")]
    ElevationCanceled,
    /// The setup helper failed.
    #[error("Windows setup helper failed during {stage:?} ({code:?}): {detail}")]
    HelperFailed {
        /// Versioned helper stage.
        stage: SetupStage,
        /// Stable helper failure classification.
        code: SetupFailureCode,
        /// Native Win32, HRESULT, NetAPI, NTSTATUS-mapped, or WFP code.
        native_code: Option<u32>,
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
