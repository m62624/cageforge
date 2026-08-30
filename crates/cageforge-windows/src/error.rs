// SPDX-License-Identifier: Apache-2.0

//! Typed Windows backend and provisioning failures.

use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_command::CommandError;
use cageforge_policy::{FilesystemMode, NetworkMode};
use thiserror::Error;

use crate::filesystem_plan::FilesystemPlanError;
use crate::network::{WindowsNetworkGatewayError, WindowsNetworkRuntimeError};
use crate::runner_launch::RunnerLaunchError;
use crate::runner_protocol::{
    WindowsRunnerFailureCode, WindowsRunnerFailureStage, WindowsRunnerProtocolError,
};
use crate::runner_session::RunnerSessionError;
use crate::runner_stdio::WindowsStandardStreamError;
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
    /// The protected capability-SID record could not be read.
    #[error("failed to read protected Windows capability-SID state {path:?}: {source}")]
    CapabilityStateRead {
        /// Capability-SID state path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The protected capability-SID record was malformed or internally inconsistent.
    #[error("invalid protected Windows capability-SID state {path:?}: {detail}")]
    CapabilityStateInvalid {
        /// Capability-SID state path.
        path: PathBuf,
        /// Exact validation failure.
        detail: String,
    },
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
    /// A protected setup path is relative, a reparse point, or resolves to another object.
    #[error("protected Windows setup path is unsafe at {path:?}: {detail}")]
    ProtectedPathUnsafe {
        /// Rejected state, credential, marker, or helper path.
        path: PathBuf,
        /// Exact lexical, reparse-point, or final-path failure.
        detail: String,
    },
    /// A protected setup path has the wrong object owner or effective DACL.
    #[error("protected Windows setup security descriptor mismatch at {path:?}: {actual}")]
    ProtectedSecurityDescriptorMismatch {
        /// State, credential, marker, or helper path.
        path: PathBuf,
        /// Read-back owner and DACL SDDL.
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
    /// A decrypted credential is empty, contains NUL, or is not valid UTF-8.
    #[error("decrypted {component} Windows sandbox credential has invalid encoding")]
    CredentialEncoding {
        /// Offline or online credential role.
        component: &'static str,
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
    /// The protected command-runner manifest could not be read.
    #[error("failed to read protected Windows command-runner manifest {path:?}: {source}")]
    RunnerManifestRead {
        /// Manifest path.
        path: PathBuf,
        /// Filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The protected command-runner manifest could not be decoded.
    #[error("failed to decode protected Windows command-runner manifest {path:?}: {source}")]
    RunnerManifestDecode {
        /// Manifest path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// One protected command-runner manifest field differs from setup state.
    #[error(
        "Windows command-runner manifest field {field:?} mismatch: expected {expected:?}, found {actual:?}"
    )]
    RunnerManifestFieldMismatch {
        /// Stable manifest field name.
        field: &'static str,
        /// Value committed by the setup contract.
        expected: String,
        /// Value read from the manifest.
        actual: String,
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
    /// Windows returned no known active firewall profiles or unknown profile bits.
    #[error("Windows Firewall returned invalid active-profile mask {mask:#x}")]
    FirewallActiveProfilesInvalid {
        /// Raw `INetFwPolicy2::CurrentProfileTypes` bitmask.
        mask: i32,
    },
    /// Windows Firewall is disabled for one currently active profile.
    #[error("Windows Firewall is disabled for active profile {profile:#x}")]
    FirewallProfileDisabled {
        /// One `NET_FW_PROFILE_TYPE2` bit.
        profile: i32,
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
    /// The setup marker is a reparse point or resolves outside its expected path.
    #[error("Windows setup state path is unsafe at {path:?}: {detail}")]
    StatePathUnsafe {
        /// Rejected setup marker path.
        path: PathBuf,
        /// Exact lexical, reparse-point, or final-path failure.
        detail: String,
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
    /// A setup executable source was not one stable non-reparse file.
    #[error("Windows setup resource {path:?} is not safe to execute or stage: {detail}")]
    HelperResourceUnsafe {
        /// Rejected setup helper or command-runner path.
        path: PathBuf,
        /// Exact lexical, reparse-point, identity, or final-path mismatch.
        detail: String,
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
        /// Last native setup checkpoint recorded by the helper.
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
    /// At least one live child still depends on the installed setup boundary.
    #[error("cannot uninstall Windows setup while a sandbox child is active")]
    ActiveSandboxes,
    /// The protected setup lifecycle lock could not be acquired or verified.
    #[error("failed to coordinate Windows setup uninstall: {source}")]
    UninstallCoordination {
        /// Exact protected-lock failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Persistent host ACLs or materialized paths could not be restored exactly.
    #[error("failed to restore Windows filesystem state before uninstall: {source}")]
    UninstallFilesystemCleanup {
        /// Exact journal, identity, ACL, or removal failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
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
    /// Constructing the shared ingress or one isolated policy route failed.
    #[error(transparent)]
    NetworkGateway(#[from] WindowsNetworkGatewayError),
    /// The process-wide proxy ingress failed while a child still depended on it.
    #[error(transparent)]
    NetworkRuntime(#[from] WindowsNetworkRuntimeError),
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
    /// Selecting or transforming the requested environment failed.
    #[error("failed to prepare the Windows command environment: {source}")]
    EnvironmentPreparation {
        /// Portable environment validation failure.
        #[source]
        source: CommandError,
    },
    /// A command, path, or environment value could not be encoded safely.
    #[error("Windows runner request field {field} contains an embedded NUL")]
    RequestEncoding {
        /// Rejected runner request field.
        field: &'static str,
    },
    /// Native filesystem planning failed after portable policy preparation.
    #[error("failed to plan Windows filesystem enforcement: {source}")]
    FilesystemPlanning {
        /// Exact native planning failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Applying or reconciling native filesystem enforcement failed.
    #[error("failed to apply Windows filesystem enforcement: {source}")]
    FilesystemEnforcement {
        /// Exact ACL, capability-state, or path-validation failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The authenticated dedicated-account runner could not be launched.
    #[error("failed to launch the authenticated Windows command runner: {source}")]
    RunnerLaunch {
        /// Exact pipe, desktop, token, process, or Job preparation failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The bounded parent-runner protocol failed.
    #[error(transparent)]
    RunnerProtocol(#[from] WindowsRunnerProtocolError),
    /// Preparing or duplicating an explicit standard-stream handle failed.
    #[error(transparent)]
    StandardStream(#[from] WindowsStandardStreamError),
    /// The parent-owned Job or runner process boundary failed.
    #[error("Windows parent process boundary failed: {source}")]
    RunnerBoundary {
        /// Exact Job or process-boundary failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The authenticated runner rejected one native child operation.
    #[error("Windows command runner failed during {stage:?}/{code:?} ({native_code:?}): {detail}")]
    RunnerFailure {
        /// Native runner phase.
        stage: WindowsRunnerFailureStage,
        /// Exact rejected operation.
        code: WindowsRunnerFailureCode,
        /// Native Win32 code, when supplied by the failed API.
        native_code: Option<u32>,
        /// Bounded runner diagnostic.
        detail: String,
    },
    /// The sandboxed command exceeded its prepared timeout.
    #[error("the sandboxed Windows command exceeded its prepared timeout")]
    ProcessTimedOut,
    /// The authenticated runner lifecycle failed outside a typed child operation.
    #[error("Windows command lifecycle failed: {source}")]
    RunnerLifecycle {
        /// Exact transport, standard-stream, timeout, or reaping failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl WindowsBackendError {
    pub(crate) fn environment_preparation(source: CommandError) -> Self {
        Self::EnvironmentPreparation { source }
    }

    pub(crate) fn filesystem_planning(source: FilesystemPlanError) -> Self {
        Self::FilesystemPlanning {
            source: Box::new(source),
        }
    }

    pub(crate) fn filesystem_enforcement<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::FilesystemEnforcement {
            source: Box::new(source),
        }
    }

    pub(crate) fn runner_launch(source: RunnerLaunchError) -> Self {
        Self::RunnerLaunch {
            source: Box::new(source),
        }
    }

    pub(crate) fn runner_protocol(source: WindowsRunnerProtocolError) -> Self {
        Self::RunnerProtocol(source)
    }

    pub(crate) fn runner_session(source: RunnerSessionError) -> Self {
        match source {
            RunnerSessionError::Launch(source) => Self::runner_launch(source),
            RunnerSessionError::StandardStream(source) => Self::StandardStream(source),
            RunnerSessionError::Protocol(source) => Self::runner_protocol(source),
            RunnerSessionError::Boundary(source) => Self::RunnerBoundary {
                source: Box::new(source),
            },
            RunnerSessionError::RunnerFailure {
                stage,
                code,
                native_code,
                detail,
            } => Self::RunnerFailure {
                stage,
                code,
                native_code,
                detail,
            },
            RunnerSessionError::TimedOut => Self::ProcessTimedOut,
            source => Self::RunnerLifecycle {
                source: Box::new(source),
            },
        }
    }
}
