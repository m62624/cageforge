// SPDX-License-Identifier: Apache-2.0

//! Versioned messages exchanged with the elevated setup helper.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(crate) const SETUP_PROTOCOL_VERSION: u32 = 3;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SetupRequest {
    pub(crate) version: u32,
    pub(crate) operation: SetupOperation,
    pub(crate) owner_sid: String,
    pub(crate) state_directory: PathBuf,
    pub(crate) setup_helper_sha256: String,
    pub(crate) command_runner_source: PathBuf,
    pub(crate) command_runner_sha256: String,
    pub(crate) proxy_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SetupOperation {
    Install,
    Uninstall,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SetupResponse {
    pub(crate) version: u32,
    pub(crate) outcome: SetupOutcome,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum SetupOutcome {
    Complete,
    Failed {
        stage: SetupStage,
        code: SetupFailureCode,
        native_code: Option<u32>,
        detail: String,
    },
}

/// Elevated setup stage that failed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupStage {
    /// Request framing and resource validation.
    Request,
    /// UAC and administrator-token validation.
    Elevation,
    /// Protected state-directory creation.
    StateDirectory,
    /// Persistent filesystem capability-SID state creation.
    CapabilityState,
    /// Managed local-group provisioning.
    ManagedGroup,
    /// Offline account provisioning.
    OfflineAccount,
    /// Online account provisioning.
    OnlineAccount,
    /// LSA account-right provisioning.
    AccountRights,
    /// DPAPI credential storage.
    Credentials,
    /// Windows Firewall policy installation.
    Firewall,
    /// Windows Filtering Platform installation.
    Wfp,
    /// Final setup-marker commit.
    Marker,
    /// Explicit setup removal.
    Uninstall,
}

/// Exact elevated setup failure classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupFailureCode {
    /// The helper protocol version is unsupported.
    InvalidProtocolVersion,
    /// The owner SID is malformed.
    InvalidOwnerSid,
    /// The selected setup path is unsafe.
    InvalidStateDirectory,
    /// The helper does not have an elevated administrator token.
    NotElevated,
    /// A required state directory could not be created.
    DirectoryCreate,
    /// A state-directory DACL could not be applied or verified.
    DirectoryAcl,
    /// Cryptographic capability-SID generation failed.
    CapabilityStateRandom,
    /// Existing capability-SID state could not be read.
    CapabilityStateRead,
    /// Existing capability-SID state could not be decoded or validated.
    CapabilityStateDecode,
    /// Capability-SID state could not be serialized.
    CapabilityStateSerialize,
    /// Capability-SID state could not be written durably.
    CapabilityStateWrite,
    /// Capability-SID state owner or DACL is ineffective.
    CapabilityStateAcl,
    /// The managed local group could not be created.
    GroupCreate,
    /// A sandbox user could not be created.
    UserCreate,
    /// An existing sandbox user could not be reconciled.
    UserUpdate,
    /// A sandbox account is not classified as an ordinary local user.
    UserNotRegular,
    /// A sandbox account remained disabled after reconciliation.
    UserDisabled,
    /// A sandbox account remained locked after reconciliation.
    UserLocked,
    /// Managed group membership could not be applied or verified.
    GroupMembership,
    /// Required LSA logon rights could not be applied or verified.
    BatchLogonRight,
    /// Cryptographic credential generation failed.
    RandomCredential,
    /// Machine-scope DPAPI protection failed.
    DpapiProtect,
    /// The protected credential record could not be encoded.
    CredentialSerialize,
    /// The protected credential record could not be written.
    CredentialWrite,
    /// The protected credential record DACL is ineffective.
    CredentialAcl,
    /// COM initialization for Windows Firewall failed.
    FirewallComInitialization,
    /// Windows Firewall policy could not be opened or queried.
    FirewallPolicyAccess,
    /// Group Policy prevents local firewall rules from taking effect.
    FirewallPolicyIneffective,
    /// Windows returned an empty or unknown active-profile mask.
    FirewallActiveProfilesInvalid,
    /// Windows Firewall is disabled for one active profile.
    FirewallProfileDisabled,
    /// A firewall rule could not be created.
    FirewallRuleCreate,
    /// A firewall rule could not be configured.
    FirewallRuleConfigure,
    /// An installed firewall rule failed read-back.
    FirewallRuleReadBack,
    /// The WFP engine could not be opened.
    WfpEngineOpen,
    /// A WFP transaction could not be completed.
    WfpTransaction,
    /// The Cageforge WFP provider could not be installed.
    WfpProvider,
    /// The Cageforge WFP sublayer could not be installed.
    WfpSublayer,
    /// An account-scoped WFP filter could not be installed.
    WfpFilter,
    /// WFP state failed read-back.
    WfpReadBack,
    /// The final marker could not be encoded.
    MarkerSerialize,
    /// The final marker could not be written.
    MarkerWrite,
    /// The final marker DACL is ineffective.
    MarkerAcl,
    /// The elevated helper differs from the caller-verified executable.
    HelperDigestMismatch,
    /// The command-runner resource could not be read.
    CommandRunnerRead,
    /// The command-runner resource digest changed before staging.
    CommandRunnerDigestMismatch,
    /// The command runner could not be staged behind the protected DACL.
    CommandRunnerInstall,
    /// Explicit setup cleanup failed.
    Cleanup,
    /// A live sandbox child still owns the setup lifetime boundary.
    ActiveSandboxes,
}
