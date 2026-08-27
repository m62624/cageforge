// SPDX-License-Identifier: Apache-2.0

//! Windows backend construction, capability declaration, and native lowering.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest,
    PreparedBackendRequest, SandboxBackend,
};
use cageforge_command::{
    CoreEnvironment, EnvironmentBase, EnvironmentInput, EnvironmentNameKey, TimeoutPolicy,
};
use cageforge_policy::{FilesystemMode, NetworkMode};

use crate::capability_store::CapabilityStateStore;
use crate::config::WindowsBackendConfig;
use crate::error::{
    WindowsBackendError, WindowsFilesystemShapeError, WindowsNetworkCombinationError,
};
use crate::filesystem_acl::FilesystemAclEnforcement;
use crate::filesystem_plan::{FilesystemPlan, FilesystemPlanError};
use crate::network::{ProxyAddresses, WindowsProxyIngress, WindowsProxyRoute};
use crate::process::WindowsChild;
use crate::runner_launch::RunnerLaunch;
use crate::runner_protocol::RunnerAccount;
use crate::runner_session::{PendingRunnerSpawnRequest, RunnerSession};
use crate::setup::{WindowsSetup, WindowsSetupDetails};
use crate::setup_verification::credentials::{AccountCredential, SandboxCredentials};

const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";

/// A Windows-native Cageforge backend bound to one verified elevated setup.
pub struct WindowsBackend {
    config: WindowsBackendConfig,
    setup: WindowsSetupDetails,
    credentials: SandboxCredentials,
    capability_state: CapabilityStateStore,
    command_runner: PathBuf,
    identity: BackendIdentity,
}

struct WindowsLaunchPlan {
    filesystem: FilesystemPlan,
    account: RunnerAccount,
    mode: WindowsExecutionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsExecutionMode {
    Disabled,
    ProxyRouted,
    Direct,
}

impl fmt::Debug for WindowsBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsBackend")
            .field("config", &self.config)
            .field("setup", &self.setup)
            .field("command_runner", &self.command_runner)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl WindowsBackend {
    /// Constructs a backend after verifying the complete elevated setup.
    pub fn new(config: WindowsBackendConfig) -> Result<Self, WindowsBackendError> {
        let setup = WindowsSetup::new(config.setup().clone()).verify()?;
        let credentials = crate::setup_verification::read_credentials(&setup)
            .map_err(crate::error::WindowsSetupError::from)?;
        let capability_state =
            CapabilityStateStore::new(setup.state_directory(), setup.owner_sid());
        capability_state
            .verify()
            .map_err(WindowsBackendError::filesystem_enforcement)?;
        let command_runner = setup
            .state_directory()
            .join("bin")
            .join(COMMAND_RUNNER_NAME);
        Ok(Self {
            config,
            setup,
            credentials,
            capability_state,
            command_runner,
            identity: BackendIdentity::new(),
        })
    }

    /// Returns the immutable settings used to construct this backend.
    pub const fn config(&self) -> &WindowsBackendConfig {
        &self.config
    }

    /// Returns the verified elevated setup bound to this backend instance.
    pub const fn setup(&self) -> &WindowsSetupDetails {
        &self.setup
    }

    /// Returns the protected installed command-runner path.
    pub fn command_runner_path(&self) -> &Path {
        &self.command_runner
    }

    /// Runs common Cageforge preflight and Windows-specific combination checks.
    pub fn prepare<'request>(
        &self,
        request: BackendRequest<'request>,
        context: &cageforge_policy::PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'request, Self>, WindowsBackendError> {
        let prepared = request.prepare_for(self, context)?;
        let _ = execution_mode(&prepared, self)?;
        Ok(prepared)
    }

    /// Launches a command from a backend-bound prepared request.
    pub fn spawn<'request>(
        &self,
        prepared: PreparedBackendRequest<'request, Self>,
    ) -> Result<WindowsChild, WindowsBackendError> {
        let plan = self.lower(&prepared)?;
        let sandbox = prepared.sandbox(self)?;
        let network_route = self.network_route(plan.mode, sandbox.network().clone())?;
        let enforcement = FilesystemAclEnforcement::apply(
            &plan.filesystem,
            &self.capability_state,
            self.setup.accounts().group_sid(),
        )
        .map_err(WindowsBackendError::filesystem_enforcement)?;
        let command = prepared.command_spec(self)?;
        let environment = self.environment_input(sandbox.environment().base())?;
        let mut environment = prepared.apply_environment(self, environment)?;
        if let Some(route) = &network_route {
            apply_proxy_environment(&mut environment, route.addresses());
        }
        let timeout = timeout(&prepared, self)?;
        let stdio = prepared.stdio(self)?;
        let credential = self.credential(plan.account);
        let route_sid = network_route.as_ref().map(|route| route.sid().to_string());
        let request = PendingRunnerSpawnRequest {
            command: encode_command(command.program(), command.args())?,
            working_directory: encode_field(
                "working directory",
                prepared.working_directory(self)?.as_os_str(),
            )?,
            environment_block: encode_environment(environment)?,
            capability_sids: enforcement.token_sids().to_vec(),
            route_sid,
            account: plan.account,
        };
        let launch = RunnerLaunch::start(
            &self.command_runner,
            prepared.working_directory(self)?,
            credential,
            self.setup.owner_sid(),
        )
        .map_err(WindowsBackendError::runner_launch)?;
        let session = RunnerSession::start(launch, request, stdio, timeout)
            .map_err(WindowsBackendError::runner_session)?;
        Ok(WindowsChild::new(session, enforcement, network_route))
    }

    fn lower<'request>(
        &self,
        prepared: &PreparedBackendRequest<'request, Self>,
    ) -> Result<WindowsLaunchPlan, WindowsBackendError> {
        let mode = execution_mode(prepared, self)?;
        let filesystem = FilesystemPlan::lower(self, prepared).map_err(map_filesystem_plan)?;
        let account = match mode {
            WindowsExecutionMode::Disabled | WindowsExecutionMode::ProxyRouted => {
                RunnerAccount::Offline
            }
            WindowsExecutionMode::Direct => RunnerAccount::Online,
        };
        Ok(WindowsLaunchPlan {
            filesystem,
            account,
            mode,
        })
    }

    fn credential(&self, account: RunnerAccount) -> &AccountCredential {
        match account {
            RunnerAccount::Offline => self.credentials.offline(),
            RunnerAccount::Online => self.credentials.online(),
        }
    }

    fn network_route(
        &self,
        mode: WindowsExecutionMode,
        policy: cageforge_policy_compose::EffectiveNetworkPolicy,
    ) -> Result<Option<WindowsProxyRoute>, WindowsBackendError> {
        if mode != WindowsExecutionMode::ProxyRouted {
            return Ok(None);
        }
        let ingress =
            WindowsProxyIngress::shared(self.setup.owner_sid(), self.setup.proxy_ports())?;
        let route = ingress.register_route(policy, self.config.network_gateway_config().clone())?;
        Ok(Some(route))
    }

    fn environment_input(
        &self,
        base: EnvironmentBase,
    ) -> Result<EnvironmentInput, WindowsBackendError> {
        match base {
            EnvironmentBase::All => EnvironmentInput::all(std::env::vars_os())
                .map_err(WindowsBackendError::environment_preparation),
            EnvironmentBase::Core => {
                let selected =
                    std::env::vars_os().filter(|(name, _)| is_windows_core_environment_name(name));
                let core = CoreEnvironment::from_selected(selected)
                    .map_err(WindowsBackendError::environment_preparation)?;
                Ok(EnvironmentInput::core(core))
            }
            EnvironmentBase::None => Ok(EnvironmentInput::empty()),
        }
    }
}

impl SandboxBackend for WindowsBackend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::from_capabilities([
            BackendCapability::CommandExecution,
            BackendCapability::WorkingDirectory,
            BackendCapability::StdioInherit,
            BackendCapability::StdioNull,
            BackendCapability::StdioPipe,
            BackendCapability::TimeoutBackendDefault,
            BackendCapability::TimeoutLimit,
            BackendCapability::TimeoutDisabled,
            BackendCapability::FilesystemRestricted,
            BackendCapability::FilesystemScopes,
            BackendCapability::FilesystemAbsoluteScopes,
            BackendCapability::FilesystemWorkspaceScopes,
            BackendCapability::FilesystemRootScopes,
            BackendCapability::FilesystemMinimalScopes,
            BackendCapability::FilesystemTmpdirScopes,
            BackendCapability::FilesystemReadOnlySubpaths,
            BackendCapability::FilesystemGlobs,
            BackendCapability::FilesystemGlobScanDepth,
            BackendCapability::FilesystemMissingPathBehavior,
            BackendCapability::FilesystemProtectedPaths,
            BackendCapability::NetworkDisabled,
            BackendCapability::NetworkEnabled,
            BackendCapability::NetworkDomainRules,
            BackendCapability::NetworkLocalAddressRestrictions,
            BackendCapability::NetworkResolvedTargets,
            BackendCapability::EnvironmentAll,
            BackendCapability::EnvironmentCore,
            BackendCapability::EnvironmentNone,
            BackendCapability::EnvironmentFilters,
            BackendCapability::EnvironmentOverrides,
        ])
    }
}

fn execution_mode<'request>(
    prepared: &PreparedBackendRequest<'request, WindowsBackend>,
    backend: &WindowsBackend,
) -> Result<WindowsExecutionMode, WindowsBackendError> {
    let sandbox = prepared.sandbox(backend)?;
    let _ = prepared.filesystem_lowering(backend)?;
    let _ = prepared.network_lowering(backend)?;
    let filesystem = sandbox.filesystem().requirements().mode();
    let network_requirements = sandbox.network().requirements();
    let network = network_requirements.mode();
    match (filesystem, network) {
        (FilesystemMode::Restricted, NetworkMode::Disabled) => Ok(WindowsExecutionMode::Disabled),
        (FilesystemMode::Restricted, NetworkMode::Enabled)
            if network_requirements.domain_rules()
                || network_requirements.local_address_restrictions()
                || network_requirements.resolved_targets() =>
        {
            Ok(WindowsExecutionMode::ProxyRouted)
        }
        (FilesystemMode::Restricted, NetworkMode::Enabled) => Ok(WindowsExecutionMode::Direct),
        (FilesystemMode::External, _) => Err(WindowsFilesystemShapeError::ExternalOwnership.into()),
        (_, NetworkMode::External) => Err(WindowsNetworkCombinationError::ExternalOwnership.into()),
        (filesystem, network) => Err(WindowsBackendError::InvalidLoweringModes {
            filesystem,
            network,
        }),
    }
}

fn apply_proxy_environment(
    environment: &mut BTreeMap<OsString, OsString>,
    addresses: ProxyAddresses,
) {
    const MANAGED_PROXY_NAMES: [&str; 8] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ];
    for managed_name in MANAGED_PROXY_NAMES {
        let managed_key = EnvironmentNameKey::new(OsStr::new(managed_name));
        environment.retain(|name, _| EnvironmentNameKey::new(name) != managed_key);
    }

    let http_proxy = OsString::from(format!("http://{}", addresses.http()));
    let socks_proxy = OsString::from(format!("socks5h://{}", addresses.socks()));
    environment.insert(OsString::from("HTTP_PROXY"), http_proxy.clone());
    environment.insert(OsString::from("HTTPS_PROXY"), http_proxy);
    environment.insert(OsString::from("ALL_PROXY"), socks_proxy);
    environment.insert(OsString::from("NO_PROXY"), OsString::new());
}

fn timeout<'request>(
    prepared: &PreparedBackendRequest<'request, WindowsBackend>,
    backend: &WindowsBackend,
) -> Result<Option<Duration>, WindowsBackendError> {
    match prepared.timeout_policy(backend)? {
        TimeoutPolicy::BackendDefault => Ok(Some(backend.config.default_timeout())),
        TimeoutPolicy::Limit(timeout) => Ok(Some(timeout)),
        TimeoutPolicy::Disabled => Ok(None),
    }
}

fn encode_command(
    program: &OsStr,
    arguments: &[OsString],
) -> Result<Vec<Vec<u16>>, WindowsBackendError> {
    std::iter::once(program)
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(|argument| encode_field("command argument", argument))
        .collect()
}

fn encode_field(field: &'static str, value: &OsStr) -> Result<Vec<u16>, WindowsBackendError> {
    let encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        Err(WindowsBackendError::RequestEncoding { field })
    } else {
        Ok(encoded)
    }
}

fn encode_environment(
    environment: BTreeMap<OsString, OsString>,
) -> Result<Vec<u16>, WindowsBackendError> {
    let mut environment = environment.into_iter().collect::<Vec<_>>();
    environment.sort_by_key(|(name, _)| EnvironmentNameKey::new(name));
    let mut block = Vec::new();
    for (name, value) in environment {
        block.extend(encode_field("environment variable name", &name)?);
        block.push(b'=' as u16);
        block.extend(encode_field("environment variable value", &value)?);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn is_windows_core_environment_name(name: &OsStr) -> bool {
    const CORE_NAMES: [&str; 17] = [
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    ];
    let key = EnvironmentNameKey::new(name);
    CORE_NAMES
        .iter()
        .any(|candidate| EnvironmentNameKey::new(OsStr::new(candidate)) == key)
}

fn map_filesystem_plan(error: FilesystemPlanError) -> WindowsBackendError {
    match error {
        FilesystemPlanError::BackendContract(source) => source.into(),
        FilesystemPlanError::ExternalOwnership => {
            WindowsFilesystemShapeError::ExternalOwnership.into()
        }
        FilesystemPlanError::MissingReadablePlatformBase => {
            WindowsFilesystemShapeError::MissingReadablePlatformBase.into()
        }
        FilesystemPlanError::SlashTmpScope => WindowsFilesystemShapeError::SlashTmpScope.into(),
        FilesystemPlanError::UnboundedRootGlob => {
            WindowsFilesystemShapeError::UnboundedRootGlob.into()
        }
        other => WindowsBackendError::filesystem_planning(other),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

    use pretty_assertions::assert_eq;

    use super::{apply_proxy_environment, encode_environment, is_windows_core_environment_name};
    use crate::network::ProxyAddresses;

    #[test]
    fn empty_environment_block_has_the_required_double_terminator() {
        assert_eq!(
            encode_environment(BTreeMap::new()).expect("empty environment"),
            vec![0, 0]
        );
    }

    #[test]
    fn environment_block_uses_logical_name_order_and_double_termination() {
        let environment = BTreeMap::from([
            (OsString::from("windir"), OsString::from(r"C:\Windows")),
            (OsString::from("Path"), OsString::from(r"C:\Tools")),
        ]);
        let actual = encode_environment(environment).expect("Windows environment block");
        let expected = "Path=C:\\Tools\0windir=C:\\Windows\0\0"
            .encode_utf16()
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn environment_block_rejects_embedded_nul_values() {
        let environment =
            BTreeMap::from([(OsString::from("PATH"), OsString::from("before\0after"))]);

        assert!(encode_environment(environment).is_err());
    }

    #[test]
    fn core_environment_selection_uses_portable_case_insensitive_identity() {
        assert!(is_windows_core_environment_name(OsStr::new("systemroot")));
        assert!(is_windows_core_environment_name(OsStr::new(
            "ProgramFiles(x86)"
        )));
        assert!(!is_windows_core_environment_name(OsStr::new(
            "SSH_AUTH_SOCK"
        )));
    }

    #[test]
    fn proxy_environment_replaces_user_values_after_portable_transformation() {
        let mut environment = BTreeMap::from([
            (
                OsString::from("http_proxy"),
                OsString::from("http://attacker.invalid:1"),
            ),
            (
                OsString::from("No_Proxy"),
                OsString::from("127.0.0.1,localhost"),
            ),
            (OsString::from("PATH"), OsString::from(r"C:\Tools")),
        ]);
        let addresses = ProxyAddresses::from_setup_ports(&[31_280, 31_281]).expect("ports");

        apply_proxy_environment(&mut environment, addresses);

        assert_eq!(
            environment.get(OsStr::new("HTTP_PROXY")),
            Some(&OsString::from("http://127.0.0.1:31280"))
        );
        assert_eq!(
            environment.get(OsStr::new("HTTPS_PROXY")),
            Some(&OsString::from("http://127.0.0.1:31280"))
        );
        assert_eq!(
            environment.get(OsStr::new("ALL_PROXY")),
            Some(&OsString::from("socks5h://127.0.0.1:31281"))
        );
        assert_eq!(
            environment.get(OsStr::new("NO_PROXY")),
            Some(&OsString::new())
        );
        assert!(!environment.contains_key(OsStr::new("http_proxy")));
        assert!(!environment.contains_key(OsStr::new("No_Proxy")));
        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&OsString::from(r"C:\Tools"))
        );
    }
}
