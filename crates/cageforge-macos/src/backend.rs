// SPDX-License-Identifier: Apache-2.0

//! macOS backend capability declaration and initial construction boundary.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest,
    PreparedBackendRequest, Sandbox, SandboxBackend,
};
use cageforge_command::{CoreEnvironment, EnvironmentBase, EnvironmentInput};
use cageforge_policy::PathResolutionContext;

use crate::config::MacosBackendConfig;
use crate::error::MacosBackendError;
use crate::filesystem::MacosFilesystemPlan;
use crate::network::{GatewayRuntime, MacosNetworkPlan};
use crate::process::{
    MacosChild, ParentDeathChannel, command_deadline, configure_process_group, process_group_id,
    stream,
};
use crate::seatbelt::SeatbeltProfile;

/// A macOS-native backend bound to one validated Seatbelt executable.
///
/// The backend is reusable. Each future `spawn` operation will construct its
/// own policy and process boundary; this object does not represent a shared
/// persistent sandbox.
pub struct MacosBackend {
    config: MacosBackendConfig,
    identity: BackendIdentity,
}

impl std::fmt::Debug for MacosBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MacosBackend")
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl MacosBackend {
    /// Constructs a backend after validating the fixed Seatbelt executable.
    pub fn new(config: MacosBackendConfig) -> Result<Self, MacosBackendError> {
        let path = config.seatbelt_executable().to_path_buf();
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            MacosBackendError::SeatbeltExecutable {
                path: path.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(MacosBackendError::SeatbeltExecutableSymlink { path });
        }
        if !metadata.is_file() {
            return Err(MacosBackendError::SeatbeltExecutableNotRegular { path });
        }
        Ok(Self {
            config,
            identity: BackendIdentity::new(),
        })
    }

    /// Returns the immutable backend configuration.
    pub const fn config(&self) -> &MacosBackendConfig {
        &self.config
    }

    /// Runs common Cageforge preflight and native filesystem/network lowering.
    pub fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, MacosBackendError> {
        let prepared = request.prepare_for(self, context)?;
        MacosFilesystemPlan::lower(self, &prepared)?;
        MacosNetworkPlan::lower(self, &prepared)?;
        Ok(prepared)
    }

    /// Launches one command in its own Seatbelt process boundary.
    pub fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<MacosChild, MacosBackendError> {
        let sandbox = prepared.sandbox(self)?;
        let filesystem = MacosFilesystemPlan::lower(self, &prepared)?;
        let mut network = MacosNetworkPlan::lower(self, &prepared)?;
        let timeout = match prepared.timeout_policy(self)? {
            cageforge_command::TimeoutPolicy::BackendDefault => Some(self.config.default_timeout()),
            cageforge_command::TimeoutPolicy::Limit(timeout) => Some(timeout),
            cageforge_command::TimeoutPolicy::Disabled => None,
        };
        let mut gateway = if network.requires_gateway() {
            Some(GatewayRuntime::start(
                sandbox.network().clone(),
                self.config.network_gateway().clone(),
            )?)
        } else {
            None
        };
        if let Some(runtime) = gateway.as_ref() {
            network = network.with_ingress_port(runtime.port());
        }
        let profile = SeatbeltProfile::build(&filesystem, &network)?;
        let command_spec = prepared.command_spec(self)?;
        let mut environment = prepared
            .apply_environment(self, self.environment_input(sandbox.environment().base())?)?;
        if let Some(port) = network.proxy_port() {
            apply_proxy_environment(&mut environment, port);
        }

        let mut command = std::process::Command::new(self.config.seatbelt_executable());
        command.arg("-p").arg(profile.policy());
        for definition in profile.definitions() {
            let mut definition_argument = OsString::from("-D");
            definition_argument.push(definition.name());
            definition_argument.push("=");
            definition_argument.push(definition.value());
            command.arg(definition_argument);
        }
        let parent_death = ParentDeathChannel::new()
            .map_err(|source| MacosBackendError::ParentDeathChannel { source })?;
        command.arg("--").arg("/bin/sh");
        command.arg("-c").arg(crate::process::PARENT_DEATH_WRAPPER);
        command.arg("cageforge-macos-boundary");
        command.arg(command_spec.program());
        command.args(command_spec.args());
        command.current_dir(prepared.working_directory(self)?);
        command.env_clear();
        command.envs(environment);
        let stdio = prepared.stdio(self)?;
        command.stdin(stream(stdio.stdin()));
        command.stdout(stream(stdio.stdout()));
        command.stderr(stream(stdio.stderr()));
        configure_process_group(&mut command, parent_death.read_fd());
        let deadline = command_deadline(timeout)?;
        let child = command
            .spawn()
            .map_err(|source| MacosBackendError::ProcessStart { source })?;
        let process_group_id = match process_group_id(child.id()) {
            Ok(process_group_id) => process_group_id,
            Err(error) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(MacosChild::new(
            child,
            process_group_id,
            parent_death.into_writer(),
            gateway.take(),
            deadline,
        ))
    }

    fn environment_input(
        &self,
        base: EnvironmentBase,
    ) -> Result<EnvironmentInput, MacosBackendError> {
        match base {
            EnvironmentBase::All => EnvironmentInput::all(std::env::vars_os())
                .map_err(|source| MacosBackendError::EnvironmentPreparation { source }),
            EnvironmentBase::Core => {
                let selected = std::env::vars_os().filter(|(name, _)| {
                    name.to_str().is_some_and(|name| {
                        matches!(
                            name,
                            "PATH"
                                | "SHELL"
                                | "TMPDIR"
                                | "TEMP"
                                | "TMP"
                                | "HOME"
                                | "LANG"
                                | "LC_ALL"
                                | "LC_CTYPE"
                                | "LOGNAME"
                                | "USER"
                        )
                    })
                });
                let core = CoreEnvironment::from_selected(selected)
                    .map_err(|source| MacosBackendError::EnvironmentPreparation { source })?;
                Ok(EnvironmentInput::core(core))
            }
            EnvironmentBase::None => Ok(EnvironmentInput::empty()),
        }
    }
}

impl Sandbox for MacosBackend {
    type Child = MacosChild;
    type Error = MacosBackendError;

    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &cageforge_policy::PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error> {
        MacosBackend::prepare(self, request, context)
    }

    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error> {
        MacosBackend::spawn(self, prepared)
    }
}

impl SandboxBackend for MacosBackend {
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
            BackendCapability::TimeoutDisabled,
            BackendCapability::TimeoutBackendDefault,
            BackendCapability::TimeoutLimit,
            BackendCapability::FilesystemRestricted,
            BackendCapability::FilesystemUnrestricted,
            BackendCapability::FilesystemScopes,
            BackendCapability::FilesystemAbsoluteScopes,
            BackendCapability::FilesystemWorkspaceScopes,
            BackendCapability::FilesystemRootScopes,
            BackendCapability::FilesystemMinimalScopes,
            BackendCapability::FilesystemTmpdirScopes,
            BackendCapability::FilesystemConventionalTemporaryScopes,
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
            BackendCapability::NetworkLocalIpcIsolation,
            BackendCapability::NetworkLocalIpcRules,
            BackendCapability::EnvironmentAll,
            BackendCapability::EnvironmentCore,
            BackendCapability::EnvironmentNone,
            BackendCapability::EnvironmentFilters,
            BackendCapability::EnvironmentOverrides,
        ])
    }
}

fn apply_proxy_environment(environment: &mut BTreeMap<OsString, OsString>, port: u16) {
    const PROXY_NAMES: [&str; 8] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ];
    environment.retain(|name, _| {
        !PROXY_NAMES.iter().any(|proxy_name| {
            cageforge_command::EnvironmentNameKey::new(name)
                == cageforge_command::EnvironmentNameKey::new(OsStr::new(proxy_name))
        })
    });
    let http = OsString::from(format!("http://127.0.0.1:{port}"));
    let socks = OsString::from(format!("socks5h://127.0.0.1:{port}"));
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
        environment.insert(OsString::from(name), http.clone());
    }
    for name in ["ALL_PROXY", "all_proxy"] {
        environment.insert(OsString::from(name), socks.clone());
    }
    environment.insert(OsString::from("NO_PROXY"), OsString::new());
    environment.insert(OsString::from("no_proxy"), OsString::new());
}
