// SPDX-License-Identifier: Apache-2.0

//! Linux backend construction, capability declaration, and policy lowering.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest,
    PreparedBackendRequest, SandboxBackend,
};
use cageforge_command::{EnvironmentBase, EnvironmentInput, StdioMode};
use cageforge_policy::NetworkMode;
use cageforge_policy_compose::EffectiveSandbox;
use command_fds::CommandFdExt;

use crate::bwrap::{
    discover_and_probe, discover_hardening_helper, namespace_args, open_pinned, resource_directory,
};
use crate::config::LinuxBackendConfig;
use crate::environment_transport::write_environment;
use crate::error::{LinuxBackendError, NetworkCombinationError, NetworkLoweringError};
use crate::filesystem::FilesystemPlan;
use crate::filesystem::protected_create::ProtectedCreateMonitor;
use crate::helper_protocol::{
    AUTH_FD_ENV, AUTH_TOKEN, GATEWAY_CONNECTION_LIMIT_ENV, GATEWAY_SOCKET_ENV,
    HARDENING_REQUIRED_ENV, NETWORK_MODE_DIRECT_WITHOUT_UNIX, NETWORK_MODE_DISABLED,
    NETWORK_MODE_ENV, NETWORK_MODE_PROXY, READY, RELEASE,
};
use crate::network::{GatewayRuntime, IN_SANDBOX_GATEWAY_SOCKET};
use crate::process::LinuxChild;
use crate::process::timeout::TimeoutWatchdog;

pub(crate) const IN_SANDBOX_HELPER_PATH: &str = "/dev/.cageforge-runtime/helper";
const SETUP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_DIAGNOSTIC_LIMIT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxNetworkMode {
    Direct,
    DirectWithoutUnixSockets,
    Disabled,
    ProxyRouted,
}

/// A validated immutable Bubblewrap argument plan before the command and
/// environment are appended.
#[derive(Debug)]
pub(crate) struct LinuxLaunchPlan {
    args: Vec<OsString>,
    filesystem: FilesystemPlan,
}

/// A Linux native Cageforge backend bound to one validated Bubblewrap binary.
#[derive(Debug, Clone)]
pub struct LinuxBackend {
    config: LinuxBackendConfig,
    bubblewrap: PathBuf,
    bubblewrap_file: Arc<File>,
    hardening_helper: PathBuf,
    hardening_helper_file: Arc<File>,
    timeout_supported: bool,
    identity: BackendIdentity,
}

impl LinuxBackend {
    /// Constructs a backend and verifies Bubblewrap's required namespace API.
    pub fn new(config: LinuxBackendConfig) -> Result<Self, LinuxBackendError> {
        let resource_directory = resource_directory(config.resource_directory_source())?;
        let bubblewrap = discover_and_probe(
            config.bubblewrap(),
            resource_directory.as_deref(),
            config.proc_mount(),
        )?;
        let bubblewrap_file = Arc::new(open_pinned(&bubblewrap)?);
        let hardening_helper =
            discover_hardening_helper(config.hardening_helper(), resource_directory.as_deref())?;
        let hardening_helper_file = Arc::new(
            File::open(&hardening_helper)
                .map_err(|_| LinuxBackendError::HardeningHelperUnavailable)?,
        );
        Ok(Self {
            config,
            bubblewrap: bubblewrap.path,
            bubblewrap_file,
            hardening_helper,
            hardening_helper_file,
            timeout_supported: TimeoutWatchdog::is_supported(),
            identity: BackendIdentity::new(),
        })
    }

    /// Returns the validated Bubblewrap executable path.
    pub fn bubblewrap_path(&self) -> &Path {
        &self.bubblewrap
    }

    /// Returns the validated hardening-helper executable path.
    pub fn hardening_helper_path(&self) -> &Path {
        &self.hardening_helper
    }

    pub(crate) fn hardening_helper_file(&self) -> &File {
        &self.hardening_helper_file
    }

    /// Returns the immutable settings used to construct this backend.
    pub const fn config(&self) -> &LinuxBackendConfig {
        &self.config
    }

    /// Runs the common Cageforge preflight for this backend.
    pub fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &cageforge_policy::PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, LinuxBackendError> {
        let prepared = request.prepare_for(self, context)?;
        let sandbox = prepared.sandbox(self)?;
        validate_network_lowering(self, &prepared, sandbox)?;
        Ok(prepared)
    }

    /// Lowers a prepared request to an immutable Bubblewrap plan.
    pub(crate) fn lower<'a>(
        &self,
        prepared: &PreparedBackendRequest<'a, Self>,
        gateway_mount: Option<&Path>,
    ) -> Result<LinuxLaunchPlan, LinuxBackendError> {
        let sandbox = prepared.sandbox(self)?;
        let network_mode = network_mode(sandbox)?;
        match (network_mode, gateway_mount) {
            (LinuxNetworkMode::ProxyRouted, None) => {
                return Err(NetworkLoweringError::MissingGatewayMount.into());
            }
            (
                LinuxNetworkMode::Direct
                | LinuxNetworkMode::DirectWithoutUnixSockets
                | LinuxNetworkMode::Disabled,
                Some(_),
            ) => {
                return Err(NetworkLoweringError::UnexpectedGatewayMount.into());
            }
            (LinuxNetworkMode::ProxyRouted, Some(_))
            | (
                LinuxNetworkMode::Direct
                | LinuxNetworkMode::DirectWithoutUnixSockets
                | LinuxNetworkMode::Disabled,
                None,
            ) => {}
        }
        let mut args = namespace_args(
            self.config.proc_mount(),
            matches!(
                network_mode,
                LinuxNetworkMode::Disabled | LinuxNetworkMode::ProxyRouted
            ),
        );
        validate_network_lowering(self, prepared, sandbox)?;
        let mut filesystem = crate::filesystem::lower(self, prepared, sandbox, gateway_mount)?;
        args.append(&mut filesystem.args);
        match self.config.proc_mount() {
            crate::config::ProcMountPolicy::Required => {
                args.extend(["--proc".into(), "/proc".into()]);
            }
            crate::config::ProcMountPolicy::Disabled => {
                args.extend([
                    "--tmpfs".into(),
                    "/proc".into(),
                    "--remount-ro".into(),
                    "/proc".into(),
                ]);
            }
        }
        args.extend([
            "--chdir".into(),
            prepared.working_directory(self)?.as_os_str().into(),
        ]);
        Ok(LinuxLaunchPlan { args, filesystem })
    }

    /// Launches a command from a backend-bound prepared request.
    pub fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<LinuxChild, LinuxBackendError> {
        let sandbox = prepared.sandbox(self)?;
        let network_mode = network_mode(sandbox)?;
        let mut gateway_runtime = if network_mode == LinuxNetworkMode::ProxyRouted {
            Some(GatewayRuntime::start(
                sandbox.network().clone(),
                self.config.network_gateway_config().clone(),
            )?)
        } else {
            None
        };
        let mut plan = self.lower(
            &prepared,
            gateway_runtime.as_ref().map(GatewayRuntime::mount_source),
        )?;
        let protected_create_monitor =
            ProtectedCreateMonitor::start(plan.filesystem.take_protected_create_paths())?;
        let command = prepared.command_spec(self)?;
        if command.program() == Path::new(IN_SANDBOX_HELPER_PATH) {
            return Err(LinuxBackendError::HardeningHelperPathCollision {
                path: PathBuf::from(IN_SANDBOX_HELPER_PATH),
            });
        }
        let environment = self.environment_input(sandbox.environment().base())?;
        let environment = prepared.apply_environment(self, environment)?;
        let bubblewrap_file = self
            .bubblewrap_file
            .try_clone()
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        let bubblewrap_program = format!("/proc/self/fd/{}", bubblewrap_file.as_raw_fd());
        let mut process = std::process::Command::new(bubblewrap_program);
        process.args(&plan.args);
        process.arg("--");
        process.arg(IN_SANDBOX_HELPER_PATH);
        process.arg("--apply-hardening");
        process.arg(command.program());
        process.args(command.args());
        process.env_clear();
        let (auth_reader, auth_writer) = UnixStream::pair()
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        let auth_reader = move_stream_above_standard_streams(auth_reader)
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        let mut auth_writer = move_stream_above_standard_streams(auth_writer)
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        let auth_fd = auth_reader.as_raw_fd();
        process.env(AUTH_FD_ENV, auth_fd.to_string());
        let filesystem_restricted = sandbox.filesystem().requirements().mode()
            == cageforge_policy::FilesystemMode::Restricted;
        if filesystem_restricted || network_mode != LinuxNetworkMode::Direct {
            process.env(HARDENING_REQUIRED_ENV, "1");
        }
        match network_mode {
            LinuxNetworkMode::Direct => {}
            LinuxNetworkMode::DirectWithoutUnixSockets => {
                process.env(NETWORK_MODE_ENV, NETWORK_MODE_DIRECT_WITHOUT_UNIX);
            }
            LinuxNetworkMode::Disabled => {
                process.env(NETWORK_MODE_ENV, NETWORK_MODE_DISABLED);
            }
            LinuxNetworkMode::ProxyRouted => {
                process.env(NETWORK_MODE_ENV, NETWORK_MODE_PROXY);
                process.env(GATEWAY_SOCKET_ENV, IN_SANDBOX_GATEWAY_SOCKET);
                process.env(
                    GATEWAY_CONNECTION_LIMIT_ENV,
                    self.config
                        .network_gateway_config()
                        .max_concurrent_connections()
                        .to_string(),
                );
            }
        }
        configure_stdio(&mut process, prepared.stdio(self)?);
        let timeout = match prepared.timeout_policy(self)? {
            cageforge_command::TimeoutPolicy::BackendDefault => Some(self.config.default_timeout()),
            cageforge_command::TimeoutPolicy::Limit(limit) => Some(limit),
            cageforge_command::TimeoutPolicy::Disabled => None,
        };
        let mut inherited_fds = std::mem::take(&mut plan.filesystem.preserved_files)
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        inherited_fds.push(bubblewrap_file.into());
        inherited_fds.push(auth_reader.into());
        process.preserved_fds(inherited_fds);
        let mut child = process
            .spawn()
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        if let Err(source) = auth_writer.set_write_timeout(Some(SETUP_HANDSHAKE_TIMEOUT)) {
            return Err(setup_handshake_error(&mut child, source));
        }
        if let Err(source) = auth_writer.write_all(AUTH_TOKEN) {
            return Err(setup_handshake_error(&mut child, source));
        }
        if let Some(runtime) = &gateway_runtime
            && let Err(source) = runtime.write_bridge_token(&mut auth_writer)
        {
            return Err(setup_handshake_error(&mut child, source));
        }
        if let Err(source) = write_environment(&mut auth_writer, &environment) {
            return Err(setup_handshake_error(&mut child, source));
        }
        if let Err(source) = auth_writer.set_read_timeout(Some(SETUP_HANDSHAKE_TIMEOUT)) {
            return Err(setup_handshake_error(&mut child, source));
        }
        let mut ready = vec![0; READY.len()];
        if let Err(source) = auth_writer.read_exact(&mut ready) {
            return Err(setup_handshake_error(&mut child, source));
        }
        if ready != READY {
            return Err(setup_handshake_error(
                &mut child,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "hardening helper returned an invalid setup acknowledgement",
                ),
            ));
        }
        let timeout_watchdog = match timeout {
            Some(timeout) => match TimeoutWatchdog::start(child.id(), timeout) {
                Ok(watchdog) => Some(watchdog),
                Err(error) => {
                    terminate_failed_setup(&mut child);
                    return Err(error);
                }
            },
            None => None,
        };
        if let Err(source) = auth_writer.write_all(RELEASE) {
            return Err(setup_handshake_error(&mut child, source));
        }
        if let Err(source) = auth_writer.shutdown(std::net::Shutdown::Write) {
            return Err(setup_handshake_error(&mut child, source));
        }
        let synthetic_targets = plan.filesystem.take_synthetic_targets();
        Ok(LinuxChild::new(
            child,
            timeout_watchdog,
            synthetic_targets,
            protected_create_monitor,
            gateway_runtime.take(),
            auth_writer,
        ))
    }

    fn environment_input(
        &self,
        base: EnvironmentBase,
    ) -> Result<EnvironmentInput, LinuxBackendError> {
        match base {
            EnvironmentBase::All => EnvironmentInput::all(std::env::vars_os())
                .map_err(|source| LinuxBackendError::EnvironmentPreparationFailed { source }),
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
                let core = cageforge_command::CoreEnvironment::from_selected(selected)
                    .map_err(|source| LinuxBackendError::EnvironmentPreparationFailed { source })?;
                Ok(EnvironmentInput::core(core))
            }
            EnvironmentBase::None => Ok(EnvironmentInput::empty()),
        }
    }
}

impl SandboxBackend for LinuxBackend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = BackendCapabilities::from_capabilities([
            BackendCapability::CommandExecution,
            BackendCapability::WorkingDirectory,
            BackendCapability::StdioInherit,
            BackendCapability::StdioNull,
            BackendCapability::StdioPipe,
            BackendCapability::TimeoutDisabled,
            BackendCapability::FilesystemRestricted,
            BackendCapability::FilesystemUnrestricted,
            BackendCapability::FilesystemScopes,
            BackendCapability::FilesystemAbsoluteScopes,
            BackendCapability::FilesystemWorkspaceScopes,
            BackendCapability::FilesystemRootScopes,
            BackendCapability::FilesystemMinimalScopes,
            BackendCapability::FilesystemTmpdirScopes,
            BackendCapability::FilesystemSlashTmpScopes,
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
            BackendCapability::NetworkUnixSocketIsolation,
            BackendCapability::EnvironmentAll,
            BackendCapability::EnvironmentCore,
            BackendCapability::EnvironmentNone,
            BackendCapability::EnvironmentFilters,
            BackendCapability::EnvironmentOverrides,
        ]);
        if self.timeout_supported {
            capabilities = capabilities
                .with(BackendCapability::TimeoutBackendDefault)
                .with(BackendCapability::TimeoutLimit);
        }
        capabilities
    }
}

fn terminate_failed_setup(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn setup_handshake_error(
    child: &mut std::process::Child,
    source: std::io::Error,
) -> LinuxBackendError {
    terminate_failed_setup(child);
    let mut diagnostic = String::new();
    if let Some(stderr) = child.stderr.as_mut() {
        let _ = stderr
            .take(SETUP_DIAGNOSTIC_LIMIT_BYTES)
            .read_to_string(&mut diagnostic);
    }
    LinuxBackendError::SetupHandshakeFailed { source, diagnostic }
}

fn configure_stdio(process: &mut std::process::Command, stdio: cageforge_command::StdioSpec) {
    process.stdin(stream(stdio.stdin()));
    process.stdout(stream(stdio.stdout()));
    process.stderr(stream(stdio.stderr()));
}

fn stream(mode: StdioMode) -> Stdio {
    match mode {
        StdioMode::Inherit => Stdio::inherit(),
        StdioMode::Null => Stdio::null(),
        StdioMode::Pipe => Stdio::piped(),
    }
}

fn validate_network_lowering<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    sandbox: &EffectiveSandbox,
) -> Result<(), LinuxBackendError> {
    let _ = prepared.network_lowering(backend)?;
    let requirements = sandbox.network().requirements();
    if requirements.mode() == NetworkMode::External {
        return Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::NetworkExternal,
        });
    }
    if requirements.unix_socket_rules() {
        return Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::NetworkUnixSocketRules,
        });
    }
    if network_mode(sandbox)? == LinuxNetworkMode::ProxyRouted
        && !requirements.unix_socket_isolation()
    {
        return Err(NetworkCombinationError::ProxyRequiresUnixSocketIsolation.into());
    }
    Ok(())
}

fn network_mode(sandbox: &EffectiveSandbox) -> Result<LinuxNetworkMode, LinuxBackendError> {
    let requirements = sandbox.network().requirements();
    match requirements.mode() {
        NetworkMode::Disabled => Ok(LinuxNetworkMode::Disabled),
        NetworkMode::External => Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::NetworkExternal,
        }),
        NetworkMode::Enabled
            if requirements.domain_rules()
                || requirements.local_address_restrictions()
                || requirements.resolved_targets() =>
        {
            Ok(LinuxNetworkMode::ProxyRouted)
        }
        NetworkMode::Enabled if requirements.unix_socket_isolation() => {
            Ok(LinuxNetworkMode::DirectWithoutUnixSockets)
        }
        NetworkMode::Enabled => Ok(LinuxNetworkMode::Direct),
    }
}

#[allow(unsafe_code)]
fn move_stream_above_standard_streams(stream: UnixStream) -> std::io::Result<UnixStream> {
    if stream.as_raw_fd() > libc::STDERR_FILENO {
        return Ok(stream);
    }
    let original = stream.into_raw_fd();
    let relocated =
        unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if relocated < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(original) };
        return Err(error);
    }
    unsafe { libc::close(original) };
    Ok(unsafe { UnixStream::from_raw_fd(relocated) })
}
