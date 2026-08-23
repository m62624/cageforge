// SPDX-License-Identifier: Apache-2.0

//! Linux backend construction, capability declaration, and policy lowering.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest,
    PreparedBackendRequest, SandboxBackend,
};
use cageforge_command::{EnvironmentBase, EnvironmentInput, StdioMode};
use cageforge_policy::{AccessMode, FilesystemDecision, FilesystemTarget, MissingPathBehavior};
use cageforge_policy_compose::{EffectiveFilesystemLayer, EffectiveSandbox};

use crate::bwrap::{discover_and_probe, discover_hardening_helper, namespace_args};
use crate::config::LinuxBackendConfig;
use crate::error::LinuxBackendError;
use crate::process::LinuxChild;

const IN_SANDBOX_HELPER_PATH: &str = "/dev/shm/cageforge/helper";
const HELPER_AUTH_ENV: &str = "CAGEFORGE_LINUX_HELPER_AUTH_FD";
const HELPER_AUTH_TOKEN: &[u8] = b"cageforge-linux-helper-v1";

/// A validated immutable Bubblewrap argument plan before the command and
/// environment are appended.
#[derive(Debug)]
pub(crate) struct LinuxLaunchPlan {
    args: Vec<OsString>,
    preserved_files: Vec<File>,
}

/// A Linux native Cageforge backend bound to one validated Bubblewrap binary.
#[derive(Debug, Clone)]
pub struct LinuxBackend {
    config: LinuxBackendConfig,
    bubblewrap: PathBuf,
    hardening_helper: PathBuf,
    identity: BackendIdentity,
}

impl LinuxBackend {
    /// Constructs a backend and verifies Bubblewrap's required namespace API.
    pub fn new(config: LinuxBackendConfig) -> Result<Self, LinuxBackendError> {
        let bubblewrap = discover_and_probe(config.bubblewrap(), config.proc_mount())?;
        let hardening_helper = discover_hardening_helper(config.hardening_helper())?;
        Ok(Self {
            config,
            bubblewrap,
            hardening_helper,
            identity: BackendIdentity::new(),
        })
    }

    /// Returns the validated Bubblewrap executable path.
    pub fn bubblewrap_path(&self) -> &Path {
        &self.bubblewrap
    }

    /// Runs the common Cageforge preflight for this backend.
    pub fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &cageforge_policy::PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, LinuxBackendError> {
        request.prepare_for(self, context).map_err(Into::into)
    }

    /// Lowers a prepared request to an immutable Bubblewrap plan.
    pub(crate) fn lower<'a>(
        &self,
        prepared: &PreparedBackendRequest<'a, Self>,
    ) -> Result<LinuxLaunchPlan, LinuxBackendError> {
        let sandbox = prepared.sandbox(self)?;
        let network_isolated =
            sandbox.network().requirements().mode() == cageforge_policy::NetworkMode::Disabled;
        let mut args = namespace_args(self.config.proc_mount(), network_isolated);
        validate_network_lowering(self, prepared, sandbox)?;
        let mut preserved_files = Vec::new();
        lower_filesystem(self, prepared, sandbox, &mut args, &mut preserved_files)?;
        if self.config.proc_mount() == crate::config::ProcMountPolicy::Required {
            args.extend(["--proc".into(), "/proc".into()]);
        }
        args.extend([
            "--chdir".into(),
            prepared.working_directory(self)?.as_os_str().into(),
        ]);
        Ok(LinuxLaunchPlan {
            args,
            preserved_files,
        })
    }

    /// Launches a command from a backend-bound prepared request.
    pub fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<LinuxChild, LinuxBackendError> {
        let plan = self.lower(&prepared)?;
        let command = prepared.command_spec(self)?;
        if command.program() == Path::new(IN_SANDBOX_HELPER_PATH) {
            return Err(LinuxBackendError::HardeningHelperPathCollision {
                path: PathBuf::from(IN_SANDBOX_HELPER_PATH),
            });
        }
        let environment = self.environment_input(prepared.sandbox(self)?.environment().base())?;
        let environment = prepared.apply_environment(self, environment)?;
        // Keep preserved data FDs open until Bubblewrap has consumed them.
        let _preserved_files = &plan.preserved_files;
        let mut process = std::process::Command::new(&self.bubblewrap);
        process.args(&plan.args);
        process.arg("--");
        process.arg(IN_SANDBOX_HELPER_PATH);
        process.arg("--apply-hardening");
        process.arg(command.program());
        process.args(command.args());
        process.env_clear();
        process.envs(environment);
        let (auth_reader, mut auth_writer) = UnixStream::pair()
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        auth_writer
            .write_all(HELPER_AUTH_TOKEN)
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        let auth_fd = auth_reader.as_raw_fd();
        set_close_on_exec(auth_fd, false)
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        process.env(HELPER_AUTH_ENV, auth_fd.to_string());
        let filesystem_restricted = prepared.sandbox(self)?.filesystem().requirements().mode()
            == cageforge_policy::FilesystemMode::Restricted;
        let network_isolated = prepared.sandbox(self)?.network().requirements().mode()
            == cageforge_policy::NetworkMode::Disabled;
        if filesystem_restricted || network_isolated {
            process.env("CAGEFORGE_LINUX_HARDENING_REQUIRED", "1");
        }
        if network_isolated {
            process.env("CAGEFORGE_LINUX_NETWORK_ISOLATED", "1");
        }
        configure_stdio(&mut process, prepared.stdio(self)?);
        let timeout = match prepared.timeout_policy(self)? {
            cageforge_command::TimeoutPolicy::BackendDefault => Some(self.config.default_timeout()),
            cageforge_command::TimeoutPolicy::Limit(limit) => Some(limit),
            cageforge_command::TimeoutPolicy::Disabled => None,
        };
        let child = process
            .spawn()
            .map_err(|source| LinuxBackendError::ProcessSpawnFailed { source })?;
        Ok(LinuxChild::new(child, timeout))
    }

    fn environment_input(
        &self,
        base: EnvironmentBase,
    ) -> Result<EnvironmentInput, LinuxBackendError> {
        match base {
            EnvironmentBase::All => EnvironmentInput::all(std::env::vars_os()).map_err(|source| {
                LinuxBackendError::ProcessSpawnFailed {
                    source: std::io::Error::other(source.to_string()),
                }
            }),
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
                let core = cageforge_command::CoreEnvironment::from_selected(selected).map_err(
                    |source| LinuxBackendError::ProcessSpawnFailed {
                        source: std::io::Error::other(source.to_string()),
                    },
                )?;
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
            BackendCapability::FilesystemUnrestricted,
            BackendCapability::FilesystemScopes,
            BackendCapability::FilesystemAbsoluteScopes,
            BackendCapability::FilesystemWorkspaceScopes,
            BackendCapability::FilesystemRootScopes,
            BackendCapability::FilesystemMinimalScopes,
            BackendCapability::FilesystemTmpdirScopes,
            BackendCapability::FilesystemSlashTmpScopes,
            BackendCapability::FilesystemReadOnlySubpaths,
            BackendCapability::FilesystemMissingPathBehavior,
            BackendCapability::FilesystemProtectedPaths,
            BackendCapability::NetworkDisabled,
            BackendCapability::NetworkEnabled,
            BackendCapability::EnvironmentAll,
            BackendCapability::EnvironmentCore,
            BackendCapability::EnvironmentNone,
            BackendCapability::EnvironmentFilters,
            BackendCapability::EnvironmentOverrides,
        ])
    }
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

fn lower_filesystem<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    sandbox: &EffectiveSandbox,
    args: &mut Vec<OsString>,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    let mode = sandbox.filesystem().requirements().mode();
    if mode == cageforge_policy::FilesystemMode::External {
        return Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::FilesystemExternal,
        });
    }
    if mode == cageforge_policy::FilesystemMode::Unrestricted {
        args.extend(["--bind".into(), "/".into(), "/".into()]);
        append_dev_target(args);
        append_helper_target(args);
        append_helper_mount(args, &backend.hardening_helper);
        return Ok(());
    }

    args.extend(["--tmpfs".into(), "/".into()]);
    let context = prepared.path_context(backend)?;
    let lowering = prepared.filesystem_lowering(backend)?;
    let mut mounts = BTreeMap::<PathBuf, Mount>::new();

    for layer in lowering.layers() {
        collect_layer_mounts(backend, prepared, context, layer, &mut mounts)?;
    }
    reject_reserved_runtime_paths(&mounts)?;

    if let Some((path, mount)) = mounts
        .iter()
        .find(|(path, mount)| path.as_path() == Path::new("/") && mount.is_bind())
    {
        add_bind(args, path, mount.access())?;
    }
    append_dev_target(args);
    append_helper_target(args);
    for (path, mount) in mounts
        .iter()
        .filter(|(path, mount)| path.as_path() != Path::new("/") && mount.is_bind())
    {
        add_bind(args, path, mount.access())?;
    }
    for (path, mount) in mounts.iter().filter(|(_, mount)| mount.is_mask()) {
        add_mask(args, path, *mount, preserved_files)?;
    }
    append_helper_mount(args, &backend.hardening_helper);
    Ok(())
}

fn append_dev_target(args: &mut Vec<OsString>) {
    args.extend(["--dev".into(), "/dev".into()]);
}

fn append_helper_target(args: &mut Vec<OsString>) {
    args.extend([
        "--tmpfs".into(),
        "/dev/shm".into(),
        "--dir".into(),
        "/dev/shm/cageforge".into(),
    ]);
}

fn append_helper_mount(args: &mut Vec<OsString>, helper: &Path) {
    args.extend([
        "--ro-bind".into(),
        helper.as_os_str().into(),
        IN_SANDBOX_HELPER_PATH.into(),
        "--remount-ro".into(),
        "/dev/shm".into(),
    ]);
}

fn reject_reserved_runtime_paths(
    mounts: &BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    if let Some(path) = mounts.keys().find(|path| {
        path.as_path() != Path::new("/") && (path.starts_with("/dev") || path.starts_with("/proc"))
    }) {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.clone(),
            reason: "the Linux backend reserves /dev and /proc for its namespace runtime"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_network_lowering<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    sandbox: &EffectiveSandbox,
) -> Result<(), LinuxBackendError> {
    let lowering = prepared.network_lowering(backend)?;
    for layer in lowering.layers() {
        if layer.mode() != cageforge_policy::NetworkMode::Enabled {
            continue;
        }
        if !layer.domains().is_empty()
            || layer.domain_mode() != cageforge_policy::DomainMode::Enabled
        {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::NetworkDomainRules,
            });
        }
        if layer.local_network_access() != cageforge_policy::LocalNetworkAccess::Allow {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::NetworkLocalAddressRestrictions,
            });
        }
        if !layer.unix_sockets().is_empty()
            || layer.unix_socket_mode() != cageforge_policy::UnixSocketMode::Enabled
        {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::NetworkUnixSockets,
            });
        }
    }
    if sandbox.network().requirements().resolved_targets() {
        return Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::NetworkResolvedTargets,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mount {
    Read,
    Write,
    ReadOnly,
    Deny,
}

impl Mount {
    fn is_bind(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    fn is_mask(self) -> bool {
        matches!(self, Self::ReadOnly | Self::Deny)
    }

    fn access(self) -> AccessMode {
        match self {
            Self::Read | Self::ReadOnly | Self::Deny => AccessMode::Read,
            Self::Write => AccessMode::Write,
        }
    }
}

fn collect_layer_mounts<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    context: &cageforge_policy_compose::EffectivePathContext,
    layer: EffectiveFilesystemLayer<'_>,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    for rule in layer.entries() {
        let FilesystemTarget::Scope(selector) = rule.target() else {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::FilesystemGlobs,
            });
        };
        for path in context.resolve(selector) {
            add_scope_mount(
                backend,
                prepared,
                &path,
                rule.missing_path_behavior(),
                mounts,
            )?;
            for subpath in rule.read_only_subpaths() {
                for subpath in context.resolve(subpath) {
                    add_protected_mask(&subpath, mounts);
                }
            }
        }
    }
    for (root, mount) in mounts.clone() {
        if mount == Mount::Write {
            for protected in layer.protected_relative_paths() {
                let protected_path = root.join(protected);
                add_protected_mask(&protected_path, mounts);
            }
        }
    }
    Ok(())
}

fn add_scope_mount<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    path: &Path,
    missing: MissingPathBehavior,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    let decision = prepared
        .filesystem_access_for_path(backend, path)
        .map_err(LinuxBackendError::Contract)?;
    let mount = match decision {
        FilesystemDecision::Read => Mount::Read,
        FilesystemDecision::Write => Mount::Write,
        FilesystemDecision::Deny => Mount::Deny,
        FilesystemDecision::ExternallyEnforced => {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::FilesystemExternal,
            });
        }
    };
    add_existing_or_mask(path, mount, missing, mounts)
}

fn add_existing_or_mask(
    path: &Path,
    mount: Mount,
    missing: MissingPathBehavior,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            reason: "mount target must be an absolute non-empty path".to_string(),
        });
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(_source) if missing == MissingPathBehavior::Skip => return Ok(()),
        Err(source) => {
            return Err(LinuxBackendError::FilesystemLoweringFailed {
                path: path.to_path_buf(),
                reason: source.to_string(),
            });
        }
    }
    mounts
        .entry(path.to_path_buf())
        .and_modify(|current| *current = stricter_mount(*current, mount))
        .or_insert(mount);
    Ok(())
}

fn add_protected_mask(path: &Path, mounts: &mut BTreeMap<PathBuf, Mount>) {
    mounts
        .entry(path.to_path_buf())
        .and_modify(|current| *current = stricter_mount(*current, Mount::ReadOnly))
        .or_insert(Mount::ReadOnly);
}

fn stricter_mount(left: Mount, right: Mount) -> Mount {
    match (left, right) {
        (Mount::Deny, _) | (_, Mount::Deny) => Mount::Deny,
        (Mount::ReadOnly, _) | (_, Mount::ReadOnly) => Mount::ReadOnly,
        (Mount::Read, _) | (_, Mount::Read) => Mount::Read,
        (Mount::Write, Mount::Write) => Mount::Write,
    }
}

fn add_bind(
    args: &mut Vec<OsString>,
    path: &Path,
    access: AccessMode,
) -> Result<(), LinuxBackendError> {
    let source =
        fs::canonicalize(path).map_err(|source| LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
    args.push(match access {
        AccessMode::Read => "--ro-bind".into(),
        AccessMode::Write => "--bind".into(),
        AccessMode::Deny => unreachable!(),
    });
    args.push(source.as_os_str().into());
    args.push(path.as_os_str().into());
    Ok(())
}

fn add_mask(
    args: &mut Vec<OsString>,
    path: &Path,
    mount: Mount,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    if path == Path::new("/") {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            reason: "the filesystem root cannot be masked".to_string(),
        });
    }
    match (mount, fs::symlink_metadata(path)) {
        (Mount::ReadOnly, Ok(metadata)) if metadata.file_type().is_symlink() => {
            return Err(LinuxBackendError::FilesystemLoweringFailed {
                path: path.to_path_buf(),
                reason: "read-only symbolic links cannot be lowered safely".to_string(),
            });
        }
        (Mount::ReadOnly, Ok(_)) => {
            let source = fs::canonicalize(path).map_err(|source| {
                LinuxBackendError::FilesystemLoweringFailed {
                    path: path.to_path_buf(),
                    reason: source.to_string(),
                }
            })?;
            args.push("--ro-bind".into());
            args.push(source.as_os_str().into());
            args.push(path.as_os_str().into());
        }
        (Mount::Deny, Ok(metadata)) if metadata.is_dir() => {
            args.extend([
                "--perms".into(),
                "000".into(),
                "--tmpfs".into(),
                path.as_os_str().into(),
                "--remount-ro".into(),
                path.as_os_str().into(),
            ]);
        }
        (Mount::Deny, Ok(metadata)) if metadata.is_file() => {
            let file = File::open("/dev/null").map_err(|source| {
                LinuxBackendError::FilesystemLoweringFailed {
                    path: path.to_path_buf(),
                    reason: source.to_string(),
                }
            })?;
            let fd = file.as_raw_fd();
            set_close_on_exec(fd, false).map_err(|source| {
                LinuxBackendError::FilesystemLoweringFailed {
                    path: path.to_path_buf(),
                    reason: source.to_string(),
                }
            })?;
            preserved_files.push(file);
            args.extend([
                "--perms".into(),
                "000".into(),
                "--ro-bind-data".into(),
                fd.to_string().into(),
                path.as_os_str().into(),
            ]);
        }
        (Mount::Deny, Ok(_)) => {
            return Err(LinuxBackendError::FilesystemLoweringFailed {
                path: path.to_path_buf(),
                reason: "denied symbolic links cannot be lowered safely".to_string(),
            });
        }
        (Mount::ReadOnly | Mount::Deny, Err(_)) => {
            args.extend([
                "--perms".into(),
                "000".into(),
                "--tmpfs".into(),
                path.as_os_str().into(),
                "--remount-ro".into(),
                path.as_os_str().into(),
            ]);
        }
        (Mount::Read | Mount::Write, _) => unreachable!(),
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_close_on_exec(fd: std::os::fd::RawFd, close_on_exec: bool) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let updated = if close_on_exec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
