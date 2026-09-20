// SPDX-License-Identifier: Apache-2.0

//! Translation from CLI values to the existing Cageforge execution API.

#[cfg(feature = "config")]
use std::ffi::OsString;
#[cfg(feature = "config")]
use std::io::{self, IsTerminal, Write};
#[cfg(feature = "config")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use crate::cli::SetupCommand;
use crate::cli::{Cli, Command, PermissionsCommand, RunArgs};
#[cfg(feature = "config")]
use crate::cli::{PermissionsListArgs, PermissionsRevokeAllArgs, PermissionsRevokeArgs};
use crate::error::CliError;

#[cfg(all(feature = "config", any(target_os = "linux", target_os = "macos")))]
const ENV_HOME: &str = "HOME";
#[cfg(all(feature = "config", target_os = "windows"))]
const ENV_LOCAL_APP_DATA: &str = "LOCALAPPDATA";
#[cfg(all(feature = "config", target_os = "linux"))]
const ENV_XDG_STATE_HOME: &str = "XDG_STATE_HOME";
#[cfg(feature = "config")]
const CAGEFORGE_STATE_DIRECTORY: &str = "cageforge";
#[cfg(feature = "config")]
const PERMISSION_STORE_FILE: &str = "permissions.json";
#[cfg(all(feature = "config", target_os = "linux"))]
const UNIX_LOCAL_DIRECTORY: &str = ".local";
#[cfg(all(feature = "config", target_os = "linux"))]
const UNIX_STATE_DIRECTORY: &str = "state";
#[cfg(all(feature = "config", target_os = "macos"))]
const MACOS_LIBRARY_DIRECTORY: &str = "Library";
#[cfg(all(feature = "config", target_os = "macos"))]
const MACOS_APPLICATION_SUPPORT_DIRECTORY: &str = "Application Support";

#[cfg(feature = "config")]
struct Invocation {
    command: cageforge::CommandRequest,
    effective: cageforge::EffectiveSandbox,
    context: cageforge::PathResolutionContext,
    gateway: cageforge::GatewayConfig,
}

/// Executes a parsed CLI request and returns the process exit code.
pub fn execute(cli: Cli) -> Result<u8, CliError> {
    match cli.command {
        Command::Run(args) => execute_run(args),
        Command::Schema => execute_schema(),
        Command::Permissions(command) => execute_permissions(command),
        #[cfg(target_os = "windows")]
        Command::Setup(operation) => execute_setup(operation),
    }
}

#[cfg(feature = "config")]
fn execute_permissions(command: PermissionsCommand) -> Result<u8, CliError> {
    match command {
        PermissionsCommand::List(args) => execute_permissions_list(args),
        PermissionsCommand::Revoke(args) => execute_permissions_revoke(args),
        PermissionsCommand::RevokeAll(args) => execute_permissions_revoke_all(args),
    }
}

#[cfg(not(feature = "config"))]
fn execute_permissions(_command: PermissionsCommand) -> Result<u8, CliError> {
    Err(CliError::ConfigFeatureRequired)
}

#[cfg(feature = "config")]
fn open_permission_store(path: Option<&Path>) -> Result<cageforge::PermissionStore, CliError> {
    Ok(cageforge::PermissionStore::open(permission_store_path(
        path,
    )?)?)
}

#[cfg(feature = "config")]
fn execute_permissions_list(args: PermissionsListArgs) -> Result<u8, CliError> {
    let cursor = args
        .cursor
        .as_deref()
        .map(cageforge::GrantPageCursor::from_token)
        .transpose()?;
    let request = cageforge::GrantPageRequest::new(args.page_size, cursor)?;
    let store = open_permission_store(args.permission_store.as_deref())?;
    let page = store.list_page(request)?;
    for entry in page.entries() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.id,
            entry.tool_id,
            entry.tool_version,
            entry.platform,
            entry.architecture,
            format!("{:?}", entry.scope).to_lowercase(),
            entry
                .expires_at
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        );
    }
    if let Some(cursor) = page.next_cursor() {
        println!("next-cursor\t{}", cursor.to_token());
    }
    Ok(0)
}

#[cfg(feature = "config")]
fn execute_permissions_revoke(args: PermissionsRevokeArgs) -> Result<u8, CliError> {
    let id = cageforge::GrantId::from_hex(&args.id)
        .map_err(|_| cageforge::StoreError::InvalidGrantId)?;
    let store = open_permission_store(args.permission_store.as_deref())?;
    match store.revoke(id)? {
        cageforge::RevokeResult::Revoked => {
            println!("revoked\t{id}");
            Ok(0)
        }
        cageforge::RevokeResult::NotFound => Err(cageforge::StoreError::GrantNotFound.into()),
    }
}

#[cfg(feature = "config")]
fn execute_permissions_revoke_all(args: PermissionsRevokeAllArgs) -> Result<u8, CliError> {
    if !args.yes {
        return Err(CliError::PermissionStoreConfirmationRequired);
    }
    let store = open_permission_store(args.permission_store.as_deref())?;
    store.revoke_all()?;
    println!("revoked-all");
    Ok(0)
}

#[cfg(feature = "config")]
fn execute_run(args: RunArgs) -> Result<u8, CliError> {
    let config = cageforge::Config::from_file(&args.config)?;
    let platform = cageforge::PlatformId::current().map_err(|error| {
        CliError::Config(cageforge::ConfigError::InvalidValue {
            profile: args.profile.clone().unwrap_or_else(|| "default".to_owned()),
            field: "platform".to_owned(),
            value: error.to_string(),
        })
    })?;
    let profile = match args.profile.as_deref() {
        Some(name) => config.resolve_for_platform(name, platform)?,
        None => config.resolve_default_for_platform(platform)?,
    };
    let command = command_from_args(&profile, args.command)?;
    let current_directory = std::env::current_dir()?;
    let workspace_roots = resolve_workspace_roots(&current_directory, profile.workspace_roots())?;
    let context = runtime_context(
        &current_directory,
        &workspace_roots,
        profile.executable_roots(),
    )?;
    let environment = command.environment().clone();
    let mut ceiling = cageforge::PolicyCeiling::new(profile.policy().clone(), environment.clone());
    if !workspace_roots.is_empty() {
        ceiling = ceiling.with_workspace_roots(workspace_roots.clone())?;
    }
    let mut composition =
        cageforge::CompositionRequest::new(profile.policy(), &environment, &ceiling);
    if !workspace_roots.is_empty() {
        composition = composition.with_workspace_roots(workspace_roots)?;
    }
    let effective = cageforge::compose(composition)?;
    let effective = match profile.approval().mode() {
        cageforge::PermissionMode::Disabled => effective,
        cageforge::PermissionMode::Preflight => {
            let config_bytes = std::fs::read(&args.config)?;
            let executable_bytes = std::fs::read(std::env::current_exe()?)?;
            let program = command.command().program().to_string_lossy().into_owned();
            let identity = cageforge::PreflightIdentity::new(
                "cageforge-cli",
                env!("CARGO_PKG_VERSION"),
                cageforge::sha256_digest(&executable_bytes),
                cageforge::sha256_digest(&config_bytes),
                platform,
                std::env::consts::ARCH,
            );
            let plan = cageforge::PreflightPlan::from_policy_with_ceiling(
                profile.policy(),
                &context,
                effective,
                &environment,
                &ceiling,
                identity,
            )?
            .with_process_program(program)?;
            let store_path = permission_store_path(args.permission_store.as_deref())?;
            let store = cageforge::PermissionStore::open(store_path)?;
            let grant = match store.get(plan.request())? {
                Some(grant) => grant,
                None => {
                    if args.approve
                        || prompt_for_approval(plan.request(), profile.approval().timeout_ms())?
                    {
                        let scope = match profile.approval().persistence() {
                            cageforge::ApprovalPersistence::Launch => {
                                cageforge::PermissionScope::Launch
                            }
                            cageforge::ApprovalPersistence::Session => {
                                cageforge::PermissionScope::Session
                            }
                            cageforge::ApprovalPersistence::Persistent => {
                                cageforge::PermissionScope::Persistent
                            }
                        };
                        let grant = cageforge::GrantAuthority::new()
                            .approve_with(
                                plan.request(),
                                plan.request().capabilities().clone(),
                                scope,
                                None,
                            )
                            .map_err(cageforge::PreflightError::from)?;
                        if scope == cageforge::PermissionScope::Persistent {
                            store.put(&grant, plan.request())?;
                        }
                        grant
                    } else {
                        return Err(CliError::PermissionDenied);
                    }
                }
            };
            plan.authorize(grant)?.effective().clone()
        }
        mode => {
            return Err(CliError::Preflight(
                cageforge::PreflightError::UnsupportedMode(mode),
            ));
        }
    };
    let invocation = Invocation {
        command,
        effective,
        context,
        gateway: profile.network_gateway().clone(),
    };
    #[cfg(target_os = "windows")]
    warn_if_windows_setup_is_unavailable();
    execute_native(invocation)
}

#[cfg(feature = "config")]
fn permission_store_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    #[cfg(target_os = "linux")]
    {
        let state_directory = match std::env::var_os(ENV_XDG_STATE_HOME) {
            Some(value) if !value.is_empty() => absolute_environment_path(value)?,
            _ => home_directory()?
                .join(UNIX_LOCAL_DIRECTORY)
                .join(UNIX_STATE_DIRECTORY),
        };
        Ok(store_path_in(state_directory))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(store_path_in(
            home_directory()?
                .join(MACOS_LIBRARY_DIRECTORY)
                .join(MACOS_APPLICATION_SUPPORT_DIRECTORY),
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let local_app_data = std::env::var_os(ENV_LOCAL_APP_DATA).ok_or(
            CliError::PermissionStorePathUnavailable {
                variable: ENV_LOCAL_APP_DATA,
            },
        )?;
        Ok(store_path_in(absolute_environment_path(local_app_data)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(CliError::PermissionStorePathUnavailable {
            variable: "a supported platform user-data directory",
        })
    }
}

#[cfg(all(feature = "config", any(target_os = "linux", target_os = "macos")))]
fn home_directory() -> Result<PathBuf, CliError> {
    let value = std::env::var_os(ENV_HOME)
        .ok_or(CliError::PermissionStorePathUnavailable { variable: ENV_HOME })?;
    absolute_environment_path(value)
}

#[cfg(all(
    feature = "config",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn absolute_environment_path(value: std::ffi::OsString) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(CliError::PermissionStorePathNotAbsolute { path })
    }
}

#[cfg(all(
    feature = "config",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn store_path_in(state_directory: PathBuf) -> PathBuf {
    state_directory
        .join(CAGEFORGE_STATE_DIRECTORY)
        .join(PERMISSION_STORE_FILE)
}

#[cfg(all(test, feature = "config"))]
mod tests {
    use super::*;

    #[test]
    fn explicit_store_path_has_priority() {
        let explicit = Path::new("/tmp/cageforge-test/permissions.json");
        assert_eq!(permission_store_path(Some(explicit)).unwrap(), explicit);
    }

    #[test]
    fn default_store_path_uses_the_native_cageforge_suffix() {
        let path = permission_store_path(None).unwrap();
        assert!(path.ends_with(Path::new("cageforge/permissions.json")));
    }

    #[test]
    fn environment_store_roots_must_be_absolute() {
        let error = absolute_environment_path(std::ffi::OsString::from("relative/state"))
            .expect_err("relative environment path must be rejected");
        assert!(matches!(
            error,
            CliError::PermissionStorePathNotAbsolute { .. }
        ));
    }
}

#[cfg(feature = "config")]
fn prompt_for_approval(
    request: &cageforge::PermissionRequest,
    timeout_ms: u64,
) -> Result<bool, CliError> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(false);
    }
    eprintln!(
        "Cageforge preflight request for {} {} on {}:",
        request.tool_id(),
        request.tool_version(),
        request.platform()
    );
    for capability in request.capabilities().filesystem() {
        eprintln!(
            "  filesystem {:?}: {}",
            capability.operation(),
            capability.path()
        );
    }
    for capability in request.capabilities().network() {
        eprintln!("  network: {}", capability.endpoint());
    }
    for capability in request.capabilities().child_processes() {
        eprintln!("  child process: {}", capability.program());
    }
    eprint!("Approve this request? [y/N] ");
    io::stderr().flush()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut answer = String::new();
        let _ = io::stdin().read_line(&mut answer);
        let _ = sender.send(answer);
    });
    let answer = receiver
        .recv_timeout(std::time::Duration::from_millis(timeout_ms))
        .map_err(|_| CliError::Preflight(cageforge::PreflightError::ApprovalTimeout))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}

#[cfg(target_os = "windows")]
fn execute_setup(operation: SetupCommand) -> Result<u8, CliError> {
    let setup = cageforge::WindowsSetup::new(cageforge::WindowsSetupConfig::new());
    match operation {
        SetupCommand::Install => {
            let details = setup.install()?;
            println!(
                "Windows Cageforge setup is ready (state directory: {:?})",
                details.state_directory()
            );
        }
        SetupCommand::Status => match setup.status()? {
            cageforge::WindowsSetupStatus::Missing { marker_path } => {
                println!("Windows Cageforge setup is missing ({marker_path:?})");
            }
            cageforge::WindowsSetupStatus::Stale {
                marker_path,
                reason,
            } => {
                println!("Windows Cageforge setup is stale ({marker_path:?}, reason: {reason:?})");
            }
            cageforge::WindowsSetupStatus::Ready(details) => {
                println!(
                    "Windows Cageforge setup is ready (version {}, state directory: {:?})",
                    details.version(),
                    details.state_directory()
                );
            }
        },
        SetupCommand::Uninstall => {
            setup.uninstall()?;
            println!("Windows Cageforge setup was removed");
        }
    }
    Ok(0)
}

#[cfg(all(feature = "config", target_os = "windows"))]
fn warn_if_windows_setup_is_unavailable() {
    let setup = cageforge::WindowsSetup::new(cageforge::WindowsSetupConfig::new());
    match setup.status() {
        Ok(cageforge::WindowsSetupStatus::Missing { .. }) => {
            eprintln!(
                "warning: Windows Cageforge setup is not installed; run `cageforge-cli setup install` before running a sandbox"
            );
        }
        Ok(cageforge::WindowsSetupStatus::Stale { .. }) => {
            eprintln!(
                "warning: Windows Cageforge setup is stale; run `cageforge-cli setup install` to reconcile it"
            );
        }
        Ok(cageforge::WindowsSetupStatus::Ready(_)) | Err(_) => {}
    }
}

#[cfg(not(feature = "config"))]
fn execute_run(_args: RunArgs) -> Result<u8, CliError> {
    Err(CliError::ConfigFeatureRequired)
}

#[cfg(feature = "config")]
fn command_from_args(
    profile: &cageforge::ResolvedProfile,
    command: Vec<OsString>,
) -> Result<cageforge::CommandRequest, CliError> {
    if command.is_empty() {
        return profile
            .command()
            .cloned()
            .map(|request| request.with_stdio(cageforge::StdioSpec::inherited()))
            .ok_or(CliError::MissingCommand);
    }
    let mut parts = command.into_iter();
    let program = parts.next().ok_or(CliError::InvalidCommand)?;
    let command_spec = cageforge::CommandSpec::new(program)?.with_args(parts)?;
    let mut request =
        cageforge::CommandRequest::new(command_spec).with_stdio(cageforge::StdioSpec::inherited());
    if let Some(template) = profile.command() {
        request = request
            .with_environment(template.environment().clone())
            .with_timeout_policy(template.timeout_policy());
        if let Some(directory) = template.working_directory() {
            request = request.with_working_directory(directory.to_path_buf())?;
        }
    }
    Ok(request)
}

#[cfg(feature = "config")]
fn resolve_workspace_roots(
    current_directory: &Path,
    declarations: &[PathBuf],
) -> Result<Vec<PathBuf>, CliError> {
    declarations
        .iter()
        .map(|declaration| {
            if cageforge::contains_parent_traversal(declaration) {
                return Err(CliError::InvalidWorkspaceRoot {
                    path: declaration.clone(),
                });
            }
            let path = if declaration.is_absolute() {
                declaration.clone()
            } else {
                current_directory.join(declaration)
            };
            Ok(cageforge::normalize_lexical_path(&path).into_owned())
        })
        .collect()
}

#[cfg(feature = "config")]
fn runtime_context(
    current_directory: &Path,
    workspace_roots: &[PathBuf],
    executable_roots: &[PathBuf],
) -> Result<cageforge::PathResolutionContext, CliError> {
    let mut context = cageforge::PathResolutionContext::new()
        .with_root(platform_root(current_directory))?
        .with_minimal_path(platform_minimal_root(current_directory)?)?
        .with_current_directory(current_directory.to_path_buf())?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        context = context
            .with_tmpdir(std::env::temp_dir())?
            .with_slash_tmp(PathBuf::from("/tmp"))?;
    }
    #[cfg(target_os = "linux")]
    {
        for path in ["/bin", "/lib", "/lib64"] {
            context = context.with_minimal_path(PathBuf::from(path))?;
        }
    }
    #[cfg(target_os = "windows")]
    {
        context = context.with_tmpdir(std::env::temp_dir())?;
    }
    for root in workspace_roots {
        context = context.with_workspace_root(root.clone())?;
    }
    for root in executable_roots {
        context = context.with_executable_root(root.clone())?;
    }
    Ok(context)
}

#[cfg(feature = "config")]
fn platform_root(current_directory: &Path) -> PathBuf {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = current_directory;
        PathBuf::from("/")
    }
    #[cfg(target_os = "windows")]
    {
        current_directory
            .ancestors()
            .last()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(r"C:\"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        current_directory.to_path_buf()
    }
}

#[cfg(feature = "config")]
fn platform_minimal_root(current_directory: &Path) -> Result<PathBuf, CliError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = current_directory;
        Ok(PathBuf::from("/usr"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = current_directory;
        let system_root = std::env::var_os("SystemRoot")
            .ok_or(CliError::WindowsSystemRootUnavailable)
            .map(PathBuf::from)?;
        if !system_root.is_absolute() {
            return Err(CliError::WindowsSystemRootNotAbsolute { path: system_root });
        }
        Ok(system_root.join("System32"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(current_directory.to_path_buf())
    }
}

#[cfg(all(
    feature = "config",
    any(target_os = "linux", target_os = "windows", target_os = "macos",)
))]
fn execute_native(invocation: Invocation) -> Result<u8, CliError> {
    let config = cageforge::NativeSandboxConfig::new().with_network_gateway(invocation.gateway);
    #[cfg(target_os = "linux")]
    let config = config.with_hardening_helper_path(std::env::current_exe()?);
    #[cfg(target_os = "macos")]
    let config = config.with_helper_executable(std::env::current_exe()?)?;
    let backend = cageforge::native_sandbox_with(config)?;
    let mut child = backend.launch(
        cageforge::BackendRequest::new(&invocation.command, &invocation.effective),
        &invocation.context,
    )?;
    Ok(child.wait()?.code().unwrap_or(1) as u8)
}

#[cfg(all(
    feature = "config",
    not(any(target_os = "linux", target_os = "windows", target_os = "macos",))
))]
fn execute_native(_invocation: Invocation) -> Result<u8, CliError> {
    let Invocation {
        command,
        effective,
        context,
        gateway,
    } = _invocation;
    drop((command, effective, context, gateway));
    Err(CliError::NativeSandbox(
        cageforge::NativeSandboxError::UnsupportedPlatform {
            target_os: std::env::consts::OS,
        },
    ))
}

#[cfg(feature = "config")]
fn execute_schema() -> Result<u8, CliError> {
    println!("{}", cageforge::config_schema_json()?);
    Ok(0)
}

#[cfg(not(feature = "config"))]
fn execute_schema() -> Result<u8, CliError> {
    Err(CliError::ConfigFeatureRequired)
}
