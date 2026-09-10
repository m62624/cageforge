// SPDX-License-Identifier: Apache-2.0

//! Translation from CLI values to the existing Cageforge execution API.

#[cfg(feature = "config")]
use std::ffi::OsString;
#[cfg(feature = "config")]
use std::path::{Path, PathBuf};

#[cfg(all(feature = "windows", target_os = "windows"))]
use crate::cli::SetupCommand;
use crate::cli::{Cli, Command, RunArgs};
use crate::error::CliError;

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
        #[cfg(all(feature = "windows", target_os = "windows"))]
        Command::Setup(operation) => execute_setup(operation),
    }
}

#[cfg(feature = "config")]
fn execute_run(args: RunArgs) -> Result<u8, CliError> {
    let config = cageforge::Config::from_file(&args.config)?;
    let profile = match args.profile.as_deref() {
        Some(name) => config.resolve(name)?,
        None => config.resolve_default()?,
    };
    let command = command_from_args(&profile, args.command)?;
    let current_directory = std::env::current_dir()?;
    let workspace_roots = resolve_workspace_roots(&current_directory, profile.workspace_roots())?;
    let context = runtime_context(&current_directory, &workspace_roots)?;
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
    let invocation = Invocation {
        command,
        effective,
        context,
        gateway: profile.network_gateway().clone(),
    };
    #[cfg(all(feature = "windows", target_os = "windows"))]
    warn_if_windows_setup_is_unavailable();
    execute_native(invocation)
}

#[cfg(all(feature = "windows", target_os = "windows"))]
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

#[cfg(all(feature = "windows", target_os = "windows"))]
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
) -> Result<cageforge::PathResolutionContext, CliError> {
    let mut context = cageforge::PathResolutionContext::new()
        .with_root(platform_root(current_directory))?
        .with_minimal_path(platform_minimal_root(current_directory))?
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
fn platform_minimal_root(current_directory: &Path) -> PathBuf {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = current_directory;
        PathBuf::from("/usr")
    }
    #[cfg(target_os = "windows")]
    {
        platform_root(current_directory).join("Windows\\System32")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        current_directory.to_path_buf()
    }
}

#[cfg(all(
    feature = "config",
    any(
        all(feature = "linux", target_os = "linux"),
        all(feature = "windows", target_os = "windows"),
        all(feature = "macos", target_os = "macos"),
    )
))]
fn execute_native(invocation: Invocation) -> Result<u8, CliError> {
    let config = cageforge::NativeSandboxConfig::new().with_network_gateway(invocation.gateway);
    #[cfg(all(feature = "linux", target_os = "linux"))]
    let config = config.with_hardening_helper_path(std::env::current_exe()?);
    #[cfg(all(feature = "macos", target_os = "macos"))]
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
    not(any(
        all(feature = "linux", target_os = "linux"),
        all(feature = "windows", target_os = "windows"),
        all(feature = "macos", target_os = "macos"),
    ))
))]
fn execute_native(_invocation: Invocation) -> Result<u8, CliError> {
    let Invocation {
        command,
        effective,
        context,
        gateway,
    } = _invocation;
    drop((command, effective, context, gateway));
    Err(CliError::NativeFeatureRequired)
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
