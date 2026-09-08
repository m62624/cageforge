// SPDX-License-Identifier: Apache-2.0

//! Translation from CLI values to the existing Cageforge execution API.

#[cfg(feature = "config")]
use std::ffi::OsString;
#[cfg(feature = "config")]
use std::path::{Path, PathBuf};

use crate::cli::{Cli, Command, RunArgs};
use crate::error::CliError;

/// Executes a parsed CLI request and returns the process exit code.
pub fn execute(cli: Cli) -> Result<u8, CliError> {
    match cli.command {
        Command::Run(args) => execute_run(args),
        Command::Schema => execute_schema(),
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
    execute_native(invocation)
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

#[cfg(feature = "config")]
struct Invocation {
    command: cageforge::CommandRequest,
    effective: cageforge::EffectiveSandbox,
    context: cageforge::PathResolutionContext,
    gateway: cageforge::GatewayConfig,
}

#[cfg(all(feature = "config", feature = "linux", target_os = "linux"))]
fn execute_native(invocation: Invocation) -> Result<u8, CliError> {
    let helper = std::env::current_exe()?;
    let backend = cageforge::LinuxBackend::new(
        cageforge::LinuxBackendConfig::new()
            .with_hardening_helper_path(helper)
            .with_network_gateway(invocation.gateway),
    )?;
    let prepared = backend.prepare(
        cageforge::BackendRequest::new(&invocation.command, &invocation.effective),
        &invocation.context,
    )?;
    let mut child = backend.spawn(prepared)?;
    Ok(child.wait()?.code().unwrap_or(1) as u8)
}

#[cfg(all(feature = "config", feature = "windows", target_os = "windows"))]
fn execute_native(invocation: Invocation) -> Result<u8, CliError> {
    let backend = cageforge::WindowsBackend::new(
        cageforge::WindowsBackendConfig::new().with_network_gateway(invocation.gateway),
    )?;
    let prepared = backend.prepare(
        cageforge::BackendRequest::new(&invocation.command, &invocation.effective),
        &invocation.context,
    )?;
    let mut child = backend.spawn(prepared)?;
    Ok(child.wait()?.code().unwrap_or(1) as u8)
}

#[cfg(all(feature = "config", feature = "macos", target_os = "macos"))]
fn execute_native(invocation: Invocation) -> Result<u8, CliError> {
    let backend = cageforge::MacosBackend::new(
        cageforge::MacosBackendConfig::new().with_network_gateway(invocation.gateway),
    )?;
    let prepared = backend.prepare(
        cageforge::BackendRequest::new(&invocation.command, &invocation.effective),
        &invocation.context,
    )?;
    let mut child = backend.spawn(prepared)?;
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
