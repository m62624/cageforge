// SPDX-License-Identifier: Apache-2.0

//! PyO3 implementation of the Cageforge Python binding.
//!
//! This crate owns Python handle translation only. Configuration parsing,
//! policy composition, native backend selection, and process enforcement stay
//! in the public Cageforge crates. Blocking operations run in
//! [`Python::detach`] so callers do not hold the GIL while native code waits
//! or performs stream I/O.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

#[cfg(target_os = "linux")]
use std::time::Duration;

use pyo3::PyTypeInfo;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use pyo3_stub_gen::create_exception;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pyfunction, gen_stub_pymethods};

create_exception!(
    cageforge._cageforge,
    CageforgeError,
    PyException,
    "Base class for errors raised by Cageforge."
);
create_exception!(
    cageforge._cageforge,
    CageforgeConfigurationError,
    CageforgeError,
    "The TOML configuration or runtime context is invalid."
);
create_exception!(
    cageforge._cageforge,
    CageforgeInitializationError,
    CageforgeError,
    "The native Cageforge backend could not be initialized."
);
create_exception!(
    cageforge._cageforge,
    CageforgeLaunchError,
    CageforgeError,
    "The native sandbox process could not be launched."
);
create_exception!(
    cageforge._cageforge,
    CageforgePermissionError,
    CageforgeError,
    "The trusted preflight grant was missing, invalid, expired, or insufficient."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStoreError,
    CageforgePermissionError,
    "The host-owned permission store could not complete the requested operation."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStorePathError,
    CageforgeStoreError,
    "The persistent permission store path is invalid."
);
create_exception!(
    cageforge._cageforge,
    CageforgeGrantNotFoundError,
    CageforgeStoreError,
    "The requested persistent permission grant was not found."
);
create_exception!(
    cageforge._cageforge,
    CageforgeListingSnapshotExpiredError,
    CageforgeStoreError,
    "The permission listing changed before the next page was requested."
);
create_exception!(
    cageforge._cageforge,
    CageforgeInvalidGrantIdError,
    CageforgeStoreError,
    "The persistent permission grant ID is invalid."
);
create_exception!(
    cageforge._cageforge,
    CageforgeInvalidCursorError,
    CageforgeStoreError,
    "The persistent permission listing cursor is invalid."
);
create_exception!(
    cageforge._cageforge,
    CageforgeInvalidPageSizeError,
    CageforgeStoreError,
    "The persistent permission page size is invalid."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStoreLockedError,
    CageforgeStoreError,
    "The persistent permission store lock could not be acquired."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStoreReadError,
    CageforgeStoreError,
    "The persistent permission store could not be read."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStoreWriteError,
    CageforgeStoreError,
    "The persistent permission store could not be written."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStoreFormatError,
    CageforgeStoreError,
    "The persistent permission store has an invalid format."
);
create_exception!(
    cageforge._cageforge,
    CageforgeProcessError,
    CageforgeError,
    "A sandbox process lifecycle operation failed."
);
create_exception!(
    cageforge._cageforge,
    CageforgeStreamError,
    CageforgeError,
    "A sandbox standard stream operation failed."
);
create_exception!(
    cageforge._cageforge,
    CageforgeWindowsSetupError,
    CageforgeError,
    "Windows setup provisioning or verification failed."
);
create_exception!(
    cageforge._cageforge,
    UnsupportedPlatformError,
    CageforgeError,
    "The requested Cageforge operation is unavailable on this platform."
);

struct RuntimeState {
    backend: Box<dyn cageforge::DynSandbox>,
    context: cageforge::PathResolutionContext,
    effective: cageforge::EffectiveSandbox,
    profile_command: Option<cageforge::CommandRequest>,
    preflight_required: bool,
    approved_program: Option<String>,
}

struct LifecycleState {
    closing: bool,
    closed: bool,
    active_operations: usize,
}

struct ChildState {
    child: Mutex<Box<dyn cageforge::SandboxChild<Error = cageforge::SandboxExecutionError> + Send>>,
    stdin: Mutex<Option<Box<dyn Write + Send>>>,
    stdout: Mutex<Option<Box<dyn Read + Send>>>,
    stderr: Mutex<Option<Box<dyn Read + Send>>>,
    completed_status: Mutex<Option<Option<i32>>>,
    lifecycle: Mutex<LifecycleState>,
    no_active_operations: Condvar,
}

struct OperationGuard {
    state: Arc<ChildState>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let Ok(mut lifecycle) = self.state.lifecycle.lock() else {
            return;
        };
        lifecycle.active_operations = lifecycle.active_operations.saturating_sub(1);
        if lifecycle.active_operations == 0 {
            self.state.no_active_operations.notify_all();
        }
    }
}

/// Runtime paths deliberately supplied by the host application.
#[derive(Clone)]
#[gen_stub_pyclass]
#[pyclass(frozen, get_all, skip_from_py_object, module = "cageforge._cageforge")]
pub struct RuntimeContext {
    /// Absolute process current directory.
    pub current_directory: PathBuf,
    /// Optional absolute replacement for the platform minimal path.
    pub minimal_path: Option<PathBuf>,
}

/// The result of a completed sandbox process.
#[gen_stub_pyclass]
#[pyclass(frozen, get_all, module = "cageforge._cageforge")]
pub struct ProcessResult {
    /// The exit code, or `None` when the OS reports signal-style termination.
    pub exit_code: Option<i32>,
}

/// A reusable resolved Cageforge runtime.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct Cageforge {
    state: Arc<Mutex<Option<Arc<RuntimeState>>>>,
}

/// A structured, non-authoritative permission request for one launch plan.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct PermissionRequest {
    inner: Option<cageforge::PermissionRequest>,
}

/// One typed local-IPC endpoint requested by a preflight plan.
#[gen_stub_pyclass]
#[pyclass(frozen, get_all, module = "cageforge._cageforge")]
pub struct LocalIpcEndpoint {
    /// Stable endpoint kind: `unix_socket` or `windows_named_pipe`.
    pub kind: String,
    /// Validated native endpoint value without the transport prefix.
    pub value: String,
}

/// Stable identity of one exact permission request.
#[gen_stub_pyclass]
#[pyclass(frozen, from_py_object, module = "cageforge._cageforge")]
#[derive(Clone)]
pub struct GrantId {
    inner: cageforge::GrantId,
}

/// Opaque cursor for one permission-store snapshot.
#[gen_stub_pyclass]
#[pyclass(frozen, from_py_object, module = "cageforge._cageforge")]
#[derive(Clone)]
pub struct GrantPageCursor {
    inner: cageforge::GrantPageCursor,
}

/// Safe metadata for one persistent permission grant.
#[gen_stub_pyclass]
#[pyclass(frozen, skip_from_py_object, module = "cageforge._cageforge")]
#[derive(Clone)]
pub struct GrantSummary {
    /// Stable grant ID.
    #[pyo3(get)]
    pub id: GrantId,
    /// Tool identifier.
    #[pyo3(get)]
    pub tool_id: String,
    /// Tool version.
    #[pyo3(get)]
    pub tool_version: String,
    /// Target platform.
    #[pyo3(get)]
    pub platform: String,
    /// Target architecture.
    #[pyo3(get)]
    pub architecture: String,
    /// Grant scope.
    #[pyo3(get)]
    pub scope: String,
    /// Issuance timestamp.
    #[pyo3(get)]
    pub issued_at: u64,
    /// Optional expiration timestamp.
    #[pyo3(get)]
    pub expires_at: Option<u64>,
}

/// One bounded page of persistent-grant metadata.
#[gen_stub_pyclass]
#[pyclass(frozen, skip_from_py_object, module = "cageforge._cageforge")]
#[derive(Clone)]
pub struct GrantPage {
    /// Page entries.
    #[pyo3(get)]
    pub entries: Vec<GrantSummary>,
    /// Cursor for the next page, if any.
    #[pyo3(get)]
    pub next_cursor: Option<GrantPageCursor>,
}

/// Result of removing one persistent grant.
#[gen_stub_pyclass]
#[pyclass(frozen, skip_from_py_object, module = "cageforge._cageforge")]
#[derive(Clone)]
pub struct RevokeResult {
    value: String,
}

/// An opaque trusted-host approval for a permission request.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct PermissionGrant {
    inner: Option<cageforge::PermissionGrant>,
}

/// Trusted host capability that can issue an opaque grant.
#[gen_stub_pyclass]
#[pyclass(frozen, module = "cageforge._cageforge")]
pub struct PermissionApprover;

/// Host-owned persistent permission grant store.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct PermissionStore {
    inner: Option<Arc<cageforge::PermissionStore>>,
    path: PathBuf,
}

/// A launched sandbox process and its detached standard streams.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct SandboxProcess {
    state: Arc<ChildState>,
}

/// Explicit Windows setup operations, matching the JVM binding.
#[gen_stub_pyclass]
#[pyclass(module = "cageforge._cageforge")]
pub struct WindowsSetup;

fn configuration_error(error: impl ToString) -> PyErr {
    CageforgeConfigurationError::new_err(error.to_string())
}

fn initialization_error(error: impl ToString) -> PyErr {
    CageforgeInitializationError::new_err(error.to_string())
}

fn launch_error(error: impl ToString) -> PyErr {
    CageforgeLaunchError::new_err(error.to_string())
}

fn permission_error(error: impl ToString) -> PyErr {
    CageforgePermissionError::new_err(error.to_string())
}

fn store_error(error: cageforge::StoreError) -> PyErr {
    let message = error.to_string();
    match error {
        cageforge::StoreError::PathNotAbsolute { .. } => CageforgeStorePathError::new_err(message),
        cageforge::StoreError::GrantNotFound => {
            CageforgeGrantNotFoundError::new_err("permission grant was not found")
        }
        cageforge::StoreError::ListingSnapshotExpired => {
            CageforgeListingSnapshotExpiredError::new_err(message)
        }
        cageforge::StoreError::InvalidGrantId => {
            CageforgeInvalidGrantIdError::new_err("invalid grant id")
        }
        cageforge::StoreError::InvalidCursor => CageforgeInvalidCursorError::new_err(message),
        cageforge::StoreError::InvalidPageSize { .. } => {
            CageforgeInvalidPageSizeError::new_err(message)
        }
        cageforge::StoreError::StoreLocked { .. } => CageforgeStoreLockedError::new_err(message),
        cageforge::StoreError::Read { .. } => CageforgeStoreReadError::new_err(message),
        cageforge::StoreError::Write { .. } => CageforgeStoreWriteError::new_err(message),
        cageforge::StoreError::Format { .. } => CageforgeStoreFormatError::new_err(message),
        _ => CageforgeStoreError::new_err(message),
    }
}

fn process_error(error: impl ToString) -> PyErr {
    CageforgeProcessError::new_err(error.to_string())
}

fn stream_error(error: impl ToString) -> PyErr {
    CageforgeStreamError::new_err(error.to_string())
}

#[cfg(target_os = "windows")]
fn setup_error(error: impl ToString) -> PyErr {
    CageforgeWindowsSetupError::new_err(error.to_string())
}

fn permission_scope(value: &str) -> Result<cageforge::PermissionScope, cageforge::PermissionError> {
    cageforge::PermissionScope::parse(value)
}

fn closed_permission_error(kind: &str) -> PyErr {
    permission_error(format!("Cageforge {kind} is closed"))
}

fn request_inner(value: &PermissionRequest) -> PyResult<&cageforge::PermissionRequest> {
    value
        .inner
        .as_ref()
        .ok_or_else(|| closed_permission_error("permission request"))
}

fn grant_inner(value: &PermissionGrant) -> PyResult<&cageforge::PermissionGrant> {
    value
        .inner
        .as_ref()
        .ok_or_else(|| closed_permission_error("permission grant"))
}

fn store_inner(value: &PermissionStore) -> PyResult<&Arc<cageforge::PermissionStore>> {
    value
        .inner
        .as_ref()
        .ok_or_else(|| closed_permission_error("permission store"))
}

fn absolute_path(path: PathBuf, name: &str) -> PyResult<PathBuf> {
    if !path.is_absolute() {
        return Err(configuration_error(format!(
            "{name} must be absolute: {path:?}"
        )));
    }
    Ok(path)
}

fn permission_store_path(path: PathBuf) -> PyResult<PathBuf> {
    if !path.is_absolute() {
        return Err(CageforgeStorePathError::new_err(format!(
            "permission store path must be absolute: {path:?}"
        )));
    }
    Ok(path)
}

fn resolve_workspace_roots(
    current_directory: &Path,
    declarations: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    declarations
        .iter()
        .map(|declaration| {
            if cageforge::contains_parent_traversal(declaration) {
                return Err(format!(
                    "workspace root contains parent traversal: {declaration:?}"
                ));
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

fn platform_root(current_directory: &Path) -> PathBuf {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = current_directory;
        PathBuf::from("/")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .and_then(|system_root| system_root.parent().map(Path::to_path_buf))
            .filter(|root| root.is_absolute())
            .or_else(|| current_directory.ancestors().last().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(r"C:\"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        current_directory.to_path_buf()
    }
}

fn platform_minimal_root(current_directory: &Path) -> PathBuf {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = current_directory;
        PathBuf::from("/usr")
    }
    #[cfg(target_os = "windows")]
    {
        platform_root(current_directory).join(r"Windows\System32")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        current_directory.to_path_buf()
    }
}

fn runtime_context(
    current_directory: &Path,
    workspace_roots: &[PathBuf],
    minimal_path: Option<&Path>,
) -> Result<cageforge::PathResolutionContext, String> {
    let mut context = cageforge::PathResolutionContext::new()
        .with_root(platform_root(current_directory))
        .map_err(|error| error.to_string())?
        .with_minimal_path(
            minimal_path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| platform_minimal_root(current_directory)),
        )
        .map_err(|error| error.to_string())?
        .with_current_directory(current_directory.to_path_buf())
        .map_err(|error| error.to_string())?;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        context = context
            .with_tmpdir(std::env::temp_dir())
            .map_err(|error| error.to_string())?
            .with_slash_tmp(PathBuf::from("/tmp"))
            .map_err(|error| error.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        for path in ["/bin", "/lib", "/lib64"] {
            context = context
                .with_minimal_path(PathBuf::from(path))
                .map_err(|error| error.to_string())?;
        }
    }
    #[cfg(target_os = "windows")]
    {
        context = context
            .with_tmpdir(std::env::temp_dir())
            .map_err(|error| error.to_string())?;
    }
    for root in workspace_roots {
        context = context
            .with_workspace_root(root.clone())
            .map_err(|error| error.to_string())?;
    }
    Ok(context)
}

fn runtime_inputs(
    profile: &cageforge::ResolvedProfile,
    current_directory: &Path,
    minimal_path: Option<&Path>,
) -> Result<
    (
        cageforge::PathResolutionContext,
        cageforge::EffectiveSandbox,
    ),
    String,
> {
    let (context, effective, _, _) =
        runtime_inputs_with_ceiling(profile, current_directory, minimal_path)?;
    Ok((context, effective))
}

fn runtime_inputs_with_ceiling(
    profile: &cageforge::ResolvedProfile,
    current_directory: &Path,
    minimal_path: Option<&Path>,
) -> Result<
    (
        cageforge::PathResolutionContext,
        cageforge::EffectiveSandbox,
        cageforge::EnvironmentSpec,
        cageforge::PolicyCeiling,
    ),
    String,
> {
    let workspace_roots = resolve_workspace_roots(current_directory, profile.workspace_roots())?;
    let context = runtime_context(current_directory, &workspace_roots, minimal_path)?;
    let environment = profile
        .command()
        .map(|command| command.environment().clone())
        .unwrap_or_default();
    let mut ceiling = cageforge::PolicyCeiling::new(profile.policy().clone(), environment.clone());
    if !workspace_roots.is_empty() {
        ceiling = ceiling
            .with_workspace_roots(workspace_roots.clone())
            .map_err(|error| error.to_string())?;
    }
    let mut composition =
        cageforge::CompositionRequest::new(profile.policy(), &environment, &ceiling);
    if !workspace_roots.is_empty() {
        composition = composition
            .with_workspace_roots(workspace_roots)
            .map_err(|error| error.to_string())?;
    }
    let effective = cageforge::compose(composition).map_err(|error| error.to_string())?;
    Ok((context, effective, environment, ceiling))
}

fn native_backend(
    native_directory: &Path,
    network_gateway: cageforge::GatewayConfig,
) -> Result<Box<dyn cageforge::DynSandbox>, String> {
    #[cfg(target_os = "linux")]
    {
        let config = cageforge::NativeSandboxConfig::new()
            .with_system_then_bundled_bubblewrap()
            .with_resource_directory(native_directory.to_path_buf())
            .with_hardening_helper_path(native_directory.join("cageforge-linux-helper"))
            .with_network_gateway(network_gateway)
            .with_default_timeout(Duration::from_secs(300))
            .map_err(|error| error.to_string())?;
        return cageforge::native_sandbox_with(config).map_err(|error| error.to_string());
    }
    #[cfg(target_os = "macos")]
    {
        let config = cageforge::NativeSandboxConfig::new()
            .with_helper_executable(native_directory.join("cageforge-macos-helper"))
            .map_err(|error| error.to_string())?
            .with_network_gateway(network_gateway);
        return cageforge::native_sandbox_with(config).map_err(|error| error.to_string());
    }
    #[cfg(target_os = "windows")]
    {
        let setup = cageforge::WindowsSetupConfig::new()
            .with_setup_helper_path(native_directory.join("cageforge-windows-setup.exe"))
            .map_err(|error| error.to_string())?
            .with_command_runner_path(native_directory.join("cageforge-windows-command-runner.exe"))
            .map_err(|error| error.to_string())?;
        return cageforge::native_sandbox_with(
            cageforge::NativeSandboxConfig::new()
                .with_setup(setup)
                .with_network_gateway(network_gateway),
        )
        .map_err(|error| error.to_string());
    }
    #[allow(unreachable_code)]
    {
        let _ = native_directory;
        let _ = network_gateway;
        Err(format!(
            "no Cageforge native backend is available for {}",
            std::env::consts::OS
        ))
    }
}

fn native_target_value() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn native_directory(module: &Bound<'_, PyModule>) -> PyResult<PathBuf> {
    if let Some(override_path) = std::env::var_os("CAGEFORGE_NATIVE_DIR") {
        let directory = absolute_path(PathBuf::from(override_path), "CAGEFORGE_NATIVE_DIR")?;
        validate_native_resources(&directory)?;
        return Ok(directory);
    }
    let filename = module
        .filename()
        .map_err(initialization_error)?
        .to_str()
        .map_err(|_| initialization_error("extension filename is not valid UTF-8"))?
        .to_owned();
    let package_directory = Path::new(&filename)
        .parent()
        .ok_or_else(|| initialization_error("extension has no package directory"))?;
    let directory = package_directory.join("native").join(native_target_value());
    validate_native_resources(&directory)?;
    Ok(directory)
}

fn validate_native_resources(directory: &Path) -> PyResult<()> {
    let names: &[&str] = if cfg!(target_os = "linux") {
        &[
            "cageforge-linux-helper",
            "bwrap",
            "bwrap.sha256",
            "bubblewrap-COPYING",
        ]
    } else if cfg!(target_os = "macos") {
        &["cageforge-macos-helper"]
    } else if cfg!(target_os = "windows") {
        &[
            "cageforge-windows-setup.exe",
            "cageforge-windows-command-runner.exe",
        ]
    } else {
        &[]
    };
    for name in names {
        let path = directory.join(name);
        if !path.is_file() {
            return Err(initialization_error(format!(
                "missing Cageforge native resource: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn module_native_directory(py: Python<'_>) -> PyResult<PathBuf> {
    let imported = py
        .import("cageforge._cageforge")
        .map_err(initialization_error)?;
    let module = imported
        .cast_into::<PyModule>()
        .map_err(|error| initialization_error(error.to_string()))?;
    native_directory(&module)
}

fn config_from_toml(toml: &str) -> Result<cageforge::Config, String> {
    cageforge::Config::from_toml(toml).map_err(|error| error.to_string())
}

fn normalize_toml_source(toml: String) -> String {
    toml.replace("\r\n", "\n").replace('\r', "\n")
}

fn build_preflight_request(
    toml: &str,
    profile_name: Option<&str>,
    context: &(PathBuf, Option<PathBuf>),
    tool_id: String,
    tool_version: String,
    manifest_digest: String,
    config_digest: String,
) -> Result<cageforge::PermissionRequest, String> {
    let config = config_from_toml(toml)?;
    let profile = resolve_profile(&config, profile_name)?;
    let (resolution, effective, environment, ceiling) =
        runtime_inputs_with_ceiling(&profile, &context.0, context.1.as_deref())?;
    let identity = cageforge::PreflightIdentity::new(
        tool_id,
        tool_version,
        manifest_digest,
        config_digest,
        cageforge::PlatformId::current().map_err(|error| error.to_string())?,
        std::env::consts::ARCH,
    );
    let plan = cageforge::PreflightPlan::from_policy_with_ceiling(
        profile.policy(),
        &resolution,
        effective,
        &environment,
        &ceiling,
        identity,
    )
    .map_err(|error| error.to_string())?;
    if let Some(command) = profile.command() {
        return plan
            .with_process_program(command.command().program().to_string_lossy().into_owned())
            .map(|plan| plan.request().clone())
            .map_err(|error| error.to_string());
    }
    Ok(plan.request().clone())
}

fn preflight_identity(
    request: Option<&cageforge::PermissionRequest>,
    toml: &str,
) -> Result<cageforge::PreflightIdentity, String> {
    if let Some(request) = request {
        return Ok(cageforge::PreflightIdentity::new(
            request.tool_id(),
            request.tool_version(),
            request.manifest_digest(),
            request.config_digest(),
            request.platform(),
            request.architecture(),
        ));
    }
    Ok(cageforge::PreflightIdentity::new(
        "cageforge-python",
        env!("CARGO_PKG_VERSION"),
        cageforge::sha256_digest(b"cageforge-python"),
        cageforge::sha256_digest(toml.as_bytes()),
        cageforge::PlatformId::current().map_err(|error| error.to_string())?,
        std::env::consts::ARCH,
    ))
}

fn resolve_profile(
    config: &cageforge::Config,
    profile_name: Option<&str>,
) -> Result<cageforge::ResolvedProfile, String> {
    let platform = cageforge::PlatformId::current().map_err(|error| error.to_string())?;
    match profile_name {
        Some(name) if !name.is_empty() => config.resolve_for_platform(name, platform),
        _ => config.resolve_default_for_platform(platform),
    }
    .map_err(|error| error.to_string())
}

fn command_request(
    state: &RuntimeState,
    argv: Vec<String>,
) -> Result<cageforge::CommandRequest, String> {
    if argv.is_empty() {
        return state
            .profile_command
            .clone()
            .ok_or_else(|| "profile has no command; pass a non-empty argv".to_string());
    }
    let mut parts = argv.into_iter();
    let Some(program) = parts.next() else {
        return Err("command argv must not be empty".to_string());
    };
    let spec = cageforge::CommandSpec::new(program)
        .and_then(|spec| spec.with_args(parts))
        .map_err(|error| error.to_string())?;
    let mut request =
        cageforge::CommandRequest::new(spec).with_stdio(cageforge::StdioSpec::captured());
    if let Some(template) = &state.profile_command {
        request = request
            .with_environment(template.environment().clone())
            .with_stdio(template.stdio())
            .with_timeout_policy(template.timeout_policy());
        if let Some(directory) = template.working_directory() {
            request = request
                .with_working_directory(directory.to_path_buf())
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(request)
}

fn status_value(status: Option<std::process::ExitStatus>) -> Option<Option<i32>> {
    status.map(|value| value.code())
}

#[gen_stub_pymethods]
#[pymethods]
impl RuntimeContext {
    #[new]
    #[pyo3(signature = (current_directory=None, minimal_path=None))]
    fn new(current_directory: Option<PathBuf>, minimal_path: Option<PathBuf>) -> PyResult<Self> {
        let current_directory = current_directory
            .or_else(|| std::env::current_dir().ok())
            .ok_or_else(|| configuration_error("cannot determine current directory"))?;
        Ok(Self {
            current_directory: absolute_path(current_directory, "current_directory")?,
            minimal_path: minimal_path
                .map(|path| absolute_path(path, "minimal_path"))
                .transpose()?,
        })
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl Cageforge {
    /// Returns validated profile names in deterministic lexical order.
    #[staticmethod]
    fn profile_names(toml: String) -> PyResult<Vec<String>> {
        if toml.is_empty() {
            return Err(configuration_error("TOML must not be empty"));
        }
        let config = config_from_toml(&toml).map_err(configuration_error)?;
        Ok(config.profile_names().map(str::to_owned).collect())
    }

    /// Returns the shared typed preflight request for a TOML profile.
    #[staticmethod]
    #[pyo3(signature = (toml, profile_name=None, context=None, tool_id="cageforge-python", tool_version=env!("CARGO_PKG_VERSION"), manifest_digest=None, config_digest=None))]
    fn permission_request(
        toml: String,
        profile_name: Option<String>,
        context: Option<&RuntimeContext>,
        tool_id: &str,
        tool_version: &str,
        manifest_digest: Option<String>,
        config_digest: Option<String>,
    ) -> PyResult<PermissionRequest> {
        let toml = normalize_toml_source(toml);
        let context = context
            .map(|value| (value.current_directory.clone(), value.minimal_path.clone()))
            .unwrap_or_else(|| {
                (
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    None,
                )
            });
        let request = build_preflight_request(
            &toml,
            profile_name.as_deref(),
            &context,
            tool_id.to_owned(),
            tool_version.to_owned(),
            manifest_digest.unwrap_or_else(|| cageforge::sha256_digest(b"cageforge-python")),
            config_digest.unwrap_or_else(|| cageforge::sha256_digest(toml.as_bytes())),
        )
        .map_err(configuration_error)?;
        Ok(PermissionRequest {
            inner: Some(request),
        })
    }

    /// Checks TOML parsing, profile resolution, and policy composition.
    #[staticmethod]
    #[pyo3(signature = (toml, profile_name=None, context=None))]
    fn check_toml(
        toml: String,
        profile_name: Option<String>,
        context: Option<&RuntimeContext>,
    ) -> PyResult<()> {
        let context = context
            .map(|value| (value.current_directory.clone(), value.minimal_path.clone()))
            .unwrap_or_else(|| {
                (
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    None,
                )
            });
        Python::attach(|py| {
            py.detach(move || {
                let config = config_from_toml(&toml).map_err(configuration_error)?;
                let profile = resolve_profile(&config, profile_name.as_deref())
                    .map_err(configuration_error)?;
                runtime_inputs(&profile, &context.0, context.1.as_deref())
                    .map(|_| ())
                    .map_err(configuration_error)
            })
        })
    }

    /// Creates a native runtime from TOML and the selected profile.
    #[staticmethod]
    #[pyo3(signature = (toml, profile_name=None, context=None, grant=None, request=None))]
    fn from_toml(
        py: Python<'_>,
        toml: String,
        profile_name: Option<String>,
        context: Option<&RuntimeContext>,
        grant: Option<&PermissionGrant>,
        request: Option<&PermissionRequest>,
    ) -> PyResult<Self> {
        let toml = normalize_toml_source(toml);
        if toml.is_empty() {
            return Err(configuration_error("TOML must not be empty"));
        }
        let context = context
            .map(|value| (value.current_directory.clone(), value.minimal_path.clone()))
            .unwrap_or_else(|| {
                (
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    None,
                )
            });
        let module_directory = module_native_directory(py)?;
        let grant = grant
            .map(|grant| {
                grant
                    .inner
                    .clone()
                    .ok_or_else(|| closed_permission_error("permission grant"))
            })
            .transpose()?;
        let request = request
            .map(|request| {
                request
                    .inner
                    .clone()
                    .ok_or_else(|| closed_permission_error("permission request"))
            })
            .transpose()?;
        let state = py.detach(move || {
            let config = config_from_toml(&toml).map_err(configuration_error)?;
            let profile =
                resolve_profile(&config, profile_name.as_deref()).map_err(configuration_error)?;
            let (resolution, effective, environment, ceiling) =
                runtime_inputs_with_ceiling(&profile, &context.0, context.1.as_deref())
                    .map_err(configuration_error)?;
            if profile.approval().mode() == cageforge::PermissionMode::Disabled {
                let backend = native_backend(&module_directory, profile.network_gateway().clone())
                    .map_err(initialization_error)?;
                return Ok::<_, PyErr>(RuntimeState {
                    backend,
                    context: resolution,
                    effective,
                    profile_command: profile.command().cloned(),
                    preflight_required: false,
                    approved_program: None,
                });
            }
            let identity = preflight_identity(request.as_ref(), &toml)
                .map_err(configuration_error)?;
            let plan = cageforge::PreflightPlan::from_policy_with_ceiling(
                profile.policy(),
                &resolution,
                effective,
                &environment,
                &ceiling,
                identity,
            )
            .map_err(permission_error)?;
            let plan = if let Some(command) = profile.command() {
                plan.with_process_program(
                    command.command().program().to_string_lossy().into_owned(),
                )
                .map_err(permission_error)?
            } else {
                plan
            };
            let grant = grant.ok_or_else(|| {
                permission_error("preflight approval is required; call permission_request and pass its trusted grant")
            })?;
            let effective = plan
                .authorize(grant)
                .map_err(permission_error)?
                .effective()
                .clone();
            let approved_program = profile.command().map(|command| {
                command.command().program().to_string_lossy().into_owned()
            });
            let backend = native_backend(&module_directory, profile.network_gateway().clone())
                .map_err(initialization_error)?;
            Ok::<_, PyErr>(RuntimeState {
                backend,
                context: resolution,
                effective,
                profile_command: profile.command().cloned(),
                preflight_required: true,
                approved_program,
            })
        })?;
        Ok(Self {
            state: Arc::new(Mutex::new(Some(Arc::new(state)))),
        })
    }

    /// Reads a TOML file and creates a runtime using its parent directory.
    #[staticmethod]
    #[pyo3(signature = (file, profile_name=None, context=None, grant=None, request=None))]
    fn from_toml_file(
        py: Python<'_>,
        file: PathBuf,
        profile_name: Option<String>,
        context: Option<&RuntimeContext>,
        grant: Option<&PermissionGrant>,
        request: Option<&PermissionRequest>,
    ) -> PyResult<Self> {
        let file = absolute_path(file, "file")?;
        let source_file = file.clone();
        let source = py
            .detach(move || std::fs::read_to_string(&source_file))
            .map_err(configuration_error)?;
        let context = context
            .map(|value| (value.current_directory.clone(), value.minimal_path.clone()))
            .or_else(|| file.parent().map(|parent| (parent.to_path_buf(), None)))
            .map(|(current_directory, minimal_path)| RuntimeContext {
                current_directory,
                minimal_path,
            });
        Self::from_toml(py, source, profile_name, context.as_ref(), grant, request)
    }

    /// Returns the native resource target selected by this interpreter.
    #[staticmethod]
    fn native_target() -> String {
        native_target_value()
    }

    /// Launches the profile command, or an explicit argv when supplied.
    #[pyo3(signature = (argv=None))]
    fn launch(&self, py: Python<'_>, argv: Option<Vec<String>>) -> PyResult<SandboxProcess> {
        let argv = argv.unwrap_or_default();
        let state = Arc::clone(&self.state);
        let runtime = {
            let guard = state
                .lock()
                .map_err(|_| launch_error("runtime is poisoned"))?;
            Arc::clone(
                guard
                    .as_ref()
                    .ok_or_else(|| launch_error("runtime is closed"))?,
            )
        };
        let child = py.detach(move || {
            let request = command_request(&runtime, argv).map_err(launch_error)?;
            if runtime.preflight_required {
                let program = request.command().program().to_string_lossy();
                if runtime.approved_program.as_deref() != Some(program.as_ref()) {
                    return Err(permission_error(
                        "preflight grant is bound to the profile command; prepare and authorize the requested argv first",
                    ));
                }
            }
            let backend_request = cageforge::BackendRequest::new(&request, &runtime.effective);
            let mut child = runtime
                .backend
                .launch(backend_request, &runtime.context)
                .map_err(launch_error)?;
            Ok::<_, PyErr>(ChildState {
                stdin: Mutex::new(child.take_stdin()),
                stdout: Mutex::new(child.take_stdout()),
                stderr: Mutex::new(child.take_stderr()),
                child: Mutex::new(child),
                completed_status: Mutex::new(None),
                lifecycle: Mutex::new(LifecycleState {
                    closing: false,
                    closed: false,
                    active_operations: 0,
                }),
                no_active_operations: Condvar::new(),
            })
        })?;
        Ok(SandboxProcess {
            state: Arc::new(child),
        })
    }

    /// Releases the runtime handle. Existing process objects remain owned by
    /// their own native child boundary.
    fn close(&self) -> PyResult<()> {
        let runtime = self
            .state
            .lock()
            .map_err(|_| process_error("runtime is poisoned"))?
            .take();
        drop(runtime);
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _ty: Option<Py<PyAny>>,
        _value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PermissionRequest {
    /// Returns the stable JSON representation used by host adapters.
    fn json(&self) -> PyResult<String> {
        serde_json::to_string(request_inner(self)?).map_err(permission_error)
    }

    /// Returns the requesting tool identifier.
    fn tool_id(&self) -> PyResult<&str> {
        Ok(request_inner(self)?.tool_id())
    }
    /// Returns the tool version.
    fn tool_version(&self) -> PyResult<&str> {
        Ok(request_inner(self)?.tool_version())
    }
    /// Returns the selected platform.
    fn platform(&self) -> PyResult<&str> {
        Ok(request_inner(self)?.platform().as_str())
    }
    /// Returns the request digest.
    fn digest(&self) -> PyResult<String> {
        Ok(request_inner(self)?.digest())
    }

    /// Returns the stable ID used by the persistent grant store.
    fn grant_id(&self) -> PyResult<GrantId> {
        Ok(GrantId {
            inner: request_inner(self)?.grant_id(),
        })
    }
    /// Returns filesystem capabilities as `(operation, path)` pairs.
    fn filesystem(&self) -> PyResult<Vec<(String, String)>> {
        Ok(request_inner(self)?
            .capabilities()
            .filesystem()
            .iter()
            .map(|capability| {
                (
                    format!("{:?}", capability.operation()).to_lowercase(),
                    capability.path().to_owned(),
                )
            })
            .collect())
    }
    /// Returns requested network endpoints.
    fn network(&self) -> PyResult<Vec<String>> {
        Ok(request_inner(self)?
            .capabilities()
            .network()
            .iter()
            .map(|capability| capability.endpoint().to_owned())
            .collect())
    }

    /// Returns typed local-IPC endpoint declarations.
    fn local_ipc(&self) -> PyResult<Vec<LocalIpcEndpoint>> {
        Ok(request_inner(self)?
            .capabilities()
            .network()
            .iter()
            .map(|capability| capability.endpoint())
            .filter_map(|endpoint| {
                endpoint
                    .strip_prefix("unix:")
                    .map(|value| LocalIpcEndpoint {
                        kind: "unix_socket".to_owned(),
                        value: value.to_owned(),
                    })
                    .or_else(|| {
                        endpoint
                            .strip_prefix("pipe:")
                            .map(|value| LocalIpcEndpoint {
                                kind: "windows_named_pipe".to_owned(),
                                value: value.to_owned(),
                            })
                    })
            })
            .collect())
    }

    /// Releases the request and makes later operations fail closed.
    fn close(&mut self) {
        self.inner = None;
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _ty: Option<Py<PyAny>>,
        _value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) -> PyResult<bool> {
        self.close();
        Ok(false)
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PermissionApprover {
    /// Creates a session-scoped grant for the complete request.
    #[new]
    fn new() -> Self {
        Self
    }

    /// Approves the complete request through the trusted host capability.
    #[pyo3(signature = (request, scope="session", expires_at=None))]
    fn approve(
        &self,
        request: &PermissionRequest,
        scope: &str,
        expires_at: Option<u64>,
    ) -> PyResult<PermissionGrant> {
        let scope = permission_scope(scope).map_err(permission_error)?;
        let request = request_inner(request)?;
        let inner = cageforge::GrantAuthority::new()
            .approve_with(request, request.capabilities().clone(), scope, expires_at)
            .map_err(permission_error)?;
        Ok(PermissionGrant { inner: Some(inner) })
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PermissionStore {
    /// Opens a host-owned permission store at an absolute path.
    #[staticmethod]
    fn open(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        Self::new(py, path)
    }

    /// Opens a host-owned permission store at an absolute path.
    #[new]
    fn new(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        let path = permission_store_path(path)?;
        let open_path = path.clone();
        let inner =
            py.detach(move || cageforge::PermissionStore::open(open_path).map_err(store_error))?;
        Ok(Self {
            inner: Some(Arc::new(inner)),
            path,
        })
    }

    /// Returns the configured store path.
    fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Returns a valid persisted grant for the exact request, if present.
    fn get(
        &self,
        py: Python<'_>,
        request: &PermissionRequest,
    ) -> PyResult<Option<PermissionGrant>> {
        let store = store_inner(self)?.clone();
        let request = request_inner(request)?.clone();
        py.detach(move || {
            store
                .get(&request)
                .map(|grant| grant.map(|inner| PermissionGrant { inner: Some(inner) }))
                .map_err(store_error)
        })
    }

    /// Persists a persistent grant after validating it against the request.
    fn put(
        &self,
        py: Python<'_>,
        grant: &PermissionGrant,
        request: &PermissionRequest,
    ) -> PyResult<()> {
        let store = store_inner(self)?.clone();
        let grant = grant_inner(grant)?.clone();
        let request = request_inner(request)?.clone();
        py.detach(move || store.put(&grant, &request).map_err(store_error))
    }

    /// Lists one bounded page of safe persistent-grant summaries.
    #[pyo3(signature = (page_size=50, cursor=None))]
    fn list_page(
        &self,
        py: Python<'_>,
        page_size: usize,
        cursor: Option<&GrantPageCursor>,
    ) -> PyResult<GrantPage> {
        let store = store_inner(self)?.clone();
        let cursor = cursor.map(|value| value.inner.clone());
        py.detach(move || {
            let request =
                cageforge::GrantPageRequest::new(page_size, cursor).map_err(store_error)?;
            let page = store.list_page(request).map_err(store_error)?;
            Ok(GrantPage {
                entries: page
                    .entries()
                    .iter()
                    .map(|entry| GrantSummary {
                        id: GrantId { inner: entry.id },
                        tool_id: entry.tool_id.clone(),
                        tool_version: entry.tool_version.clone(),
                        platform: entry.platform.as_str().to_owned(),
                        architecture: entry.architecture.clone(),
                        scope: format!("{:?}", entry.scope).to_lowercase(),
                        issued_at: entry.issued_at,
                        expires_at: entry.expires_at,
                    })
                    .collect(),
                next_cursor: page
                    .next_cursor()
                    .cloned()
                    .map(|inner| GrantPageCursor { inner }),
            })
        })
    }

    /// Revokes one persistent grant for future launches.
    fn revoke(&self, py: Python<'_>, id: &GrantId) -> PyResult<RevokeResult> {
        let store = store_inner(self)?.clone();
        let id = id.inner;
        py.detach(move || {
            store
                .revoke(id)
                .map(|result| RevokeResult {
                    value: match result {
                        cageforge::RevokeResult::Revoked => "revoked".to_owned(),
                        cageforge::RevokeResult::NotFound => "not-found".to_owned(),
                    },
                })
                .map_err(store_error)
        })
    }

    /// Revokes all persistent grants while retaining the store file.
    fn revoke_all(&self, py: Python<'_>) -> PyResult<()> {
        let store = store_inner(self)?.clone();
        py.detach(move || store.revoke_all().map_err(store_error))
    }

    /// Releases the store and makes later operations fail closed.
    fn close(&mut self) {
        self.inner = None;
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _ty: Option<Py<PyAny>>,
        _value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) -> PyResult<bool> {
        self.close();
        Ok(false)
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl PermissionGrant {
    /// Returns the digest of the request this grant authorizes.
    fn request_digest(&self) -> PyResult<&str> {
        Ok(grant_inner(self)?.request_digest())
    }

    /// Returns the grant lifetime as `launch`, `session`, or `persistent`.
    fn scope(&self) -> PyResult<String> {
        Ok(format!("{:?}", grant_inner(self)?.scope()).to_lowercase())
    }

    /// Returns the optional Unix expiration timestamp.
    fn expires_at(&self) -> PyResult<Option<u64>> {
        Ok(grant_inner(self)?.expires_at())
    }

    /// Releases the grant and makes later operations fail closed.
    fn close(&mut self) {
        self.inner = None;
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _ty: Option<Py<PyAny>>,
        _value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) -> PyResult<bool> {
        self.close();
        Ok(false)
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl GrantId {
    /// Parses a stable hexadecimal grant ID.
    #[staticmethod]
    fn from_hex(value: &str) -> PyResult<Self> {
        cageforge::GrantId::from_hex(value)
            .map(|inner| Self { inner })
            .map_err(|_| CageforgeInvalidGrantIdError::new_err("invalid grant id"))
    }

    /// Returns the canonical lowercase hexadecimal ID.
    fn hex(&self) -> String {
        self.inner.to_hex()
    }

    fn __str__(&self) -> String {
        self.hex()
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl GrantPageCursor {
    /// Returns the opaque cursor token.
    fn token(&self) -> String {
        self.inner.to_token()
    }

    /// Parses a cursor token returned by a previous page.
    #[staticmethod]
    fn from_token(value: &str) -> PyResult<Self> {
        cageforge::GrantPageCursor::from_token(value)
            .map(|inner| Self { inner })
            .map_err(store_error)
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl RevokeResult {
    /// Returns `revoked` or `not-found`.
    fn value(&self) -> &str {
        &self.value
    }

    fn __str__(&self) -> &str {
        &self.value
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl SandboxProcess {
    /// Returns the native process identifier.
    fn id(&self, py: Python<'_>) -> PyResult<u32> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            let child = state
                .child
                .lock()
                .map_err(|_| process_error("process is poisoned"))?;
            Ok(child.id())
        })
    }

    /// Returns whether stdin is connected to a pipe.
    fn has_stdin(&self, py: Python<'_>) -> PyResult<bool> {
        stream_present(py, &self.state, StreamKind::Stdin)
    }

    /// Returns whether stdout is connected to a pipe.
    fn has_stdout(&self, py: Python<'_>) -> PyResult<bool> {
        stream_present(py, &self.state, StreamKind::Stdout)
    }

    /// Returns whether stderr is connected to a pipe.
    fn has_stderr(&self, py: Python<'_>) -> PyResult<bool> {
        stream_present(py, &self.state, StreamKind::Stderr)
    }

    /// Reads up to `size` bytes from stdout.
    fn read_stdout(&self, py: Python<'_>, size: usize) -> PyResult<Py<PyBytes>> {
        read_stream(py, &self.state, StreamKind::Stdout, size)
    }

    /// Reads up to `size` bytes from stderr.
    fn read_stderr(&self, py: Python<'_>, size: usize) -> PyResult<Py<PyBytes>> {
        read_stream(py, &self.state, StreamKind::Stderr, size)
    }

    /// Writes bytes to stdin and returns the number written.
    fn write_stdin(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<usize> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            let mut stream = state
                .stdin
                .lock()
                .map_err(|_| stream_error("stdin is poisoned"))?
                .take()
                .ok_or_else(|| stream_error("stdin is not piped or is closed"))?;
            let result = stream.write(&data).map_err(stream_error);
            state
                .stdin
                .lock()
                .map_err(|_| stream_error("stdin is poisoned"))?
                .replace(stream);
            result
        })
    }

    /// Closes the stdin pipe.
    fn close_stdin(&self, py: Python<'_>) -> PyResult<()> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            state
                .stdin
                .lock()
                .map_err(|_| stream_error("stdin is poisoned"))?
                .take();
            Ok(())
        })
    }

    /// Returns the result without waiting, or `None` while running.
    fn try_wait(&self, py: Python<'_>) -> PyResult<Option<ProcessResult>> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            let mut child = state
                .child
                .lock()
                .map_err(|_| process_error("process is poisoned"))?;
            if let Some(status) = *state
                .completed_status
                .lock()
                .map_err(|_| process_error("process status is poisoned"))?
            {
                return Ok(Some(ProcessResult { exit_code: status }));
            }
            let status = child.try_wait().map_err(process_error)?;
            if let Some(value) = status_value(status) {
                *state
                    .completed_status
                    .lock()
                    .map_err(|_| process_error("process status is poisoned"))? = Some(value);
                return Ok(Some(ProcessResult { exit_code: value }));
            }
            Ok(None)
        })
    }

    /// Waits until the process exits or its configured timeout fires.
    fn wait(&self, py: Python<'_>) -> PyResult<ProcessResult> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            loop {
                {
                    let mut child = state
                        .child
                        .lock()
                        .map_err(|_| process_error("process is poisoned"))?;
                    if let Some(status) = *state
                        .completed_status
                        .lock()
                        .map_err(|_| process_error("process status is poisoned"))?
                    {
                        return Ok(ProcessResult { exit_code: status });
                    }
                    if let Some(value) = status_value(child.try_wait().map_err(process_error)?) {
                        *state
                            .completed_status
                            .lock()
                            .map_err(|_| process_error("process status is poisoned"))? =
                            Some(value);
                        return Ok(ProcessResult { exit_code: value });
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        })
    }

    /// Terminates and confirms the complete sandbox boundary.
    fn kill(&self, py: Python<'_>) -> PyResult<()> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            let _operation = begin_operation(&state)?;
            terminate_child(&state)
        })
    }

    /// Terminates the process if needed and releases its native streams.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let state = Arc::clone(&self.state);
        py.detach(move || {
            {
                let mut lifecycle = state
                    .lifecycle
                    .lock()
                    .map_err(|_| process_error("process lifecycle is poisoned"))?;
                while lifecycle.closing && !lifecycle.closed {
                    lifecycle = state
                        .no_active_operations
                        .wait(lifecycle)
                        .map_err(|_| process_error("process lifecycle is poisoned"))?;
                }
                if lifecycle.closed {
                    return Ok(());
                }
                lifecycle.closing = true;
            }
            let termination = terminate_child(&state);
            let mut lifecycle = state
                .lifecycle
                .lock()
                .map_err(|_| process_error("process lifecycle is poisoned"))?;
            while lifecycle.active_operations != 0 {
                lifecycle = state
                    .no_active_operations
                    .wait(lifecycle)
                    .map_err(|_| process_error("process lifecycle is poisoned"))?;
            }
            lifecycle.closed = true;
            lifecycle.closing = false;
            state.no_active_operations.notify_all();
            termination
        })
    }

    /// Compatibility alias for `wait()`.
    fn wait_for(&self, py: Python<'_>) -> PyResult<ProcessResult> {
        self.wait(py)
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _ty: Option<Py<PyAny>>,
        _value: Option<Py<PyAny>>,
        _traceback: Option<Py<PyAny>>,
    ) -> PyResult<bool> {
        Python::attach(|py| self.close(py))?;
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

fn stream_present(py: Python<'_>, state: &Arc<ChildState>, stream: StreamKind) -> PyResult<bool> {
    let state = Arc::clone(state);
    py.detach(move || {
        let _operation = begin_operation(&state)?;
        let present = match stream {
            StreamKind::Stdin => state
                .stdin
                .lock()
                .map_err(|_| stream_error("stream is poisoned"))?
                .is_some(),
            StreamKind::Stdout => state
                .stdout
                .lock()
                .map_err(|_| stream_error("stream is poisoned"))?
                .is_some(),
            StreamKind::Stderr => state
                .stderr
                .lock()
                .map_err(|_| stream_error("stream is poisoned"))?
                .is_some(),
        };
        Ok(present)
    })
}

fn begin_operation(state: &Arc<ChildState>) -> PyResult<OperationGuard> {
    let mut lifecycle = state
        .lifecycle
        .lock()
        .map_err(|_| process_error("process lifecycle is poisoned"))?;
    if lifecycle.closing || lifecycle.closed {
        return Err(process_error("sandbox process is closed"));
    }
    lifecycle.active_operations += 1;
    Ok(OperationGuard {
        state: Arc::clone(state),
    })
}

fn terminate_child(state: &Arc<ChildState>) -> PyResult<()> {
    let mut child = state
        .child
        .lock()
        .map_err(|_| process_error("process is poisoned"))?;
    let mut completed_status = state
        .completed_status
        .lock()
        .map_err(|_| process_error("process status is poisoned"))?;
    if completed_status.is_some() {
        return Ok(());
    }
    child.kill().map_err(process_error)?;
    *completed_status = Some(None);
    Ok(())
}

fn read_stream(
    py: Python<'_>,
    state: &Arc<ChildState>,
    stream: StreamKind,
    size: usize,
) -> PyResult<Py<PyBytes>> {
    if size == 0 {
        return Ok(PyBytes::new(py, &[]).unbind());
    }
    let state = Arc::clone(state);
    let bytes = py.detach(move || {
        let _operation = begin_operation(&state)?;
        let target = match stream {
            StreamKind::Stdout => &state.stdout,
            StreamKind::Stderr => &state.stderr,
            StreamKind::Stdin => return Err(stream_error("stdin is not readable")),
        };
        let mut stream = target
            .lock()
            .map_err(|_| stream_error("stream is poisoned"))?
            .take()
            .ok_or_else(|| stream_error("stream is not piped or is closed"))?;
        let result = (|| {
            let mut bytes = vec![0_u8; size];
            let count = stream.read(&mut bytes).map_err(stream_error)?;
            bytes.truncate(count);
            Ok::<_, PyErr>(bytes)
        })();
        target
            .lock()
            .map_err(|_| stream_error("stream is poisoned"))?
            .replace(stream);
        result
    })?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

#[gen_stub_pymethods]
#[pymethods]
impl WindowsSetup {
    /// Returns whether this interpreter runs on Windows.
    #[staticmethod]
    fn is_supported() -> bool {
        cfg!(target_os = "windows")
    }

    /// Installs or reconciles the owner-scoped Windows boundary.
    #[staticmethod]
    fn install(py: Python<'_>) -> PyResult<()> {
        windows_setup_call(py, WindowsSetupOperation::Install)
    }

    /// Returns `"missing"`, `"stale"`, or `"ready"` without provisioning.
    #[staticmethod]
    fn status(py: Python<'_>) -> PyResult<String> {
        windows_setup_status(py)
    }

    /// Verifies the complete owner-scoped Windows setup.
    #[staticmethod]
    fn verify(py: Python<'_>) -> PyResult<()> {
        windows_setup_call(py, WindowsSetupOperation::Verify)
    }

    /// Removes the owner-scoped Windows boundary.
    #[staticmethod]
    fn uninstall(py: Python<'_>) -> PyResult<()> {
        windows_setup_call(py, WindowsSetupOperation::Uninstall)
    }
}

enum WindowsSetupOperation {
    Install,
    Verify,
    Uninstall,
}

fn windows_setup_call(py: Python<'_>, operation: WindowsSetupOperation) -> PyResult<()> {
    if !cfg!(target_os = "windows") {
        return Err(UnsupportedPlatformError::new_err(
            "Windows setup is available only on Windows",
        ));
    }
    let native_directory = module_native_directory(py)?;
    py.detach(move || {
        #[cfg(target_os = "windows")]
        {
            let setup_config = cageforge::WindowsSetupConfig::new()
                .with_setup_helper_path(native_directory.join("cageforge-windows-setup.exe"))
                .map_err(setup_error)?
                .with_command_runner_path(
                    native_directory.join("cageforge-windows-command-runner.exe"),
                )
                .map_err(setup_error)?;
            let setup = cageforge::WindowsSetup::new(setup_config);
            match operation {
                WindowsSetupOperation::Install => setup.install().map(|_| ()),
                WindowsSetupOperation::Verify => setup.verify().map(|_| ()),
                WindowsSetupOperation::Uninstall => setup.uninstall(),
            }
            .map_err(setup_error)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            let _ = operation;
            Err(UnsupportedPlatformError::new_err(
                "Windows setup is available only on Windows",
            ))
        }
    })
}

fn windows_setup_status(py: Python<'_>) -> PyResult<String> {
    if !cfg!(target_os = "windows") {
        return Err(UnsupportedPlatformError::new_err(
            "Windows setup is available only on Windows",
        ));
    }
    let native_directory = module_native_directory(py)?;
    py.detach(move || {
        #[cfg(target_os = "windows")]
        {
            let setup_config = cageforge::WindowsSetupConfig::new()
                .with_setup_helper_path(native_directory.join("cageforge-windows-setup.exe"))
                .map_err(setup_error)?
                .with_command_runner_path(
                    native_directory.join("cageforge-windows-command-runner.exe"),
                )
                .map_err(setup_error)?;
            match cageforge::WindowsSetup::new(setup_config)
                .status()
                .map_err(setup_error)?
            {
                cageforge::WindowsSetupStatus::Missing { .. } => Ok("missing".to_string()),
                cageforge::WindowsSetupStatus::Stale { .. } => Ok("stale".to_string()),
                cageforge::WindowsSetupStatus::Ready(_) => Ok("ready".to_string()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err(UnsupportedPlatformError::new_err(
                "Windows setup is available only on Windows",
            ))
        }
    })
}

#[gen_stub_pyfunction(module = "cageforge._cageforge")]
#[pyfunction]
fn native_target() -> String {
    native_target_value()
}

/// Registers the extension module and its structured errors.
#[pymodule]
fn _cageforge(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Cageforge>()?;
    module.add_class::<RuntimeContext>()?;
    module.add_class::<SandboxProcess>()?;
    module.add_class::<ProcessResult>()?;
    module.add_class::<WindowsSetup>()?;
    module.add_class::<PermissionRequest>()?;
    module.add_class::<LocalIpcEndpoint>()?;
    module.add_class::<GrantId>()?;
    module.add_class::<GrantPageCursor>()?;
    module.add_class::<GrantSummary>()?;
    module.add_class::<GrantPage>()?;
    module.add_class::<RevokeResult>()?;
    module.add_class::<PermissionGrant>()?;
    module.add_class::<PermissionApprover>()?;
    module.add_class::<PermissionStore>()?;
    module.add_function(wrap_pyfunction!(native_target, module)?)?;
    module.add("CageforgeError", CageforgeError::type_object(module.py()))?;
    module.add(
        "CageforgeConfigurationError",
        CageforgeConfigurationError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeInitializationError",
        CageforgeInitializationError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeLaunchError",
        CageforgeLaunchError::type_object(module.py()),
    )?;
    module.add(
        "CageforgePermissionError",
        CageforgePermissionError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStoreError",
        CageforgeStoreError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStorePathError",
        CageforgeStorePathError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeGrantNotFoundError",
        CageforgeGrantNotFoundError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeListingSnapshotExpiredError",
        CageforgeListingSnapshotExpiredError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeInvalidGrantIdError",
        CageforgeInvalidGrantIdError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeInvalidCursorError",
        CageforgeInvalidCursorError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeInvalidPageSizeError",
        CageforgeInvalidPageSizeError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStoreLockedError",
        CageforgeStoreLockedError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStoreReadError",
        CageforgeStoreReadError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStoreWriteError",
        CageforgeStoreWriteError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStoreFormatError",
        CageforgeStoreFormatError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeProcessError",
        CageforgeProcessError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeStreamError",
        CageforgeStreamError::type_object(module.py()),
    )?;
    module.add(
        "CageforgeWindowsSetupError",
        CageforgeWindowsSetupError::type_object(module.py()),
    )?;
    module.add(
        "UnsupportedPlatformError",
        UnsupportedPlatformError::type_object(module.py()),
    )?;
    Ok(())
}

pyo3_stub_gen::define_stub_info_gatherer!(stub_info);
