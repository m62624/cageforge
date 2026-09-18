// SPDX-License-Identifier: Apache-2.0

//! JNI implementation for the JVM Cageforge binding.
//!
//! This crate is deliberately private and is not a second Rust API. It owns
//! only the JVM handle translation and delegates policy parsing, composition,
//! native backend construction, and process lifecycle to `cageforge`.

#![deny(missing_docs)]

mod error;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jbyteArray, jint, jlong, jobjectArray, jstring};
use jni::{Env, EnvUnowned};

use crate::error::{BindingError, BindingErrorKind, ffi_call_kind};

struct RuntimeState {
    backend: Box<dyn cageforge::DynSandbox>,
    context: cageforge::PathResolutionContext,
    effective: cageforge::EffectiveSandbox,
    profile_command: Option<cageforge::CommandRequest>,
    preflight_required: bool,
    approved_program: Option<String>,
}

struct ChildState {
    child: Mutex<Box<dyn cageforge::SandboxChild<Error = cageforge::SandboxExecutionError> + Send>>,
    stdin: Mutex<Option<Box<dyn Write + Send>>>,
    stdout: Mutex<Option<Box<dyn Read + Send>>>,
    stderr: Mutex<Option<Box<dyn Read + Send>>>,
    completed_status: Mutex<Option<jint>>,
}

fn java_string(env: &mut Env<'_>, value: JString<'_>, name: &str) -> Result<String, BindingError> {
    value
        .try_to_string(env)
        .map_err(|error| format!("invalid {name}: {error}").into())
}

fn optional_profile(env: &mut Env<'_>, value: JString<'_>) -> Result<Option<String>, BindingError> {
    if value.is_null() {
        return Ok(None);
    }
    java_string(env, value, "profile name").map(Some)
}

fn optional_path(
    env: &mut Env<'_>,
    value: JString<'_>,
    name: &str,
) -> Result<Option<PathBuf>, BindingError> {
    if value.is_null() {
        return Ok(None);
    }
    path(java_string(env, value, name)?, name).map(Some)
}

fn path(value: String, name: &str) -> Result<PathBuf, BindingError> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{name} must be absolute: {path:?}").into());
    }
    Ok(path)
}

fn resolve_workspace_roots(
    current_directory: &Path,
    declarations: &[PathBuf],
) -> Result<Vec<PathBuf>, BindingError> {
    declarations
        .iter()
        .map(|declaration| {
            if cageforge::contains_parent_traversal(declaration) {
                return Err(
                    format!("workspace root contains parent traversal: {declaration:?}").into(),
                );
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

fn native_backend(
    native_directory: &Path,
    _network_gateway: cageforge::GatewayConfig,
) -> Result<Box<dyn cageforge::DynSandbox>, String> {
    #[cfg(target_os = "linux")]
    {
        let config = cageforge::NativeSandboxConfig::new()
            .with_system_then_bundled_bubblewrap()
            .with_resource_directory(native_directory.to_path_buf())
            .with_hardening_helper_path(native_directory.join("cageforge-linux-helper"))
            .with_network_gateway(_network_gateway)
            .with_default_timeout(Duration::from_secs(300))
            .map_err(|error| error.to_string())?;
        return cageforge::native_sandbox_with(config).map_err(|error| error.to_string());
    }
    #[cfg(target_os = "macos")]
    {
        let config = cageforge::NativeSandboxConfig::new()
            .with_helper_executable(native_directory.join("cageforge-macos-helper"))
            .map_err(|error| error.to_string())?
            .with_network_gateway(_network_gateway);
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
                .with_network_gateway(_network_gateway),
        )
        .map_err(|error| error.to_string());
    }
    #[allow(unreachable_code)]
    {
        let _ = native_directory;
        Err(format!(
            "no Cageforge native backend is available for {}",
            std::env::consts::OS
        ))
    }
}

fn runtime_from_toml(
    toml: String,
    profile_name: Option<String>,
    current_directory: String,
    native_directory: String,
    minimal_directory: Option<String>,
    grant_handle: jlong,
    request_handle: jlong,
) -> Result<jlong, BindingError> {
    let current_directory = path(current_directory, "current directory")?;
    let native_directory = path(native_directory, "native resource directory")?;
    let minimal_directory = minimal_directory
        .map(|value| path(value, "minimal directory"))
        .transpose()?;
    let config = config_from_toml(&toml)
        .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    let profile = resolve_profile(&config, profile_name.as_deref())
        .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    let (context, effective, environment, ceiling) =
        runtime_inputs_with_ceiling(&profile, &current_directory, minimal_directory.as_deref())
            .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    if profile.approval().mode() == cageforge::PermissionMode::Disabled {
        let backend = native_backend(&native_directory, profile.network_gateway().clone())
            .map_err(|error| BindingError::new(BindingErrorKind::Initialization, error))?;
        let state = RuntimeState {
            backend,
            context,
            effective,
            profile_command: profile.command().cloned(),
            preflight_required: false,
            approved_program: None,
        };
        return Ok(Box::into_raw(Box::new(state)) as jlong);
    }
    let identity = preflight_identity(request_handle, &toml)?;
    let plan = cageforge::PreflightPlan::from_policy_with_ceiling(
        profile.policy(),
        &context,
        effective,
        &environment,
        &ceiling,
        identity,
    )
    .map_err(|error| BindingError::new(BindingErrorKind::Permission, error.to_string()))?;
    let plan = if let Some(command) = profile.command() {
        plan.with_process_program(command.command().program().to_string_lossy().into_owned())
            .map_err(|error| BindingError::new(BindingErrorKind::Permission, error.to_string()))?
    } else {
        plan
    };
    let grant = grant_ref(grant_handle)?.clone();
    let effective = plan
        .authorize(grant)
        .map_err(|error| BindingError::new(BindingErrorKind::Permission, error.to_string()))?
        .effective()
        .clone();
    let approved_program = profile
        .command()
        .map(|command| command.command().program().to_string_lossy().into_owned());
    let backend = native_backend(&native_directory, profile.network_gateway().clone())
        .map_err(|error| BindingError::new(BindingErrorKind::Initialization, error))?;
    let state = RuntimeState {
        backend,
        context,
        effective,
        profile_command: profile.command().cloned(),
        preflight_required: true,
        approved_program,
    };
    Ok(Box::into_raw(Box::new(state)) as jlong)
}

fn preflight_identity(
    request_handle: jlong,
    toml: &str,
) -> Result<cageforge::PreflightIdentity, BindingError> {
    if request_handle != 0 {
        let request = request_ref(request_handle)?.clone();
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
        "cageforge-java",
        env!("CARGO_PKG_VERSION"),
        cageforge::sha256_digest(b"cageforge-java"),
        cageforge::sha256_digest(toml.as_bytes()),
        cageforge::PlatformId::current().map_err(|error| {
            BindingError::new(BindingErrorKind::Configuration, error.to_string())
        })?,
        std::env::consts::ARCH,
    ))
}

fn config_from_toml(toml: &str) -> Result<cageforge::Config, String> {
    cageforge::Config::from_toml(toml).map_err(|error| error.to_string())
}

fn permission_request_from_toml(
    toml: &str,
    profile_name: Option<&str>,
    current_directory: &Path,
    minimal_directory: Option<&Path>,
    identity: cageforge::PreflightIdentity,
) -> Result<cageforge::PermissionRequest, BindingError> {
    let config = config_from_toml(toml)
        .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    let profile = resolve_profile(&config, profile_name)
        .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    let (context, effective, environment, ceiling) =
        runtime_inputs_with_ceiling(&profile, current_directory, minimal_directory)
            .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error))?;
    let plan = cageforge::PreflightPlan::from_policy_with_ceiling(
        profile.policy(),
        &context,
        effective,
        &environment,
        &ceiling,
        identity,
    )
    .map_err(|error| BindingError::new(BindingErrorKind::Configuration, error.to_string()))?;
    let plan = if let Some(command) = profile.command() {
        plan.with_process_program(command.command().program().to_string_lossy().into_owned())
            .map_err(|error| {
                BindingError::new(BindingErrorKind::Configuration, error.to_string())
            })?
    } else {
        plan
    };
    Ok(plan.request().clone())
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

fn java_string_array<'local>(
    env: &mut Env<'local>,
    values: impl IntoIterator<Item = String>,
) -> Result<jobjectArray, BindingError> {
    let values: Vec<String> = values.into_iter().collect();
    let empty = env.new_string("")?;
    let array = JObjectArray::<JString>::new(env, values.len(), &empty)?;
    for (index, value) in values.into_iter().enumerate() {
        let value = env.new_string(value)?;
        array.set_element(env, index, &value)?;
    }
    Ok(array.into_raw())
}

fn store_binding_error(error: cageforge::StoreError) -> BindingError {
    let message = error.to_string();
    let kind = match &error {
        cageforge::StoreError::GrantNotFound => BindingErrorKind::GrantNotFound,
        cageforge::StoreError::ListingSnapshotExpired => BindingErrorKind::ListingSnapshotExpired,
        cageforge::StoreError::InvalidGrantId => BindingErrorKind::InvalidGrantId,
        cageforge::StoreError::InvalidCursor => BindingErrorKind::InvalidCursor,
        cageforge::StoreError::InvalidPageSize { .. } => BindingErrorKind::InvalidPageSize,
        cageforge::StoreError::StoreLocked { .. } => BindingErrorKind::StoreLocked,
        cageforge::StoreError::Read { .. } => BindingErrorKind::StoreRead,
        cageforge::StoreError::Write { .. } => BindingErrorKind::StoreWrite,
        cageforge::StoreError::Format { .. } => BindingErrorKind::StoreFormat,
        _ => BindingErrorKind::PermissionStore,
    };
    BindingError::new(kind, message)
}

/// Returns validated profile names from an in-memory TOML document.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeProfileNames<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    toml: JString<'caller>,
) -> jobjectArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Configuration, |env| {
        let config = config_from_toml(&java_string(env, toml, "TOML")?)?;
        java_string_array(env, config.profile_names().map(str::to_owned))
    })
}

/// Validates TOML parsing, profile resolution, and policy composition.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCheckToml<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    toml: JString<'caller>,
    profile: JString<'caller>,
    current_directory: JString<'caller>,
    minimal_directory: JString<'caller>,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Configuration, |env| {
        let config = config_from_toml(&java_string(env, toml, "TOML")?)?;
        let profile = resolve_profile(&config, optional_profile(env, profile)?.as_deref())?;
        let current_directory = path(
            java_string(env, current_directory, "current directory")?,
            "current directory",
        )?;
        let minimal_directory = optional_path(env, minimal_directory, "minimal directory")?;
        let _ = runtime_inputs(&profile, &current_directory, minimal_directory.as_deref())?;
        Ok(())
    });
}

/// Creates an opaque native preflight request handle for the JVM API.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequest<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    toml: JString<'caller>,
    profile: JString<'caller>,
    current_directory: JString<'caller>,
    minimal_directory: JString<'caller>,
    tool_id: JString<'caller>,
    tool_version: JString<'caller>,
    manifest_digest: JString<'caller>,
    config_digest: JString<'caller>,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Configuration, |env| {
        let toml = java_string(env, toml, "TOML")?;
        let profile = optional_profile(env, profile)?;
        let current_directory = path(
            java_string(env, current_directory, "current directory")?,
            "current directory",
        )?;
        let minimal_directory = optional_path(env, minimal_directory, "minimal directory")?;
        let tool_id = java_string(env, tool_id, "tool id")?;
        let tool_version = if tool_version.is_null() {
            env!("CARGO_PKG_VERSION").to_owned()
        } else {
            java_string(env, tool_version, "tool version")?
        };
        let manifest_digest = if manifest_digest.is_null() {
            cageforge::sha256_digest(b"cageforge-java")
        } else {
            java_string(env, manifest_digest, "manifest digest")?
        };
        let config_digest = if config_digest.is_null() {
            cageforge::sha256_digest(toml.as_bytes())
        } else {
            java_string(env, config_digest, "config digest")?
        };
        let identity = cageforge::PreflightIdentity::new(
            tool_id,
            tool_version,
            manifest_digest,
            config_digest,
            cageforge::PlatformId::current().map_err(|error| {
                BindingError::new(BindingErrorKind::Configuration, error.to_string())
            })?,
            std::env::consts::ARCH,
        );
        let request = permission_request_from_toml(
            &toml,
            profile.as_deref(),
            &current_directory,
            minimal_directory.as_deref(),
            identity,
        )?;
        Ok(Box::into_raw(Box::new(request)) as jlong)
    })
}

fn request_ref(handle: jlong) -> Result<&'static cageforge::PermissionRequest, BindingError> {
    if handle == 0 {
        return Err(BindingError::new(
            BindingErrorKind::Permission,
            "permission request handle is closed",
        ));
    }
    // SAFETY: the handle is created by nativePermissionRequest and reclaimed
    // exactly once by nativeClosePermissionRequest.
    Ok(unsafe { &*(handle as *const cageforge::PermissionRequest) })
}

/// Returns a read-only JSON representation of an opaque request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestJson<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Configuration, |env| {
        let request = request_ref(request)?;
        let json = serde_json::to_string(request)
            .map_err(|error| BindingError::from(error.to_string()))?;
        Ok(env.new_string(json)?.into_raw())
    })
}

macro_rules! permission_request_string_getter {
    ($name:ident, $getter:ident) => {
        /// Returns one string field from an opaque permission request.
        #[unsafe(no_mangle)]
        pub extern "system" fn $name<'caller>(
            mut unowned_env: EnvUnowned<'caller>,
            _class: JClass<'caller>,
            request: jlong,
        ) -> jstring {
            ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
                let value = request_ref(request)?.$getter();
                Ok(env.new_string(value)?.into_raw())
            })
        }
    };
}

permission_request_string_getter!(
    Java_ai_cageforge_NativeBridge_nativePermissionRequestToolId,
    tool_id
);
permission_request_string_getter!(
    Java_ai_cageforge_NativeBridge_nativePermissionRequestToolVersion,
    tool_version
);

/// Returns the target platform from an opaque permission request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestPlatform<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let value = request_ref(request)?.platform().as_str();
        Ok(env.new_string(value)?.into_raw())
    })
}

/// Returns the canonical digest of an opaque permission request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestDigest<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let digest = request_ref(request)?.digest();
        Ok(env.new_string(digest)?.into_raw())
    })
}

/// Returns the stable grant ID bound to an opaque JVM permission request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestGrantId<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        Ok(env
            .new_string(request_ref(request)?.grant_id().to_hex())?
            .into_raw())
    })
}

/// Returns filesystem capabilities from an opaque permission request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestFilesystem<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jobjectArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let values = request_ref(request)?
            .capabilities()
            .filesystem()
            .iter()
            .flat_map(|capability| {
                [
                    format!("{:?}", capability.operation()).to_lowercase(),
                    capability.path().to_owned(),
                ]
            });
        java_string_array(env, values)
    })
}

/// Returns network capabilities from an opaque permission request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionRequestNetwork<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
) -> jobjectArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let values = request_ref(request)?
            .capabilities()
            .network()
            .iter()
            .map(|capability| capability.endpoint().to_owned());
        java_string_array(env, values)
    })
}

/// Releases an opaque JVM permission request handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeClosePermissionRequest(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    request: jlong,
) {
    if request != 0 {
        // SAFETY: the handle is owned by PermissionRequest and is closed once.
        unsafe { drop(Box::from_raw(request as *mut cageforge::PermissionRequest)) };
    }
}

/// Issues an opaque session grant from a request presented by the JVM host.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeApprovePermissionRequest<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: jlong,
    scope: JString<'caller>,
    expires_at: jlong,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let request = request_ref(request)?.clone();
        let scope_value = java_string(env, scope, "permission scope")?;
        let scope = cageforge::PermissionScope::parse(&scope_value)
            .map_err(|error| BindingError::new(BindingErrorKind::Permission, error.to_string()))?;
        let expires_at = (expires_at >= 0).then_some(expires_at as u64);
        let grant = cageforge::GrantAuthority::new()
            .approve_with(&request, request.capabilities().clone(), scope, expires_at)
            .map_err(|error| BindingError::new(BindingErrorKind::Permission, error.to_string()))?;
        Ok(Box::into_raw(Box::new(grant)) as jlong)
    })
}

/// Returns the request digest bound to an opaque JVM permission grant.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionGrantRequestDigest<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    grant: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        Ok(env
            .new_string(grant_ref(grant)?.request_digest())?
            .into_raw())
    })
}

/// Returns the lifetime of an opaque JVM permission grant.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionGrantScope<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    grant: jlong,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let scope = format!("{:?}", grant_ref(grant)?.scope()).to_lowercase();
        Ok(env.new_string(scope)?.into_raw())
    })
}

/// Returns a grant's expiration timestamp, or `-1` when it has no expiry.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionGrantExpiresAt(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    grant: jlong,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |_env| {
        Ok(grant_ref(grant)?
            .expires_at()
            .map_or(-1, |value| value as jlong))
    })
}

/// Releases an opaque JVM permission grant handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeClosePermissionGrant(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    grant: jlong,
) {
    if grant != 0 {
        // SAFETY: the handle is owned by the JVM PermissionGrant object and is
        // closed at most once by that object.
        unsafe { drop(Box::from_raw(grant as *mut cageforge::PermissionGrant)) };
    }
}

/// Opens a host-owned permission store at an absolute path.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeOpenPermissionStore<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    path_value: JString<'caller>,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |env| {
        let value = java_string(env, path_value, "permission store path")?;
        let path = path(value, "permission store path")?;
        let store = cageforge::PermissionStore::open(path).map_err(store_binding_error)?;
        Ok(Box::into_raw(Box::new(store)) as jlong)
    })
}

/// Looks up a persisted grant for an exact request; zero means no match.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionStoreGet<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    store: jlong,
    request: jlong,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |_env| {
        let store = store_ref(store)?;
        let request = request_ref(request)?;
        let Some(grant) = store.get(request).map_err(store_binding_error)? else {
            return Ok(0);
        };
        Ok(Box::into_raw(Box::new(grant)) as jlong)
    })
}

/// Persists a grant after validating it against the exact request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionStorePut<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    store: jlong,
    grant: jlong,
    request: jlong,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Permission, |_env| {
        store_ref(store)?
            .put(grant_ref(grant)?, request_ref(request)?)
            .map_err(store_binding_error)?;
        Ok(())
    });
}

/// Returns one flattened, typed page of safe grant summaries.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionStoreListPage<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    store: jlong,
    page_size: jint,
    cursor: JString<'caller>,
) -> jobjectArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::PermissionStore, |env| {
        let cursor = if cursor.is_null() {
            None
        } else {
            Some(
                cageforge::GrantPageCursor::from_token(&java_string(
                    env,
                    cursor,
                    "permission listing cursor",
                )?)
                .map_err(store_binding_error)?,
            )
        };
        let page_size = if page_size < 0 { 0 } else { page_size as usize };
        let request =
            cageforge::GrantPageRequest::new(page_size, cursor).map_err(store_binding_error)?;
        let page = store_ref(store)?
            .list_page(request)
            .map_err(store_binding_error)?;
        let next = page
            .next_cursor()
            .map_or_else(String::new, cageforge::GrantPageCursor::to_token);
        let mut values = vec![next];
        for entry in page.entries() {
            values.extend([
                entry.id.to_hex(),
                entry.tool_id.clone(),
                entry.tool_version.clone(),
                entry.platform.as_str().to_owned(),
                entry.architecture.clone(),
                format!("{:?}", entry.scope).to_lowercase(),
                entry.issued_at.to_string(),
                entry
                    .expires_at
                    .map_or_else(|| "-1".to_owned(), |value| value.to_string()),
            ]);
        }
        java_string_array(env, values)
    })
}

/// Revokes one persistent grant for future launches.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionStoreRevoke<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    store: jlong,
    id: JString<'caller>,
) -> jstring {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::PermissionStore, |env| {
        let id = cageforge::GrantId::from_hex(&java_string(env, id, "grant id")?)
            .map_err(|_| BindingError::new(BindingErrorKind::InvalidGrantId, "invalid grant id"))?;
        let result = store_ref(store)?.revoke(id).map_err(store_binding_error)?;
        Ok(env
            .new_string(match result {
                cageforge::RevokeResult::Revoked => "revoked",
                cageforge::RevokeResult::NotFound => "not-found",
            })?
            .into_raw())
    })
}

/// Revokes all persistent grants while retaining the store file.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativePermissionStoreRevokeAll(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    store: jlong,
) {
    ffi_call_kind(
        &mut unowned_env,
        BindingErrorKind::PermissionStore,
        |_env| {
            store_ref(store)?
                .revoke_all()
                .map_err(store_binding_error)?;
            Ok(())
        },
    );
}

/// Releases an opaque JVM permission store handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeClosePermissionStore(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    store: jlong,
) {
    if store != 0 {
        // SAFETY: the handle is created by nativeOpenPermissionStore and is
        // closed at most once by PermissionStore.close().
        unsafe { drop(Box::from_raw(store as *mut cageforge::PermissionStore)) };
    }
}

fn command_from_array<'local>(
    env: &mut Env<'local>,
    argv: JObjectArray<'local, JString<'local>>,
) -> Result<Vec<String>, String> {
    let length = argv
        .len(env)
        .map_err(|error| format!("cannot read command arguments: {error}"))?;
    let mut values = Vec::with_capacity(length);
    for index in 0..length {
        let value = argv
            .get_element(env, index)
            .map_err(|error| format!("cannot read command argument {index}: {error}"))?;
        values.push(java_string(env, value, "command argument").map_err(String::from)?);
    }
    Ok(values)
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

fn runtime_ref(handle: jlong) -> Result<&'static RuntimeState, String> {
    if handle == 0 {
        return Err("runtime handle is closed".to_string());
    }
    // SAFETY: handles are created from Box::into_raw and reclaimed exactly
    // once by `native_close_runtime`; Java treats the value as opaque.
    Ok(unsafe { &*(handle as *const RuntimeState) })
}

fn child_ref(handle: jlong) -> Result<&'static ChildState, String> {
    if handle == 0 {
        return Err("process handle is closed".to_string());
    }
    // SAFETY: handles are created from Box::into_raw and reclaimed exactly
    // once by `native_close_process`; Java treats the value as opaque.
    Ok(unsafe { &*(handle as *const ChildState) })
}

fn grant_ref(handle: jlong) -> Result<&'static cageforge::PermissionGrant, BindingError> {
    if handle == 0 {
        return Err(BindingError::new(
            BindingErrorKind::Permission,
            "preflight approval grant is required",
        ));
    }
    // SAFETY: the handle is created by nativeApprovePermissionRequest and is
    // reclaimed exactly once by nativeClosePermissionGrant.
    Ok(unsafe { &*(handle as *const cageforge::PermissionGrant) })
}

fn store_ref(handle: jlong) -> Result<&'static cageforge::PermissionStore, BindingError> {
    if handle == 0 {
        return Err(BindingError::new(
            BindingErrorKind::Permission,
            "permission store handle is closed",
        ));
    }
    // SAFETY: the handle is created by nativeOpenPermissionStore and
    // reclaimed exactly once by nativeClosePermissionStore.
    Ok(unsafe { &*(handle as *const cageforge::PermissionStore) })
}

/// Creates a native runtime from an in-memory TOML document.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCreate<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    toml: JString<'caller>,
    profile: JString<'caller>,
    current_directory: JString<'caller>,
    native_directory: JString<'caller>,
    minimal_directory: JString<'caller>,
    grant: jlong,
    request: jlong,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Initialization, |env| {
        runtime_from_toml(
            java_string(env, toml, "TOML")?,
            optional_profile(env, profile)?,
            java_string(env, current_directory, "current directory")?,
            java_string(env, native_directory, "native resource directory")?,
            if minimal_directory.is_null() {
                None
            } else {
                Some(java_string(env, minimal_directory, "minimal directory")?)
            },
            grant,
            request,
        )
    })
}

/// Launches a process from a runtime handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeLaunch<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    runtime: jlong,
    argv: JObjectArray<'caller, JString<'caller>>,
) -> jlong {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Launch, |env| {
        let runtime = runtime_ref(runtime)?;
        let request = command_request(runtime, command_from_array(env, argv)?)?;
        if runtime.preflight_required {
            let program = request.command().program().to_string_lossy();
            if runtime.approved_program.as_deref() != Some(program.as_ref()) {
                return Err("preflight grant is bound to the profile command; prepare and authorize the requested argv first".to_owned().into());
            }
        }
        let backend_request = cageforge::BackendRequest::new(&request, &runtime.effective);
        let mut child = runtime
            .backend
            .launch(backend_request, &runtime.context)
            .map_err(|error| error.to_string())?;
        let stdin = child.take_stdin();
        let stdout = child.take_stdout();
        let stderr = child.take_stderr();
        Ok(Box::into_raw(Box::new(ChildState {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(stdout),
            stderr: Mutex::new(stderr),
            completed_status: Mutex::new(None),
        })) as jlong)
    })
}

/// Returns the native child identifier.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeId<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jint {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Process, |_env| {
        let child = child_ref(process)?;
        let child = child
            .child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        Ok(child.id() as jint)
    })
}

fn stream_is_piped(process: jlong, stream: StreamKind) -> Result<bool, String> {
    let child = child_ref(process)?;
    match stream {
        StreamKind::Stdin => Ok(child
            .stdin
            .lock()
            .map_err(|_| "process stream handle is poisoned".to_string())?
            .is_some()),
        StreamKind::Stdout => Ok(child
            .stdout
            .lock()
            .map_err(|_| "process stream handle is poisoned".to_string())?
            .is_some()),
        StreamKind::Stderr => Ok(child
            .stderr
            .lock()
            .map_err(|_| "process stream handle is poisoned".to_string())?
            .is_some()),
    }
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

/// Returns whether stdin is connected to a JVM-writable pipe.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeHasStdin<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jni::sys::jboolean {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |_env| {
        Ok(stream_is_piped(process, StreamKind::Stdin)?)
    })
}

/// Returns whether stdout is connected to a JVM-readable pipe.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeHasStdout<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jni::sys::jboolean {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |_env| {
        Ok(stream_is_piped(process, StreamKind::Stdout)?)
    })
}

/// Returns whether stderr is connected to a JVM-readable pipe.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeHasStderr<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jni::sys::jboolean {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |_env| {
        Ok(stream_is_piped(process, StreamKind::Stderr)?)
    })
}

fn status_code(status: Option<std::process::ExitStatus>) -> jint {
    match status {
        None => -1,
        Some(status) => status.code().map_or(-2, |code| code as jint),
    }
}

/// Checks process completion without waiting.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeTryWait<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jint {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Process, |_env| {
        let child = child_ref(process)?;
        let mut child_guard = child
            .child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        if let Some(status) = *child
            .completed_status
            .lock()
            .map_err(|_| "process status is poisoned".to_string())?
        {
            return Ok(status);
        }
        let status = child_guard
            .try_wait()
            .map(status_code)
            .map_err(|error| error.to_string())?;
        if status != -1 {
            *child
                .completed_status
                .lock()
                .map_err(|_| "process status is poisoned".to_string())? = Some(status);
        }
        Ok(status)
    })
}

/// Waits for process completion.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWait<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jint {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Process, |_env| {
        let child = child_ref(process)?;
        loop {
            let status = {
                let mut child_guard = child
                    .child
                    .lock()
                    .map_err(|_| "process handle is poisoned".to_string())?;
                if let Some(status) = *child
                    .completed_status
                    .lock()
                    .map_err(|_| "process status is poisoned".to_string())?
                {
                    return Ok(status);
                }
                let status = child_guard
                    .try_wait()
                    .map(status_code)
                    .map_err(|error| error.to_string())?;
                if status != -1 {
                    *child
                        .completed_status
                        .lock()
                        .map_err(|_| "process status is poisoned".to_string())? = Some(status);
                }
                status
            };
            if status != -1 {
                return Ok(status);
            }
            // Do not hold the child lifecycle mutex while waiting. This lets
            // a concurrent nativeKill acquire the same per-process handle.
            thread::sleep(Duration::from_millis(5));
        }
    })
}

/// Terminates the complete sandbox process boundary.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeKill<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Process, |_env| {
        let child = child_ref(process)?;
        let mut child_guard = child
            .child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        if child
            .completed_status
            .lock()
            .map_err(|_| "process status is poisoned".to_string())?
            .is_some()
        {
            return Ok(());
        }
        child_guard.kill().map_err(|error| error.to_string())?;
        *child
            .completed_status
            .lock()
            .map_err(|_| "process status is poisoned".to_string())? = Some(-2);
        Ok(())
    });
}

/*
 * The child lifecycle and each detached standard stream have independent
 * locks. A blocking read or write must not prevent nativeKill from acquiring
 * the lifecycle lock; terminating the boundary closes the peer pipe and
 * releases the blocked I/O operation.
 */
fn read_stream(child: &ChildState, stdout: bool, size: jint) -> Result<Vec<u8>, String> {
    if size <= 0 || size > 16 * 1024 * 1024 {
        return Err("read size must be between 1 and 16777216 bytes".to_string());
    }
    let stream_slot = if stdout { &child.stdout } else { &child.stderr };
    let mut stream = stream_slot
        .lock()
        .map_err(|_| "process stream handle is poisoned".to_string())?
        .take()
        .ok_or_else(|| "requested stream is not piped".to_string())?;
    let result = (|| {
        let mut bytes = vec![0; size as usize];
        let read = stream.read(&mut bytes).map_err(|error| error.to_string())?;
        bytes.truncate(read);
        Ok(bytes)
    })();
    stream_slot
        .lock()
        .map_err(|_| "process stream handle is poisoned".to_string())?
        .replace(stream);
    result
}

/*
 * Writes use the independently owned stdin pipe for the same reason as
 * reads: a full pipe may block, but it must not block lifecycle control.
 */
fn write_stdin(child: &ChildState, bytes: &[u8]) -> Result<jint, String> {
    let mut stdin = child
        .stdin
        .lock()
        .map_err(|_| "process stream handle is poisoned".to_string())?
        .take()
        .ok_or_else(|| "stdin is not piped".to_string())?;
    let result = stdin
        .write_all(bytes)
        .map(|()| bytes.len() as jint)
        .map_err(|error| error.to_string());
    child
        .stdin
        .lock()
        .map_err(|_| "process stream handle is poisoned".to_string())?
        .replace(stdin);
    result
}

fn close_stdin(child: &ChildState) -> Result<(), String> {
    *child
        .stdin
        .lock()
        .map_err(|_| "process stream handle is poisoned".to_string())? = None;
    Ok(())
}

/// Reads up to `size` bytes from stdout.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeReadStdout<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
    size: jint,
) -> jbyteArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |env| {
        let child = child_ref(process)?;
        read_stream(child, true, size)
            .map_err(BindingError::from)
            .and_then(|bytes| {
                env.byte_array_from_slice(&bytes)
                    .map(|array| array.into_raw())
                    .map_err(Into::into)
            })
    })
}

/// Reads up to `size` bytes from stderr.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeReadStderr<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
    size: jint,
) -> jbyteArray {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |env| {
        let child = child_ref(process)?;
        read_stream(child, false, size)
            .map_err(BindingError::from)
            .and_then(|bytes| {
                env.byte_array_from_slice(&bytes)
                    .map(|array| array.into_raw())
                    .map_err(Into::into)
            })
    })
}

/// Writes bytes to stdin.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWriteStdin<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
    data: JByteArray<'caller>,
) -> jint {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |env| {
        let bytes = env.convert_byte_array(data)?;
        let child = child_ref(process)?;
        write_stdin(child, &bytes).map_err(BindingError::from)
    })
}

/// Closes the JVM-owned stdin pipe so the child observes EOF.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCloseStdin<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Stream, |_env| {
        close_stdin(child_ref(process)?).map_err(BindingError::from)
    });
}

/// Closes a runtime handle and drops its backend.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCloseRuntime<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    runtime: jlong,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Internal, |_env| {
        if runtime == 0 {
            return Ok(());
        }
        // SAFETY: Java owns each handle exactly once; close is idempotent at
        // the facade, which zeroes its field before calling this function.
        unsafe { drop(Box::from_raw(runtime as *mut RuntimeState)) };
        Ok(())
    });
}

/// Closes a process handle and drops its native child.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCloseProcess<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::Process, |_env| {
        if process == 0 {
            return Ok(());
        }
        // SAFETY: Java owns each handle exactly once; close is idempotent at
        // the facade, which zeroes its field before calling this function.
        unsafe { drop(Box::from_raw(process as *mut ChildState)) };
        Ok(())
    });
}

#[cfg(target_os = "windows")]
fn windows_setup(native_directory: &Path) -> Result<cageforge::WindowsSetup, BindingError> {
    let setup = cageforge::WindowsSetupConfig::new()
        .with_setup_helper_path(native_directory.join("cageforge-windows-setup.exe"))
        .map_err(|error| BindingError::from(error.to_string()))?
        .with_command_runner_path(native_directory.join("cageforge-windows-command-runner.exe"))
        .map_err(|error| BindingError::from(error.to_string()))?;
    Ok(cageforge::WindowsSetup::new(setup))
}

/// Installs the Windows elevated boundary, invoking UAC when required.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWindowsInstall<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    native_directory: JString<'caller>,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::WindowsSetup, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)?
                .install()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError::from(
                "Windows setup is available only on Windows".to_string(),
            ))
        }
    });
}

/// Reads the owner-scoped Windows setup state without provisioning it.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWindowsStatus<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    native_directory: JString<'caller>,
) -> jint {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::WindowsSetup, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            let status = windows_setup(&directory)?
                .status()
                .map_err(|error| error.to_string())?;
            Ok(match status {
                cageforge::WindowsSetupStatus::Missing { .. } => 0,
                cageforge::WindowsSetupStatus::Stale { .. } => 1,
                cageforge::WindowsSetupStatus::Ready(_) => 2,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<jint, _>(BindingError::from(
                "Windows setup is available only on Windows".to_string(),
            ))
        }
    })
}

/// Verifies the complete owner-scoped Windows setup.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWindowsVerify<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    native_directory: JString<'caller>,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::WindowsSetup, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)?
                .verify()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError::from(
                "Windows setup is available only on Windows".to_string(),
            ))
        }
    });
}

/// Removes the Windows elevated boundary.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWindowsUninstall<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    native_directory: JString<'caller>,
) {
    ffi_call_kind(&mut unowned_env, BindingErrorKind::WindowsSetup, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)?
                .uninstall()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError::from(
                "Windows setup is available only on Windows".to_string(),
            ))
        }
    });
}
