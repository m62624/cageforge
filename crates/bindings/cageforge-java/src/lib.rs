// SPDX-License-Identifier: Apache-2.0

//! JNI implementation for the JVM Cageforge binding.
//!
//! This crate is deliberately private and is not a second Rust API. It owns
//! only the JVM handle translation and delegates policy parsing, composition,
//! native backend construction, and process lifecycle to `cageforge`.

#![deny(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(all(feature = "linux", target_os = "linux"))]
use std::time::Duration;

use jni::errors::ErrorPolicy;
use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::{Env, EnvUnowned};

struct RuntimeState {
    backend: Box<dyn cageforge::DynSandbox>,
    context: cageforge::PathResolutionContext,
    effective: cageforge::EffectiveSandbox,
    profile_command: Option<cageforge::CommandRequest>,
}

struct ChildState {
    child: Box<dyn cageforge::SandboxChild<Error = cageforge::SandboxExecutionError> + Send>,
}

#[derive(Debug)]
struct BindingError(String);

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BindingError {}

impl From<String> for BindingError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<BindingError> for String {
    fn from(error: BindingError) -> Self {
        error.0
    }
}

impl From<jni::errors::Error> for BindingError {
    fn from(error: jni::errors::Error) -> Self {
        Self(error.to_string())
    }
}

struct ThrowCageforgeException;

impl<T: Default> ErrorPolicy<T, BindingError> for ThrowCageforgeException {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        error: BindingError,
    ) -> jni::errors::Result<T> {
        if !env.exception_check() {
            let class = env.find_class(jni::jni_str!("ai/cageforge/CageforgeException"))?;
            let message = jni::strings::JNIString::new(error.to_string());
            let _ = env.throw_new(class, message);
        }
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        _payload: Box<dyn std::any::Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        if !env.exception_check() {
            let class = env.find_class(jni::jni_str!("ai/cageforge/CageforgeException"))?;
            let message = jni::strings::JNIString::new("Cageforge native binding panicked");
            let _ = env.throw_new(class, message);
        }
        Ok(T::default())
    }
}

fn ffi_call<'local, T: Default>(
    env: &mut EnvUnowned<'local>,
    operation: impl FnOnce(&mut Env<'local>) -> Result<T, BindingError>,
) -> T {
    env.with_env(operation).resolve::<ThrowCageforgeException>()
}

fn java_string(env: &mut Env<'_>, value: JString<'_>, name: &str) -> Result<String, BindingError> {
    value
        .try_to_string(env)
        .map_err(|error| BindingError(format!("invalid {name}: {error}")))
}

fn optional_profile(env: &mut Env<'_>, value: JString<'_>) -> Result<Option<String>, BindingError> {
    if value.is_null() {
        return Ok(None);
    }
    java_string(env, value, "profile name").map(Some)
}

fn path(value: String, name: &str) -> Result<PathBuf, BindingError> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(BindingError(format!("{name} must be absolute: {path:?}")));
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
                return Err(BindingError(format!(
                    "workspace root contains parent traversal: {declaration:?}"
                )));
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
) -> Result<cageforge::PathResolutionContext, String> {
    let mut context = cageforge::PathResolutionContext::new()
        .with_root(platform_root(current_directory))
        .map_err(|error| error.to_string())?
        .with_minimal_path(platform_minimal_root(current_directory))
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
    network_gateway: cageforge::GatewayConfig,
) -> Result<Box<dyn cageforge::DynSandbox>, String> {
    #[cfg(all(feature = "linux", target_os = "linux"))]
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
    #[cfg(all(feature = "macos", target_os = "macos"))]
    {
        let config = cageforge::NativeSandboxConfig::new()
            .with_helper_executable(native_directory.join("cageforge-macos-helper"))
            .map_err(|error| error.to_string())?
            .with_network_gateway(network_gateway);
        return cageforge::native_sandbox_with(config).map_err(|error| error.to_string());
    }
    #[cfg(all(feature = "windows", target_os = "windows"))]
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
        Err(format!(
            "no Cageforge native feature is enabled for {}",
            std::env::consts::OS
        ))
    }
}

fn runtime_from_toml(
    toml: String,
    profile_name: Option<String>,
    current_directory: String,
    native_directory: String,
) -> Result<jlong, String> {
    let current_directory = path(current_directory, "current directory")?;
    let native_directory = path(native_directory, "native resource directory")?;
    let config = cageforge::Config::from_toml(&toml).map_err(|error| error.to_string())?;
    let profile = match profile_name.as_deref() {
        Some(name) if !name.is_empty() => config.resolve(name),
        _ => config.resolve_default(),
    }
    .map_err(|error| error.to_string())?;
    let workspace_roots = resolve_workspace_roots(&current_directory, profile.workspace_roots())?;
    let context = runtime_context(&current_directory, &workspace_roots)?;
    let environment = profile
        .command()
        .map(|command| command.environment().clone())
        .unwrap_or_else(cageforge::EnvironmentSpec::default);
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
    let backend = native_backend(&native_directory, profile.network_gateway().clone())?;
    let state = RuntimeState {
        backend,
        context,
        effective,
        profile_command: profile.command().cloned(),
    };
    Ok(Box::into_raw(Box::new(Mutex::new(state))) as jlong)
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
    let program = parts.next().expect("argv checked as non-empty");
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

fn runtime_ref(handle: jlong) -> Result<&'static Mutex<RuntimeState>, String> {
    if handle == 0 {
        return Err("runtime handle is closed".to_string());
    }
    // SAFETY: handles are created from Box::into_raw and reclaimed exactly
    // once by `native_close_runtime`; Java treats the value as opaque.
    Ok(unsafe { &*(handle as *const Mutex<RuntimeState>) })
}

fn child_ref(handle: jlong) -> Result<&'static Mutex<ChildState>, String> {
    if handle == 0 {
        return Err("process handle is closed".to_string());
    }
    // SAFETY: handles are created from Box::into_raw and reclaimed exactly
    // once by `native_close_process`; Java treats the value as opaque.
    Ok(unsafe { &*(handle as *const Mutex<ChildState>) })
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
) -> jlong {
    ffi_call(&mut unowned_env, |env| {
        runtime_from_toml(
            java_string(env, toml, "TOML")?,
            optional_profile(env, profile)?,
            java_string(env, current_directory, "current directory")?,
            java_string(env, native_directory, "native resource directory")?,
        )
        .map_err(BindingError::from)
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
    ffi_call(&mut unowned_env, |env| {
        let runtime = runtime_ref(runtime)?;
        let state = runtime
            .lock()
            .map_err(|_| "runtime handle is poisoned".to_string())?;
        let request = command_request(&state, command_from_array(env, argv)?)?;
        let backend_request = cageforge::BackendRequest::new(&request, &state.effective);
        let child = state
            .backend
            .launch(backend_request, &state.context)
            .map_err(|error| error.to_string())?;
        Ok(Box::into_raw(Box::new(Mutex::new(ChildState { child }))) as jlong)
    })
}

/// Returns the native child identifier.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeId<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jint {
    ffi_call(&mut unowned_env, |_env| {
        let child = child_ref(process)?;
        let child = child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        Ok(child.child.id() as jint)
    })
}

fn stream_is_piped(process: jlong, stream: StreamKind) -> Result<bool, String> {
    let child = child_ref(process)?;
    let mut child = child
        .lock()
        .map_err(|_| "process handle is poisoned".to_string())?;
    Ok(match stream {
        StreamKind::Stdin => child.child.stdin().is_some(),
        StreamKind::Stdout => child.child.stdout().is_some(),
        StreamKind::Stderr => child.child.stderr().is_some(),
    })
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
    ffi_call(&mut unowned_env, |_env| {
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
    ffi_call(&mut unowned_env, |_env| {
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
    ffi_call(&mut unowned_env, |_env| {
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
    ffi_call(&mut unowned_env, |_env| {
        let child = child_ref(process)?;
        let mut child = child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        Ok(child
            .child
            .try_wait()
            .map(status_code)
            .map_err(|error| error.to_string())?)
    })
}

/// Waits for process completion.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWait<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) -> jint {
    ffi_call(&mut unowned_env, |_env| {
        let child = child_ref(process)?;
        let mut child = child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        Ok(child
            .child
            .wait()
            .map(|status| status_code(Some(status)))
            .map_err(|error| error.to_string())?)
    })
}

/// Terminates the complete sandbox process boundary.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeKill<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
) {
    ffi_call(&mut unowned_env, |_env| {
        let child = child_ref(process)?;
        let mut child = child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        Ok(child.child.kill().map_err(|error| error.to_string())?)
    });
}

fn read_stream(child: &Mutex<ChildState>, stdout: bool, size: jint) -> Result<Vec<u8>, String> {
    if size <= 0 || size > 16 * 1024 * 1024 {
        return Err("read size must be between 1 and 16777216 bytes".to_string());
    }
    let mut child = child
        .lock()
        .map_err(|_| "process handle is poisoned".to_string())?;
    let mut bytes = vec![0; size as usize];
    let read = if stdout {
        child
            .child
            .stdout()
            .ok_or_else(|| "stdout is not piped".to_string())?
            .read(&mut bytes)
    } else {
        child
            .child
            .stderr()
            .ok_or_else(|| "stderr is not piped".to_string())?
            .read(&mut bytes)
    }
    .map_err(|error| error.to_string())?;
    bytes.truncate(read);
    Ok(bytes)
}

/// Reads up to `size` bytes from stdout.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeReadStdout<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    process: jlong,
    size: jint,
) -> jbyteArray {
    ffi_call(&mut unowned_env, |env| {
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
    ffi_call(&mut unowned_env, |env| {
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
    ffi_call(&mut unowned_env, |env| {
        let bytes = env.convert_byte_array(data)?;
        let child = child_ref(process)?;
        let mut child = child
            .lock()
            .map_err(|_| "process handle is poisoned".to_string())?;
        let stdin = child
            .child
            .stdin()
            .ok_or_else(|| "stdin is not piped".to_string())?;
        stdin.write_all(&bytes).map_err(|error| error.to_string())?;
        Ok(bytes.len() as jint)
    })
}

/// Closes a runtime handle and drops its backend.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeCloseRuntime<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    runtime: jlong,
) {
    ffi_call(&mut unowned_env, |_env| {
        if runtime == 0 {
            return Ok(());
        }
        // SAFETY: Java owns each handle exactly once; close is idempotent at
        // the facade, which zeroes its field before calling this function.
        unsafe { drop(Box::from_raw(runtime as *mut Mutex<RuntimeState>)) };
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
    ffi_call(&mut unowned_env, |_env| {
        if process == 0 {
            return Ok(());
        }
        // SAFETY: Java owns each handle exactly once; close is idempotent at
        // the facade, which zeroes its field before calling this function.
        unsafe { drop(Box::from_raw(process as *mut Mutex<ChildState>)) };
        Ok(())
    });
}

#[cfg(target_os = "windows")]
fn windows_setup(native_directory: &Path) -> cageforge::WindowsSetup {
    let setup = cageforge::WindowsSetupConfig::new()
        .with_setup_helper_path(native_directory.join("cageforge-windows-setup.exe"))
        .expect("native resource directory is absolute")
        .with_command_runner_path(native_directory.join("cageforge-windows-command-runner.exe"))
        .expect("native resource directory is absolute");
    cageforge::WindowsSetup::new(setup)
}

/// Installs the Windows elevated boundary, invoking UAC when required.
#[unsafe(no_mangle)]
pub extern "system" fn Java_ai_cageforge_NativeBridge_nativeWindowsInstall<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    native_directory: JString<'caller>,
) {
    ffi_call(&mut unowned_env, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)
                .install()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError(
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
    ffi_call(&mut unowned_env, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            let status = windows_setup(&directory)
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
            Err::<jint, _>(BindingError(
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
    ffi_call(&mut unowned_env, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)
                .verify()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError(
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
    ffi_call(&mut unowned_env, |env| {
        #[cfg(not(target_os = "windows"))]
        let _ = env;
        #[cfg(target_os = "windows")]
        {
            let directory = path(
                java_string(env, native_directory, "native resource directory")?,
                "native resource directory",
            )?;
            windows_setup(&directory)
                .uninstall()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = native_directory;
            Err::<(), _>(BindingError(
                "Windows setup is available only on Windows".to_string(),
            ))
        }
    });
}
