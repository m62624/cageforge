> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate is an independent facade over Cageforge's public sandbox API.

# cageforge

`cageforge` is the unified Rust facade for running potentially untrusted
commands, agents, plugins, build scripts, and mods inside an OS-enforced
sandbox. It re-exports Cageforge's portable command, policy, composition, and
backend-contract APIs, then exposes the same `Sandbox`, `DynSandbox`, and `SandboxChild`
operations for the native Linux, Windows, and macOS backends.

The sandbox isolates processes using the host operating system's native
enforcement mechanisms. Its guarantees depend on a correct host OS, correct
native enforcement, and a correct Cageforge implementation.

Use this crate as a library when sandboxed execution is part of your Rust
application. If you need a ready-to-use terminal wrapper for launching an
explicit program, install `cageforge-cli`; it uses this facade and the same
native backend instead of implementing a separate sandbox.

## Add the crate

Supported operating systems are:

- Linux — enable the `linux` feature;
- Windows — enable the `windows` feature; and
- macOS — enable the `macos` feature.

Choose the feature that matches the target operating system:

```toml
[dependencies]
cageforge = { version = "0.1.0", features = ["linux", "config"] }
```

The portable model is available without an OS feature. Add `config` when the
application wants to load TOML profiles. The standalone network gateway is
available through the optional `network-runtime` feature.

On Linux, `linux-bundled-bubblewrap` is an optional alternative when you do
not want to build or provide Bubblewrap separately. It includes Cageforge's
verified, fixed Bubblewrap `v0.11.2` resource; the embedded version is not
selected dynamically.

The feature surface is explicit:

| Feature | Adds | Use it when |
| --- | --- | --- |
| `linux` | Linux backend API | The program runs on Linux |
| `linux-bundled-bubblewrap` | Embedded verified Bubblewrap resource | The Linux binary should carry its fallback resource |
| `windows` | Windows backend API | The program runs on Windows |
| `macos` | macOS backend API | The program runs on macOS |
| `config` | TOML profile API | Configuration is supplied as named profiles |
| `network-runtime` | Gateway and resolver runtime | The application uses the standalone gateway API |

The default feature set is empty. The portable API is available without an OS
feature, while a native backend feature must match the compilation target.

## Shared execution API (next release)

`native_sandbox()` creates the backend for the current operating system and
enabled Cargo feature. It returns `Box<dyn DynSandbox>`, so the rest of an
application can launch commands without naming a Linux, Windows, or macOS
backend type. The dynamic API in this checkout is intended for the next
release; the published `0.1.0` uses the concrete preparation API shown below.

```rust,no_run
use std::process::ExitStatus;
use cageforge::{
    native_sandbox, BackendRequest, CommandRequest, EffectiveSandbox,
    PathResolutionContext,
};

fn run(
    command: &CommandRequest,
    effective_policy: &EffectiveSandbox,
    context: &PathResolutionContext,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let sandbox = native_sandbox()?;
    let mut child = sandbox.launch(
        BackendRequest::new(command, effective_policy),
        context,
    )?;
    Ok(child.wait()?)
}
```

Create `command`, `effective_policy`, and `context` with the existing portable
builders or a resolved TOML profile. `launch` checks the selected backend's
capabilities, prepares the complete effective policy, and starts one command
tree. Unsupported requests return an error before launch. The child exposes
standard streams, `try_wait`, `wait`, and `kill`; dropping it uses the native
backend's termination and recovery lifecycle.

Create the backend once when running several commands. To share it across
threads, convert the box into `Arc<dyn DynSandbox>`:

```rust,no_run
use std::sync::Arc;
use cageforge::{native_sandbox, DynSandbox, NativeSandboxError};

fn shared_backend() -> Result<Arc<dyn DynSandbox>, NativeSandboxError> {
    Ok(native_sandbox()?.into())
}
```

Each thread supplies its own command and effective policy to `launch`; each
returned child owns an independent sandbox instance. Backend sharing does not
serialize the commands for their whole lifetime.

Use `native_sandbox_with(NativeSandboxConfig::new()...)` for custom native
settings. `NativeSandboxConfig` exposes the matching backend's existing
configuration builders, including Linux helper selection and Windows setup
location. On Windows, explicitly install setup through `WindowsSetup` first;
backend construction verifies that installation without requesting UAC.
Missing features or native prerequisites produce `NativeSandboxError`.
`SandboxExecutionError` identifies the failed execution operation and retains
the concrete native error in its source chain.

## Explicit preparation

The facade keeps the preparation and launch steps explicit so the effective
policy is checked before the operating-system backend starts a process:

```rust,no_run
use std::path::PathBuf;

#[cfg(all(feature = "linux", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cageforge::{
        compose, BackendRequest, CommandRequest, CommandSpec, CompositionRequest, EnvironmentSpec,
        LinuxBackend, LinuxBackendConfig, PathResolutionContext, PolicyCeiling, Sandbox,
        SandboxPolicy,
    };

    let workspace = std::env::current_dir()?;
    let environment = EnvironmentSpec::inherit_core();
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), environment.clone())
        .with_workspace_roots([workspace.clone()])?;
    let effective = compose(
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_workspace_roots([workspace.clone()])?,
    )?;

    let command_spec = CommandSpec::new("cargo")?.with_args(["build", "--release"])?;
    let command = CommandRequest::new(command_spec)
    .with_working_directory(workspace.clone())?
    .with_environment(environment);
    let context = PathResolutionContext::new()
        .with_root(PathBuf::from("/"))?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(PathBuf::from("/usr"))?
        .with_tmpdir(std::env::temp_dir())?
        .with_current_directory(workspace)?;

    let backend = LinuxBackend::new(LinuxBackendConfig::new())?;
    let prepared = Sandbox::prepare(&backend, BackendRequest::new(&command, &effective), &context)?;
    let mut child = Sandbox::spawn(&backend, prepared)?;
    let status = child.wait()?;
    assert!(status.success());
    Ok(())
}

#[cfg(not(all(feature = "linux", target_os = "linux")))]
fn main() {}
```

The example uses Linux names because the backend configuration is native. The
portable flow is the same on all platforms: create the matching backend,
compose the policy, call `prepare`, then call `spawn`. Windows setup is
documented in the [Windows backend README](../cageforge-windows/README.md);
the [Linux backend README](../cageforge-linux/README.md) and
[macOS backend README](../cageforge-macos/README.md) describe their native
requirements and configuration.

## How a sandbox instance works

Each call to `spawn` starts one root command inside a new sandbox instance. The
instance applies the effective filesystem, environment, network, timeout, and
process-tree policy to that command and to every descendant it creates:

```text
your application
└── root command
    ├── child process
    ├── helper or worker
    └── another descendant
```

The operating system carries the native restrictions through the process tree.
The descendants can use their normal command-line options and APIs, but they
cannot use them to grant themselves permissions outside the effective policy.
When the root command exits, the child handle reports its typed status and the
facade closes the instance's native resources. A timeout or explicit
termination applies to the complete descendant tree.

To run several independent operations, call `spawn` separately for each
top-level command. Every call gets its own process boundary, timeout, and
native enforcement state. If one root command deliberately starts a shell and
runs several commands inside that shell, those commands share the same
instance and policy.

For example, an application can start Cargo through the facade in the same way
it starts any other program:

```text
application
└── cargo build --release       <- one sandbox instance
    ├── rustc
    ├── build script
    └── linker
```

Cargo and its children retain their normal behavior while inheriting the
permissions selected for that instance. A CLI can expose the same flow as
`my-tool cargo test`: it builds a `CommandRequest`, prepares it with the
selected policy, and starts it through `spawn`.

## Re-exported API

The root module re-exports the portable public APIs from
[`cageforge-command`](https://docs.rs/cageforge-command/latest/cageforge_command/),
[`cageforge-policy`](https://docs.rs/cageforge-policy/latest/cageforge_policy/),
[`cageforge-policy-compose`](https://docs.rs/cageforge-policy-compose/latest/cageforge_policy_compose/),
[`cageforge-path`](https://docs.rs/cageforge-path/latest/cageforge_path/), and
[`cageforge-backend-api`](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/).
The public configuration types from
[`cageforge-network-proxy`](https://docs.rs/cageforge-network-proxy/latest/cageforge_network_proxy/)
are always re-exported; enable `network-runtime` to expose its standalone
gateway and resolver runtime as well. Native backends use that runtime
internally when their effective policy requires routed networking.
The `config` feature additionally re-exports
[`cageforge-config`](https://docs.rs/cageforge-config/latest/cageforge_config/).
The matching OS feature re-exports that backend's configuration, child, and
typed error types.

`Sandbox` is the common high-level trait for `prepare` and `spawn`.
`SandboxChild` covers the common child lifecycle: standard streams, polling,
waiting, and termination. Native child types and errors remain available when
platform-specific behavior or diagnostics are needed.

The public facade is synchronous. Internal network gateways may use helper
threads or asynchronous tasks; an application using the facade does not need
to select an async runtime. In an async application, run blocking process
operations in its blocking-task facility.

For complete platform-specific behavior and native setup, see the
documentation for [`cageforge-linux`](https://docs.rs/cageforge-linux/latest/cageforge_linux/),
[`cageforge-windows`](https://docs.rs/cageforge-windows/latest/cageforge_windows/),
and [`cageforge-macos`](https://docs.rs/cageforge-macos/latest/cageforge_macos/).
The same guides are available directly in the repository: [Linux README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-linux/README.md),
[Windows README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-windows/README.md),
and [macOS README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-macos/README.md).
