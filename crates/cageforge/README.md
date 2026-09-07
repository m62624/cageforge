> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

# cageforge

`cageforge` is the unified Rust facade for running potentially untrusted
commands, agents, plugins, build scripts, and mods inside an OS-enforced
sandbox. It re-exports Cageforge's portable command, policy, composition, and
backend-contract APIs, then exposes the same `Sandbox` and `SandboxChild`
operations for the native Linux, Windows, and macOS backends.

The sandbox isolates processes using the host operating system's native
enforcement mechanisms. Its guarantees depend on a correct host OS, correct
native enforcement, and a correct Cageforge implementation.

## Add the crate

Select only the native backend for the target platform. Add `config` when the
application wants to load TOML profiles. The standalone network gateway is
available through the optional `network-runtime` feature:

```toml
[dependencies]
cageforge = { version = "0.1.0", features = ["linux", "config"] }
```

Use `windows` on Windows or `macos` on macOS instead of `linux`. The portable
model is available without an OS feature; native dependencies are optional.
On Linux, use `linux-bundled-bubblewrap` when the application deliberately
wants the backend's embedded, verified Bubblewrap resource instead of the
system or externally staged executable selection.

## Run a command

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

## What happens to Cargo's child processes

One `spawn` creates one sandbox boundary around the root command and its whole
descendant tree:

```text
cageforge
└── cargo build --release
    ├── rustc
    ├── build.rs
    └── linker
```

Cargo keeps its normal command-line options. Its `rustc`, build scripts,
linker, and other descendants inherit the same boundary and therefore the
same effective filesystem, environment, and network permissions. A second
top-level `spawn` creates a separate instance. If several commands are placed
inside one explicitly launched shell, they intentionally share that one
instance.

The facade does not intercept commands launched outside the application. A
CLI can wrap this API so that a user can run `my-tool cargo test`; the wrapper
then creates the backend and starts Cargo through `spawn`.

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
