> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate is an independent facade over Cageforge's public sandbox API.

# cageforge

`cageforge` is a cross-platform Rust sandbox for AI agents and other untrusted
code. It provides one execution API for Linux, macOS, and Windows, with
portable types for commands, policies, environment handling, and backend
capabilities. The crate also offers a host-selected dynamic interface when an
application should select its backend at runtime.

The sandbox isolates processes using the host operating system's native
enforcement mechanisms. Its guarantees depend on a correct host OS, correct
native enforcement, and a correct Cageforge implementation.

Use this crate as a library when sandboxed execution is part of your Rust
application. If you need a ready-to-use terminal wrapper for launching an
explicit program, install `cageforge-cli`; it uses this facade and the same
native backend instead of implementing a separate sandbox.

## Add the crate

```toml
[dependencies]
cageforge = { version = "x.y.z", features = ["config"] }
```

The facade selects `cageforge-linux`, `cageforge-windows`, or
`cageforge-macos` automatically from the compilation target. The portable
model and native backend are therefore available without an OS feature. Add
`config` when the application wants to load TOML profiles. The standalone network gateway is
available through the optional `network-runtime` feature.

For the complete TOML flow and separate runnable profiles for each operating
system, see the [`cageforge-config` configuration guide](../cageforge-config/examples/CONFIGURATION_GUIDE.md).

On Linux, `linux-bundled-bubblewrap` is an optional alternative when you do
not want to build or provide Bubblewrap separately. It includes Cageforge's
verified, fixed Bubblewrap `v0.12.0` resource; the embedded version is not
selected dynamically.

The feature surface is small and intentional:

| Feature | Adds | Use it when |
| --- | --- | --- |
| `linux-bundled-bubblewrap` | Embedded verified Bubblewrap resource | The Linux binary should carry its fallback resource |
| `config` | TOML profile API | Configuration is supplied as named profiles |
| `network-runtime` | Gateway and resolver runtime | The application uses the standalone gateway API |

The default feature set is empty. `linux-bundled-bubblewrap` changes only how
the Linux Bubblewrap resource is packaged; it is not a backend selector.

## Unified execution API

`native_sandbox()` selects the native backend for the current operating system
target operating system. It returns `Box<dyn DynSandbox>`, so an application
can launch commands through one API without naming a Linux, Windows, or macOS
backend type. The static `Sandbox` API is available when the application needs
direct access to a concrete backend and its native configuration.

```rust,no_run
use std::{path::PathBuf, process::ExitStatus, time::Duration};

use cageforge::{
    compose, native_sandbox, BackendRequest, CommandRequest, CommandSpec,
    CompositionRequest, EnvironmentSpec, PathResolutionContext, PolicyCeiling,
    SandboxPolicy,
};

fn run_build() -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let workspace = std::env::current_dir()?;

    // Keep the command environment explicit: inherit the runtime's core
    // variables and add only the setting this build needs.
    let environment = EnvironmentSpec::inherit_core()
        .with_var("CARGO_TERM_COLOR", "always")?;

    // The requested policy allows edits in the workspace, temporary files,
    // and read-only access to the rest of the runtime filesystem. Network
    // access remains disabled by this preset.
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), environment.clone())
        .with_workspace_roots([workspace.clone()])?;
    let effective = compose(
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_workspace_roots([workspace.clone()])?,
    )?;

    let command = CommandRequest::new(
        CommandSpec::new("cargo")?.with_args(["build", "--release"] )?,
    )
    .with_working_directory(workspace.clone())?
    .with_environment(environment)
    .with_timeout(Duration::from_secs(15 * 60));

    // Special policy selectors are resolved from runtime paths supplied by
    // the caller. These values keep the example portable across OS families.
    let (system_root, minimal_path) = if cfg!(target_os = "windows") {
        let system_root = PathBuf::from(std::env::var_os("SystemRoot").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "SystemRoot is not set")
        })?);
        (system_root.clone(), system_root.join("System32"))
    } else {
        (PathBuf::from("/"), PathBuf::from("/usr"))
    };
    let mut context = PathResolutionContext::new()
        .with_root(system_root)?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(minimal_path)?
        .with_tmpdir(std::env::temp_dir())?
        .with_current_directory(workspace)?;
    if !cfg!(target_os = "windows") {
        context = context.with_slash_tmp(PathBuf::from("/tmp"))?;
    }

    // The host-selected backend enforces the same request on Linux, macOS,
    // and Windows; no platform backend type is needed here.
    let mut child = native_sandbox()?.launch(BackendRequest::new(&command, &effective), &context)?;
    Ok(child.wait()?)
}
```

`run_build` creates the command, environment, policy, and runtime context with
portable builders, then lets `native_sandbox()` select the host backend. The
backend checks capabilities, prepares the complete effective policy, and
starts one command tree. Unsupported requests return an error before launch.
The child exposes standard streams, `try_wait`, `wait`, and `kill`; dropping it
uses the native backend's termination and recovery lifecycle.

The static flow is also available when an application needs concrete backend
configuration: create the matching backend, compose the policy, call
`prepare`, then call `spawn`. Windows setup is documented in the
[Windows backend README](../cageforge-windows/README.md); the [Linux backend
README](../cageforge-linux/README.md) and [macOS backend
README](../cageforge-macos/README.md) describe their native requirements and
configuration.

Create the backend once when running several commands. Each thread can supply
its own command and effective policy to `launch`; every returned child owns an
independent sandbox instance and native state.

Use `native_sandbox_with(NativeSandboxConfig::new())` for custom native
settings. `NativeSandboxConfig` exposes the matching backend's existing
configuration builders, including Linux/macOS helper selection and Windows setup
location. On Windows, explicitly install setup through `WindowsSetup` first;
backend construction verifies that installation without requesting UAC.
macOS uses a per-launch unprivileged helper beside the application, or at the
explicitly configured path; the CLI embeds it and requires no setup command.
Unsupported targets or native prerequisites produce `NativeSandboxError`.
`SandboxExecutionError` identifies the failed execution operation and retains
the concrete native error in its source chain.

## Rust preflight integration

The facade exposes the same typed permission flow used by the CLI, Python, and
Java adapters. A `PreflightPlan` describes the exact launch identity and
capabilities; only a trusted `GrantAuthority` can produce the opaque grant
that authorizes it. The grant is checked before native launch and is combined
with the existing policy ceiling:

```rust,no_run
use cageforge::{
    native_sandbox, sha256_digest, BackendRequest, CommandRequest, EffectiveSandbox,
    GrantAuthority, PathResolutionContext, PreflightPlan, SandboxPolicy,
};

fn launch_with_preflight(
    requested: &SandboxPolicy,
    context: &PathResolutionContext,
    effective: EffectiveSandbox,
    command: &CommandRequest,
    config_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = PreflightPlan::from_policy_current(
        requested,
        context,
        effective,
        "my-tool",
        env!("CARGO_PKG_VERSION"),
        sha256_digest(b"my-tool-manifest"),
        sha256_digest(config_bytes),
    )?;

    // This authority belongs to the trusted host or approval adapter.
    let grant = GrantAuthority::new().approve(plan.request());
    let authorized = plan.authorize(grant)?;
    let sandbox = native_sandbox()?;
    let mut child = sandbox.launch(
        BackendRequest::new(command, authorized.effective()),
        context,
    )?;
    let _status = child.wait()?;
    Ok(())
}
```

The request is descriptive and the grant is opaque. A mismatched, expired, or
insufficient grant returns a typed `PreflightError` before the backend can
start a process; there is no permission escalation inside a running process.

The three request types have different security roles:

- `CommandRequest` describes what to execute: the program, arguments,
  environment, working directory, and lifecycle settings.
- `BackendRequest` couples that command to a composed `EffectiveSandbox` for
  one native backend handoff.
- `PermissionRequest` is the host-facing preflight description of what the
  tool asks to receive before launch. It carries the tool identity and
  version, manifest and configuration digests, platform and architecture, and
  filesystem, network, and child-process capabilities.

`PermissionRequest` is descriptive and has no authority. A trusted host turns
it into an opaque `PermissionGrant`; the grant is checked against the request
and the policy ceiling before the `BackendRequest` reaches Linux, macOS, or
Windows enforcement. The permission request is generated from the resolved
TOML profile and runtime context, so identity and native path data cannot be
silently replaced by a hand-edited TOML grant.
Rust hosts that persist decisions can use `PermissionStore` with the same
request digest and audit metadata used by the language bindings.

The store path belongs to the trusted host. `PermissionStore::open` accepts
the chosen path; the CLI exposes the same choice as `--permission-store PATH`
and defaults to `permissions.json` beside the selected TOML file. That
default is a per-project convenience, not a mandatory system-wide database.
A trusted host may deliberately share one path across projects or choose
separate stores. The Python and Java bindings expose `PermissionStore` with
the same `open/get/put` sequence. A store is used only for explicitly
persistent grants and is protected by the native filesystem security rules of
the host OS. It is revocable host state: the owner may delete it to clear all
saved approvals. Hosts should keep it outside any workspace that the sandbox
can write.

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
The `config` feature also re-exports
[`cageforge-config`](https://docs.rs/cageforge-config/latest/cageforge_config/).
The target OS re-exports that backend's configuration, child, and typed error
types.

`Sandbox` is the common high-level trait for `prepare` and `spawn`.
`SandboxChild` covers the common child lifecycle: standard streams, polling,
waiting, and termination. Native child types and errors remain available when
platform-specific behavior or diagnostics are needed.

The public facade is synchronous. Internal network gateways may use helper
threads or asynchronous tasks. An async application only needs to run the
blocking process operations in its blocking-task facility.

For complete platform-specific behavior and native setup, see the
documentation for [`cageforge-linux`](https://docs.rs/cageforge-linux/latest/cageforge_linux/),
[`cageforge-windows`](https://docs.rs/cageforge-windows/latest/cageforge_windows/),
and [`cageforge-macos`](https://docs.rs/cageforge-macos/latest/cageforge_macos/).
The same guides are available directly in the repository: [Linux README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-linux/README.md),
[Windows README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-windows/README.md),
and [macOS README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-macos/README.md).
