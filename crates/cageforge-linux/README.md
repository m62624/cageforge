> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-linux

`cageforge-linux` is the Linux execution backend for Cageforge. It validates a
composed request against the capabilities of one configured backend instance,
lowers the complete effective policy into Bubblewrap mounts, namespaces,
seccomp rules, environment state, and process-lifecycle controls, and starts
the command inside that boundary.

The crate is intended for applications that need a native Linux sandbox behind
the portable Cageforge policy API. A future `cageforge-core` facade will select
this backend on Linux; applications may also use `LinuxBackend` directly.

## Workspace role

| Crate | Role in the relationship |
|---|---|
| `cageforge-config` | Optionally resolves TOML profiles into validated command, policy, environment, and gateway values. |
| `cageforge-command` | Supplies validated argv, cwd, stdio, timeout, and environment intent. |
| `cageforge-policy` | Supplies portable filesystem and network rules. |
| `cageforge-policy-compose` | Produces the `EffectiveSandbox` formed by the requested policy and its outer ceiling. |
| `cageforge-backend-api` | Binds preflight output to this backend instance and verifies every required capability. |
| `cageforge-network-proxy` | Enforces restricted HTTP, CONNECT, and SOCKS5 destinations through exact resolved addresses. |
| `cageforge-linux` | Converts the prepared values above into the Linux-native process boundary. |
| `cageforge-core` | Will provide the final target-selecting facade over native backends. |

The data flow is:

```text
command + requested policy + PolicyCeiling + runtime paths
                              │
                              ▼
                     EffectiveSandbox
                              │
                              ▼
               LinuxBackend::prepare
                              │
                              ▼
             backend-bound prepared request
                              │
                              ▼
                 LinuxBackend::spawn
```

## Linux requirements

The backend prefers a compatible system Bubblewrap executable and falls back to
the validated `cageforge-resources/bwrap` resource produced by
`cageforge-bwrap`. Construction validates both executables, checks the bundled
SHA-256 manifest when applicable, and probes the Bubblewrap options required by
the backend. `LinuxBackendConfig` also supports explicit executable and
resource-directory paths for applications with a custom package layout.

A release package can use this layout:

```text
application/
├── bin/application
└── cageforge-resources/
    ├── bwrap
    ├── bwrap.sha256
    └── cageforge-linux-helper
```

Build and stage the bundled Bubblewrap with:

```text
cargo run -p cageforge-bwrap -- --output cageforge-resources/bwrap
```

The source build needs a Linux C compiler, `pkg-config`, and `libcap`
development files. The system executable remains the first choice so Linux
distributions can provide their maintained package; the bundled executable is
the reproducible fallback for application distributions.

The host kernel must permit the user, mount, PID, and—when requested—network
namespaces used by Bubblewrap. A missing prerequisite is reported as a typed
`LinuxBackendError`; restricted requests are never widened into an ordinary
host process.

## Basic use

Build and compose the portable values first, provide the runtime paths used by
symbolic selectors, then prepare and spawn through the same backend instance:

```rust,no_run
use std::path::PathBuf;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_linux::{LinuxBackend, LinuxBackendConfig};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = std::env::current_dir()?;
    let environment = EnvironmentSpec::inherit_core();
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), environment.clone())
        .with_workspace_roots([workspace.clone()])?;
    let effective = compose(
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_workspace_roots([workspace.clone()])?,
    )?;

    let command = CommandRequest::new(CommandSpec::new("/usr/bin/true")?)
        .with_working_directory(workspace.clone())?
        .with_environment(environment);
    let context = PathResolutionContext::new()
        .with_root(PathBuf::from("/"))?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(PathBuf::from("/bin"))?
        .with_minimal_path(PathBuf::from("/usr"))?
        .with_tmpdir(std::env::temp_dir())?
        .with_slash_tmp(PathBuf::from("/tmp"))?
        .with_current_directory(workspace)?;

    let backend = LinuxBackend::new(LinuxBackendConfig::new())?;
    let prepared = backend.prepare(BackendRequest::new(&command, &effective), &context)?;
    let status = backend.spawn(prepared)?.wait()?;
    assert!(status.success());
    Ok(())
}
```

Preparation is bound to the exact `LinuxBackend` identity. A prepared request
cannot be launched by another instance, cannot substitute a broader path
context, and cannot bypass capability checks by returning to the original
command or requested policy.

## Filesystem behavior

Restricted policies become a deterministic Bubblewrap mount plan. The backend
supports absolute, workspace, system-root, minimal-runtime, temporary, and
`/tmp` scopes; read/write/deny precedence; read-only carve-outs; bounded deny
globs; missing-path behavior; and protected metadata paths. Existing mount
sources are pinned for the Bubblewrap handoff, and native lowering accounts for
symlinks before launch.

Writable scopes protect `.git` by default. Trusted applications may explicitly
request `.git` writes through
`FilesystemPolicy::dangerously_allow_git_write()` or the matching
`cageforge-config` TOML setting:

```toml
[profiles.runtime.filesystem.security]
dangerously_allow_git_write = true
additional_protected_paths = [".metadata"]
```

The opt-out affects only the built-in `.git` entry. Additional protected paths
remain protected, and a stricter `PolicyCeiling` may retain `.git` protection
or cause preparation to reject the requested weakening.

## Network behavior

Disabled networking receives an isolated network namespace. Restricted domain
policies use the same isolation plus a private authenticated gateway for HTTP,
HTTP `CONNECT`, and SOCKS5 `CONNECT`. The gateway resolves once, evaluates all
returned addresses against both effective policy layers, and connects only to
the consumed `AuthorizedSocketAddr`. Direct connections from the child cannot
bypass that route.

Gateway sockets, authentication tokens, connection budgets, timeout state,
and cleanup handles are owned per backend launch. Separate instances therefore
apply separate network policies and lifecycle limits. Filesystem data is shared
only when callers deliberately give multiple instances the same writable host
path; coordination for the same protected missing path is UID-scoped so one
instance cannot remove another instance's active protection.

## Process lifecycle

`LinuxChild` exposes the child identifier, configured pipe handles, `try_wait`,
`wait`, and `kill`. Backend-default and explicit timeout policies are enforced
by a pidfd-based watchdog when the kernel supports it. Timeout, policy-monitor
failure, gateway failure, explicit termination, and `Drop` terminate and reap
the Bubblewrap PID namespace boundary and clean up per-run resources.

Use `LinuxBackendError` for typed construction, preflight, lowering, setup,
gateway, process, timeout, and cleanup failures. Capability errors identify the
exact portable requirement that the configured backend cannot enforce.
