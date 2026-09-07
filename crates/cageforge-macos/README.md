> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

The sandbox isolates processes using the host operating system's native
enforcement mechanisms. Its guarantees depend on a correct host OS, correct
native enforcement, and a correct Cageforge implementation.

# cageforge-macos

`cageforge-macos` is the macOS-native backend for Cageforge's library API. It
provides an OS-enforced Seatbelt sandbox for applications that need to run
potentially untrusted commands, agents, plugins, build scripts, and mods. A
caller gives it a validated command, a composed effective policy, and the
runtime paths needed to resolve that policy; the backend returns a
backend-bound prepared request or a typed error before the command starts.

## Sandbox model

Each `spawn` creates one sandbox boundary around one command and its complete
descendant process tree. The boundary:

- limits access to files and the working directory;
- limits network access and routing;
- isolates child processes;
- applies timeouts and terminates the complete process tree;
- passes only explicitly authorized file descriptors or handles; and
- supports multiple independent instances at the same time.

`MacosBackend` and the policy can be reused for several commands, while every
spawn receives its own Seatbelt profile, process group, timeout, gateway, and
cleanup lifecycle. Several backend instances and children may run
concurrently with different policies.

## Workspace role

| Crate | Role in the relationship |
|---|---|
| `cageforge-config` | Optionally resolves TOML profiles into validated command, policy, environment, and gateway values. |
| `cageforge-command` | Supplies validated argv, cwd, stdio, timeout, and environment intent. |
| `cageforge-policy` | Supplies portable filesystem and network rules. |
| `cageforge-policy-compose` | Produces the `EffectiveSandbox` formed by the requested policy and its outer ceiling. |
| `cageforge-backend-api` | Binds preflight output to this backend instance and verifies every required capability. |
| `cageforge-network-proxy` | Enforces restricted HTTP, CONNECT, and SOCKS5 destinations through exact resolved addresses. |
| `cageforge-macos` | Converts the prepared values above into the macOS-native Seatbelt process boundary. |
| `cageforge-core` | Will provide the final target-selecting facade over native backends. |

The integration sequence is:

```text
command + requested policy + PolicyCeiling + runtime paths
                              │
                              ▼
                     EffectiveSandbox
                              │
                              ▼
              MacosBackend::prepare
                              │
                              ▼
             backend-bound prepared request
                              │
                              ▼
                MacosBackend::spawn
```

## macOS requirements

The backend enters the native Seatbelt boundary through the absolute trusted
executable `/usr/bin/sandbox-exec`. `MacosBackend::new` checks that the
configured executable exists, is a regular file, and is not a symbolic link.
An application with a different trusted package layout may select another
absolute executable with `MacosBackendConfig`.

The macOS host must provide Seatbelt and the native process-group and file
descriptor operations used by the backend. Cross-target compilation checks the
Rust API surface; native enforcement is exercised on a macOS runner. A
missing executable or native operation is returned as a typed
`MacosBackendError`; the backend does not silently fall back to an ordinary
unsandboxed process.

`MacosBackendConfig::with_default_timeout` controls the timeout used when a
command selects `TimeoutPolicy::BackendDefault`. Gateway bounds can be changed
with `with_network_gateway`. These settings apply to each spawned instance;
the backend itself is reusable.

## Basic use

Compose the portable values first, provide the runtime paths used by symbolic
selectors, then prepare and spawn through the same backend instance:

```rust,no_run
use std::path::PathBuf;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_macos::{MacosBackend, MacosBackendConfig};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{compose, CompositionRequest, PolicyCeiling};

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

    let command = CommandRequest::new(CommandSpec::new("/bin/echo")?.with_arg("ready")?)
        .with_working_directory(workspace.clone())?
        .with_environment(environment);
    let context = PathResolutionContext::new()
        .with_root(PathBuf::from("/"))?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(PathBuf::from("/usr"))?
        .with_tmpdir(std::env::temp_dir())?
        .with_slash_tmp(PathBuf::from("/tmp"))?
        .with_current_directory(workspace)?;

    let backend = MacosBackend::new(MacosBackendConfig::new())?;
    let prepared = backend.prepare(BackendRequest::new(&command, &effective), &context)?;
    let status = backend.spawn(prepared)?.wait()?;
    assert!(status.success());
    Ok(())
}
```

Preparation is bound to the exact `MacosBackend` identity. A prepared request
cannot be launched by another instance, substitute a broader path context, or
bypass capability checks by returning to the original command or policy.

## One policy, several commands

`SandboxPolicy` contains the rules. `MacosBackend` is the reusable native
execution engine. `CommandRequest` describes one command, and `spawn` creates
one macOS sandbox boundary for that command and every descendant it starts:

```text
SandboxPolicy + MacosBackend + CommandRequest
                              │
                              ▼
                           spawn()
                              │
                              ▼
                    one Seatbelt boundary
```

Compose the policy and create the backend once, then prepare and spawn each
command separately. Each call creates a separate boundary, even when it uses
the same policy and backend.

If `cargo` starts `rustc` and `build.rs`, those descendants remain inside that
command's boundary:

```text
one sandbox boundary
└── cargo
    └── rustc
        └── build.rs
```

For one shared boundary around several steps, an application may explicitly
launch a shell command; the shell and all its steps then form one process
tree. Cageforge is a library and does not provide a `cageforge run` command.

## Filesystem behavior

The effective filesystem policy is lowered into a closed-by-default Seatbelt
profile before launch. The backend supports absolute, workspace, root,
minimal-runtime, temporary, and `/tmp` scopes; read/write modes; read-only
carve-outs; protected paths; missing-path behavior; and bounded deny globs.
Native validation rejects unsafe symbolic-link and path-boundary relationships
before the profile is started.

The fixed profile grants only the read-only system paths needed by ordinary
macOS command-line runtimes. Caller filesystem scopes are added explicitly by
the effective policy; they do not inherit an accidental global read or write
grant. A scope that cannot be represented safely in the Seatbelt profile is
rejected with a typed `MacosFilesystemError`.

Writable workspace scopes protect `.git` by default. Applications may
explicitly opt out through `FilesystemPolicy::dangerously_allow_git_write()`
or the matching `cageforge-config` TOML setting; additional protected paths
remain protected and an outer `PolicyCeiling` can retain that protection.

## Protection matrix

The backend combines these protections according to the effective policy. A
capability is advertised only when its native lowering is available;
unsupported combinations are rejected before launch.

| Protection | When it is active | What it enforces |
|---|---|---|
| Seatbelt profile | Every sandboxed launch | Applies a closed-by-default macOS authorization profile to the complete descendant tree. |
| Process-group boundary | Every launch | Keeps the command and descendants in one group so timeout, kill, and recovery target the complete tree. |
| Parent-death watcher | Every launch | Terminates the process group if the owning parent disappears. |
| Explicit filesystem scopes | Restricted filesystem | Allows only the effective read/write scopes, read-only carve-outs, and required fixed runtime paths. |
| Protected paths and deny globs | Configured protected or denied paths | Rejects unsafe path lowering and blocks protected metadata and matching glob targets. |
| Symlink and path-boundary checks | Filesystem lowering | Prevents a writable symbolic link or alternate path relationship from escaping the requested scope. |
| Network isolation | Disabled or restricted networking | Blocks direct networking when disabled and routes restricted connections through the authenticated gateway. |
| Exact gateway authorization | Domain, local-address, or resolved-target restrictions | Resolves once, checks the effective policy, and verifies the exact destination immediately before connecting. |
| Local IPC policy | Local IPC restrictions | Isolates local IPC and supports exact pathname Unix-socket rules; unsupported deny combinations fail typed and closed. |
| Environment isolation | Every launch | Applies the selected inherited base, filters, and overrides only to the sandboxed command. |
| Explicit standard streams | Every launch | Uses only the requested inherit, null, or pipe endpoints and closes unrelated descriptors before execution. |
| Timeout | Backend-default or explicit limit | Terminates and confirms the complete process group within the prepared deadline. |
| Recovery owner | Failed termination or cleanup | Retains the boundary and enforcement resources, retries bounded termination and gateway cleanup, and releases them only after confirmation. |
| Typed errors | Setup, prepare, spawn, wait, and cleanup | Identifies the failing native stage without requiring callers to parse display text. |

External filesystem or network ownership is not treated as local macOS
enforcement. The backend returns a typed unsupported result unless a trusted
integration supplies the required boundary.

## Network behavior

Disabled networking is enforced by the native profile. Restricted domain,
local-address, and resolved-target policies use a private authenticated
per-instance gateway; the profile allows only that instance's ingress path.
The gateway applies the complete effective network policy and connects only to
the exact checked `SocketAddr`. Direct connections from the child cannot
bypass the route.

Gateway sockets, authentication state, connection limits, timeout state, and
cleanup handles are owned by each launch. Separate instances therefore use
independent network policies and lifecycle limits.

Gateway shutdown has a bounded cleanup wait. If the gateway thread does not
confirm exit within that interval, a recovery owner retains the thread and its
launch-owned runtime until it exits; cleanup does not release the boundary as
if shutdown had already been confirmed.

## Process lifecycle and errors

`MacosChild` exposes the child identifier, configured standard-stream pipes,
`try_wait`, `wait`, and `kill`. `kill` terminates and confirms the complete
process group before successful cleanup. Normal completion, timeout, explicit
termination, and parent loss all retain the boundary until its termination is
confirmed.

Use `MacosBackendError` and its nested typed error enums for construction,
preflight, lowering, gateway, process, timeout, and cleanup failures. The
parent does not parse command output or diagnostics as a protocol. Display
text is for humans; applications match error variants and their sources.

The exact native enforcement correspondence and intentional differences from
the upstream design are recorded in
[`specs/0017-macos-backend-implementation.md`](../../specs/0017-macos-backend-implementation.md).
