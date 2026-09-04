> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-linux

`cageforge-linux` is the Linux-native backend for Cageforge's library API. It
provides an OS-enforced sandbox for applications that need to run potentially
untrusted commands, agents, plugins, build scripts, and mods. A caller gives it
a validated command, a composed effective policy, and the runtime paths needed
to resolve that policy; the backend returns a backend-bound prepared request or
a typed error before the command starts. The backend lowers the complete
effective policy into Bubblewrap mounts, namespaces, seccomp rules,
environment state, and process-lifecycle controls.

## Sandbox model

Each `spawn` creates one sandbox boundary around one command and its complete
descendant process tree. The boundary:

- limits access to files and the working directory;
- limits network access and routing;
- isolates child processes;
- applies timeouts and terminates the complete process tree;
- passes only explicitly authorized file descriptors or handles; and
- supports multiple independent instances at the same time.

`LinuxBackend` and the policy can be reused for several commands, while every
spawn receives its own process boundary, lifecycle, and native enforcement
state. A future `cageforge-core` facade will select this backend on Linux;
applications may also use `LinuxBackend` directly.

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

Applications that want Cageforge to build and provide the fallback
automatically can enable the Linux-only `bundled-bubblewrap` feature:

```toml
cageforge-linux = { version = "0.1", features = ["bundled-bubblewrap"] }
```

With that feature, the pinned Bubblewrap executable is embedded at build time
and materialized into a private temporary resource directory when the backend
needs a bundled fallback. Without the feature, Cageforge uses a compatible
system executable or an explicitly packaged `cageforge-resources/bwrap`; it
does not download or compile Bubblewrap implicitly. An explicit resource
directory remains authoritative in both modes.

The embedded executable remains the unchanged upstream Bubblewrap component
under LGPL-2.0-or-later; enabling this feature does not relicense it as
Apache-2.0. A distribution that ships the embedded mode must preserve the
Bubblewrap license notice and corresponding machine-readable source. The
`cageforge-bwrap` crate contains both in its published package.

The host kernel must permit the user, mount, PID, IPC, and—when requested—network
namespaces used by Bubblewrap. It must also support anonymous executable files
and file sealing so Cageforge can capture Bubblewrap and the hardening helper
after validation. A missing prerequisite is reported as a typed
`LinuxBackendError`; restricted requests are never widened into an ordinary
host process. `ExecutableSnapshotFailed` identifies the executable and the
failed capture operation. After construction, each spawn uses the sealed
snapshots rather than reopening mutable package paths.

Running a Cageforge sandbox does not require `sudo`, a privileged container, or
capabilities granted to the application. The host must allow unprivileged user
namespaces and the subordinate namespace operations listed below. If an outer
container or host security policy disables them, Cageforge reports the exact
unavailable operation instead of requesting elevation or weakening the policy.

Cageforge passes all Bubblewrap flags itself; applications and end users do not
add them to the command line. If a system executable lacks an option,
`LinuxBackendError::BubblewrapIncompatible` returns a typed `BubblewrapFlag` for
every missing option. Each value exposes the exact spelling through `as_str()`
and its Cageforge use through `purpose()`. Install a compatible system
Bubblewrap or build `cageforge-linux` with `bundled-bubblewrap`; no host setting
can add an option that the executable does not implement.

| Required flag | Why Cageforge requires it |
|---|---|
| `--as-pid-1` | Run the Cageforge hardening helper as PID 1 without a separate Bubblewrap reaper |
| `--bind` | Mount explicitly writable host paths into the sandbox |
| `--bind-fd` | Mount writable paths from descriptors pinned before launch |
| `--bind-try` | Restore host `/dev/shm` for unrestricted filesystem mode only when it exists |
| `--cap-drop` | Remove every Linux capability from the sandboxed command; Cageforge passes `ALL` |
| `--chdir` | Enter the validated working directory before execution |
| `--disable-userns` | Prevent the command from creating nested user namespaces |
| `--dir` | Create required in-sandbox mount-point directories |
| `--dev` | Create an isolated `/dev` filesystem |
| `--die-with-parent` | Kill the sandbox boundary if Bubblewrap or its parent dies |
| `--new-session` | Start the sandbox in a separate terminal session |
| `--perms` | Set exact modes on synthetic mount targets, mask files, and the captured hardening helper |
| `--proc` | Mount procfs for the sandbox PID namespace |
| `--remount-ro` | Make completed mount targets read-only |
| `--ro-bind` | Mount explicitly readable host paths without write access |
| `--ro-bind-data` | Materialize immutable file masks and the captured hardening helper from Cageforge-supplied descriptors |
| `--ro-bind-fd` | Mount read-only paths from descriptors pinned before launch |
| `--tmpfs` | Create isolated filesystem roots and in-memory deny masks |
| `--unshare-ipc` | Isolate System V IPC and POSIX message queues |
| `--unshare-net` | Isolate the network stack when direct networking is denied |
| `--unshare-pid` | Isolate process identifiers and the process tree |
| `--unshare-user` | Create the user and mount privilege boundary |

Flag support and host permission are different failures. Once support is
confirmed, backend construction probes each host-sensitive operation
separately. The corresponding error identifies the exact operation, native
diagnostic, and host requirement:

| Bubblewrap flag | Isolation | Host requirement when its probe fails |
|---|---|---|
| `--unshare-user` | User and mount privileges | Enable unprivileged user namespaces and permit them for the application in the host security policy; do not disable the policy globally |
| `--unshare-pid` | Process tree and PID view | Use a kernel and outer container configuration that permit `CLONE_NEWPID` |
| `--unshare-ipc` | System V shared memory, semaphores, and message queues | Use a kernel and outer container configuration that permit `CLONE_NEWIPC` |
| `--unshare-net` | Network stack | Use a kernel and outer container configuration that permit `CLONE_NEWNET` |
| `--cap-drop ALL` | Effective, permitted, inheritable, bounding, and ambient capability sets | Permit capability reduction inside user namespaces; Cageforge never asks applications to retain a Linux capability |
| `--disable-userns` | Nested user-namespace creation | Permit Bubblewrap to apply its namespaced `user.max_user_namespaces` lockdown; Cageforge has no portable policy grant for nested user namespaces |
| `--proc /proc` | procfs scoped to the sandbox PID namespace | Permit procfs mounts inside user and PID namespaces |

The runtime errors remain distinct: `NamespaceUnavailable` names one namespace,
`CapabilityDropUnavailable` covers capability clearing,
`NestedUserNamespaceIsolationUnavailable` covers the nested-userns lockdown,
and `ProcMountUnavailable` covers the procfs mount. Cageforge preserves the
Bubblewrap diagnostic in each error.

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

`LinuxBackend` is reusable rather than a persistent shared container. Each
`spawn` creates a new sandbox boundary for one command process tree, including
any descendants it starts. Multiple children or backend instances may run
concurrently; their gateway, lifecycle, and enforcement state is separate,
while host paths are shared only when the effective filesystem scopes allow it.

## One policy, several commands

`SandboxPolicy` contains the rules. `LinuxBackend` is the reusable native
execution engine. `CommandRequest` describes one command, and `spawn` creates
one Linux sandbox boundary for that command and every descendant it starts:

```text
SandboxPolicy + LinuxBackend + CommandRequest
                              │
                              ▼
                           spawn()
                              │
                              ▼
                    one Bubblewrap boundary
```

Compose the policy and create the backend once, then prepare and spawn each
command separately. The following uses the `effective`, `context`,
`workspace`, and `environment` values prepared in the example above:

```rust,no_run
use std::error::Error;
use std::path::Path;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_linux::LinuxBackend;
use cageforge_policy::PathResolutionContext;
use cageforge_policy_compose::EffectiveSandbox;

fn run_three(
    backend: &LinuxBackend,
    effective: &EffectiveSandbox,
    context: &PathResolutionContext,
    workspace: &Path,
    environment: &EnvironmentSpec,
) -> Result<(), Box<dyn Error>> {
    let commands: &[(&str, &[&str])] = &[
        ("/usr/bin/cargo", &["check"]),
        ("/usr/bin/cargo", &["test"]),
        ("/usr/bin/git", &["diff", "--check"]),
    ];

    for (program, arguments) in commands {
        let command_spec = CommandSpec::new(*program)?.with_args(arguments.iter().copied())?;
        let command = CommandRequest::new(command_spec)
            .with_working_directory(workspace.to_path_buf())?
            .with_environment(environment.clone());
        let prepared = backend.prepare(
            BackendRequest::new(&command, effective),
            context,
        )?;
        let status = backend.spawn(prepared)?.wait()?;
        if !status.success() {
            break;
        }
    }
    Ok(())
}

let _ = run_three;
```

This creates three independent boundaries. They use the same effective policy,
but have separate Bubblewrap processes, process trees, timeout state, gateway
state, and cleanup lifecycle. If `cargo` starts `rustc` and `build.rs`, those
descendants remain inside the boundary of that particular `spawn`:

```text
one sandbox boundary
└── cargo
    └── rustc
        └── build.rs
```

For one shared boundary around several steps, an application may explicitly
launch a shell command, but then the shell and all three steps form one process
tree. Cageforge itself is a library and does not provide a `cageforge run`
command; an application can expose its own CLI around this API.

## Filesystem behavior

Restricted policies become a deterministic Bubblewrap mount plan. The backend
supports absolute, workspace, system-root, minimal-runtime, temporary, and
`/tmp` scopes; read/write/deny precedence; read-only carve-outs; bounded deny
globs; missing-path behavior; and protected metadata paths. Existing mount
sources are pinned for the Bubblewrap handoff, and native lowering accounts for
symlinks before launch. The Bubblewrap executable and hardening helper are also
kept pinned for the lifetime of the backend, closing replacement races between
construction and a later spawn.

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

## Protection matrix

The backend combines these protections according to the effective policy. A
feature being available on Linux does not widen a request that did not ask for
it, and an unsupported combination is rejected before launch.

| Protection | When it is active | What it enforces |
|---|---|---|
| Bubblewrap user and mount namespaces | Restricted filesystem or isolated network mode | Separates the child filesystem/network view from the host |
| New session and parent-lifetime binding | Every Bubblewrap launch | Uses `--new-session`, `--die-with-parent`, and the native parent-death signal so the boundary cannot outlive its owner |
| PID namespace and fresh `/proc` | Default `ProcMountPolicy::Required` | Gives the child an isolated process view and prevents host `/proc` exposure |
| IPC namespace | Every Bubblewrap launch | Prevents access to host System V shared-memory segments, semaphore sets, and message queues |
| Empty Linux capability sets | Every Bubblewrap launch | Uses `--cap-drop ALL` so namespace-root and host-root callers cannot pass capabilities to the command |
| Nested user-namespace lockdown | Every Bubblewrap launch | Uses `--disable-userns` so the command cannot reacquire namespace-local capabilities through `CLONE_NEWUSER` |
| Anonymous session keyring | Every Bubblewrap launch | Replaces the inherited session keyring before the command starts so host keys cannot be read by serial number |
| Private device and runtime view | Every restricted filesystem launch | Builds the child `/dev` view, hides Cageforge runtime paths from the command, and exposes only the deliberately mounted helper/gateway endpoints |
| Empty-root or layered bind mounts | Restricted filesystem | Allows only effective read/write scopes and masks denied paths |
| Read-only carve-outs | A writable scope with read-only subpaths | Keeps narrower paths read-only inside writable parents |
| Deny-glob expansion | A deny glob | Expands bounded matches, accounts for symlinks, and masks every authorized match |
| Protected metadata paths | `.git` by default plus configured additional paths | Blocks existing paths and monitors missing paths against creation/replacement with inotify and fail-closed cleanup |
| Symlink and mount-boundary checks | Any native filesystem lowering | Rejects writable symlink escapes and unsafe path/mount relationships |
| Protected-directory inode pinning | Protected-path monitor | Rejects a replacement directory before removal instead of deleting a different entry under the protected name |
| Descriptor pinning and sealed executable snapshots | Mount sources, Bubblewrap, and hardening helper | Keeps mount sources bound to validated descriptors and prevents later package-path changes from changing launched executables |
| Close-on-exec and FD inheritance | Every launch | Keeps mount, authentication, gateway, and coordination descriptors out of unrelated child processes |
| Helper authentication | Every hardened launch | Requires the backend-owned descriptor, peer-namespace check, and authentication token before the helper runs |
| Bridge token authentication | Restricted gateway routing | Prevents another same-user process from using the per-run TCP-to-gateway bridge |
| Private gateway socket permissions | Restricted gateway routing | Uses a per-run private directory and mode `0600` socket before accepting ingress |
| Synthetic-target lock and identity | Missing protected masks shared by launches | Serializes registry changes and checks device/inode ownership before cleanup |
| Protected-owner identity | Synthetic-target registry | Uses PID plus Linux process start time, so PID reuse cannot preserve stale ownership |
| Framed setup/status protocol | Every helper launch | Validates magic, lengths, entry limits, names, values, duplicates, and typed command status |
| Seccomp and `no_new_privs` | Restricted filesystem, disabled/direct-isolated network, or proxy routing | Blocks ptrace, `process_vm_*`, `io_uring`, forbidden Unix-socket operations, and disallowed network families or socket operations in the child boundary |
| Core-dump and dumpability hardening | Hardened launches | Prevents core dumps and keeps the restricted process non-dumpable |
| Disabled network namespace and socket filter | `NetworkMode::Disabled` | Removes direct IP access and rejects pathname-capable AF_UNIX datagram/seqpacket endpoints while preserving process-local stream IPC |
| Restricted gateway routing | Domain-restricted network | Uses one DNS snapshot, exact resolved-address authorization, authenticated proxy ingress, and bounded relay timeouts |
| Unix-socket isolation | Proxy routing or direct mode without Unix sockets | Blocks pathname Unix-socket escapes while preserving only the explicitly supported IPC behavior |
| Environment frame limits | Every helper launch | Bounds entry count, per-value size, and aggregate setup memory |
| Timeout and parent-death handling | Backend-default or limited timeout, plus every boundary | Uses PIDFD-based timeout termination, Bubblewrap parent binding, and cleanup to terminate the complete sandbox boundary when the command expires or its owner disappears |
| Setup and readiness deadlines | Helper, bridge, and gateway startup | Bounds authentication, environment transfer, status exchange, bridge port publication, and gateway handshakes so startup cannot hang indefinitely |

`External` filesystem or network ownership is not treated as local Linux
enforcement. The backend returns a typed unsupported result unless a future
trusted integration supplies the required enforcement boundary. Likewise,
`Unrestricted` modes intentionally disable only the corresponding local
restriction; they do not bypass the helper, lifecycle, descriptor, or setup
integrity protections needed to start the process safely.

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

## Process lifecycle and errors

`LinuxChild` exposes the child identifier, configured pipe handles, `try_wait`,
`wait`, and `kill`. Backend-default and explicit timeout policies are enforced
by a pidfd-based watchdog when the kernel supports it. Timeout, policy-monitor
failure, gateway failure, explicit termination, and `Drop` terminate and reap
the Bubblewrap PID namespace boundary and clean up per-run resources.

Use `LinuxBackendError` for typed construction, preflight, lowering, setup,
gateway, process, timeout, and cleanup failures. Capability errors identify the
exact portable requirement that the configured backend cannot enforce.

Native lowering failures do not require callers to parse a repeated reason
string. For example, `LinuxBackendError::FilesystemLoweringFailed` contains a
`FilesystemLoweringError` identifying metadata inspection, a writable symlink,
an invalid mount target, a pinned-source failure, or another exact lowering
case. Network mount mismatches and gateway lifecycle failures use the same
typed sub-error pattern. This lets an application decide whether to retry,
report a configuration problem, or fail closed without depending on display
text.

`NetworkGatewayRuntimeError::Failed` carries a
`NetworkGatewayRuntimeFailure` such as runtime construction, listener
registration, listener I/O, or an unexpected early stop. Gateway lifecycle
callers therefore do not need to classify a free-form diagnostic string.

The same rule applies to the native helper boundary. `LinuxHardeningError`,
`LinuxBridgeError`, `SeccompBuildError`, `EnvironmentFrameError`, and
`StatusFrameError` identify the failing operation as typed `thiserror`
variants. `SetupHandshakeError` preserves whether the failure came from the
authenticated channel, the environment frame, or the gateway token. Display
text is for humans; callers should match the enum and its nested source rather
than parse a message such as `reason` or `message`.

Session-keyring isolation failures are reported as
`LinuxHelperSetupFailureKind::KeyringIsolation` and retain the originating OS
error number. Cageforge does not continue with the caller's inherited session
keyring when the kernel rejects isolation.

The helper environment frame is bounded before allocation: at most 4,096
entries, 1 MiB per variable, and 16 MiB in aggregate. These are protocol
integrity limits that prevent a malformed or hostile authenticated frame from
causing unbounded memory allocation; they are not a replacement for the
portable environment policy.

For restricted launches, the helper also disables Linux core dumps and marks
the hardened process non-dumpable before starting the command. These are
process-boundary safeguards, not settings that modify the long-lived parent
application.
