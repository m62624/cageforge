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
namespaces used by Bubblewrap. A missing prerequisite is reported as a typed
`LinuxBackendError`; restricted requests are never widened into an ordinary
host process. After construction, the validated Bubblewrap executable and
hardening helper are pinned by open file descriptors; each spawn uses those
validated objects rather than reopening their paths.

Cageforge passes all Bubblewrap flags itself; applications and end users do not
add them to the command line. Backend construction probes each namespace
separately. `LinuxBackendError::NamespaceUnavailable` identifies the exact
namespace, its Bubblewrap flag, the native diagnostic, and the corresponding
host requirement:

| Bubblewrap flag | Isolation | Host requirement when its probe fails |
|---|---|---|
| `--unshare-user` | User and mount privileges | Enable unprivileged user namespaces and permit them for the application in the host security policy; do not disable the policy globally |
| `--unshare-pid` | Process tree and PID view | Use a kernel and outer container configuration that permit `CLONE_NEWPID` |
| `--unshare-ipc` | System V shared memory, semaphores, and message queues | Use a kernel and outer container configuration that permit `CLONE_NEWIPC` |
| `--unshare-net` | Network stack | Use a kernel and outer container configuration that permit `CLONE_NEWNET` |

If the executable itself lacks a required option, the separate
`LinuxBackendError::BubblewrapIncompatible` error lists every missing flag.

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
| Private device and runtime view | Every restricted filesystem launch | Builds the child `/dev` view, hides Cageforge runtime paths from the command, and exposes only the deliberately mounted helper/gateway endpoints |
| Empty-root or layered bind mounts | Restricted filesystem | Allows only effective read/write scopes and masks denied paths |
| Read-only carve-outs | A writable scope with read-only subpaths | Keeps narrower paths read-only inside writable parents |
| Deny-glob expansion | A deny glob | Expands bounded matches, accounts for symlinks, and masks every authorized match |
| Protected metadata paths | `.git` by default plus configured additional paths | Blocks existing paths and monitors missing paths against creation/replacement with inotify and fail-closed cleanup |
| Symlink and mount-boundary checks | Any native filesystem lowering | Rejects writable symlink escapes and unsafe path/mount relationships |
| Protected-directory inode pinning | Protected-path monitor | Rejects a replacement directory before removal instead of deleting a different entry under the protected name |
| Descriptor pinning | Mount sources, Bubblewrap, and hardening helper | Prevents path replacement from changing the file handed to Bubblewrap |
| Close-on-exec and FD inheritance | Every launch | Keeps mount, authentication, gateway, and coordination descriptors out of unrelated child processes |
| Helper authentication | Every hardened launch | Requires the backend-owned descriptor, peer-namespace check, and authentication token before the helper runs |
| Bridge token authentication | Restricted gateway routing | Prevents another same-user process from using the per-run TCP-to-gateway bridge |
| Private gateway socket permissions | Restricted gateway routing | Uses a per-run private directory and mode `0600` socket before accepting ingress |
| Synthetic-target lock and identity | Missing protected masks shared by launches | Serializes registry changes and checks device/inode ownership before cleanup |
| Protected-owner identity | Synthetic-target registry | Uses PID plus Linux process start time, so PID reuse cannot preserve stale ownership |
| Framed setup/status protocol | Every helper launch | Validates magic, lengths, entry limits, names, values, duplicates, and typed command status |
| Seccomp and `no_new_privs` | Restricted filesystem, disabled/direct-isolated network, or proxy routing | Blocks ptrace, `process_vm_*`, `io_uring`, forbidden Unix-socket operations, and disallowed network families or socket operations in the child boundary |
| Core-dump and dumpability hardening | Hardened launches | Prevents core dumps and keeps the restricted process non-dumpable |
| Disabled network namespace | `NetworkMode::Disabled` | Removes direct network access from the child |
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

## Process lifecycle

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

The helper environment frame is bounded before allocation: at most 4,096
entries, 1 MiB per variable, and 16 MiB in aggregate. These are protocol
integrity limits that prevent a malformed or hostile authenticated frame from
causing unbounded memory allocation; they are not a replacement for the
portable environment policy.

For restricted launches, the helper also disables Linux core dumps and marks
the hardened process non-dumpable before starting the command. These are
process-boundary safeguards, not settings that modify the long-lived parent
application.
