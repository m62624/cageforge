> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-windows

`cageforge-windows` is the Windows-native backend for Cageforge's library API.
It provides an OS-enforced sandbox for applications that need to run
potentially untrusted commands, agents, plugins, build scripts, and mods. A
caller gives it a validated command, a composed effective policy, and the
runtime paths needed to resolve that policy; the backend returns a
backend-bound prepared request or a typed error before the command starts. The
backend turns one backend-bound `PreparedBackendRequest` into a restricted Windows
process tree with account, token, ACL, desktop, Job Object, handle-inheritance,
firewall/WFP, and per-process network-route enforcement.

## Sandbox model

Each `spawn` creates one sandbox boundary around one command and its complete
descendant process tree. The boundary:

- limits access to files and the working directory;
- limits network access and routing;
- isolates child processes;
- applies timeouts and terminates the complete process tree;
- passes only explicitly authorized file descriptors or handles; and
- supports multiple independent instances at the same time.

`WindowsBackend` and the policy can be reused for several commands, while every
spawn receives its own process boundary, lifecycle, and native enforcement
state. Multiple backend instances and launches can run simultaneously with
different filesystem and network policies without sharing their route or
capability authority.

## Workspace role

| Crate | Role in the relationship |
|---|---|
| `cageforge-config` | Optionally resolves TOML profiles into validated command, policy, environment, and gateway values. |
| `cageforge-command` | Supplies validated argv, cwd, stdio, timeout, and environment intent. |
| `cageforge-policy` | Supplies portable filesystem and network rules. |
| `cageforge-policy-compose` | Produces the `EffectiveSandbox` formed by the requested policy and its outer ceiling. |
| `cageforge-backend-api` | Binds preflight output to this backend instance and verifies every required capability. |
| `cageforge-network-proxy` | Enforces exact resolved-target HTTP and SOCKS5 gateway policy. |
| `cageforge-windows` | Applies the Windows-native setup, ACL, token, process, Job Object, desktop, firewall/WFP, and route boundary. |
| `cageforge-core` | Will provide the final target-selecting facade over native backends. |

The integration sequence is:

```text
command + requested policy + PolicyCeiling + runtime paths
                              │
                              ▼
                     EffectiveSandbox
                              │
                              ▼
              WindowsBackend::prepare
                              │
                              ▼
             backend-bound prepared request
                              │
                              ▼
                WindowsBackend::spawn
```

## Windows requirements and setup

The strong Windows backend has one administrator-approved provisioning step.
`WindowsSetup::install` requests UAC only when setup state must be created or
reconciled. Ordinary `WindowsBackend::new`, `prepare`, and `spawn` calls use
the verified installed state and do not request UAC for every command.

`WindowsSetup` represents this persistent owner-scoped provisioning, not a
single command sandbox. For one signed-in Windows user, the setup has one
state root: repeated installation with that same root is serialized and
idempotent, while a different root is rejected with the typed
`WindowsSetupError::OwnerSetupConflict` before global account, firewall, or
WFP state is reconciled. To run several isolated workloads, reuse the verified
setup and create one or more `WindowsBackend` instances; each `spawn` then
creates its own launch boundary.

Setup creates two persistent ordinary local accounts scoped to the signed-in
owner:

- an offline account for disabled and proxy-routed networking;
- an online account for unrestricted direct networking.

It also creates a managed local group, DPAPI-protected credentials, protected
state and lock files, owner-scoped ACLs, offline firewall rules, and mandatory
WFP filters. The setup marker is written only after all required components have
been configured and read back. If WFP or another mandatory component cannot be
verified, setup fails closed and the backend will not launch a command.

The accounts remain installed between launches. This avoids requiring UAC and
firewall/WFP reconfiguration for every process. `WindowsSetup::uninstall` is an
explicit owner-scoped operation; it refuses to remove state while a backend or
child still holds the lifecycle boundary and never recursively deletes unknown
files.

The default release layout is:

```text
application/
├── bin/application.exe
└── cageforge-resources/
    ├── cageforge-windows-setup.exe
    ├── cageforge-windows-command-runner.exe
    └── runner-manifest.json
```

`WindowsSetupConfig` can instead select the sibling executables or explicit
absolute paths. Resource selection is not a download: every helper and runner
is opened through a pinned handle, checked for reparse and final-path changes,
hashed, and retained through the operation that uses it. When the
`bundled-helpers` feature is enabled, the default configuration selects the
release resource layout shown above; without default features, it selects the
sibling executable layout. The feature does not embed helper binaries or turn
an unverified pathname into a trusted executable. An application can always
select `Bundled`, `Sibling`, or an explicit absolute path through
`WindowsSetupConfig`.

The crate exposes documentation targets for the supported Windows library
architectures:

```toml
[package.metadata.docs.rs]
targets = ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]
```

Native enforcement is performed by Windows APIs. Cross-compiling the library
checks its target surface, but does not replace execution on Windows.

## Basic use

Provision the setup explicitly, compose the portable values, then prepare and
spawn through the same backend instance:

```rust,no_run
use std::path::PathBuf;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{compose, CompositionRequest, PolicyCeiling};
use cageforge_windows::{WindowsBackend, WindowsBackendConfig, WindowsSetup, WindowsSetupConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let setup_config = WindowsSetupConfig::new();
    let setup = WindowsSetup::new(setup_config.clone());
    setup.install()?; // Administrator approval through UAC, when required.

    let workspace = std::env::current_dir()?;
    let environment = EnvironmentSpec::inherit_core();
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), environment.clone())
        .with_workspace_roots([workspace.clone()])?;
    let effective = compose(
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_workspace_roots([workspace.clone()])?,
    )?;

    let command = CommandRequest::new(CommandSpec::new("cmd.exe")?)
        .with_working_directory(workspace.clone())?
        .with_environment(environment);
    let context = PathResolutionContext::new()
        .with_root(PathBuf::from(r"C:\"))?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(PathBuf::from(r"C:\Windows\System32"))?
        .with_current_directory(workspace)?;

    let backend = WindowsBackend::new(
        WindowsBackendConfig::new().with_setup(setup_config),
    )?;
    let prepared = backend.prepare(BackendRequest::new(&command, &effective), &context)?;
    let status = backend.spawn(prepared)?.wait()?;
    assert!(status.success());
    Ok(())
}
```

`WindowsBackend::prepare` binds the request to the exact backend identity and
validates the complete effective filesystem, network, environment, stdio, cwd,
and timeout contract. `spawn` accepts only that prepared value; it does not
reconstruct policy from the original request.

One `spawn` protects the command and all of its descendants as one process
tree. Separate `spawn` calls are separate sandbox instances and may run at the
same time with different policies. They share host data only where their
effective filesystem scopes deliberately name the same path.

## One policy, several commands

`SandboxPolicy` contains the rules. `WindowsBackend` is the reusable native
execution engine. `CommandRequest` describes one command, and `spawn` creates
one Windows sandbox boundary for that command and every descendant it starts:

```text
SandboxPolicy + WindowsBackend + CommandRequest
                                │
                                ▼
                             spawn()
                                │
                                ▼
                    one token and Job boundary
```

`WindowsSetup::install` is performed once when the owner-scoped setup is not
yet installed or needs reconciliation. It is provisioning for the backend,
not a separate sandbox around one command. After setup, compose the policy and
create the backend once, then prepare and spawn each command separately. The
following uses the `effective`, `context`, `workspace`, and `environment`
values prepared in the example above:

```rust,no_run
use std::error::Error;
use std::path::Path;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::PathResolutionContext;
use cageforge_policy_compose::EffectiveSandbox;
use cageforge_windows::WindowsBackend;

fn run_three(
    backend: &WindowsBackend,
    effective: &EffectiveSandbox,
    context: &PathResolutionContext,
    workspace: &Path,
    environment: &EnvironmentSpec,
) -> Result<(), Box<dyn Error>> {
    let commands: &[(&str, &[&str])] = &[
        ("cargo.exe", &["check"]),
        ("cargo.exe", &["test"]),
        ("git.exe", &["diff", "--check"]),
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

This creates three independent Windows sandbox instances. They use the same
effective policy, but have separate restricted tokens, Job Objects, process
trees, route state, timeout state, and cleanup lifecycle. If `cargo` starts
`rustc` and `build.rs`, those descendants remain inside the boundary of that
particular `spawn`:

```text
one sandbox boundary
└── cargo
    └── rustc
        └── build.rs
```

For one shared boundary around several steps, an application may explicitly
launch a shell command, but then the shell and all steps form one process tree.
Cageforge itself is a library and does not provide a `cageforge run` command;
an application can expose its own CLI around this API.

## Filesystem behavior

The effective filesystem policy is lowered into a Windows ACL plan before any
launch. Absolute, workspace, root, minimal-runtime, temporary, read-only,
protected, missing-path, and bounded glob forms are validated against native
path identity. Existing objects are inspected through handles that do not
follow reparse points. A path replacement, junction, symlink, alternate data
stream, device path, drive alias, or changed final identity fails closed.

Writable workspace scopes protect `.git` by default. Applications may
explicitly opt out through `FilesystemPolicy::dangerously_allow_git_write()` or
the matching `cageforge-config` setting; additional protected paths remain
protected and an outer `PolicyCeiling` can retain the protection.

Missing protected and read-only paths are materialized only after the existing
ancestor chain has been pinned. The journal and marker make recovery
resumable, while cleanup removes only the exact object that Cageforge created.
An active child, non-empty directory, reparse substitution, descriptor drift,
or unexpected descendant returns a typed cleanup failure rather than deleting
an unrelated host object.

## Protection matrix

The backend combines the following protections according to the effective
policy. A capability is advertised only when its native setup and runtime path
are available; unsupported ownership combinations return a typed error before
launch.

| Protection | When it is active | What it enforces |
|---|---|---|
| Owner-scoped setup identity | Every installed setup | Binds accounts, state, credentials, firewall, WFP, and helper resources to the real user's SID. |
| Persistent low-privilege accounts | Every restricted launch | Runs the command as a verified ordinary offline or online local account, never as the current user or an administrator. |
| DPAPI credentials and protected state | Setup and every launch | Keeps account passwords and capability state out of argv, environment, logs, and public status; protects their files with owner/DACL verification. |
| Pinned helper and runner resources | Setup, verification, and launch | Checks digest, owner, DACL, reparse state, and final path through retained handles so a pathname replacement cannot redirect elevation or execution. |
| Versioned setup lifecycle and lock | Install, launch, cleanup, and uninstall | Serializes mutations, excludes uninstall while children are active, and recovers only exact durable state. |
| Write-ahead ACL journal | Every persistent ACL mutation | Records complete before/after descriptors and file identity before mutation; a replacement or third descriptor state fails closed. |
| Handle-pinned filesystem paths | Restricted filesystem | Checks volume, file identity, final path, and reparse state before applying or restoring ACLs. |
| Capability and profile SIDs | Restricted filesystem | Gives each complete effective filesystem profile its own deny authority and gives each writable root a separate allow authority. |
| Native ACL enforcement | Restricted filesystem | Applies read, write, deny, read-only, protected-path, missing-path, and inherited-DACL rules without widening on a path race. |
| Transactional missing-path materialization | Missing protected or read-only paths | Creates only Cageforge-owned components with their final descriptor, records a random marker, and removes them only after exact identity and descriptor checks. |
| Restricted primary token | Every restricted launch | Drops maximum privileges, applies LUA and write-restricted token behavior, and retains only the required traversal privilege plus checked capability SIDs. |
| Per-launch route SID | Proxy-routed networking | Adds one cryptographically random restricting SID to that launch's token, but never to the token default DACL or another launch. |
| Private desktop | Every restricted launch | Creates a launch-unique desktop in the sandbox logon session with a verified DACL; the child receives no host desktop or window-station handle. |
| Job Object boundary | Every restricted launch | Assigns the child atomically at creation, enables kill-on-close and all configured UI restrictions, and disallows breakaway. |
| Explicit HANDLE list | Every restricted launch | Passes only the three validated standard-stream endpoints to the child; unrelated inheritable handles cannot cross the boundary. |
| Linear HANDLE ownership | Every launch | Closes runner duplicates after process creation and Job assignment while `WindowsChild` retains its parent pipe endpoints until their documented lifecycle boundary. |
| Authenticated runner transport | Every launch | Uses bounded, versioned typed frames for readiness, spawn, failure, and exit; expected failures become typed library errors. |
| Private named-pipe authentication | Runner bootstrap and lifecycle | Uses launch-unique protected pipes, verifies server PID and owner identity, and rejects forged or direct helper protocols. |
| Offline firewall and WFP deny boundary | Disabled and proxy-routed networking | Blocks direct outbound and loopback access for the offline account; failure to verify WFP is fatal. |
| Direct networking account separation | Unrestricted direct networking | Uses the separately verified online account for direct sockets without weakening restricted filesystem enforcement. |
| Four-tuple PID attribution | Proxy-routed networking | Maps an accepted IPv4 connection to its owning PID, pins process identity against PID reuse, and reads the exact token restriction set. |
| Exact per-process route selection | Proxy-routed networking | Enters a route only when exactly one registered route SID matches the client token; missing, stale, duplicate, and foreign routes fail closed. |
| Exact gateway target verification | HTTP and SOCKS5 routing | Resolves once, checks the effective policy, and verifies the exact `SocketAddr` immediately before connecting. |
| Environment isolation | Every launch | Selects `all`, `core`, or `none` through typed transformations, canonicalizes Windows variable identity, terminates the environment block correctly, and owns proxy overrides. |
| Timeout and complete-tree termination | Backend-default or explicit timeout, kill, drop, and parent loss | Terminates the runner-owned Job boundary and descendants, closes pipes, stops watchdogs, and releases routes and ACL leases in a deterministic order. |
| Concurrent-instance isolation | Multiple backend instances or children | Keeps account state, profile authorities, lifecycle leases, routes, gateway policies, and process trees separate. |
| Typed fail-closed errors | Setup, prepare, spawn, wait, and cleanup | Identifies the failing native stage and code. |

`External` filesystem or network ownership and pathname local-IPC policy are
not advertised as Windows-native capabilities. Unrestricted filesystem
execution and the platform-specific conventional Unix temporary scope are also
rejected before lowering because this backend has no verified native boundary
for them. Windows named pipes are handled as Windows objects through token,
desktop, DACL, and explicit-handle controls; they are not silently treated as
Unix sockets.

## Network behavior

Disabled and proxy-routed modes use the verified offline account and its
firewall/WFP deny boundary. Direct mode uses the separately verified online
account. Restricted filesystem plus unrestricted direct networking remains a
native restricted launch. An unrestricted filesystem request is rejected by
common capability preflight; Windows never widens ownership by launching it as
the caller's current identity.

For domain, local-address, or resolved-target restrictions, the backend creates
one random route SID and registers one gateway policy for that launch. The
fixed IPv4 loopback ingress requires exclusive port ownership, attributes the
connection by the reversed TCP four-tuple, checks the process creation identity
and token, and selects exactly one route. The route then enters the independent
Cageforge HTTP or SOCKS5 gateway, which rechecks the exact resolved destination
at connect time. A process cannot use another instance's route SID or gateway
credential.

## Process lifecycle and errors

`WindowsChild` exposes the child identifier, configured standard-stream pipes,
`try_wait`, `wait`, `kill`, and `close_stdin`. Its lifetime retains the runner
boundary, private desktop, Job Object relationship, filesystem enforcement,
network route, and active-child lease. Completion releases the route and ACL
resources only after the process boundary and runner lifecycle have finished.

The parent does not parse runner `stdout` or `stderr` as a protocol. The
authenticated runner reports `Ready`, `Spawned`, `Exited`, and typed `Failed`
frames through the bounded transport. `stderr` is only a non-authoritative
diagnostic for direct invocation or for the case where even the authenticated
failure report cannot be established.

`WindowsSetup::uninstall` is intentionally separate from child cleanup. Drop or
wait for every `WindowsChild` and backend before uninstalling so that the
protected setup resources can be reconciled in their dependency order.
