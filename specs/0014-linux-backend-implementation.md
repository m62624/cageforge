# Specification 0014: Linux Backend Implementation

Status: implemented; the behavior and security contract for the current
`cageforge-linux` implementation

## 1. Purpose

This specification defines the first native Cageforge backend: Linux process
execution with operating-system filesystem and process isolation. It turns the
portable values produced by `cageforge-config`, `cageforge-command`,
`cageforge-policy`, and `cageforge-policy-compose` into a Linux enforcement
plan consumed through `cageforge-backend-api`.

The backend is an independent library crate. It must not import Codex crates,
Codex protocol types, Codex legacy configuration names, telemetry, PTY
abstractions, or product-specific process/session types.

The backend must not be considered complete merely because it can construct a
Bubblewrap command line. Completion requires the command to be executed inside
the intended Linux isolation boundary and the boundary to be covered by
black-box integration tests on a Linux runner.

## 2. Workspace and target boundary

The package name is `cageforge-linux` and its Rust library name is
`cageforge_linux`.

Linux implementation modules and native integration tests must use the exact
target family:

```rust
#[cfg(target_os = "linux")]
```

Do not use `cfg(unix)` for Linux enforcement tests: that would also compile
them on macOS. Architecture-specific cases may additionally use
`cfg(target_arch = "x86_64")` or `cfg(target_arch = "aarch64")`, but those
conditions must not replace the Linux OS condition.

The crate must remain buildable as part of the workspace on non-Linux hosts,
but it must not expose a fake successful Linux backend there. Linux-only
backend types and implementation modules are conditionally compiled. A
non-Linux caller must receive an explicit unsupported-platform result from any
cross-platform entry point rather than silently executing without enforcement.

The crate must not depend on `cageforge-core`. The dependency direction is:

```text
cageforge-core (future facade)
        ↓
cageforge-linux
        ↓
cageforge-backend-api
        ↓
portable Cageforge crates
```

In the first implementation, `cageforge-core` may remain a placeholder while
the Linux backend is tested directly through its public API.

## 3. Upstream reference and deliberate exclusions

The Linux design is behavior-reviewed against these Codex areas:

- `codex-rs/sandboxing/src/manager.rs`;
- `codex-rs/sandboxing/src/bwrap.rs`;
- `codex-rs/sandboxing/src/landlock.rs`;
- `codex-rs/linux-sandbox/src/launcher.rs`;
- `codex-rs/linux-sandbox/src/linux_run_main.rs`;
- `codex-rs/linux-sandbox/src/landlock.rs`;
- `codex-rs/process-hardening/src/lib.rs`; and
- `codex-rs/bwrap` and its separately licensed Bubblewrap source.

These files are behavioral references, not a permission to copy their source.
If a future implementation copies or substantially adapts any upstream file,
the exact source path, frozen commit, copyright, license, and material-change
notice must be added before that file enters the repository.

The following Codex concerns remain outside the first backend:

- Codex `PermissionProfile`, approval, guardian, trust, and managed policy
  flows;
- Codex process/session identifiers, app-server, exec-server, and PTY
  orchestration;
- Codex telemetry and product startup warnings;
- product-specific MITM, credential injection, telemetry, and managed-network
  control-plane infrastructure; and
- legacy Landlock compatibility behavior that exists only to preserve old
  Codex configuration modes.

The backend may use Landlock as a new defense-in-depth or fallback design only
after a separate implementation decision proves that it preserves the
effective Cageforge policy. It must not reproduce legacy compatibility paths
just because Codex still contains them.

## 4. Complete Linux API and setting inventory

### 4.1 Codex API surface reviewed

The following Codex APIs and internal entry points were reviewed because they
participate in Linux sandbox behavior:

| Codex API or area | Responsibility | Cageforge decision |
|---|---|---|
| `SandboxType` and `SandboxablePreference` | Select or forbid a platform sandbox | Replaced by `SandboxBackend` capabilities and typed preflight errors |
| `SandboxManager::select_initial` | Choose an initial platform implementation | Backend selection belongs to a future facade or caller |
| `SandboxManager::transform` | Lower a product execution request to a sandbox command | Replaced by Linux-specific lowering from `PreparedBackendRequest` |
| `SandboxManager::transform_for_direct_spawn` | Alternate direct-spawn lowering | Not copied; Linux backend owns one verified launch path |
| `SandboxCommand`, `SandboxExecRequest`, and transform request structs | Product process handoff | Replaced by `CommandRequest`, `EffectiveSandbox`, and Linux prepared state |
| `create_linux_sandbox_command_args_for_permission_profile` | Build helper CLI arguments | Replaced by typed Linux plan construction; no JSON `PermissionProfile` boundary |
| `LandlockCommand` | Parse the Linux helper CLI | Internal implementation detail, not public Cageforge API |
| `run_main` | Self-invoking helper entry point | Optional private binary entry point; library callers use `LinuxBackend` |
| `find_system_bwrap_in_path` and bwrap warning helpers | Discover and probe Bubblewrap | Replaced by typed backend construction and `LinuxBackendError` |
| `BwrapOptions` and `BwrapNetworkMode` | Select proc, network, and glob-scan behavior | Replaced by typed `LinuxBackendConfig` plus effective policy lowering |
| `apply_permission_profile_to_current_thread` | Apply seccomp, `no_new_privs`, and legacy Landlock | Reimplemented behind the Linux backend; no Codex error types |
| `spawn_process` and `SpawnRequest` | Process/PTY orchestration | Linux backend supports the Cageforge command/stdio contract; PTY remains separate |
| sandbox violation event and telemetry APIs | Product observability | Excluded; callers receive typed process/backend errors |

Codex's public exports are not a direct checklist for Cageforge's public API.
Several are exported only because Codex has multiple product execution paths.
The Cageforge backend must expose the smallest API that can safely perform the
same native enforcement.

### 4.2 Linux helper settings reviewed

Codex's Linux helper currently accepts or derives these settings:

| Setting | Meaning | Cageforge treatment |
|---|---|---|
| sandbox policy cwd | Base for workspace and special-path resolution | Supplied through validated `PathResolutionContext` |
| command cwd | Logical cwd of the child | Comes from prepared working-directory API |
| permission profile | Combined filesystem/network policy | Replaced by `EffectiveSandbox` |
| legacy Landlock flag | Old compatibility pipeline | Not exposed in the first backend |
| inner seccomp stage | Internal second execution stage | Private implementation detail |
| proxy-only network flag | Route all child IP traffic through an enforcing proxy inside an isolated namespace | Implemented as a private Linux runtime selected from effective policy; not exposed as a product flag |
| proxy route specification | Internal TCP/UDS bridge setup | Private typed launch data generated by the backend; never caller-authored text |
| proc mount switch | Whether a fresh `/proc` is mounted | Typed `ProcMountPolicy`, secure default required |
| trailing command argv | Program and arguments | `CommandSpec`/`CommandRequest`, with NUL validation |
| system versus bundled bwrap | Launcher source | Prefers validated system bwrap and falls back to the licensed `cageforge-bwrap` resource |
| bwrap `--argv0` support | Inner helper compatibility | Automatically probed; never caller-configured |
| user namespace availability | Kernel/runtime prerequisite | Verified during backend construction or required CI preflight |
| WSL1 detection | Bubblewrap cannot provide the required namespace | Explicit typed unsupported-platform error |
| platform default read roots | Minimal executable/runtime visibility | Backend-defined Linux defaults, documented and tested |
| glob scan depth | Bound for deny-glob expansion | Enforced by the native scanner; unsafe root-prefix scans and match-limit overflow fail closed |

No raw helper flag, JSON profile, mutable environment map, or positional boolean
may be added as a public Cageforge API merely because it exists in the Codex
helper.

### 4.3 Cageforge public API

The Linux crate exposes this typed construction and execution surface:

```text
LinuxBackendConfig
  ├── bubblewrap source: system, bundled, system-then-bundled, or explicit validated path
  ├── resource directory: sibling or explicit path
  ├── hardening helper: sibling, resource, sibling-then-resource, or explicit validated path
  ├── proc mount policy: required or explicitly disabled
  ├── backend-default command timeout
  └── restricted-network gateway limits and timeouts

LinuxBackend
  ├── new(config) -> Result<Self, LinuxBackendError>
  ├── capabilities() -> BackendCapabilities
  ├── prepare(request, runtime_context) -> Result<PreparedBackendRequest<Self>, ...>
  └── spawn(prepared) -> Result<LinuxChild, LinuxBackendError>
```

The ownership rules are:

- construction validates bwrap, kernel prerequisites, and configuration;
- `prepare` calls the common `BackendRequest::prepare_for` contract;
- `lower` consumes the complete immutable filesystem, network, environment,
  command, cwd, stdio, and timeout views;
- lowering is an internal immutable stage and is not exposed as a launch-plan
  argument API, so callers cannot bypass the authenticated hardening helper;
- `spawn` accepts only a backend-bound prepared request and constructs the
  internal launch plan itself; and
- all setup, lowering, launch, and OS failures have typed Linux error variants.

`ProcMountPolicy::Required` is the default. An explicitly disabled proc mount
must never be represented by an unlabelled `bool`, and the backend must reject
it when the selected policy requires proc visibility for correctness or
security. `BubblewrapSource` must distinguish discovery from an explicit path;
the backend must probe `--as-pid-1`, permission support, and argv0 compatibility
before accepting the executable.

### 4.4 Cageforge crate graph and the final facade

The native backend must use the existing Cageforge crates as one narrow data
flow. No crate may bypass an earlier security boundary or reconstruct a
broader value from an earlier stage:

```text
cageforge-config
    │  resolves trusted TOML into validated command/environment/policy values
    ▼
cageforge-command + cageforge-policy
    │  own portable execution intent and filesystem/network semantics
    ▼
cageforge-policy-compose
    │  computes requested policy ∩ PolicyCeiling = EffectiveSandbox
    ▼
cageforge-backend-api
    │  derives required capabilities and performs side-effect-free preflight
    ▼
cageforge-linux / cageforge-macos / cageforge-windows
    │  lower the prepared request and perform native enforcement
    ▼
operating-system process boundary
```

The Linux backend must consume the crates as follows:

| Crate | Backend responsibility boundary | Linux rule |
|---|---|---|
| `cageforge-config` | Produces validated values from TOML | Do not parse TOML or depend on config at runtime; consume its resolved outputs only |
| `cageforge-command` | Owns argv, working-directory intent, stdio, timeout, and environment intent | Use the prepared command, checked working directory, typed stdio/timeout values, and backend-selected core environment |
| `cageforge-path` | Owns portable native path equality, ordering, containment, and lexical path identity | Use it for portable path semantics; Linux canonicalization, symlink, mount, and descriptor safety remain native backend responsibilities |
| `cageforge-policy` | Owns declarative filesystem/network rules and resolved-target authorization inputs | Consume complete effective lowering; never turn a lexical decision or hostname decision into direct host I/O permission |
| `cageforge-policy-compose` | Narrows requested policy by the outer `PolicyCeiling` | Backend receives `EffectiveSandbox` only; it must preserve both composition layers and all narrowing requirements |
| `cageforge-backend-api` | Owns capability derivation, runtime-context validation, identity binding, and prepared handoff | Call `BackendRequest::prepare_for`; lower only `PreparedBackendRequest<LinuxBackend>` |
| `cageforge-core` | Future ergonomic facade and backend selection | May depend on selected backends; must not be a security bypass or a second policy implementation |
| `cageforge-upstream-review` | Development-time upstream tracking | Never a runtime dependency |

The final `cageforge-core` crate is intended to provide one convenient entry
point for applications, but it does not mean that every backend is compiled
into every binary. Its implementation must select the target-appropriate
backend through target configuration and optional backend features. A Linux
binary uses `cageforge-linux`, a macOS binary uses `cageforge-macos`, and a
Windows binary uses `cageforge-windows`; unsupported targets return a typed
platform error rather than a no-op backend.

The final facade may expose an API shaped like this:

```text
Engine::new(config) -> Result<Engine, CoreError>
Engine::prepare(command, effective_sandbox, runtime) -> Result<PreparedExecution, CoreError>
PreparedExecution::launch() -> Result<Child, CoreError>
```

These names are illustrative until the first native backend exists. The
non-negotiable behavior is that `Engine::prepare` delegates to the selected
backend's `BackendRequest::prepare_for`, and launch accepts only the
backend-bound prepared result. `Engine` must not expose a method that accepts a
raw `SandboxPolicy`, a raw `PolicyCeiling`, an unchecked `CommandRequest`, or a
hostname-only network decision for launch.

There is no cross-platform promise that a feature exists merely because one
backend supports it. The selected backend reports its actual
`BackendCapabilities` for its configured enforcement mechanism. Preparation
computes the exact capabilities required by the effective request:

```text
required(request) ⊆ advertised(selected_backend)
```

If this relation is false, preparation returns
`UnsupportedCapability { capability }` before any child process, file access,
DNS operation, or socket connection. The facade must not silently:

- fall back from Bubblewrap to an unenforced process;
- replace a restricted filesystem policy with unrestricted access;
- replace exact network authorization with hostname-only authorization;
- treat `External` as locally enforced; or
- claim a capability because another operating system backend supports it.

A backend may implement several native mechanisms internally, but each
configured instance must advertise the intersection of capabilities that its
chosen mechanism actually enforces. If a Linux implementation can enforce
workspace filesystem rules with Bubblewrap but cannot enforce Unix-socket
rules, a request requiring Unix-socket rules is rejected; it is never launched
with only the workspace restriction. This is the single capability contract
shared by all future backends.

## 5. Portable handoff contract

Every launch must begin with:

1. a `CommandRequest`;
2. an `EffectiveSandbox` produced by policy composition; and
3. a runtime `PathResolutionContext` containing the backend's absolute current
   directory and discovered special roots.

The backend must call `BackendRequest::prepare_for` and retain the resulting
`PreparedBackendRequest<'_, Self>`. It must not accept a raw
`SandboxPolicy`, a raw `PolicyCeiling`, or an unbound prepared request for
native lowering.

The backend must consume all immutable lowering layers from the prepared
request. It must not reconstruct policy from only the requested side, only the
ceiling side, or only aggregate decision helpers.

Capability advertising is an enforcement promise. The backend must advertise a
capability only after its implementation and integration tests prove that the
capability is enforced. Unsupported filesystem scopes, environment bases,
network modes, glob behavior, missing-path behavior, and timeout modes must
return the existing typed backend error rather than degrade to a broader mode.

## 6. Linux request matrix and error contract

The backend must answer every effective request with exactly one of these
outcomes: enforce it, delegate it through an explicitly trusted integration, or
return a typed unsupported/error result. There is no implicit fallback from a
restricted request to an unrestricted process.

| Effective request family | First Linux backend behavior |
|---|---|
| command execution | Enforce through the prepared command and Linux process boundary |
| explicit or inherited working directory | Resolve against the prepared runtime context and verify against effective filesystem policy |
| inherited, null, or piped stdio | Map to the corresponding native `std::process` handles |
| backend-default, limited, or disabled timeout | Enforce through the Linux child lifecycle; timeout must terminate the sandbox process group |
| restricted filesystem | Support all validated scopes that can be lowered safely |
| unrestricted filesystem | Support only when no restricted filesystem layer is required; network isolation may still require Bubblewrap |
| external filesystem enforcement | Reject by default unless a future trusted integration supplies proof of the external boundary |
| absolute/workspace/root/minimal/tmpdir/slash-tmp scopes | Resolve from `EffectivePathContext`; reject missing or ambiguous context |
| deny globs and scan depth | Expand existing matches before launch, include canonical symlink targets, enforce scan depth, and fail closed on unsafe or over-broad expansion |
| read-only subpaths | Apply after writable binds and preserve narrower carve-outs |
| missing-path behavior | Implement error/skip exactly; never reinterpret skip as write permission |
| default/additional protected paths | Protect existing and not-yet-existing paths against modification, replacement, and creation |
| disabled network | Isolate the network namespace, reject every pathname-capable AF_UNIX endpoint, and apply required process hardening while preserving process-local stream socketpair IPC |
| unrestricted network | Preserve host network only when no narrower network restriction is requested |
| external network enforcement | Reject by default without a trusted external integration |
| domain rules | Enforce through an isolated namespace and backend-owned HTTP/SOCKS gateway that resolves once and applies both effective policy layers |
| private/loopback/link-local restrictions | Enforce at the gateway using every resolved address before any exact connection attempt |
| `ResolvedNetworkTarget` authorization | Require one captured target and immediate exact-address authorization; connect only with the consumed authorized address |
| Unix socket rules | Proxy-routed mode denies pathname-capable AF_UNIX sockets while preserving AF_UNIX stream socketpair IPC; explicit allowlists remain typed unsupported on Linux |
| all/core/none environment bases | Apply the selected base; Linux `core` variables are selected by the backend |
| environment filters | Apply include/exclude filters after selecting the base and preserve the portable ordering |
| environment set/remove overrides | Apply after the selected base and filters according to `EnvironmentSpec` |
| external owner identity | Treat as a declaration only; do not claim enforcement without an integration proof |

The capability set must be derived from the configured backend and the actual
implemented lowering. In particular, a backend that only isolates all network
traffic must not advertise `NetworkDomainRules`,
`NetworkLocalAddressRestrictions`, `NetworkResolvedTargets`, or
`NetworkUnixSockets`.

Linux errors must preserve the stage and security meaning of a failure. The
minimum taxonomy is:

- `UnsupportedPlatform`;
- `UnsupportedCapability { capability }`;
- `InvalidConfiguration`;
- `BubblewrapUnavailable`;
- `BubblewrapIncompatible { missing: Vec<BubblewrapFlag> }`;
- `NamespaceUnavailable { namespace, message }`;
- `CapabilityDropUnavailable { message }`;
- `NestedUserNamespaceIsolationUnavailable { message }`;
- `ProcMountUnavailable { message }`;
- `UnsupportedSeccompArchitecture`;
- `InvalidRuntimeContext`;
- `FilesystemLoweringFailed`;
- `NetworkLoweringFailed`;
- `HardeningFailed`;
- `ProcessSpawnFailed`;
- `ProcessTimedOut`; and
- `ChildTerminatedByPolicy`.

Errors must retain the underlying OS error where one exists, but they must not
expose a generic string in place of a typed security decision. Filesystem
lowering therefore carries a `FilesystemLoweringError` sub-error rather than a
free-form `reason`; network mount relationships, unsupported combinations,
policy-lowering expectations, gateway setup, hardening, bridge, framed
environment/status transport, and gateway lifecycle failures use the same
typed sub-error approach. Dynamic diagnostics from Bubblewrap or the host
gateway may remain strings because they are external observations, not
security decisions. Every error variant that can be produced before launch
must have a black-box negative test.

The helper protocol also has explicit resource bounds: 4,096 environment
entries, 1 MiB per entry, and 16 MiB per complete environment frame. The
writer and reader enforce the same bounds. This prevents a malformed setup
frame from turning the authenticated transport into an unbounded allocator.

## 7. Linux enforcement architecture

### 7.1 Bubblewrap process boundary

The first Linux implementation uses a system Bubblewrap executable discovered
outside the current working directory. The backend must validate the selected
executable before use and must reject a missing or incompatible executable.

Bundled Bubblewrap is implemented as the separately identified
`cageforge-bwrap` component described in Specification 0015. Bubblewrap keeps
its own upstream license and notices; it is never treated as Apache-2.0
Cageforge code. The backend verifies a bundled digest on the opened file,
copies the validated executable into an anonymous sealed memory file, repeats
all capability probes against that snapshot, and executes only the sealed
descriptor. A later path replacement or in-place source update therefore
cannot change the binary used for a spawn. The hardening helper is captured by
the same immutable-snapshot mechanism and copied into the sandbox through
Bubblewrap's descriptor-data operation with mode `0500`.

The pinning contract includes the regular-file identity captured during
compatibility validation. If the Bubblewrap path names a different device or
inode when the backend is constructed, construction fails closed instead of
launching an unprobed replacement. Snapshot creation, copying, permission
setup, sealing, and read-only launch-descriptor failures remain separate typed
operations. Neither executable is launched while a writable snapshot
descriptor remains open. The helper snapshot supports repeated launches from
one backend without sharing a consumed file offset.

The frozen Codex baseline recorded in [UPSTREAM.md](../UPSTREAM.md) discovers,
probes, and executes system Bubblewrap by pathname. Cageforge intentionally
uses the immutable snapshot above because its reusable library boundary may
outlive mutable application or packaged-resource paths.

The generated Bubblewrap plan must establish, as applicable:

- a new user namespace;
- a new PID namespace;
- a new IPC namespace for every launch;
- empty effective, permitted, inheritable, bounding, and ambient Linux
  capability sets for the user command;
- disabled nested user-namespace creation for the user command;
- a new network namespace when the effective network mode requires isolation;
- a fresh `/proc` unless the backend has a documented, typed reason to reject
  or disable it;
- a process-death relationship with the launcher;
- the verified working directory; and
- the complete filesystem mount plan before the user command starts.

The backend must execute the command only after the complete plan is built and
validated. A partially built plan must never be launched.

The IPC namespace is unconditional because the portable policy has no
capability that authorizes access to host System V shared-memory segments,
semaphore sets, or message queues. Mounting a private `/dev/shm` protects the
filesystem-backed POSIX shared-memory namespace but does not isolate those
System V IPC objects. The frozen Codex Bubblewrap plans in
`codex-rs/linux-sandbox/src/bwrap.rs` unshare user and PID namespaces but retain
the host IPC namespace. Cageforge intentionally requires Bubblewrap's
`--unshare-ipc` flag and probes it before accepting the executable, because it
runs arbitrary third-party commands rather than a product-controlled helper.

Compatibility validation must probe user, PID, IPC, and network namespace
creation separately. A runtime denial returns
`NamespaceUnavailable { namespace, message }`; its display form identifies the
exact Bubblewrap flag and the corresponding kernel or outer-container
requirement. A missing command-line option remains
`BubblewrapIncompatible { missing: Vec<BubblewrapFlag> }`. Every
`BubblewrapFlag` value must provide the exact command-line spelling and a
non-empty explanation of the Cageforge operation that requires it. The error's
display form includes both for every missing option and tells the operator to
install a compatible system Bubblewrap or use the `bundled-bubblewrap` feature.
This executable-compatibility error remains separate from native host denials,
preventing an IPC, PID, network, capability, nested-userns, or procfs
restriction from being reported as missing executable support.

When procfs is required, the backend must probe `--proc /proc` independently.
A native denial returns `ProcMountUnavailable { message }`; its display form
names the exact flag, preserves Bubblewrap's diagnostic, and identifies procfs
mount permission inside user and PID namespaces as the host prerequisite.

Every launch must pass `--cap-drop ALL`, even when the application itself runs
as UID 0. Upstream Bubblewrap intentionally inherits the caller's effective
capabilities by default when its real UID is zero; creating another user
namespace does not by itself clear those capabilities. The frozen Codex
Bubblewrap plans do not pass an explicit capability-drop option. Cageforge
intentionally strengthens that behavior because arbitrary plugin, agent, game,
or build commands have no portable capability grant and must receive zeroed
effective, permitted, inheritable, bounding, and ambient sets. Compatibility
validation checks both the option and a native capability-drop probe;
`CapabilityDropUnavailable { message }` identifies a runtime denial without
misreporting it as a namespace failure.

Every launch must also pass `--disable-userns`. Creating a nested user
namespace grants the creating process capabilities in that namespace and
widens the Linux kernel attack surface even after the outer capability sets
were cleared. The portable policy has no capability that authorizes
`CLONE_NEWUSER`, so neither unrestricted filesystem nor unrestricted network
access implies permission to create one. Bubblewrap applies a namespaced
`user.max_user_namespaces` lockdown, enters its final user namespace, and
verifies that another namespace cannot be created. The frozen Codex
Bubblewrap plans do not request this lockdown; Cageforge intentionally uses a
stricter default for arbitrary third-party commands. Missing option support is
reported by `BubblewrapIncompatible`; a native lockdown failure is
`NestedUserNamespaceIsolationUnavailable { message }`.

The backend reserves `/dev` for Bubblewrap's minimal device tree, `/proc` for
the fresh PID namespace, and `/dev/.cageforge-runtime` for the authenticated
helper and restricted-network bridge. A policy rule that targets one of these
runtime paths or a descendant is rejected during lowering rather than being
silently shadowed by internal mounts. Internal helper and gateway mounts are
read-only or hidden from the user command. A root-wide policy necessarily
includes the reserved runtime path, but the runtime itself is not writable by
the child.

### 7.2 Filesystem lowering

Filesystem lowering must preserve every effective layer:

- restricted, unrestricted, and externally enforced modes;
- absolute, workspace, root, minimal, temporary, and `/tmp` scopes;
- read, write, and deny access;
- deny globs and their scan-depth limit are expanded by a backend-owned native
  scanner before Bubblewrap starts; both logical matches and canonical
  symlink targets are masked;
- read-only subpaths;
- missing-path behavior; and
- default and additional protected relative paths.

For restricted read policies, the backend must create a read-only baseline or
an empty root with only approved read mounts. Writable roots must be layered
after the read baseline. Narrower rules must be applied in deterministic
specificity order so that a narrower deny or read-only carve-out cannot be
overwritten accidentally by a broader bind mount.

Before creating a mount plan, the backend must resolve existing paths using
Linux filesystem semantics and account for symlinks, mount points, and bind
mounts. A lexical `Allow` from the portable policy is not permission to call a
host filesystem operation directly. Missing paths must follow the effective
`MissingPathBehavior`; they must not silently become writable.

Any bind mount whose logical source or destination crosses a symlink below a
writable scope must be rejected before Bubblewrap starts. This prevents an
explicit child scope from turning a mutable workspace symlink into a bind of
an unrelated host directory; the failure must be a typed lowering error, not a
late Bubblewrap handshake failure.

Protected paths must be mounted read-only or otherwise blocked before the
command can create or replace them. The implementation must cover both
existing protected paths and protected paths that do not yet exist.

`.git` is the default protected relative path below writable scopes. A trusted
request may explicitly opt out through the typed policy API or the matching
TOML security setting when the sandbox is not used for source-code work. That
opt-out removes only the default `.git` entry: additional protected paths stay
active, and a stricter ceiling or backend may retain protection or reject the
request. Native tests must cover the default, opt-out, restored ceiling, and
additional-path cases.

Bubblewrap mount-source descriptors remain close-on-exec in the parent and are
made inheritable only in the child-side spawn hook. The validated Bubblewrap
and hardening-helper descriptors follow the same rule. This is required for
threaded applications: temporarily clearing close-on-exec in the parent would
allow an unrelated concurrent process spawn to inherit another sandbox
instance's host mount descriptors.

The protected-create monitor must not remove a path through an unchecked host
pathname. It opens every parent component with `openat(..., O_NOFOLLOW)`,
opens the final directory without following symlinks, compares its device/inode
identity with the current parent-relative entry, and only then reserves and
removes the entry. A replacement or identity mismatch fails closed rather than
deleting a different directory under the protected name; recursive cleanup
must not follow child symlinks.
Protected-path monitoring also rejects a writable symlink in the parent chain
before registering the monitor. Cross-process synthetic-mount owner markers
include the process start time as well as the PID, so PID reuse cannot keep a
stale owner alive indefinitely. Bridge readiness has a finite deadline and a
startup timeout is returned as a typed error; no setup phase may wait forever
for a child that failed before publishing its port.

### 7.3 Process hardening

The restricted child must receive Linux process hardening before the untrusted
command can run:

- enable `PR_SET_NO_NEW_PRIVS` whenever seccomp or another restricted policy
  requires it;
- set `PR_SET_DUMPABLE` to zero on the trusted helper and set `RLIMIT_CORE` to
  zero for both the helper and command;
- replace the caller's inherited session keyring with a new anonymous session
  keyring for every launch, including otherwise unrestricted policies;
- establish the command as a traced child of the trusted helper before
  `execve`, then set `PTRACE_O_EXITKILL` and keep that trace relationship for
  the complete command lifetime, because Linux resets an ordinary executable's
  dumpable attribute during `execve`; this prevents another same-user process
  from attaching in the post-exec window that a pre-exec
  `PR_SET_DUMPABLE(0)` call cannot close;
- install a narrowly defined seccomp policy for the selected network and
  process restrictions;
- apply hardening to the child boundary, not to the long-lived parent process;
- preserve close-on-exec and explicit file-descriptor inheritance rules; and
- return a typed backend error if the requested hardening cannot be installed.

The frozen Codex baseline applies `PR_SET_DUMPABLE(0)` to its own process in
`codex-rs/process-hardening/src/lib.rs` and installs the Linux command seccomp
filter in `codex-rs/linux-sandbox/src/landlock.rs`. Cageforge executes arbitrary
third-party programs rather than only a pre-hardened product binary, so it must
add the trusted parent-tracer boundary above. The helper establishes tracing
and `PTRACE_O_EXITKILL` before publishing setup readiness, follows fork, vfork,
clone, and exec events, and applies the same options to every new tracee before
letting it run. The command's seccomp filter permits only its one pre-exec
`PTRACE_TRACEME` request and rejects every other `ptrace` operation; after exec
the existing trace relationship makes another `PTRACE_TRACEME` fail as well.
It rejects `clone(CLONE_UNTRACED)` and returns `ENOSYS` for `clone3`, whose
pointer-based flags cannot be inspected by classic seccomp, so compatible
runtimes fall back to inspectable `clone`. The helper forwards command signals
and reports the original raw exit status through the authenticated status
channel.

The frozen Codex baseline and Bubblewrap leave the caller's session keyring
attached to the sandboxed process. A user namespace does not revoke keys that
the process possesses through that inherited keyring, so a command that learns
a host key serial number can still read the key. Cageforge deliberately
isolates this additional boundary in the authenticated helper with
`keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)`. A kernel rejection fails setup as
the typed `KeyringIsolation` category instead of launching with the host
keyring.

The frozen Codex restricted-network seccomp policy permits every AF_UNIX
`socket()` and `socketpair()` type, blocks `connect` and `sendto`, but leaves
`sendmsg` available. Linux datagram endpoints can supply a pathname through
`sendmsg(msg_name=...)`, and datagram socketpair endpoints can also be
redirected with `connect` or `sendto`. The frozen proxy-routed policy likewise
permits every AF_UNIX socketpair type on the assumption that those descriptors
cannot reach a pathname socket. Cageforge therefore permits AF_UNIX
`SOCK_STREAM` sockets and socketpairs, including normal `CLOEXEC` and
`NONBLOCK` flags, but denies `SOCK_DGRAM` and `SOCK_SEQPACKET` endpoints whenever
pathname Unix isolation is required. The base socket type is checked with the
Linux UAPI type mask so creation flags cannot bypass or accidentally trigger
the rule. This preserves process-local stream IPC without leaving a pathname
Unix-socket route around disabled or proxy-routed networking.

Before the command is released, the authenticated helper channel carries a
framed setup result. A rejected setup includes a stable typed failure category
and the originating OS error number when one exists; `stderr` is supplemental
diagnostic output and is not the error API. Unknown tags and failure codes fail
closed. Authentication failures themselves are not sent over an untrusted or
unverified channel.

After release, the same authenticated channel carries either the command's raw
wait status or a stable typed helper-runtime failure with its originating OS
error number. A helper-side command-start, command-wait, or trace-supervision
failure must never be represented as the user command's exit code; in
particular, an internal command-start failure cannot be confused with a real
command that exits with status 126. A missing, truncated, or unknown runtime
frame is a typed transport failure. `stderr` remains only supplemental or
last-resort diagnostic output when the authenticated channel itself is broken.

The frozen Codex `codex-rs/linux-sandbox/src/linux_run_main.rs` inner stage
forks, reaps, and exits with the final command status; internal failures panic
inside that product helper. Cageforge intentionally keeps a distinct private
runtime-result protocol because its trusted helper remains alive to supervise
arbitrary third-party process trees and the per-sandbox network bridge. Library
callers therefore receive helper failures as `LinuxBackendError` values rather
than parsing helper stderr or interpreting reserved-looking exit codes.

The backend must not claim that a filesystem capability is enforced merely
because `no_new_privs` or seccomp was installed. Filesystem and process
capabilities remain separately advertised.

### 7.4 Network lowering

Network namespace isolation implements all-network-disabled behavior. Narrower
enabled policies use the same isolated namespace plus a backend-owned gateway;
direct child connections have no route to the host network and proxy-aware
traffic reaches the gateway through a private Unix/TCP bridge.

The Linux network runtime must:

1. resolve a hostname once;
2. construct a `ResolvedNetworkTarget` containing every result;
3. authorize the exact `SocketAddr` immediately before connecting; and
4. connect only to the authorized address without performing an unverified
   second lookup.

The gateway must implement ordinary HTTP proxying, HTTP `CONNECT`, and SOCKS5
`CONNECT` without re-resolving an authorized hostname. A malformed request,
empty DNS result, private-address violation, target outside the captured
resolution, bridge failure, or unsupported protocol fails closed. Product
features such as MITM, credential injection, audit upload, and remote policy
reload remain outside this backend.

The host-side authenticated relay must release its local bridge slot when the
gateway handler completes or either transport direction closes. After gateway
completion it may drain already-produced gateway output only within the
configured relay-idle bound; a sandbox process that keeps its request half open
after a handshake timeout or protocol rejection must not retain that slot.
The frozen Codex `linux-sandbox/src/proxy_routing.rs` bridge joins its cloned
TCP reader after closing only the write half. Cageforge intentionally closes
both TCP halves after final gateway EOF and bounds host-side output draining,
because its per-sandbox bridge exposes a finite connection budget to arbitrary
third-party commands.

Every launch owns a distinct gateway socket directory, ingress token,
connection semaphore, timeout state, and cleanup handle. Concurrent instances
must not authenticate to, consume the budget of, or clean up another
instance's gateway. Host coordination for a missing protected mount target is
shared only by UID and canonical host target, so two instances protecting the
same path cannot tear down that protection while either remains active.

### 7.5 Environment and command execution

The backend must select the actual Linux core environment before applying the
portable `EnvironmentSpec`. The `CoreEnvironment` label must never be applied
to the full inherited host environment.

The process layer must use the prepared command specification, verified working
directory, prepared stdio, selected timeout policy, and narrowed environment.
It must not read the original unverified command cwd after preflight.

## 8. Crate module layout

The implementation remains one public backend crate with focused private
modules:

```text
crates/cageforge-linux/
├── src/
│   ├── lib.rs                    # public API and Linux cfg boundary
│   ├── backend.rs                # preflight, lowering orchestration, spawn
│   ├── bwrap.rs                  # executable discovery and namespace arguments
│   ├── config.rs                 # typed backend settings
│   ├── error.rs                  # typed Linux failures
│   ├── filesystem/               # native mount, glob, and protected-path plan
│   ├── hardening/                # authenticated helper, seccomp, environment
│   ├── network/                  # per-launch gateway and bridge lifecycle
│   ├── process/                  # child and pidfd timeout lifecycle
│   ├── environment_transport.rs  # bounded helper environment handoff
│   ├── helper_protocol.rs        # private authenticated setup protocol
│   └── status_transport.rs       # user-command exit status handoff
└── tests/linux_backend.rs             # black-box Linux enforcement suite
```

The test files must begin with the Linux target guard:

```rust
#![cfg(target_os = "linux")]
```

They must exercise the public backend API. Internal helpers may have focused
unit tests only where black-box execution cannot observe the required
invariant, such as deterministic argument ordering.

## 9. Required Linux integration tests

The native test suite must fail when its required Linux prerequisites are not
available in the required CI job. It must not silently convert missing
Bubblewrap, unavailable user namespaces, unavailable proc mounts, or failed
hardening into a passing skip. Optional developer environments may run the
portable tests without native prerequisites, but the dedicated Linux backend
job is an enforcement gate.

### Filesystem tests

- read-only root denies writes outside an approved writable root;
- writable workspace allows writes only within the effective workspace roots;
- `.git` and configured protected paths cannot be created, replaced, or
  modified;
- read-only subpaths remain read-only under writable parents;
- nested deny and writable carve-outs preserve specificity order;
- missing paths follow error and skip behavior exactly;
- symlink-in-path cannot escape the approved root;
- mount and bind-mount boundaries cannot widen access; and
- a cwd outside the effective filesystem is rejected before launch.

### Process tests

- command argv, stdio, environment, and verified cwd reach the child;
- relative cwd is resolved against the runtime current directory;
- timeout and cancellation terminate the sandboxed process tree;
- dropping a running `LinuxChild` terminates and reaps the Bubblewrap boundary;
- parent death does not leave an orphaned sandbox process;
- restricted and unrestricted filesystem modes cannot attach to host System V
  IPC objects;
- restricted and unrestricted commands launched by a namespace-root caller
  have zero effective, permitted, inheritable, bounding, and ambient Linux
  capabilities;
- restricted and unrestricted commands cannot create nested user namespaces;
- restricted and unrestricted commands cannot read keys possessed through the
  caller's inherited session keyring;
- `NoNewPrivs` is visible inside the restricted child; and
- unsupported capabilities fail before the child is started.

### Network tests

- disabled networking rejects loopback and public destinations;
- disabled networking rejects pathname Unix datagrams sent through `sendmsg`
  while preserving process-local stream socketpair IPC;
- unrestricted networking is not accidentally treated as disabled;
- hostname-only decisions cannot authorize a connection;
- an address outside the captured `ResolvedNetworkTarget` is rejected;
- domain allow and deny rules are enforced for HTTP `CONNECT` and SOCKS5;
- private and loopback DNS results remain denied unless policy explicitly
  permits them; and
- direct child connections cannot bypass the isolated gateway.

## 10. Linux CI contract

The Linux backend CI must run on real Linux runners, not a generic portable
job and not a Docker image that hides the host kernel requirements.

The initial required matrix is:

| Runner | Rust target | Purpose |
|---|---|---|
| `ubuntu-24.04` or the project Linux x64 runner | `x86_64-unknown-linux-gnu` | required Linux enforcement tests |
| `ubuntu-24.04-arm` or the project Linux ARM64 runner | `aarch64-unknown-linux-gnu` | required architecture coverage |

Each Linux backend job must:

1. install `pkg-config`, `libcap` development files, and any native build
   packages required by the selected Rust dependencies;
2. enable unprivileged user namespaces and verify that the setting took
   effect; on Ubuntu runners that expose
   `kernel.apparmor_restrict_unprivileged_userns`, disable that CI-only
   restriction before probing `uid_map`, because `kernel.unprivileged_userns_clone`
   alone does not guarantee that the runner permits the mapping;
3. verify that `--disable-userns` prevents nested user-namespace creation;
4. verify as UID 0 that `--cap-drop ALL` clears every Linux capability set
   inside the Bubblewrap user namespace;
5. build `cageforge-bwrap`, stage its `bwrap` and `bwrap.sha256` resources,
   build the backend and runtime helper, and run the tests against the staged
   Bubblewrap;
6. run formatting, Clippy with `-D warnings`, and the backend integration
   suite;
7. preserve `RUST_BACKTRACE=1` and produce a JUnit or equivalent test report;
8. cancel superseded runs for the same pull request; and
9. fail the required status when native prerequisites or enforcement tests
   fail.

The portable default job must continue to test all portable crates on one
Linux runner. A change to a portable crate, `cageforge-core`, workspace
metadata, or CI configuration must run the complete OS matrix. A change only
to `cageforge-linux` may select Linux core/backend jobs, but the branch
protection gate must require their stable aggregate result.

Cross-compilation to musl may be a build/release check, but it does not replace
runtime enforcement tests on a glibc Linux runner. Runtime tests must not claim
coverage for a target that was only compiled.

## 11. Implementation order

Implementation must proceed in these stages:

1. add the crate skeleton with the Linux cfg boundary and non-Linux compile
   behavior;
2. implement backend identity, capability declaration, and
   `BackendRequest::prepare_for` handoff;
3. implement deterministic filesystem lowering and Bubblewrap plan tests;
4. implement actual process launch and Linux namespace setup;
5. add process hardening and required hardening tests;
6. add filesystem escape and protected-path integration tests;
7. add only the network modes whose exact enforcement is implemented;
8. update Linux CI and label routing to run the real crate; and
9. run the complete workspace and native Linux test matrix before considering
   `cageforge-core` facade work.

No later backend crate should be started until the Linux backend's required
tests, Clippy, documentation, and Linux CI gate pass.

## 12. Readiness criteria

`cageforge-linux` is ready for the next platform backend only when:

- every advertised capability has a corresponding enforcement test;
- every unsupported capability has a typed negative test;
- filesystem tests cover symlink, mount, protected-path, and cwd boundaries;
- process tests cover timeout, cleanup, stdio, environment, and hardening;
- network tests prove exact-address handling or explicitly prove the feature is
  rejected as unsupported;
- x86_64 and ARM64 Linux runners pass without prerequisite skips;
- portable workspace tests remain green on Linux, macOS, and Windows; and
- provenance and third-party license records are complete if any upstream or
  bundled source is introduced.
