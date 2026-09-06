# Specification 0017: macOS Backend Implementation

Status: draft; implementation starts on `feat/macos-sandbox`

## 1. Purpose

`cageforge-macos` is the macOS-native execution backend for Cageforge. It
accepts a backend-bound `PreparedBackendRequest<'_, MacosBackend>` and lowers
the complete effective command, filesystem, network, environment, stdio, and
timeout contract into an OS-enforced Seatbelt boundary.

The backend is a reusable library object. Every `spawn` creates a separate
Seatbelt policy and process boundary for one command and its descendants.
Several calls may run concurrently with different effective policies; no
mutable global policy or shared authorization table may make one instance
inherit another instance's rules.

The implementation is independently authored in Cageforge. The frozen Codex
checkout is a behavioral reference only; no Codex source or product protocol
is copied into this crate.

## 2. Platform and dependency boundary

The native implementation and native integration tests use the exact guard:

```rust
#[cfg(target_os = "macos")]
```

The crate remains a workspace member and cross-target build surface on other
hosts, but it must not report a successful macOS sandbox there. A non-macOS
caller receives an explicit unsupported-platform result from a future
cross-platform facade rather than silently launching an ordinary process.

The crate may depend on `cageforge-backend-api`, `cageforge-command`,
`cageforge-network-proxy`, `cageforge-path`, `cageforge-policy`, and
`cageforge-policy-compose`, plus focused macOS/standard-library bindings. It
must not depend on Codex crates, PTY or agent protocols, telemetry, or
product-specific process state.

## 3. Frozen upstream correspondence

The behavior review is against commit
`c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc` recorded in `UPSTREAM.md`:

| Codex area | Behavior reviewed | Cageforge decision |
| --- | --- | --- |
| `codex-rs/sandboxing/src/seatbelt.rs` | Seatbelt command construction, closed-by-default policy, filesystem scopes, protected paths, glob denials, Unix sockets, and proxy-port rules | Independently reimplemented against `EffectiveSandbox`; no Codex command/profile types are exposed |
| `codex-rs/sandboxing/src/seatbelt_base_policy.sbpl` | Required loader, process, device, preference, IPC, and system-service allowances | Re-authored as Cageforge policy text and reviewed for the supported command contract |
| `codex-rs/sandboxing/src/seatbelt_network_policy.sbpl` | Minimal network service allowances needed by macOS clients | Re-authored and composed only with the selected effective network mode |
| `codex-rs/sandboxing/src/restricted_read_only_platform_defaults.sbpl` | Minimal system/framework visibility for restricted commands | Re-authored as a Cageforge platform-default policy; it is never used to grant workspace access |
| `codex-rs/sandboxing/src/manager.rs` and `src/spawn.rs` | Platform selection and process handoff | Replaced by `SandboxBackend`, backend-bound preparation, and `MacosChild`; PTY remains outside the portable API |

Every retained behavior must have an allowed and denied black-box test on a
macOS runner. Any Seatbelt rule whose effect cannot be demonstrated on the
supported runner is not advertised as a capability.

## 4. Native enforcement contract

`MacosBackend::new` validates the fixed `/usr/bin/sandbox-exec` executable (or
an explicitly selected absolute executable) before any command launch. The
backend never searches `PATH` for the enforcement executable. Each launch
passes a complete closed-by-default profile through `-p`, with policy values
supplied as separate `-D` parameters; untrusted paths are never interpolated
into executable arguments or shell text.

The policy is built from both immutable layers returned by
`PreparedBackendRequest::filesystem_lowering` and
`PreparedBackendRequest::network_lowering`. A backend must not lower only the
requested policy or only the ceiling. Candidate scope intersections are
checked again through the prepared effective decision before they become
Seatbelt allow rules.

The filesystem lowering must:

- reject externally owned filesystem enforcement and unsupported ownership
  combinations with typed errors;
- resolve workspace, root, minimal, temporary, and absolute selectors only
  through the narrowed effective path context;
- apply missing-path `Error` or `Skip` exactly, without silently creating an
  absent target;
- reject NUL, parent traversal, symlink, and unsupported native path forms
  before policy construction;
- enforce read, write, deny, read-only descendant, protected-relative-path,
  and deny-glob rules without widening an effective intersection;
- bound glob expansion according to the effective scan-depth requirement and
  fail closed when the requested semantics cannot be represented; and
- keep platform-default reads separate from caller workspace and write
  scopes.

Unrestricted filesystem access is supported only when Seatbelt's explicit
unrestricted profile is selected and the effective policy is unrestricted.
An external filesystem owner is never treated as unrestricted local access.

For network enforcement:

- disabled networking has no outbound or inbound network allowance;
- unrestricted enabled networking retains direct network behavior only when
  the complete effective policy has no domain, local-address, or Unix-socket
  narrowing requirements;
- domain rules and local-address restrictions use a per-spawn authenticated
  `cageforge-network-proxy` ingress, and the Seatbelt policy permits only that
  instance's loopback port(s);
- the ingress prepends its private gateway authentication proof and never
  places the proof in the command environment or argv;
- the gateway performs one DNS snapshot and authorizes the exact
  `SocketAddr` immediately before connecting; and
- pathname Unix-socket rules are lowered only when their exact Seatbelt
  semantics are demonstrated. Otherwise the backend returns the typed
  unsupported-capability error and never silently permits all sockets.

Each proxy ingress and gateway owns its policy, key, listener, and limits.
Dropping one child closes and joins only its own runtime. A second instance
cannot reuse the first instance's policy merely because both are on loopback.

## 5. Process and lifecycle contract

The backend maps `StdioSpec` to explicit inherited, null, or piped standard
streams. The child API owns all pipe endpoints and never uses stdout or stderr
as a control protocol. Setup and launch failures are typed library errors.

The Seatbelt boundary is placed in its own process group. A timeout, explicit
kill, parent drop, or launch failure terminates the complete process group and
waits for confirmation before releasing gateway and child resources. If a
bounded cleanup attempt cannot confirm termination, a detached recovery owner
retains the child and all enforcement resources and retries termination; it
does not release a live boundary's policy resources as if cleanup succeeded.

The command timeout is per prepared command and is distinct from gateway
handshake/relay limits. Backend construction and one command's timeout do not
serialize unrelated instances.

## 6. Capabilities

The backend advertises only capabilities implemented and tested on the native
macOS runner. The intended complete set includes command execution, checked
working directories, all standard streams, all timeout modes, restricted and
unrestricted filesystem modes, supported scope/glob/protection families,
disabled and enabled networking, exact resolved-target authorization, and all
portable environment transformations.

External ownership and any unsupported Unix-socket or native path behavior
remain typed unsupported capabilities. Capability declarations are not a
promise that a value can merely be parsed.

## 7. Required tests and CI

Portable tests cover capability declarations, deterministic profile rendering,
both effective lowering layers, path validation, environment application,
stdio, timeout modes, and independent backend identities.

Native macOS black-box tests cover at least:

- a command and all descendants inherit the Seatbelt boundary;
- reads and writes outside effective scopes are denied;
- writable roots retain read-only and protected descendants;
- symlink/path and deny-glob escape attempts fail closed;
- disabled networking blocks direct connections;
- enabled unrestricted networking preserves direct connections;
- restricted networking reaches only exact authorized gateway targets;
- separate simultaneous instances retain separate policies and gateway keys;
- unrelated inherited file descriptors do not cross the launch boundary;
- timeout, explicit kill, drop, and parent death terminate the complete group;
- every expected setup, policy, launch, and lifecycle failure is typed; and
- every enabled feature combination passes formatting, Clippy, tests, and
  documentation checks.

The common-component jobs must not replace this native test. The dedicated
`macOS sandbox` job runs on the explicit current macOS runner and is selected
on `main`, when the macOS crate or its transitive dependencies change in a PR,
or when the maintainer adds `sandbox-macos`.

## 8. Release boundary

The crate is Apache-2.0 Cageforge-authored code with no bundled third-party
source. Its public README describes the reusable library API and one-spawn/
one-boundary model. Exact upstream correspondence and audit history remain in
this specification and `UPSTREAM.md`, not in the README.
