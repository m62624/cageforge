# Specification 0011: Backend API Contract

Status: accepted; required before native backend implementation

## Purpose

`cageforge-backend-api` is the boundary between Cageforge's portable command
and policy models and an operating-system backend. It defines the common
capability and preparation contract without implementing process launch,
filesystem I/O, DNS, network I/O, PTY handling, or operating-system
enforcement.

The crate is intentionally smaller than `cageforge-core`. Native backends
implement this contract, while `cageforge-core` later provides an ergonomic
facade and backend selection after native backends exist.

## Required input boundary

The backend API accepts:

- a `cageforge_command::CommandRequest` describing execution intent; and
- a `cageforge_policy_compose::EffectiveSandbox` containing the requested
  policy narrowed by its outer `PolicyCeiling`.

It must not accept a raw `SandboxPolicy` as an enforcement request. A backend
must never bypass policy composition by using the requested policy directly.

The API may retain read-only access to the executable/argv values and effective
sandbox in a prepared request, but it must not expose mutable policy or command
internals. The prepared request must not return the original `CommandRequest`:
its optional or relative working directory would let a backend accidentally
discard the checked runtime directory. Backends use the prepared command spec,
the separate checked working directory, and the typed environment/stdio/timeout
accessors instead.

## Public contract

The crate will expose the following independent concepts:

- `BackendCapability`: one typed capability that a native backend may support;
- `BackendCapabilities`: a deterministic set of supported capabilities;
- `BackendRequest`: the command and effective sandbox submitted for preflight;
- `PreparedBackendRequest<'_, B>`: an opaque, validated handoff produced only
  after preflight succeeds and type-bound to the `SandboxBackend` `B` whose
  capabilities were checked, with a runtime identity check for the exact
  backend instance;
- `BackendContractError`: common failures such as unsupported capabilities,
  invalid runtime context, or invalid environment preparation; and
- `SandboxBackend`: a synchronous preparation trait implemented by native
  backends.

`BackendRequest::prepare_for` performs preparation using the capabilities
advertised by the supplied `SandboxBackend` and a backend-supplied runtime
`PathResolutionContext`. The trait itself exposes only
capability discovery, so an implementation cannot override the common
preflight algorithm and validate against a broader, self-selected capability
set. The API does not define a common process type, async runtime, PTY, signal
model, cancellation model, or process-tree lifecycle. A native backend owns
those concerns in its own API and error type.

The prepared handoff is bound to the concrete backend type `B` at compile time
and stores a runtime `BackendIdentity` for the exact instance passed to
`prepare_for`. A native lowering method should accept
`PreparedBackendRequest<'_, Self>` and pass that same instance to every
accessor. This prevents a request preflighted against one backend instance
from being consumed by another instance of the same type with different
capabilities or enforcement state. The prepared handoff also stores the
capability snapshot and each accessor rejects a changed snapshot with a typed
`BackendCapabilitiesMismatch` error. The identity and snapshot checks are
caller-managed contract checks, not proof that operating-system enforcement
exists.

Capability values must use enums or named types rather than ambiguous boolean
parameters. The capability vocabulary must cover the portable inputs that can
change backend safety:

- filesystem access modes and protected paths;
- workspace, root, temporary, and minimal path scopes, with separate
  capabilities for absolute, workspace, system-root, minimal, temporary-
  directory, and slash-tmp selectors, including the runtime scope needed by
  workspace-relative selectors and deny globs;
- deny-glob support, including explicit and unbounded scan-depth semantics,
  and missing-path behavior;
- network domain rules, resolved-address authorization, local-address
  restrictions, and Unix sockets;
- external enforcement declarations;
- environment bases, filters, and overrides; and
- supported command stdio and timeout modes.

In particular, a restricted filesystem rule with a concrete scope requires
`FilesystemMissingPathBehavior`, and a locally enforced network policy with
`LocalNetworkAccess::Deny` requires `NetworkLocalAddressRestrictions` in
addition to exact resolved-target authorization.

The API must not claim a capability merely because a portable value can be
parsed. A native backend must report a capability only when it can enforce the
corresponding rule safely.

## Preflight behavior

Preparation is a synchronous, side-effect-free validation step. It receives
the backend's runtime `PathResolutionContext` and must:

1. verify that the effective policy and command can be represented by the
   backend's capabilities;
2. preserve the effective workspace-root restriction and use
   `EffectiveSandbox::path_context` with the backend's runtime context;
3. require a backend-selected `CoreEnvironment` before applying a core
   environment request;
4. reject unsupported filesystem rules with a typed error instead of silently
   dropping or widening them;
5. consume only the combined effective decisions, aggregate requirements, and
   complete immutable lowering views exposed by `EffectiveSandbox`; private
   requested/ceiling policies are never a backend choice. Every layer in a
   lowering view is mandatory input to native enforcement; and
6. keep network preparation on the resolved-target path. A hostname-only
   decision is never a connection authorization.

Preparation must always receive the runtime current directory and evaluate the
effective working directory against the effective filesystem policy. If the
command contains an explicit working directory, it is resolved against that
runtime directory when relative. If the command omits one, the runtime
directory is the directory the child would otherwise inherit. A missing
runtime current directory is a typed preparation error; a backend cannot
satisfy the `WorkingDirectory` capability by silently inheriting its own
process cwd. Denied directories fail preparation with a typed error.

The prepared request also exposes checked lowering helpers. Its
`PreparedBackendRequest::command_spec` contains only the executable and argv;
the checked cwd is available only from
`PreparedBackendRequest::working_directory`. This keeps a backend from
reconstructing an unchecked inherited or relative cwd from the original
command. The remaining launch values are exposed through typed accessors, and
the final environment is available only through
`PreparedBackendRequest::apply_environment`.
The other checked lowering helpers are:
`PreparedBackendRequest::path_context` returns the runtime context already
narrowed during `prepare_for`; `PreparedBackendRequest::working_directory`
returns the effective cwd resolved against that context; and
`PreparedBackendRequest::apply_environment` applies a backend-selected
`EnvironmentInput`. The prepared request also exposes effective filesystem
decision helpers using this bound context and the resolved network
authorization flow, so a backend does not need to manually combine requested
and ceiling policies. A symbolic filesystem selector with no paths in the
effective context is denied; it cannot be evaluated against a broader runtime
context. The context is also bound to this effective result, so contexts from
different requests are rejected. Their composition failures remain typed
backend contract errors.

`PreparedBackendRequest::filesystem_lowering` and
`PreparedBackendRequest::network_lowering` expose the complete immutable rule
inputs for native lowering. Filesystem layers include access rules, protected
relative paths, missing-path behavior, and glob settings. Network layers
include domain and Unix-socket rules, default modes, and local-address policy.
These views deliberately do not expose an independent requested or ceiling
policy; native code must apply every layer together.

The `CommandRequest::environment` value must equal the requested environment
used to create the `EffectiveSandbox`. Mixing a command with a composed result
from another environment specification is a typed contract error, not a
reason to choose one source implicitly.

`UnsupportedCapability` remains matchable by its `BackendCapability` value and
must render a human-readable description of the missing enforcement category;
diagnostics must not require callers to decode an opaque boolean or numeric
code.

Preparation must not perform filesystem, DNS, or socket I/O. Native backends
perform those operations only after successful preparation and must follow
`specs/0012-native-backend-safety-contract.md`.

## Native backend responsibilities

The native backend remains responsible for:

- selecting and verifying its actual OS enforcement mechanism;
- resolving or constraining symlinks, junctions, reparse points, mounts, and
  drive boundaries;
- preventing validation/use races with descriptor- or handle-relative
  operations or an equivalent OS-native mechanism;
- resolving DNS once, checking every result, authorizing the exact
  `SocketAddr` immediately before connecting, and connecting only to that
  checked address;
- selecting the platform-specific core environment allowlist; and
- returning backend-specific errors for OS setup, spawn, and lifecycle
  failures.

`ExternalOwner` remains a caller-supplied identity token. The backend or
embedding application must separately establish that the external enforcement
boundary exists and is trusted.

## Dependency boundaries

`cageforge-backend-api` may depend on:

- `cageforge-command`;
- `cageforge-path`;
- `cageforge-policy`;
- `cageforge-policy-compose`; and
- a typed error dependency such as `thiserror`.

It must not depend on `cageforge-config`, a process runtime, PTY, network
proxy, telemetry, an agent protocol, or a platform backend. Configuration is
an optional producer of the input values, not part of the backend contract.

`cageforge-core` may depend on this API and on selected native backends later,
but this API must never depend on `cageforge-core`. That direction keeps the
contract reusable by applications that do not use the Cageforge facade.

## Required tests

The crate must use black-box integration tests in its `tests/` directory.
Tests must cover:

- successful preparation of a valid effective command and policy;
- rejection of every unsupported capability category;
- workspace-root ceilings and effective path contexts;
- protected metadata paths and deny-glob preservation;
- complete filesystem and network lowering views, including both composition
  layers;
- missing-path behavior and local-address restriction capabilities;
- environment base selection and filtering requirements;
- network preparation without hostname-only authorization;
- typed errors for invalid runtime context and unsupported rules; and
- the invariant that preparation cannot produce a request broader than the
  supplied `EffectiveSandbox`.

Property tests should generate combinations of effective policies and
capability sets to verify monotonicity and fail-closed behavior. Portable
backend API logic must maintain at least 90% line coverage. Native enforcement
tests belong to each native backend's operating-system CI runner and are not
replaced by this crate's portable tests.

## Relationship to Codex

The contract is behaviorally informed by the execution boundary in
`codex-rs/sandboxing`, its process consumers, and the policy transformation
layer. Cageforge does not copy those implementation files or expose Codex
protocol, PTY, proxy, telemetry, or product-specific types.
