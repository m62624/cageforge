# Specification 0008: Portable Command Model

Status: accepted; portable implementation complete

## Purpose

`cageforge-command` describes portable command-execution intent. It is a small
request crate that can be reused by applications and later passed through the
policy-composition and backend layers.

The crate does not launch processes, parse TOML, apply sandbox restrictions,
allocate PTYs, manage process sessions, or expose a harness protocol.
Working-directory validation uses the shared `cageforge-path` crate so its
lexical parent-traversal and Windows path semantics match policy, config, and
composition layers.

## Upstream design inputs

The design was checked against the current Codex checkout at
`c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc`, especially:

- `codex-rs/sandboxing/src/spawn.rs` for argv, cwd, environment, stdio intent,
  and timeout-adjacent launch inputs;
- `codex-rs/core/src/sandboxing/mod.rs` and `codex-rs/core/src/spawn.rs` for
  the execution boundary that consumes those launch inputs;
- `codex-rs/app-server-protocol/src/protocol/v2/command_exec.rs` for command,
  cwd, environment overrides, output/streaming controls, and timeout concepts;
- `codex-rs/protocol/src/models.rs` for the product-bound local shell request;
- `codex-rs/protocol/src/config_types.rs` for environment inheritance and
  filtering semantics.
- `codex-rs/protocol/src/shell_environment.rs` and
  `codex-rs/core/src/exec_env.rs` for the final environment application
  boundary, excluding Codex-only context-variable scrubbing.

This is a behavioral boundary specification, not a source import. The
Cageforge implementation uses new types and a new API; it does not expose
Codex protocol types, legacy configuration names, approval state, proxy state,
telemetry, PTY handles, or Codex process/session identifiers.

## Canonical model

### `CommandSpec`

An argv vector consists of one non-empty executable program and zero or more
native `OsString` arguments. The program and arguments reject NUL characters at
construction time. Shell parsing is never implicit. A caller that wants a
shell must place the shell executable and its arguments in the vector.

### `EnvironmentSpec`

The caller chooses an `All`, `Core`, or `None` base environment and then
applies canonical wildcard filters whose actions are `Include` or `Exclude`.
The default is `Core`; callers must opt in explicitly to `All`. Set-to-empty
and removal are distinct. Variable names reject empty values, `=`, and NUL;
values and filter patterns reject NUL. `*` matches zero or more characters and
`?` matches one character.

The command crate stores the portable request only. `Core` is intentionally a
backend-defined conservative environment set because safe variables are
platform-specific. Environment variable matching is case-insensitive so the
same request has safe behavior on Windows and POSIX systems. The portable
application order is `inherit → exclude → set/remove → include`.
The `*`/`?` matcher is provided by the `wildmatch` crate, which is also the
matcher used by the corresponding Codex environment model; Cageforge keeps
validation and policy precedence in its own API.
`EnvironmentSpec::apply_to` applies the latter three stages to a base map that
the backend selected according to `All`, `Core`, or `None`. A variable removed
by an exclude is not restored by an include; an explicit set can intentionally
restore its named variable at the later set stage. Explicit names and filter
patterns are canonicalized case-insensitively, so case variants cannot create
two logical variables. `EnvironmentPattern` uses that same canonical identity
for equality, hashing, and ordering, while `as_str()` preserves declaration
spelling for diagnostics and serialization. Conflicting set/remove requests are rejected by the
config layer. The portable crate does not define the contents of `Core`;
each native backend supplies that platform's conservative base map before
calling `apply_to`.

The type intentionally does not reproduce Codex's product-specific secret
patterns, environment discovery, shell profiles, or configuration compatibility
rules. It stores only generic filter intent; config parsing resolves profile
data into this canonical model rather than introducing a second launch
representation.

### `StdioSpec`

Each of stdin, stdout, and stderr independently uses `Inherit`, `Null`, or
`Pipe`. The default is closed stdin with piped stdout/stderr, suitable for a
non-interactive harness. PTY allocation and terminal resizing remain backend or
adapter concerns.

### `TimeoutPolicy`

Timeout intent has three states:

- `BackendDefault` uses the default selected by the backend or resolved
  profile;
- `Limit(Duration)` applies an explicit maximum duration;
- `Disabled` removes the automatic timeout.

Cancellation is intentionally not a fourth timeout variant. It is a separate
execution-lifecycle signal that can terminate a request regardless of its
timeout policy, matching the separation in Codex's `ExecExpiration` and native
Windows execution inputs.

### `CommandRequest`

The request combines a command, optional native working directory, environment,
stdio routing, and a `TimeoutPolicy`. Empty, NUL-containing, and
parent-traversing working directories are rejected; relative working-directory
resolution is otherwise deliberately deferred to the backend boundary, where
the execution context and policy are available.

## Dependency boundary

`cageforge-command` has no runtime dependency on `cageforge-policy` or any OS
crate. The future graph is:

```text
cageforge-policy       cageforge-command
         \               /
       cageforge-policy-compose
                |
       cageforge-backend-api
```

This avoids putting enforcement or process-launch assumptions into the
portable request type. `cageforge-config` parses user profiles and produces
both a `CommandRequest` and a `SandboxPolicy`; `cageforge-policy-compose`
narrows the policy and environment against a `PolicyCeiling`, while the future
backend API combines the resulting constraints with command execution and
native capability checks.

## Required tests

The public integration suite covers:

- empty and NUL-containing program rejection;
- native arguments, including empty arguments and NUL rejection;
- all/core/none environments, deterministic overrides, set/remove distinction,
  case-insensitive canonical include/exclude filtering, ordered environment
  application, and invalid names/values/patterns;
- explicit and default stdio modes;
- optional native cwd, NUL and parent-traversal rejection, and timeout
  replacement/removal;
- complete object equality and error display.

Portable command logic must retain at least 90% Tarpaulin coverage. Native
process and sandbox behavior is tested later in each backend crate on its
native runner.
