# Specification 0007: Portable Command Model

Status: accepted design

## Purpose

`cageforge-command` describes portable command-execution intent. It is a small
request crate that can be reused by harnesses and later composed with
`cageforge-policy` by `cageforge-backend-api`.

The crate does not launch processes, parse TOML, apply sandbox restrictions,
allocate PTYs, manage process sessions, or expose a harness protocol.

## Upstream audit inputs

The design was checked against the current Codex checkout at
`c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc`, especially:

- `codex-rs/sandboxing/src/spawn.rs` for argv, cwd, environment, stdio intent,
  and timeout-adjacent launch inputs;
- `codex-rs/app-server-protocol/src/protocol/v2/command_exec.rs` for command,
  cwd, environment overrides, output/streaming controls, and timeout concepts;
- `codex-rs/protocol/src/models.rs` for the product-bound local shell request;
- `codex-rs/protocol/src/config_types.rs` for environment inheritance and
  filtering semantics.

This is a behavioral audit, not a source import. The Cageforge implementation
uses new types and a new API; it does not expose Codex protocol types, legacy
configuration names, approval state, proxy state, telemetry, PTY handles, or
Codex process/session identifiers.

## Canonical model

### `CommandSpec`

An argv vector consists of one non-empty executable program and zero or more
native `OsString` arguments. The program and arguments reject NUL characters at
construction time. Shell parsing is never implicit. A caller that wants a
shell must place the shell executable and its arguments in the vector.

### `EnvironmentSpec`

The caller chooses either inherited or empty base environment and then applies
explicit set/remove overrides. Set-to-empty and removal are distinct. Variable
names reject empty values, `=`, and NUL; values reject NUL.

The type intentionally does not reproduce Codex's product-specific filtering
policy. Pattern-based environment filtering belongs in the future config layer
if Cageforge needs it, and must resolve to this canonical model rather than
introduce a second launch representation.

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
stdio routing, and a `TimeoutPolicy`. Empty and NUL-containing working
directories are rejected; relative working-directory resolution is deliberately
deferred to the backend boundary, where the execution context and policy are
available.

## Dependency boundary

`cageforge-command` has no runtime dependency on `cageforge-policy` or any OS
crate. The future graph is:

```text
cageforge-policy       cageforge-command
         \               /
          cageforge-backend-api
```

This avoids putting enforcement or process-launch assumptions into the
portable request type. `cageforge-config` will later parse user profiles and
produce both a `CommandRequest` and a `SandboxPolicy`.

## Required tests

The public integration suite covers:

- empty and NUL-containing program rejection;
- native arguments, including empty arguments and NUL rejection;
- inherited/empty environments, deterministic overrides, set/remove
  distinction, and invalid names/values;
- explicit and default stdio modes;
- optional native cwd, NUL rejection, and timeout replacement/removal;
- complete object equality and error display.

Portable command logic must retain at least 90% Tarpaulin coverage. Native
process and sandbox behavior is tested later in each backend crate on its
native runner.
