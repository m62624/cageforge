# Specification 0003: Policy and Command API Audit

Status: completed audit baseline

## Scope

This audit covers the two implementation crates currently present in the
workspace:

- `cageforge-policy`;
- `cageforge-command`.

The comparison was performed on 2026-08-17 against the local Codex checkout at
commit `c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc`. The relevant Codex areas
were:

- `codex-rs/protocol/src/permissions.rs`;
- `codex-rs/protocol/src/models.rs`;
- `codex-rs/protocol/src/protocol.rs`;
- `codex-rs/app-server-protocol/src/protocol/v2/command_exec.rs`;
- `codex-rs/app-server-protocol/src/protocol/v2/process.rs`;
- `codex-rs/sandboxing/src/spawn.rs`;
- `codex-rs/core/src/exec.rs`.

This is a behavioral and boundary audit. Neither current Cageforge crate
contains copied or source-derived Codex implementation.

The audit was rechecked against the same local Codex `main` commit on
2026-08-17. The portable policy and command boundaries remain aligned with the
reviewed protocol, sandboxing, app-server, and execution inputs. The commit is
now frozen in `upstream-review.toml`; future changes are review candidates for
these two crates and are not pulled or merged automatically.

## Findings

Every public item has one of three jobs:

1. construct a validated request or policy;
2. expose a read-only value needed by a future config or backend boundary;
3. evaluate the portable semantics that a backend must enforce.

The current repository uses the public API from black-box integration tests.
The future `cageforge-config`, `cageforge-backend-api`, and native backend
crates are the intended production consumers. An item not referenced by the
current repository is not automatically dead code: these crates are libraries,
and their backend boundary does not exist yet.

## `cageforge-policy`

| Public surface | Public methods covered by this decision | Current use and Codex comparison | Decision |
|---|---|---|---|
| `AccessMode` | `can_read`, `can_write`, `most_restrictive`, `permits` | Exercised by `tests/policy.rs`; corresponds to Codex's filesystem access mode and its conflict precedence. | Keep. Matching and backend validation need both capability checks and deterministic precedence. |
| `PathResolutionContext` | `new`, `with_workspace_root`, `with_minimal_path`, `with_tmpdir`, `with_slash_tmp`, `workspace_roots`, `minimal_paths`, `tmpdir`, `slash_tmp` | Exercised by path-resolution tests; replaces Codex's product-specific cwd and special-path materialization with caller-supplied runtime context. | Keep. The backend owns platform path discovery, while this crate owns safe resolution. |
| `PathSelector` | `absolute`, `workspace_root`, `workspace`, `minimal`, `tmpdir`, `slash_tmp`, `resolve`, `path`, `is_special` | Exercised by selector and filesystem tests; covers Codex absolute, workspace/project-root, minimal, temporary, and `/tmp` scopes. | Keep. The representation is opaque so callers cannot bypass constructor validation with an invalid path. |
| `PathPattern` | `absolute`, `workspace`, `as_str`, `is_absolute` | Exercised by glob tests; replaces Codex `globset` and product protocol types with a small validated portable pattern model. | Keep. The pattern text and root kind must be inspectable by a backend or serializer. |
| `FilesystemRule` | `new`, `from_target`, `absolute_glob`, `workspace_glob`, `with_missing_path_behavior`, `with_read_only_subpath`, `target`, `access`, `missing_path_behavior`, `read_only_subpaths` | Exercised by rule, carve-out, missing-path, and glob tests; maps to Codex filesystem entries, writable-root carve-outs, and skip-missing behavior. | Keep. `from_target` supports custom scope/glob values; the two glob constructors are typed convenience entry points. `with_read_only_subpath` is fallible and only accepts a writable parent. |
| `FilesystemPolicy` | `restricted`, `unrestricted`, `external`, `with_glob_scan_max_depth`, `mode`, `entries`, `glob_scan_max_depth`, `with_rule`, `validate`, `normalized`, `access_for`, `access_for_path` | Exercised by filesystem policy tests; covers Codex managed/unrestricted/external ownership, recursive matching, normalization, and backend glob depth. | Keep. Restriction-only builders reject non-restricted modes. `access_for` is the symbolic-selector inspection path; `access_for_path` is concrete enforcement evaluation. They are not interchangeable. |
| `DomainRule` and `UnixSocketRule` | `DomainRule::new`, `pattern`, `access`; `UnixSocketRule::new`, `path`, `access` | Exercised by network tests; corresponds to Codex domain and Unix-socket restrictions while keeping proxy and product types outside this crate. | Keep. Backends need normalized rules and read-only access to their targets. |
| `NetworkPolicy` | `disabled`, `enabled`, `external`, `mode`, `domain_mode`, `unix_socket_mode`, `with_domain_mode`, `with_unix_socket_mode`, `domains`, `unix_sockets`, `with_domain`, `with_unix_socket`, `validate`, `access_for_domain`, `allows_domain`, `allows_unix_socket` | Exercised by network tests; separates network enforcement ownership from domain/socket defaults, as Codex does across protocol and native backends. | Keep. `access_for_domain` reports rule matching; `allows_domain` and `allows_unix_socket` apply the complete policy. Disabled mode may retain inert rules for inspection but always denies; external mode rejects local rules at construction. |
| `SandboxPolicy` | `new`, `read_only`, `workspace`, `full_access`, `filesystem`, `network`, `validate` | Exercised by built-in policy tests; combines the portable filesystem and network boundaries without exposing Codex `PermissionProfile` or legacy mode names. | Keep. This is the composition root for future profile resolution and backend preparation. |

The methods most likely to look unused in a local grep are intentional:
`access_for` supports symbolic policy inspection, `entries`/`domains`/
`unix_sockets` support backend compilation, and the getters support config
round-tripping without exposing mutable internals. No policy method is removed
by this audit.

### Ownership and mutability

All policy fields are private. Read-only access uses shared references, slices,
`Option<&T>`, or copyable enums. Policy changes use consuming `with_*` builders
and validated constructors. Fallible builders reject contradictory modes,
parent traversal, and NUL-containing path inputs at the public boundary. The
API does not expose mutable slices, public fields, public enum payloads, or
`*_mut` escape hatches that could create an invalid policy without a subsequent
validation step.

## `cageforge-command`

| Public surface | Public methods covered by this decision | Current use and Codex comparison | Decision |
|---|---|---|---|
| `CommandSpec` | `new`, `with_arg`, `with_args`, `program`, `args`, `into_parts` | Exercised by `tests/command.rs`; corresponds to Codex argv handling in `command_exec`, `process`, and `sandboxing::spawn`. | Keep. Argument builders are fallible and reject NUL before `into_parts`; `into_parts` is the owned handoff a process backend needs. |
| `EnvironmentSpec` | `inherit_all`, `empty`, `base`, `overrides`, `override_for`, `with_var`, `without_var` | Exercised by environment tests; maps to Codex inherited/empty environment construction and set/remove overrides without importing Codex filtering or telemetry rules. | Keep. `override_for` is a direct backend lookup; the sorted map gives deterministic inspection. |
| `CommandRequest` | `new`, `with_working_directory`, `without_working_directory`, `with_environment`, `with_stdio`, `with_timeout`, `with_timeout_policy`, `use_backend_timeout`, `disable_timeout`, `command`, `working_directory`, `environment`, `stdio`, `timeout_policy` | Exercised by request tests; combines the launch inputs split across Codex app-server protocol and execution code. | Keep. The named timeout methods keep call sites explicit, and cwd removal is required for reusable builder composition. |
| `StdioSpec` | `new`, `captured`, `inherited`, `with_stdin`, `with_stdout`, `with_stderr`, `stdin`, `stdout`, `stderr` | Exercised by stdio tests; maps to Codex piped, inherited, and null stream setup. PTY allocation remains outside this crate. | Keep. Each stream is independently configurable without introducing PTY or OS handles. |
| `TimeoutPolicy` | `BackendDefault`, `Limit`, `Disabled` | Exercised by timeout tests; matches Codex's default/custom/disabled timeout intent. Cancellation remains a separate lifecycle signal, as in Codex execution code. | Keep. Three variants are the complete portable timeout model. |
| `CommandError` | `Display` and `Error` implementations | Exercised by invalid-input and display tests; provides stable construction errors without importing a process backend. | Keep. Constructors need a public error type. |

The command crate intentionally does not add process spawning, PTY handles,
output caps, process identifiers, protocol serialization, network proxy state,
or sandbox policy fields. Those concerns belong to the backend or harness
adapter that consumes this request.

### Ownership and mutability

All command fields are private. `program`, `args`, `overrides`, and request
components are available through shared references or copyable values. The
`with_*` methods consume and return the request so composition stays explicit;
fallible argv and cwd builders reject NUL before a backend handoff. There are
no public mutable collections that could bypass command or environment-name
validation. `into_parts` is the deliberate owned handoff for a process backend.

## Follow-up rule

Before removing a public item, first check the downstream crate that consumes
the boundary and the matching Codex behavior. If the item is only redundant
with a legacy compatibility layer, remove it. If it is a backend handoff,
inspection method, or portable semantic decision, keep it and add an
integration test when the consumer is implemented.
