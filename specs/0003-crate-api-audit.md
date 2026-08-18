# Specification 0003: Policy and Command API

Status: accepted

## Scope

This specification covers the two implementation crates that define the
policy and command boundaries:

- `cageforge-policy`;
- `cageforge-command`.

The comparison uses the Codex commit recorded in `upstream-review.toml`. The
relevant Codex areas are:

- `codex-rs/protocol/src/permissions.rs`;
- `codex-rs/protocol/src/models.rs`;
- `codex-rs/protocol/src/protocol.rs`;
- `codex-rs/app-server-protocol/src/protocol/v2/command_exec.rs`;
- `codex-rs/app-server-protocol/src/protocol/v2/process.rs`;
- `codex-rs/sandboxing/src/spawn.rs`;
- `codex-rs/core/src/sandboxing/mod.rs`;
- `codex-rs/core/src/spawn.rs`;
- `codex-rs/core/src/exec.rs`;
- `codex-rs/core/src/exec_env.rs`;
- `codex-rs/protocol/src/config_types.rs`;
- `codex-rs/protocol/src/shell_environment.rs`.
- `codex-rs/network-proxy/src/policy.rs` for host normalization behavior.

This is a behavioral and boundary specification. Neither current Cageforge
crate contains copied or source-derived Codex implementation. The commit is
frozen in `upstream-review.toml`; future upstream changes are review candidates
for these two crates and are not pulled or merged automatically.

## API decisions

Every public item has one of three jobs:

1. construct a validated request or policy;
2. expose a read-only value needed by a future config or backend boundary;
3. evaluate the portable semantics that a backend must enforce.

The current repository uses the public API from black-box integration tests.
The current `cageforge-config`, future `cageforge-backend-api`, and native
backend crates are the intended production consumers. An item not referenced by
the current repository is not automatically dead code: these crates are
libraries, and their backend boundary does not exist yet.

The shared path contract, configuration model, and policy-composition contract
are specified separately in `0005`, `0009`, and `0010`. They are included in
the cross-crate reuse decision below, but this document does not duplicate
their API tables.

## `cageforge-policy`

| Public surface | Public methods covered by this decision | Current use and Codex comparison | Decision |
|---|---|---|---|
| `AccessMode` | `can_read`, `can_write`, `most_restrictive`, `permits` | Exercised by `tests/policy.rs`; corresponds to Codex's filesystem access mode and its conflict precedence. | Keep. Matching and backend validation need both capability checks and deterministic precedence. |
| `FilesystemDecision` | `as_access_mode`, `is_externally_enforced` | Exercised by policy tests; preserves the distinction between local deny and Codex-style externally owned enforcement. | Keep. A backend must not treat delegated enforcement as a local denial. |
| `PathResolutionContext` | `new`, `with_root`, `with_workspace_root`, `with_minimal_path`, `with_tmpdir`, `with_slash_tmp`, `root_paths`, `workspace_roots`, `minimal_paths`, `tmpdir`, `slash_tmp` | Exercised by path-resolution tests; replaces Codex's product-specific cwd and special-path materialization with caller-supplied runtime context. | Keep. The backend owns platform path discovery, while this crate owns safe resolution. |
| `PathSelector` | `absolute`, `workspace_root`, `root`, `workspace`, `minimal`, `tmpdir`, `slash_tmp`, `resolve`, `path`, `is_special` | Exercised by selector and filesystem tests; covers Codex absolute, system-root, workspace/project-root, minimal, temporary, and `/tmp` scopes. | Keep. The representation is opaque so callers cannot bypass constructor validation with an invalid path, and equality, hashing, and ordering use `cageforge-path` native semantics. |
| `PathPattern` | `absolute`, `workspace`, `as_str`, `is_absolute` | Exercised by glob tests; wraps a small validated portable pattern model and uses Codex-compatible `globset` syntax without exposing Codex protocol types. | Keep. The pattern text and root kind must be inspectable by a backend or serializer. |
| `FilesystemRule` | `new`, fallible `from_target`, `absolute_glob`, `workspace_glob`, `with_missing_path_behavior`, `with_read_only_subpath`, `target`, `access`, `missing_path_behavior`, `read_only_subpaths` | Exercised by rule, carve-out, missing-path, and glob tests; maps to Codex filesystem entries, writable-root carve-outs, and skip-missing behavior. | Keep. Portable glob rules are deny-only; read/write glob access returns a typed unsupported error. `with_read_only_subpath` is fallible, requires a writable parent, and rejects concrete selectors that are visibly outside that parent. |
| `FilesystemPolicy` | `restricted`, `unrestricted`, `external`, `with_glob_scan_max_depth`, `mode`, `entries`, `glob_scan_max_depth`, `with_rule`, `validate`, `normalized`, `access_for`, `access_for_path` | Exercised by filesystem policy tests; covers Codex managed/unrestricted/external ownership, recursive matching, normalization, and backend glob depth. | Keep. Queries return `FilesystemDecision`; external ownership is `ExternallyEnforced`, not local `Deny`. `access_for` is the symbolic-selector inspection path; `access_for_path` is concrete enforcement evaluation. They are not interchangeable. |
| `DomainRule` and `UnixSocketRule` | `DomainRule::new`, `pattern`, `access`; `UnixSocketRule::new`, `path`, `access` | Exercised by network tests; corresponds to Codex domain and Unix-socket restrictions while keeping proxy and product types outside this crate. | Keep. Backends need normalized rules and read-only access to their targets. |
| `NetworkPolicy` | `disabled`, `enabled`, `unrestricted`, `external`, `mode`, `domain_mode`, `unix_socket_mode`, `local_network_access`, `with_domain_mode`, `with_unix_socket_mode`, `with_local_network_access`, `domains`, `unix_sockets`, `with_domain`, `with_unix_socket`, `validate`, `access_for_domain`, `decision_for_domain`, `decision_for_domain_with_resolved_ips`, `decision_for_unix_socket`, `allows_domain`, `allows_unix_socket` | Exercised by network tests; separates network enforcement ownership and resolved-address safety from proxy/runtime concerns. | Keep. `enabled` retains the safe local-destination default; `unrestricted` is the explicit no-local-restriction preset. `access_for_domain` reports rule matching; the `decision_for_*` methods apply the complete policy and preserve `Allow`, `Deny`, and `ExternallyEnforced`. Resolved hostname checks fail closed on empty DNS results and non-public addresses, including allowlisted hostnames; the exact `localhost` literal may opt in through an exact allow rule. DNS remains a backend responsibility. Boolean helpers return true only for local `Allow`. Domain inputs normalize host case, ports, trailing dots, bracketed IP literals, and `globset`-compatible `*`, `?`, classes, and ranges. |
| `NetworkDecision` | `is_allowed`, `is_externally_enforced` | Exercised by network decision tests; preserves the same ownership distinction as filesystem decisions without importing Codex types. | Keep. Backends must inspect this value when external enforcement is possible; they must not interpret `ExternallyEnforced` as local deny or local allow. |
| `SandboxPolicy` | `new`, `read_only`, `workspace`, `full_access`, `filesystem`, `network`, `validate` | Exercised by built-in policy tests; combines the portable filesystem and network boundaries without exposing Codex `PermissionProfile` or legacy mode names. | Keep. This is the composition root for future profile resolution and backend preparation. |

The methods most likely to look unused in a local grep are intentional:
`access_for` supports symbolic policy inspection, `entries`/`domains`/
`unix_sockets` support backend compilation, and the getters support config
round-tripping without exposing mutable internals. No policy method is removed
by this specification.

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
| `EnvironmentSpec` | `inherit_all`, `empty`, `base`, `overrides`, `override_for`, `filters`, `filter_action_for`, `with_var`, `without_var`, `with_filter`, `with_include_pattern`, `with_exclude_pattern`, `apply_to` | Exercised by environment tests; maps to Codex inherited/empty environment construction, filtering, and set/remove overrides without importing Codex filtering or telemetry rules. Wildcard matching delegates to the same `wildmatch` crate used by Codex. | Keep. Variable names and filter patterns use one case-insensitive logical namespace, and the backend selects the platform-specific `Core` base map. |
| `CommandRequest` | `new`, `with_working_directory`, `without_working_directory`, `with_environment`, `with_stdio`, `with_timeout`, `with_timeout_policy`, `use_backend_timeout`, `disable_timeout`, `command`, `working_directory`, `environment`, `stdio`, `timeout_policy` | Exercised by request tests; combines the launch inputs split across Codex app-server protocol and execution code. | Keep. The named timeout methods keep call sites explicit, cwd removal is required for reusable builder composition, and cwd parent traversal is rejected before backend resolution. |
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
fallible argv and cwd builders reject NUL and cwd parent traversal before a
backend handoff. There are
no public mutable collections that could bypass command or environment-name
validation. `into_parts` is the deliberate owned handoff for a process backend.

## Cross-crate reuse decisions

The workspace keeps a single owner for each reusable semantic operation:

- `cageforge-path` owns lexical path equality, containment, case handling, and
  parent-traversal checks. Policy, command, config, composition, and the
  upstream-review tool reuse it instead of maintaining local path helpers.
- `cageforge-policy` uses `globset` for filesystem and domain patterns. Its
  domain normalization and filesystem component handling are intentionally
  different layers around that matcher, not duplicate glob implementations.
- `cageforge-command` uses the `wildmatch` crate for the small `*`/`?`
  environment-pattern language used by Codex. The previous local dynamic
  matcher is not part of the API anymore.
- `cageforge-config` retains raw-string merge helpers because it merges TOML
  declarations before typed model construction. Those helpers do not perform
  runtime path or environment enforcement and must not become a second policy
  implementation.
- `cageforge-policy-compose` owns narrowing between two already validated
  policies. It must not be folded into `cageforge-policy`, and it must not
  materialize a third mutable rule list that could widen access.
- No additional shared `text`, `merge`, or `sandbox-core` crate is justified
  by the current code. Adding one would spread small boundary-specific rules
  without removing a real implementation or dependency.

The Codex crates remain design inputs rather than Cageforge dependencies:
`codex-protocol` and `codex-sandboxing` combine policy models with product
protocols and native launch behavior; `codex-config` combines TOML with
runtime discovery; and `codex-network-proxy` owns DNS, proxy, and connection
enforcement. Reusing those crates would violate the standalone dependency
boundary rather than remove duplication.

## Maintenance rule

Before removing a public item, first check the downstream crate that consumes
the boundary and the matching Codex behavior. If the item is only redundant
with a legacy compatibility layer, remove it. If it is a backend handoff,
inspection method, or portable semantic decision, keep it and add an
integration test when the consumer is implemented.
