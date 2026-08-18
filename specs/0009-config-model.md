# Specification 0009: Cageforge Config Model

Status: accepted; portable implementation complete

## Purpose

`cageforge-config` is the strict TOML boundary for Cageforge. It resolves
named profiles into the already validated `SandboxPolicy` and optional
`CommandRequest` values. It does not launch processes, discover paths, select a
native backend, or expose Codex protocol/configuration types.

The design was informed by the Codex `config` crate and its permission-profile
resolution, but this crate has its own schema and API. Codex legacy names and
aliases are not accepted.

## Dependency boundary

```text
cageforge-config
    ├── cageforge-policy
    └── cageforge-command
```

The workspace declares these local crates in `[workspace.dependencies]`. The
config crate consumes their public APIs and never reaches into their private
modules. It produces requested values; it does not apply a `PolicyCeiling`.

Configuration is trusted application input. Resolution memoizes completed
profiles and tracks the active inheritance stack by name, so shared ancestors
are not recomputed for every branch of a large legal inheritance graph. No
arbitrary size or depth limit is imposed by this crate; callers handling an
untrusted wire format must apply an input-size boundary before parsing.

## TOML shape

```toml
default_profile = "workspace"

[profiles.workspace]
inherits = ["base"]
description = "Workspace development profile"

[profiles.workspace.workspace_roots]
"/work/shared" = true
"/work/generated" = false

[profiles.workspace.filesystem]
mode = "restricted"
glob_scan_max_depth = 8
additional_protected_paths = [".cargo"]
rules = [
  { target = "workspace-root", access = "write" },
]

[profiles.workspace.filesystem.security]
dangerously_allow_git_write = false

[profiles.workspace.network]
mode = "enabled"
domain_mode = "restricted"
local_network_access = "deny"
domains = [
  { pattern = "api.example.com:443", access = "allow" },
  { pattern = "[2001:db8::1]:443", access = "deny" },
]

[profiles.workspace.command]
program = "cargo"
args = ["test", "--workspace"]

[profiles.workspace.command.environment]
inherit = "core"
set = { RUST_BACKTRACE = "1" }
remove = ["CARGO_TERM_COLOR"]

[profiles.workspace.command.environment.filters]
"CARGO_*" = "include"
"RUST_*" = "include"
"TOKEN_*" = "exclude"

[profiles.workspace.command.stdio]
stdin = "null"
stdout = "pipe"
stderr = "pipe"

[profiles.workspace.command.timeout]
mode = "limit"
milliseconds = 60000
```

Filesystem rule targets are `absolute`, `workspace`, `workspace-root`, `root`,
`minimal`, `tmpdir`, `slash-tmp`, `absolute-glob`, and `workspace-glob`.
Absolute and workspace paths are still validated by `cageforge-policy`.

Network modes are `disabled`, `enabled`, and `external`. Domain and Unix
socket defaults are `disabled`, `enabled`, or `restricted`.
`local_network_access` is `deny` by default and can be explicitly set to
`allow` for resolved non-public destinations. Command stdio
modes are `inherit`, `null`, and `pipe`; timeout modes are
`backend-default`, `limit`, and `disabled`.

Domain patterns are passed through `cageforge-policy` host normalization:
matching is case-insensitive, trailing dots and host ports are ignored,
bracketed IPv6 literals are unwrapped, IP literals are canonicalized, and
`globset`-compatible wildcards, classes, ranges, and negative classes are
validated before resolution.
Working-directory values are passed to `cageforge-command`, which rejects
empty, NUL-containing, and parent-traversing paths before backend resolution.

## Resolution rules

- `default_profile` is optional in the document; `resolve_default` requires it.
- `inherits` is an ordered list. Parent profiles are merged from left to right
  using a stack-local cycle detector; shared ancestors are legal, while a
  repeated profile on the current resolution chain is rejected with the full
  cycle. A child overrides scalar values and an exact canonical rule target,
  while distinct rules remain available for specificity-based evaluation.
- Filesystem, domain, and Unix-socket rules use deterministic canonical target
  keys. Domain keys use the policy crate's host normalization, including
  ports, trailing dots, bracketed IP literals, and supported globs. An exact
  child target replaces an inherited target; overlapping but distinct targets
  are evaluated by specificity, and equal-specificity capability conflicts are
  resolved conservatively.
- Command argv replaces as a complete list when specified by the child.
- Environment assignments/removals and stdio fields merge by key; a child
  value overrides the inherited value.
- `description` is metadata for the selected profile. A child description
  replaces inherited metadata; an inherited description is not copied into a
  child that does not define one.
- `workspace_roots` is an inheritable path-to-enabled map. A child can disable
  an inherited declaration with `false`. Inheritance compares declarations
  using `cageforge-path` native path identity, including Windows case rules,
  before applying the child value. Resolution returns enabled path declarations
  in deterministic lexical order; the backend resolves relative paths and
  registers absolute roots in its execution context.
- The upstream runtime state that combines profile roots with harness/runtime
  roots is tracked separately from TOML parsing; Cageforge keeps that merge at
  the future backend/context boundary.
- `root` is a symbolic filesystem target. The selected backend must populate
  `PathResolutionContext` with POSIX `/` or the relevant Windows drive/UNC
  roots; config resolution never discovers system roots.
- Environment inheritance is `all`, `core`, or `none`; omitted inheritance
  means `core`. The canonical `filters` table maps patterns to `include` or
  `exclude`, rejects case-insensitive duplicate patterns, and merges exact
  patterns by child override. Variable set/remove names use the same
  case-insensitive identity during validation and inheritance merge. Excludes
  have precedence over includes; an explicit set is applied after exclusion
  and may intentionally restore its named variable. The backend defines the
  platform-specific `core` set. A backend that evaluates a hostname with
  `decision_for_domain_with_resolved_ips` supplies every resolved address and
  supplies an empty list after a failed or timed-out lookup. The config crate
  only stores the typed local-network choice; it never performs DNS.
- `additional_protected_paths` is additive. Restricted profiles protect `.git`
  below writable scopes by default. The explicit
  `[profiles.<name>.filesystem.security] dangerously_allow_git_write = true`
  opt-out is available for trusted callers that really need repository
  metadata writes; a later composer or backend may reject the request.
- Glob rules are portable deny rules. `read` and `write` glob access is rejected
  as a typed unsupported policy because native backend support is not uniform.
- Unknown TOML fields are errors. A typo must not silently produce a weaker
  policy.
- Unknown profiles, invalid profile names, missing command programs, inheritance
  cycles, invalid enum values, and invalid policy/command values are errors.
- A profile without a filesystem section resolves to an empty restricted policy;
  a profile without a network section resolves to disabled networking.
- A profile may omit `command`; this is useful for policy-only consumers.
- Composition with an outer safety limit is performed after resolution by
  `cageforge-policy-compose`; config never assumes that the requested profile
  is the effective policy.
- The JSON Schema uses typed enum values for modes, access, targets, filters,
  stdio, and timeouts, and describes unknown-field rejection. It does not
  replace semantic resolution checks such as inheritance cycles or policy
  safety validation.

All final values are constructed through `cageforge-policy` and
`cageforge-command`, so their path, mode, NUL, environment, and ownership
invariants remain authoritative.

## Public API

The crate exposes:

- `Config::from_toml` and `Config::from_file`;
- `profile_names`, `default_profile_name`, `resolve`, and `resolve_default`;
- `ResolvedProfile::policy` and `ResolvedProfile::command`;
- `ResolvedProfile::description` and `ResolvedProfile::workspace_roots`;
- `config_schema_json` for editor and preflight tooling;
- `ConfigError::diagnostic` for stable JSON-ready diagnostics with parser
  locations when available;
- `ConfigError` with profile and field context.

Fields in the parsed representation remain private. Callers receive shared
references to resolved values and cannot mutate a profile into an unchecked
state.

## Testing

Black-box integration tests in `crates/cageforge-config/tests/` cover parsing,
strict unknown-field handling, inheritance order, cycle and unknown-profile
errors, all profile section modes, command/environment/stdio/timeout mapping,
environment filtering, protected metadata, profile metadata, workspace-root inheritance, schema and
diagnostic serialization, policy validation failures, and a policy-only
profile. Bounded `proptest` suites additionally generate every filesystem
target and missing-path mode, absolute/workspace paths and globs, host forms
with ports/IPv6/wildcards/trailing dots, Unix-socket paths, profile metadata,
file loading, schema-valid documents, diagnostics, unknown-profile/default
errors, and invalid enum/string values. The crate must maintain at least 90%
line coverage.
