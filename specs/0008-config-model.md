# Specification 0008: Cageforge Config Model

Status: accepted for the second implementation milestone

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
modules.

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

[profiles.workspace.network]
mode = "disabled"

[profiles.workspace.command]
program = "cargo"
args = ["test", "--workspace"]

[profiles.workspace.command.environment]
inherit = "core"
[profiles.workspace.command.environment.filters]
"CARGO_*" = "include"
"RUST_*" = "include"
"TOKEN_*" = "exclude"
set = { RUST_BACKTRACE = "1" }
remove = ["CARGO_TERM_COLOR"]

[profiles.workspace.command.stdio]
stdin = "null"
stdout = "pipe"
stderr = "pipe"

[profiles.workspace.command.timeout]
mode = "limit"
milliseconds = 60000
```

Filesystem rule targets are `absolute`, `workspace`, `workspace-root`,
`minimal`, `tmpdir`, `slash-tmp`, `absolute-glob`, and `workspace-glob`.
Absolute and workspace paths are still validated by `cageforge-policy`.

Network modes are `disabled`, `enabled`, and `external`. Domain and Unix
socket defaults are `disabled`, `enabled`, or `restricted`. Command stdio
modes are `inherit`, `null`, and `pipe`; timeout modes are
`backend-default`, `limit`, and `disabled`.

## Resolution rules

- `default_profile` is optional in the document; `resolve_default` requires it.
- `inherits` is an ordered list. Parent profiles are merged from left to right.
  A child overrides scalar values and an exact canonical rule target, while
  distinct rules remain available for specificity-based evaluation.
- Filesystem, domain, and Unix-socket rules use deterministic canonical target
  keys. An exact child target replaces an inherited target; overlapping but
  distinct targets are evaluated by specificity, and equal-specificity
  capability conflicts are resolved conservatively.
- Command argv replaces as a complete list when specified by the child.
- Environment assignments/removals and stdio fields merge by key; a child
  value overrides the inherited value.
- `description` is metadata for the selected profile. A child description
  replaces inherited metadata; an inherited description is not copied into a
  child that does not define one.
- `workspace_roots` is an inheritable path-to-enabled map. A child can disable
  an inherited declaration with `false`. Resolution returns enabled path
  declarations in deterministic lexical order; the backend resolves relative
  paths and registers absolute roots in its execution context.
- Environment inheritance is `all`, `core`, or `none`; omitted inheritance
  means `core`. The canonical `filters` table maps patterns to `include` or
  `exclude`, rejects case-insensitive duplicate patterns, and merges exact
  patterns by child override. Excludes have precedence over includes. The
  backend defines the platform-specific `core` set.
- `additional_protected_paths` is additive. Restricted profiles always protect
  `.git` below writable scopes; configuration cannot remove that default.
- Unknown TOML fields are errors. A typo must not silently produce a weaker
  policy.
- Unknown profiles, invalid profile names, missing command programs, inheritance
  cycles, invalid enum values, and invalid policy/command values are errors.
- A profile without a filesystem section resolves to an empty restricted policy;
  a profile without a network section resolves to disabled networking.
- A profile may omit `command`; this is useful for policy-only consumers.
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
profile. The crate must maintain at least 90% line coverage.
