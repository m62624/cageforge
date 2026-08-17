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

[profiles.workspace.filesystem]
mode = "restricted"
glob_scan_max_depth = 8
rules = [
  { target = "workspace-root", access = "write", read_only_subpaths = [
      { target = "workspace", path = ".git" },
  ] },
]

[profiles.workspace.network]
mode = "disabled"

[profiles.workspace.command]
program = "cargo"
args = ["test", "--workspace"]

[profiles.workspace.command.environment]
base = "empty"
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
- `inherits` is an ordered list. Parent profiles are merged from left to right,
  then the child overrides scalar values.
- Filesystem rules, domains, and Unix socket rules append during inheritance.
- Command argv replaces as a complete list when specified by the child.
- Environment assignments/removals and stdio fields merge by key; a child
  value overrides the inherited value.
- Unknown TOML fields are errors. A typo must not silently produce a weaker
  policy.
- Unknown profiles, invalid profile names, missing command programs, inheritance
  cycles, invalid enum values, and invalid policy/command values are errors.
- A profile without a filesystem section resolves to an empty restricted policy;
  a profile without a network section resolves to disabled networking.
- A profile may omit `command`; this is useful for policy-only consumers.

All final values are constructed through `cageforge-policy` and
`cageforge-command`, so their path, mode, NUL, environment, and ownership
invariants remain authoritative.

## Public API

The crate exposes:

- `Config::from_toml` and `Config::from_file`;
- `profile_names`, `default_profile_name`, `resolve`, and `resolve_default`;
- `ResolvedProfile::policy` and `ResolvedProfile::command`;
- `ConfigError` with profile and field context.

Fields in the parsed representation remain private. Callers receive shared
references to resolved values and cannot mutate a profile into an unchecked
state.

## Testing

Black-box integration tests in `crates/cageforge-config/tests/` cover parsing,
strict unknown-field handling, inheritance order, cycle and unknown-profile
errors, all profile section modes, command/environment/stdio/timeout mapping,
policy validation failures, and a policy-only profile. The crate must maintain
at least 90% line coverage.
