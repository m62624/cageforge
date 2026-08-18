> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-config

`cageforge-config` is the strict TOML boundary for Cageforge. It resolves
named profiles into validated `SandboxPolicy` and optional `CommandRequest`
values that a harness or native backend can consume.

It does not launch processes, discover paths, choose an operating-system
backend, configure a network proxy, allocate a PTY, or expose Codex protocol
types. The schema is Cageforge's own schema: legacy Codex configuration names
and aliases are not accepted.

## Workspace role

| Crate | Role | Runtime dependencies | Used by |
|---|---|---|---|
| `cageforge-config` | Strict TOML profile parsing and inheritance | `cageforge-policy`, `cageforge-command` | Harness adapters and future backend API crates |
| `cageforge-policy` | Portable filesystem and network policy semantics | None | This crate and backend API crates |
| `cageforge-command` | Portable command and process-launch intent | None | This crate and backend API crates |

The dependencies are local workspace crates, declared through
`[workspace.dependencies]` in the Plugmem-style workspace layout. The config
crate consumes only their public APIs, so every resolved value keeps the
invariants enforced by those model crates.

## Configuration example

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
rules = [
  { target = "workspace-root", access = "write" },
  { target = "workspace", path = ".git", access = "read" },
]

[profiles.workspace.network]
mode = "disabled"

[profiles.workspace.command]
program = "cargo"
args = ["test", "--workspace"]

[profiles.workspace.command.environment]
inherit = "core"
filters = { "CARGO_*" = "include", "RUST_*" = "include", "*TOKEN*" = "exclude" }

[profiles.workspace.command.timeout]
mode = "limit"
milliseconds = 60000
```

More complete, copyable scenarios are in the tested
[configuration examples](examples/README.md). They explain the TOML syntax,
profile inheritance, environment stage order, protected metadata, and the
native Unix/macOS versus Windows path forms.

Filesystem targets are `absolute`, `workspace`, `workspace-root`, `minimal`,
`tmpdir`, `slash-tmp`, `absolute-glob`, and `workspace-glob`. Network modes are
`disabled`, `enabled`, and `external`; domain and Unix-socket defaults are
`disabled`, `enabled`, or `restricted`. Stdio modes are `inherit`, `null`, and
`pipe`. Timeout modes are `backend-default`, `limit`, and `disabled`.

Unknown TOML fields, unknown profiles, invalid profile names, inheritance
cycles, missing command programs, invalid paths, NUL values, contradictory
policy modes, and invalid enum values are rejected. A profile without a
filesystem section is an empty restricted policy; a profile without a network
section denies networking; the command section is optional.

`workspace_roots` is an inheritable path-to-enabled map. `true` enables a root
and `false` disables an inherited root. The resolved paths are declarations;
the backend resolves relative paths against its execution context before
registering absolute roots in its path context.

Command environments support `all`, `core`, and `none` inheritance bases;
omitting `inherit` selects `core`. The `filters` table maps portable `*` and
`?` patterns to `include` or `exclude`. Matching is case-insensitive and
excludes take precedence. The command environment stages are
`inherit → exclude → set/remove → include`; an include cannot restore an
inherited variable already removed by an exclude. The backend decides which
platform variables belong to the `core` set. Restricted filesystem profiles
protect `.git` below writable scopes by default; trusted callers can request
the explicit TOML opt-out
`[profiles.<name>.filesystem.security] dangerously_allow_git_write = true`.

## Library API

```rust
use cageforge_config::Config;

let config = Config::from_toml(source)?;
let resolved = config.resolve_default()?;

let policy = resolved.policy();
if let Some(command) = resolved.command() {
    // Pass both values to a backend or harness adapter.
    let _program = command.command().program();
    let _filesystem = policy.filesystem();
}
# Ok::<(), cageforge_config::ConfigError>(())
```

The public fields remain private. Resolved policies and commands are exposed
through shared references, while mutation is possible only by rebuilding the
source TOML and resolving it again. This prevents callers from bypassing path,
NUL, environment, or ownership invariants after validation.

The full API reference is available on
[docs.rs](https://docs.rs/cageforge-config/latest/cageforge_config/).

`config_schema_json()` returns the structural JSON Schema for editor tooling
and preflight validation. `ConfigError::diagnostic()` returns a stable,
machine-readable diagnostic with an error code, profile/field context, and a
source location when the TOML parser provides one. Neither API replaces the
typed resolution errors used by the library.

`ConfigError` separates TOML/profile errors from policy and command errors.
The latter remain available as typed source errors, so a harness can handle a
configuration problem at the correct layer without parsing error text.

## Tests

The black-box integration suite is in `crates/cageforge-config/tests/`. It
covers strict parsing, inheritance order, platform-native paths, all policy
and command modes, environment filtering, profile metadata, workspace roots,
schema and diagnostics, invalid values, and policy-only profiles. The crate is
required to maintain at least 90% line coverage.

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
