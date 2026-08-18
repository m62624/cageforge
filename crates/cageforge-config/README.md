> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-config

`cageforge-config` is the strict TOML boundary for Cageforge. It resolves
named profiles into validated `SandboxPolicy` and optional `CommandRequest`
values that other crates or applications can consume.

The schema is Cageforge's own schema. Profile values can be passed directly to
an execution layer, or narrowed first with `cageforge-policy-compose` and a
`PolicyCeiling`.

## Workspace role

| Crate | Role | Runtime dependencies | Used by |
|---|---|---|---|
| `cageforge-config` | Strict TOML profile parsing and inheritance | `cageforge-policy`, `cageforge-command` | Application integrations and backend API crates |
| `cageforge-policy` | Portable filesystem and network policy semantics | None | This crate, policy composition, and backend integrations |
| `cageforge-command` | Portable command and process-launch intent | None | This crate and backend API integrations |

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

More complete, copyable scenarios are in the
[configuration examples](examples/README.md). They explain the TOML syntax,
profile inheritance, environment stage order, protected metadata, and the
native Unix/macOS versus Windows path forms.

Filesystem targets are `absolute`, `workspace`, `workspace-root`, `root`, `minimal`,
`tmpdir`, `slash-tmp`, `absolute-glob`, and `workspace-glob`. Network modes are
`disabled`, `enabled`, and `external`; domain and Unix-socket defaults are
`disabled`, `enabled`, or `restricted`. Stdio modes are `inherit`, `null`, and
`pipe`. Timeout modes are `backend-default`, `limit`, and `disabled`.

Domain patterns use the policy crate's host normalization: matching is
case-insensitive, trailing dots and host ports are ignored, and bracketed
IPv6 literals are accepted. `*` and `?` can be used for host globs, including
mid-label patterns such as `region*.example.com`. For example,
`Example.com:443` and `example.com:8443` address the same canonical host rule,
so a child profile overrides an inherited rule even when it spells a port
differently.

Unknown TOML fields, unknown profiles, invalid profile names, inheritance
cycles, missing command programs, invalid paths, NUL values, contradictory
policy modes, and invalid enum values are rejected. A profile without a
filesystem section is an empty restricted policy; a profile without a network
section denies networking; the command section is optional.

`workspace_roots` is an inheritable path-to-enabled map. `true` enables a root
and `false` disables an inherited root. The resolved paths are declarations;
the backend resolves relative paths against its execution context before
registering absolute roots in its path context.

The filesystem target `root` is symbolic as well: the backend supplies POSIX
`/` or the relevant Windows drive/UNC roots to the policy context. Config
resolution never discovers system roots. Portable glob rules support
`access = "deny"`; read/write glob requests are rejected because native
support is not uniform across Linux, macOS, and Windows.

Command environments support `all`, `core`, and `none` inheritance bases;
omitting `inherit` selects `core`. The `filters` table maps portable `*` and
`?` patterns to `include` or `exclude`. Matching is case-insensitive and
excludes take precedence over includes. Explicit set/remove names are also
case-insensitive, and a later case variant replaces the same logical name.
The command environment stages are `inherit → exclude → set/remove → include`;
an include cannot restore an inherited variable already removed by an exclude,
but an explicit set can intentionally do so. The backend decides which
platform variables belong to the `core` set. Restricted filesystem profiles
protect `.git` below writable scopes by default; trusted callers can request
the explicit TOML opt-out
`[profiles.<name>.filesystem.security] dangerously_allow_git_write = true`.

## Library API

```rust
use cageforge_config::Config;

let source = r#"
default_profile = "workspace"

[profiles.workspace]
"#;
let config = Config::from_toml(source)?;
let resolved = config.resolve_default()?;

let policy = resolved.policy();
if let Some(command) = resolved.command() {
    // Pass both values to the execution integration.
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
The latter remain available as typed source errors, so an integrating
application can handle a configuration problem at the correct layer without
parsing error text.

## Using the resolved values

`cageforge-config` is a configuration adapter, so another project can keep its
own runtime and backend while reusing the same validated policy and command
models. The normal Cageforge flow is:

```text
TOML → cageforge-config → SandboxPolicy/CommandRequest
                              │
                              v
                    policy composition/backend
```

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
