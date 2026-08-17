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

[profiles.workspace.command.timeout]
mode = "limit"
milliseconds = 60000
```

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

`ConfigError` separates TOML/profile errors from policy and command errors.
The latter remain available as typed source errors, so a harness can handle a
configuration problem at the correct layer without parsing error text.

## Tests

The black-box integration suite is in `crates/cageforge-config/tests/`. It
covers strict parsing, inheritance order, platform-native paths, all policy
and command modes, invalid values, and policy-only profiles. The crate is
required to maintain at least 90% line coverage.

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
