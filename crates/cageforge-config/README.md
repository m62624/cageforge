> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

This crate is a supporting component of the [`cageforge`](https://crates.io/crates/cageforge) crate, a cross-platform Rust sandbox for AI agents and untrusted code.

# cageforge-config

`cageforge-config` is the strict TOML boundary for Cageforge. It resolves
named profiles into validated `SandboxPolicy`, optional `CommandRequest`, and
outbound `GatewayConfig` values that other crates or applications can consume.

Configuration is treated as trusted input. Resolution iteratively linearizes
the reachable inheritance graph once and merges canonical entries through
indexed maps, so shared ancestors are applied once and legal diamond-shaped
inheritance remains efficient for large configuration files.

The schema is Cageforge's own schema. Profile values can be passed directly to
an execution layer, or narrowed first with `cageforge-policy-compose` and a
`PolicyCeiling`.

## When to use it

Use this crate when users or operators need named TOML profiles, inheritance,
editor schema, and structured configuration diagnostics. If an application
already has a typed configuration model, it can build `cageforge-policy` and
`cageforge-command` values directly instead.

Configuration flows from source text to a resolved profile:

```text
TOML text/file
     │
     ▼
Config::from_toml / Config::from_file
     │
     ▼
Config::resolve / resolve_default
     │
     ▼
ResolvedProfile
    ├── policy()  -> SandboxPolicy
    ├── command() -> CommandRequest
    ├── network_gateway() -> GatewayConfig
    ├── workspace_roots() -> backend declarations
    └── executable_roots() -> macOS runtime declarations
```

`ResolvedProfile` is an owned, validated result. It does not discover paths or
launch anything. A backend or harness resolves declared workspace roots in its
runtime context, and an optional policy-composition layer can narrow the
result before execution.

For a portable profile with host-specific paths, keep the common declaration at
the profile root and add a platform overlay. The resolver selects the current
host explicitly through `resolve_for_platform`; it does not merge Linux paths
into a macOS or Windows launch:

```toml
[profiles.tool]
description = "Portable tool profile"

[profiles.tool.approval]
mode = "preflight"
timeout_ms = 10000
on_timeout = "deny"
persistence = "session"

[profiles.tool.platforms.linux]
[profiles.tool.platforms.linux.filesystem]
rules = [{ target = "absolute", path = "/etc/tool/config", access = "read" }]

[profiles.tool.platforms.macos]
[profiles.tool.platforms.macos.filesystem]
rules = [{ target = "absolute", path = "/Library/Application Support/tool/config", access = "read" }]

[profiles.tool.platforms.windows]
[profiles.tool.platforms.windows.filesystem]
rules = [{ target = "absolute", path = "C:/ProgramData/tool/config", access = "read" }]
```

The platform overlay can also override `filesystem`, `network`, `command`,
`workspace_roots`, and `approval`. `resolve` remains available for consumers
that intentionally want the unselected portable declaration; execution layers
should use `resolve_for_platform` or `resolve_default_for_platform`.

For a custom macOS runtime, the platform overlay can also declare
`runtime.executable_roots`. Each root must additionally be readable through an
explicit filesystem rule. The macOS backend turns the validated root into a
narrow Seatbelt `file-map-executable` rule; ordinary readable paths do not
receive that permission. See the [configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md#macos-executable-runtime-roots)
and the [`runtime-executable.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/macos/runtime-executable.toml)
example.

Local IPC uses the same platform-overlay model. Linux and macOS accept
absolute Unix-socket paths; Windows uses the local named-pipe namespace and
never treats a Windows pipe as a Unix path:

```toml
[profiles.tool.platforms.linux.local_ipc]
unix_sockets = ["/run/tool/service.sock"]

[profiles.tool.platforms.macos.local_ipc]
unix_sockets = ["/var/run/tool/service.sock"]

[profiles.tool.platforms.windows.local_ipc]
named_pipes = ['\\.\pipe\tool-service']
```

The endpoint is explicit and validated before backend launch. A backend must
advertise native enforcement for the endpoint type; otherwise preflight
returns a typed unsupported-capability error and does not start the child.
Windows named-pipe support is advertised only for the native
`NetworkWindowsNamedPipeRules` capability, which authorizes the exact local
pipe through a launch-scoped ACL transaction and a restricted token. A Unix
socket requested on Windows remains a typed unsupported-capability error.
There is no TCP or unsandboxed fallback.

The transaction retains one host-side handle per approved pipe for
original-state capture, DACL activation, read-back, restoration, and final
verification. It does not reopen a fresh named-pipe instance between those
steps.

The endpoint declaration is separate from the resources needed to start the
command. A runnable restricted profile normally also declares `minimal` read
access for the platform runtime, `workspace-root` write access when the
working directory is the workspace, and `network.mode = "disabled"` unless
the application needs another mode. An IPC rule does not grant those
resources, arbitrary files, TCP loopback, or unrelated local IPC. The
[configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md) and
[`local-ipc-platforms.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/local-ipc-platforms.toml) show the
complete Linux/macOS/Windows shape.

## Workspace role

`cageforge-config` is the strict configuration adapter.

| Crate | Role in the relationship |
|---|---|
| `cageforge-policy` | Supplies the validated filesystem and network policy model. |
| `cageforge-command` | Supplies the validated command and environment request model. |
| `cageforge-network-proxy` | Supplies gateway runtime settings without enabling its async runtime in this dependency path. |
| `cageforge-policy-compose` | Optionally narrows resolved values with an outer policy ceiling. |
| `cageforge` | Re-exports the resolved values and passes them to the selected native backend. |
| Backend integrations | Resolve declared roots and consume the resulting policy and command values. |

The config crate consumes only the public APIs of the model crates. It does not
own process launching or native filesystem or network enforcement.

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
local_network_access = "deny"

[profiles.workspace.network.gateway]
dns_timeout_ms = 5000
connect_timeout_ms = 10000
max_resolved_addresses = 32

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
[configuration examples](https://github.com/m62624/cageforge/tree/main/crates/cageforge-config/examples). They explain the TOML syntax,
profile inheritance, environment stage order, protected metadata, and the
native Unix/macOS versus Windows path forms. The
[`network-gateway.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/network-gateway.toml) fixture demonstrates
every gateway field and field-wise inheritance.

For the end-to-end TOML-to-native-launch flow, including the separate runnable
profiles and the platform-specific meaning of `minimal`, see the
[configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md).

Filesystem targets are `absolute`, `workspace`, `workspace-root`, `root`, `minimal`,
`tmpdir`, `slash-tmp`, `absolute-glob`, and `workspace-glob`. Network modes are
`disabled`, `enabled`, and `external`; domain and Unix-socket defaults are
`disabled`, `enabled`, or `restricted`. `local_network_access` is `deny` by
default and can be set to `allow` only when the consuming boundary intentionally
permits loopback, private, or link-local destinations. Stdio modes are
`inherit`, `null`, and `pipe`. Timeout modes are `backend-default`, `limit`, and
`disabled`.

Domain patterns use the policy crate's host normalization: matching is
case-insensitive, trailing dots and host ports are ignored, and bracketed
IPv6 literals are accepted. Missing, non-numeric, and out-of-range ports are
rejected. `*`, `?`, character classes such as `[a-c]`,
negative classes such as `[!x]`, and ranges can be used for host globs,
including mid-label patterns such as `region*.example.com`. For example,
`Example.com:443` and `example.com:8443` address the same canonical host rule,
so a child profile overrides an inherited rule even when it spells a port
differently.

Unknown TOML fields, unknown profiles, invalid profile names, inheritance
cycles, missing command programs, invalid paths, NUL values, contradictory
policy modes, and invalid enum values are rejected. A profile without a
filesystem section is an empty restricted policy; a profile without a network
section denies networking; the command section is optional.

`network.gateway` configures bounded proxy runtime behavior independently from
domain and Unix-socket permissions. Omitted fields use `GatewayConfig` secure
defaults. Timeouts are positive milliseconds; connection, request, address,
and header limits are positive integers. `relay_byte_limit` accepts a positive
byte count or the explicit string `"unlimited"`. Child profiles override only
the gateway fields they declare.

One profile may not declare the same canonical filesystem target, domain,
protected path, or Unix-socket path twice. This prevents declaration order or
alternate spelling from silently weakening a rule. An ordered child profile
may still override the matching inherited entry explicitly.

`workspace_roots` is an inheritable path-to-enabled map. `true` enables a root
and `false` disables an inherited root. Inheritance compares roots with the
selected target dialect from `cageforge-path`, so a Windows case variant can
override the same inherited root even when the portable TOML is read on a
different host. The resolved paths are declarations;
the backend resolves relative paths against its execution context before
registering absolute roots in its path context. When passing these roots to
`cageforge-policy-compose`, resolve them first: composition accepts only
absolute runtime roots so its ceiling comparison cannot depend on an unstated
current directory. A single profile cannot contain two keys that are the same
under the target platform's native path identity; POSIX keeps case distinct,
while Windows rejects case-only duplicates as ambiguous.

The TOML value classes use the following case rules:

| TOML value or field | POSIX (Linux/macOS) | Windows |
|---|---|---|
| `workspace_roots` keys | Case-sensitive paths | Case-insensitive paths |
| Filesystem `path` values | Case-sensitive paths | Case-insensitive paths |
| Filesystem `pattern` values | Case-sensitive path components | Case-insensitive path components |
| `additional_protected_paths` | Case-sensitive paths | Case-insensitive paths |
| Domain patterns | Case-insensitive hosts | Case-insensitive hosts |
| Environment names and filters | Case-insensitive logical names | Case-insensitive logical names |
| Profile names and ordinary strings | Exact comparison | Exact comparison |

These rules are fixed by the value's domain; TOML cannot override them with a
per-field case flag.

The filesystem target `root` is symbolic as well: the backend supplies POSIX
`/` or the relevant Windows drive/UNC roots to the policy context. Config
resolution never discovers system roots. Portable glob rules support
`access = "deny"` and Codex-compatible glob syntax; read/write glob requests
are rejected because native support is not uniform across Linux, macOS, and
Windows.

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
When filters are active, non-Unicode native environment names are removed
conservatively rather than matched through lossy conversion.

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
let gateway_config = resolved.network_gateway();
if let Some(command) = resolved.command() {
    // Pass both values to the execution integration.
    let _program = command.command().program();
    let _filesystem = policy.filesystem();
    let _dns_timeout = gateway_config.dns_timeout();
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
TOML → cageforge-config → SandboxPolicy/CommandRequest/GatewayConfig
                              │
                              v
                    policy composition/backend
```

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
