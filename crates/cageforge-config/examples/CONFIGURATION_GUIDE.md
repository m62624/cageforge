# Configuration guide

The TOML files in this directory describe policy and command intent. They are
not a replacement for native backend setup. The complete integration is:

```text
TOML -> Config::from_file -> resolve profile -> runtime context
     -> compose effective policy -> native backend prepare -> spawn
```

`cageforge-config` validates the document and resolves inheritance. It does
not discover the current directory, choose system paths, or launch a process.
The application or adapter supplies those runtime values.

## Runnable examples

The native smoke profiles are separated by operating system because executable
and filesystem path syntax is not portable:

| Target | Profile | Command |
|---|---|---|
| Linux | [`runnable/linux/smoke.toml`](runnable/linux/smoke.toml) | `/bin/echo` |
| macOS | [`runnable/macos/smoke.toml`](runnable/macos/smoke.toml) | `/bin/echo` |
| Windows | [`runnable/windows/smoke.toml`](runnable/windows/smoke.toml) | `C:/Windows/System32/cmd.exe` |

Run the profile for the host operating system only. Windows paths and
`cmd.exe` are not valid Linux or macOS commands; `/bin/echo` is not a Windows
command. Each restricted smoke profile includes `minimal` read access and a
writable workspace root.

Linux also needs a compatible Bubblewrap and unprivileged namespaces. The
bundled feature supplies the pinned Bubblewrap resource:

```console
cargo run --locked -p cageforge-cli --features linux-bundled-bubblewrap -- run \
  --config crates/cageforge-config/examples/runnable/linux/smoke.toml
```

macOS needs Seatbelt and the native Cageforge helper; the CLI packages the
helper and needs no install command:

```console
cargo run --locked -p cageforge-cli -- \
  run --config crates/cageforge-config/examples/runnable/macos/smoke.toml
```

Windows needs the one-time owner-scoped setup, the two packaged helper
executables, and an administrator-approved UAC operation. Build the CLI and
helpers beside one another, then run the release CLI:

```powershell
cargo build --locked --release -p cageforge-cli
cargo build --locked --release -p cageforge-windows --bins --features bundled-helpers
& target/release/cageforge-cli.exe setup install
& target/release/cageforge-cli.exe run `
  --config crates/cageforge-config/examples/runnable/windows/smoke.toml
```

## The `minimal` selector

`minimal` is a symbolic filesystem target. TOML does not contain a universal
path for it. The runtime context supplies one or more absolute paths, and the
policy must explicitly allow the selector:

```toml
[profiles.smoke.filesystem]
mode = "restricted"
rules = [
  { target = "minimal", access = "read" },
  { target = "workspace-root", access = "write" },
]
```

The meaning on each platform is:

| Platform | Paths supplied by the built-in adapters | Why `minimal` matters |
|---|---|---|
| Linux | `/usr`, `/bin`, `/lib`, and `/lib64` | Bubblewrap starts from a fresh root. Without `minimal` or readable `root`, the executable or its ELF loader is absent. |
| macOS | `/usr` by default; Seatbelt also has an explicit standard-runtime baseline | A simple system command can use the fixed baseline, but `minimal` keeps the platform-runtime dependency explicit and portable. It does not grant the workspace or arbitrary host paths. |
| Windows | `Windows\\System32` plus the system root context | Restricted ACL planning requires a readable `root` or `minimal` platform base. `minimal` is the narrow choice for system executables. |

The CLI and JVM binding populate these paths automatically. A direct Rust
backend caller must provide the paths for the target OS explicitly. This is a
Linux example; use `/usr` plus the Seatbelt runtime paths on macOS, and the
drive-qualified system root plus `Windows\\System32` on Windows:

```rust,no_run
let context = PathResolutionContext::new()
    .with_root(PathBuf::from("/"))?
    .with_minimal_path(PathBuf::from("/usr"))?
    .with_minimal_path(PathBuf::from("/bin"))?
    .with_minimal_path(PathBuf::from("/lib"))?
    .with_minimal_path(PathBuf::from("/lib64"))?;
```

Use `root` only when the command needs the entire supplied system root. It is
broader than `minimal`; neither selector is inferred from the TOML text.

This follows the same platform-default principle reviewed in the local Codex
baseline: Linux adds standard executable and loader roots when minimal
defaults are requested, macOS adds its standard runtime/framework rules, and
Windows carries platform defaults as an explicit native input. Cageforge keeps
the public TOML schema independent and requires the corresponding symbolic
policy rule before a backend can use any of these paths.

## Paths and selectors

Use `workspace-root` for the declared workspace itself and `workspace` for a
relative path below it. Use `absolute` for a native absolute path, `tmpdir`
for the platform temporary directory, and `slash-tmp` only for a POSIX `/tmp`
mapping. `absolute-glob` and `workspace-glob` are deny patterns.

POSIX examples use `/var/lib/tool` and `/var/tmp/tool/**/*.json`. Windows
examples use drive-qualified paths such as `C:/ProgramData/tool`; forward
slashes avoid TOML escaping and are accepted by the Windows path layer. Do not
copy a Windows absolute path into a Linux/macOS profile or a POSIX `/tmp` rule
into a Windows profile.

`workspace_roots` is a declaration map. Relative entries are resolved by the
adapter against its chosen current directory and then supplied to
`PathResolutionContext`. The config crate never assumes that the process
working directory is the workspace.

## Other profile sections

- `filesystem` selects restricted, unrestricted, or externally owned access;
- `network` selects disabled, direct enabled, or external ownership and can
  restrict domains and Unix sockets;
- `local_ipc` declares typed platform endpoints: absolute Unix sockets under
  the Linux/macOS overlays and local `\\.\pipe\name` named pipes under the
  Windows overlay;
- `command` contains the executable, argv, working directory, environment,
  stdio, and timeout;
- `command.environment` applies the documented base/filter/set/remove stages;
- `network.gateway` bounds proxy runtime resources independently of domain
  authorization; and
- `inherits` composes named profiles, with semantic child overrides.

### Preflight approval and the permission request

The TOML controls the policy and approval behavior; it does not contain a
grant. When a resolved profile uses `approval.mode = "preflight"`, the Rust
facade, CLI, Python binding, or Java binding builds a `PermissionRequest` from
the resolved policy and runtime identity. That request includes the selected
`PlatformId`, architecture, executable/tool identity, config and manifest
digests, resolved native paths, network capabilities, and child-process
capabilities. A trusted host then returns an opaque `PermissionGrant` before
the native backend is launched.

Use [`permission-preflight.toml`](permission-preflight.toml) for one profile
that applies the same policy to all three operating systems while adding a
different native config path for each platform. The platform overlay is chosen
by the typed `PlatformId`; Linux paths are never compared with Windows paths.

Use [`permission-session.toml`](permission-session.toml) when approval should
last only for the current host session. It still requires a trusted approval
before launch, but its `session` persistence must remain in memory and must not
create or update `permissions.json`. Use
[`permission-inheritance.toml`](permission-inheritance.toml) when a shared
approval policy needs a narrower child profile: scalar approval fields merge
field-by-field, and a platform overlay is applied after inheritance. In that
example the Windows overlay disables approval while retaining the inherited
timeout and persistence values for inspection.

For Local IPC, use [`local-ipc-platforms.toml`](local-ipc-platforms.toml).
Linux and macOS retain the existing Unix-socket enforcement. Windows validates
named-pipe names but remains fail-closed until the native backend proves strict
authorization and denial of neighboring named pipes; it never converts the
request to TCP or launches without the requested boundary.

Approval is disabled when the `[profiles.<name>.approval]` section is omitted.
`mode = "preflight"` is fail-closed: an absent or late approval denies the
launch. `persistence = "session"` keeps the grant in memory, while
`persistence = "persistent"` allows the trusted host to write it to its
host-owned `permissions.json` store after approval. The store is not policy
input and must not be edited as TOML.

An omitted filesystem section resolves to an empty restricted policy. An
omitted network section denies networking. A profile without `command` is
valid for a harness that supplies its own typed command or for the CLI when
argv is provided after `--`.

## Rust, CLI, and JVM integration

For Rust, enable `cageforge`'s `config` feature. The facade selects the native
backend from the compilation target; resolve the profile, build the runtime
context, compose an effective policy, and call `native_sandbox().launch` or
the concrete backend's `prepare`/`spawn`.

For the CLI:

```console
cageforge-cli run --config sandbox.toml --profile smoke -- echo ready
cageforge-cli schema > cageforge-schema.json
```

The command after `--` is argv, not shell text. If the profile has a command,
the CLI uses it when no argv follows.

For the JVM binding, `Cageforge.fromTomlFile` and `Cageforge.checkToml` accept
the same profile. `RuntimeContext` supplies the absolute current directory and
an optional custom minimal path. Supplying a runtime path alone is not enough:
the TOML must still contain the `minimal` read rule.

```kotlin
val context = RuntimeContext(workspace.toAbsolutePath(), Path.of("/usr"))
Cageforge.checkToml(Files.readString(configPath), "smoke", context)
Cageforge.fromTomlFile(configPath, "smoke", context).use { sandbox ->
    sandbox.launch(listOf("/bin/echo", "ready")).use { process ->
        check(process.waitFor().exitCode == 0)
    }
}
```

## Validation

The configuration test suite parses every checked-in `.toml` fixture and
resolves the fixtures for the current host. macOS CI runs the matching native
smoke profile; Linux native CI runs the backend enforcement suite in its
QEMU/KVM guest, while the Linux config and CLI smoke profile can be run locally
with the command above. Windows CI resolves the Windows profile on a Windows
runner and the backend suite covers native preparation. Run the portable
fixture check locally with:

```console
cargo test --locked -p cageforge-config --all-targets
```

For backend requirements and lifecycle behavior, continue to the [facade
README](../../cageforge/README.md), [Linux README](../../cageforge-linux/README.md),
[macOS README](../../cageforge-macos/README.md), [Windows README](../../cageforge-windows/README.md),
or [JVM binding README](../../bindings/cageforge-java/README.md).
