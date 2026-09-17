> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate is an independent command-line adapter over Cageforge's public API.

This crate is a supporting component of the [`cageforge`](https://crates.io/crates/cageforge) crate, a cross-platform Rust sandbox for AI agents and untrusted code.

# cageforge-cli

`cageforge-cli` runs an explicitly selected program inside the native Cageforge
sandbox for the current operating system. It is a thin wrapper for untrusted
tools, agents, plugins, build scripts, mod loaders, and ordinary applications.

The user lists the required access in a TOML profile: for example, read-only
system runtime paths, one writable application directory, selected environment
variables, an exact network policy, and a timeout. The CLI does not guess which
files or hosts a program needs. The command after `--` is passed as native argv;
it is never interpreted as shell text.

The [configuration guide](../cageforge-config/examples/CONFIGURATION_GUIDE.md)
contains one runnable profile for Linux, macOS, and Windows and explains the
platform-specific `minimal` runtime scope.

## Install the CLI

Release binaries are built for Linux, macOS, and Windows on x86_64 and ARM64
on every tagged release. Choose one installation method; each installs the
same `cageforge-cli` binary. Release assets include target-labelled archives,
checksums, shell and PowerShell installers, and Windows `.msi` packages.

### Homebrew (macOS / Linux)

From the [`m62624/homebrew-cageforge`](https://github.com/m62624/homebrew-cageforge)
tap:

```console
$ brew install m62624/cageforge/cageforge-cli
```

### Installer script (no Rust toolchain)

`latest` points to the newest published release:

```console
# Linux / macOS (POSIX sh)
$ curl --proto '=https' --tlsv1.2 -LsSf https://github.com/m62624/cageforge/releases/latest/download/cageforge-cli-installer.sh | sh
```

```powershell
# Windows (PowerShell), alternative to the .msi
> powershell -ExecutionPolicy Bypass -c "irm https://github.com/m62624/cageforge/releases/latest/download/cageforge-cli-installer.ps1 | iex"
```

### Windows `.msi`

Download `cageforge-cli-*.msi` from the
[Cageforge releases page](https://github.com/m62624/cageforge/releases). Double-click
the installer; Windows registers it for normal upgrades and uninstalls.

### `cargo binstall`

After the first crates.io release, [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)
can download the prebuilt binary instead of compiling it:

```console
$ cargo binstall cageforge-cli
```

### From source

Source installation requires a Rust toolchain. The native backend is selected
automatically for the target operating system:

```console
# Linux, using a system Bubblewrap
$ cargo install --locked cageforge-cli

# Linux, with the verified embedded Bubblewrap resource
$ cargo install --locked cageforge-cli --features linux-bundled-bubblewrap

# Windows and macOS use the same command on their respective runners.
```

From a local Cageforge checkout:

```console
$ cargo install --path crates/cageforge-cli --locked
```

`linux-bundled-bubblewrap` is the only platform-specific build option. It
embeds the verified Bubblewrap resource for Linux; unsupported targets never
fall back to an ordinary unsandboxed process.

### Uninstall

```console
$ cargo uninstall cageforge-cli
```

For Homebrew use `brew uninstall cageforge-cli`. For an MSI, uninstall
`Cageforge CLI` from Windows Installed apps. Shell and PowerShell installers do
not install an uninstaller; remove the installed binary manually from
`~/.cargo/bin/cageforge-cli` on Linux/macOS or
`%USERPROFILE%\.cargo\bin\cageforge-cli.exe` on Windows.

The Linux release binary is self-contained: its authenticated hardening-helper
entry point is included in the same executable, so a separate helper binary is
not installed.

### Windows first-time setup

Windows requires one administrator-approved provisioning step before the first
sandbox run:

```console
> cageforge-cli setup install
> cageforge-cli setup status
```

`setup install` may show a UAC prompt. It creates or verifies the persistent
Windows sandbox accounts, ACLs, firewall/WFP rules, protected state, and helper
resources. Later `cageforge-cli run` invocations only verify that setup and do
not request UAC for every command. If setup is missing or stale, `run` prints a
warning and then returns the typed Windows setup error.

To remove Cageforge-owned Windows setup objects after all sandbox processes
have stopped:

```console
> cageforge-cli setup uninstall
```

This command removes the system setup, not the CLI executable. Uninstall the
CLI separately through Installed apps, Homebrew, Cargo, or manual binary
removal as described above.

### macOS launch resources

On macOS the CLI embeds its helper and registers a temporary, unprivileged
launchd service for each command. No `sudo` or `setup install` step is needed.
The service supervises the command's descendants, including after the CLI is
killed. After confirmed termination it removes the per-launch registration and
known files; unfamiliar or replaced files are left untouched. There are no
persistent sandbox accounts to uninstall on macOS.

## Build from source

The backend is selected from the target OS. The CLI enables its configuration
layer by default:

```toml
[dependencies]
cageforge-cli = "x.y.z"
```

The only optional native packaging feature is
`linux-bundled-bubblewrap`; the CLI enables its `config` feature by default
for normal installs. It never falls back to an unsandboxed process on an
unsupported target.

## Preflight approval and persistent grants

Approval is disabled by default. To make the CLI ask the trusted host before
launch, enable preflight in the selected profile:

```toml
[profiles.tool.approval]
mode = "preflight"
timeout_ms = 10000
on_timeout = "deny"
persistence = "persistent"
```

Run it interactively, or use `--approve` only when the caller is itself the
trusted approval host:

```console
$ cageforge-cli run --config permission-preflight.toml --approve \
    --permission-store /var/lib/my-tool/permissions.json -- tool
```

`--permission-store PATH` selects the host-owned persistent grant store. If
omitted, the CLI uses `permissions.json` beside the selected TOML file. The
file is created only after a persistent approval, is protected by the host OS,
and can be deleted by its owner to revoke saved approvals. A sandboxed command
does not receive new permissions while it is running; a missing approval in a
non-interactive invocation is denied rather than retried or auto-approved.

## Run one program

```text
cageforge-cli run --config cageforge.toml --profile isolated -- untrusted-program --safe-mode
```

One invocation creates one OS-enforced boundary around the launcher and every
child it creates. A Cargo command therefore keeps its normal flags, while
`rustc`, `build.rs`, linkers, and other descendants inherit the same boundary.
Run separate invocations for separate independent instances. To put several
steps in one instance, explicitly launch a shell and pass its arguments after
`--`.

The CLI uses inherited standard streams so interactive programs and build
output remain visible. Applications that need captured streams should use the
typed `SandboxChild` API from the `cageforge` facade directly.

## Profile example

```toml
default_profile = "isolated"

[profiles.isolated]
workspace_roots = { "." = true }

[profiles.isolated.filesystem]
mode = "restricted"
rules = [
  { target = "minimal", access = "read" },
  { target = "workspace-root", access = "write" },
]

[profiles.isolated.network]
mode = "disabled"

[profiles.isolated.command.timeout]
mode = "limit"
milliseconds = 600000
```

This profile is portable because it uses symbolic `minimal` and
`workspace-root` selectors. The CLI supplies the platform-specific runtime
paths; use the matching runnable profile in the [configuration guide](../cageforge-config/examples/CONFIGURATION_GUIDE.md)
when the executable itself must also be selected per OS. A profile without a
command can be paired with argv after `--`; a profile without either is
rejected.

`cageforge-cli schema` prints the configuration schema for editor tooling.

## Execution flow and backend guides

The execution sequence is `Config::from_file` → profile resolution → policy
composition → `native_sandbox_with` → `DynSandbox::launch` → child lifecycle.
The shared launch operation performs native preparation and spawn. The CLI
passes its configured gateway and platform resources through the facade.

For native behavior and host requirements, see the [Linux backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-linux/README.md),
[Windows backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-windows/README.md),
and [macOS backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-macos/README.md).
The underlying facade API is documented in the [`cageforge` crate](https://docs.rs/cageforge/latest/cageforge/).
