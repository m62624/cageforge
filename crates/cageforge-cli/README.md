> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate is an independent command-line adapter over Cageforge's public API.

# cageforge-cli

`cageforge-cli` runs an explicitly selected program inside the native Cageforge
sandbox for the current operating system. It is a thin wrapper for untrusted
tools, agents, plugins, build scripts, mod loaders, and ordinary applications.

The user lists the required access in a TOML profile: for example, read-only
system runtime paths, one writable application directory, selected environment
variables, an exact network policy, and a timeout. The CLI does not guess which
files or hosts a program needs. The command after `--` is passed as native argv;
it is never interpreted as shell text.

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
# Windows (PowerShell) — alternative to the .msi
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

Source installation requires a Rust toolchain. After publication, use the
feature matching the target operating system:

```console
# Linux, using a system Bubblewrap
$ cargo install --locked cageforge-cli --no-default-features --features linux

# Linux, with the verified embedded Bubblewrap resource
$ cargo install --locked cageforge-cli --no-default-features --features linux-bundled-bubblewrap

# Windows
$ cargo install --locked cageforge-cli --no-default-features --features windows

# macOS
$ cargo install --locked cageforge-cli --no-default-features --features macos
```

From a local Cageforge checkout:

```console
$ cargo install --path crates/cageforge-cli --locked --no-default-features --features <matching-os-feature>
```

The native feature is explicit: `linux`, `linux-bundled-bubblewrap`, `windows`,
or `macos`. There is no unsandboxed fallback when a matching feature is absent.

The Linux CLI release is self-contained: the same executable contains the
authenticated entry point used by the Linux backend as its private hardening
helper. Users do not install or invoke a second helper executable.

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

## Build from source and select the backend

Build the binary with exactly one feature matching its target:

```toml
[dependencies]
cageforge-cli = { version = "0.1.0", features = ["linux"] }
```

Supported features are `linux`, `linux-bundled-bubblewrap`, `windows`, and
`macos`. The Linux bundled feature includes the verified embedded Bubblewrap
resource. The crate has no default native feature and never falls back to an
unsandboxed process when the matching feature is absent.

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
workspace_roots = { "C:/Applications/Isolated" = true }

[profiles.isolated.filesystem]
mode = "restricted"
rules = [
  { target = "root", access = "read" },
  { target = "minimal", access = "read" },
  { target = "absolute", path = "C:/Applications/Isolated", access = "write" },
]

[profiles.isolated.network]
mode = "disabled"

[profiles.isolated.command.timeout]
mode = "limit"
milliseconds = 600000
```

Use the path form appropriate for the target OS. The same profile model can
describe a read-only system scope and a specific writable application scope on
Linux, Windows, or macOS. A profile without a command can be paired with argv
after `--`; a profile without either is rejected.

`cageforge-cli schema` prints the configuration schema for editor tooling.

## What programs can run

Most ordinary user-space programs can run when their explicitly declared file,
environment, and network requirements fit the profile: command-line tools,
Cargo builds, scripts, plugins, mod loaders, and GUI applications where the OS
desktop permits them. Programs that require kernel drivers, raw devices,
mount or namespace administration, host IPC, unrestricted files, or an
undeclared network destination are expected to fail at the relevant OS
boundary.

The CLI enforces the command timeout and existing gateway limits. The current
portable API is not a complete CPU, RAM, process-count, thread-count,
write-byte, disk-space, or direct-bandwidth quota manager. A workload can
consume resources available to its allowed boundary until the timeout or native
lifecycle policy terminates it. Stronger resource quotas require future native
support on each OS.

## Architecture and documentation

The execution sequence is `Config::from_file` → profile resolution → policy
composition → `native_sandbox_with` → `DynSandbox::launch` → child lifecycle.
The shared launch operation performs native preparation and spawn. The CLI
passes its configured gateway and platform resources through the facade.

For native behavior and host requirements, see the [Linux backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-linux/README.md),
[Windows backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-windows/README.md),
and [macOS backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-macos/README.md).
The underlying facade API is documented in the [`cageforge` crate](https://docs.rs/cageforge/latest/cageforge/).
