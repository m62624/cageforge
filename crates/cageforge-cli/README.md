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

## Install and select the backend

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
composition → native backend `prepare` → native backend `spawn` → typed child
lifecycle. The CLI does not duplicate any enforcement logic.

For native behavior and host requirements, see the [Linux backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-linux/README.md),
[Windows backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-windows/README.md),
and [macOS backend README](https://github.com/m62624/cageforge/blob/main/crates/cageforge-macos/README.md).
The underlying facade API is documented in the [`cageforge` crate](https://docs.rs/cageforge/latest/cageforge/).
