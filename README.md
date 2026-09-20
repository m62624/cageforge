# Cageforge

> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

**[What Cageforge is](#what-cageforge-is) · [Use it as a library](#start-with-the-cageforge-crate) ·
[Install the CLI](#install-the-command-line-adapter) · [Workspace packages](#workspace-packages) ·
[Isolation model](#isolation-model-and-references) ·
[License](#license)**

## What Cageforge is

Cageforge is a reusable Rust toolkit for running potentially untrusted
commands, agents, plugins, build scripts, and mods inside an OS-enforced
process boundary. It describes and validates command, filesystem, environment,
and network intent, narrows that intent with an optional safety ceiling, and
hands the result to a native Linux, macOS, or Windows backend.

Use the project as a Rust library when you are integrating sandboxed execution
into an application. Install `cageforge-cli` when you want a ready-to-use
terminal command that reads a profile and launches one explicitly selected
program through the same library and native backend.

The sandbox isolates processes using the host operating system's native
enforcement mechanisms. Its guarantees depend on a correct host OS, correct
native enforcement, and a correct Cageforge implementation.

## Start with the cageforge crate

Most applications should begin with [`cageforge`](https://crates.io/crates/cageforge).
```toml
[dependencies]
cageforge = "x.y.z"
```

The `cageforge` crate selects `cageforge-linux`, `cageforge-windows`, or
`cageforge-macos` automatically from the compilation target. Add `config` only
when profiles should come from TOML.

On Linux, `linux-bundled-bubblewrap` is an optional alternative when the
application should carry its Bubblewrap resource. It includes Cageforge's
pinned Bubblewrap `v0.12.0` resource; the embedded version is fixed at build
time.

`native_sandbox()` chooses the backend for the current OS, returning
`Box<dyn DynSandbox>`. The command-running part of an
application uses the same API on all three operating systems:

```rust,ignore
let sandbox = cageforge::native_sandbox()?;
let mut child = sandbox.launch(
    cageforge::BackendRequest::new(&command, &effective_policy),
    &context,
)?;
let status = child.wait()?;
```

`command`, `effective_policy`, and `context` come from Cageforge's portable
builders or a resolved TOML profile. Use `native_sandbox_with(config)` for
native configuration and `Arc<dyn DynSandbox>` to share one reusable backend
between threads. Windows provisioning remains an explicit preceding step.
The [`cageforge` README](crates/cageforge/README.md) includes examples and the
concrete `prepare`/`spawn` API.

The execution flow is:

```text
CommandRequest + SandboxPolicy
             │
             ▼
       policy composition
             │
             ▼
   launch(request, context)
       prepare → spawn
             │
             ▼
  one boundary for the command
  and all of its descendants
```

Each `launch` or concrete `spawn` creates an independent sandbox instance. A reusable backend and
policy can prepare several commands, while every instance owns its own native
process boundary, timeout, lifecycle, and network state. If Cargo starts
`rustc`, `build.rs`, or a linker, those descendants remain inside the same
boundary as Cargo.

The `cageforge` crate is synchronous. An application with an async runtime can execute
blocking preparation, spawning, and waiting in its blocking-task facility.

## Install the command-line adapter

Applications can embed the `cageforge` crate directly, or install
`cageforge-cli` when a standalone wrapper is more convenient. The CLI accepts a
TOML profile that names the files, environment, network destinations, and
timeout a program needs, then runs one explicit argv command inside the
matching OS sandbox.

CLI releases are built for Linux, macOS, and Windows on x86_64 and ARM64 on
every tagged release. Choose one installation method; each method installs the
same `cageforge-cli` binary. The release page contains target-labelled
archives, checksums, shell and PowerShell installers, and Windows `.msi`
packages.

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
$ cargo install --locked cageforge-cli --no-default-features --features linux-bundled-bubblewrap

# Windows and macOS use the same command on their respective runners.
```

From a local Cageforge checkout, replace the package name with the path:

```console
$ cargo install --path crates/cageforge-cli --locked
```

`linux-bundled-bubblewrap` is the only platform-specific build option: it
embeds the verified Bubblewrap resource in a Linux binary. There is no
unsandboxed fallback on an unsupported target.

### Uninstall

```console
$ cargo uninstall cageforge-cli
```

For Homebrew use `brew uninstall cageforge-cli`. For an MSI, uninstall
`Cageforge CLI` from Windows Installed apps. Shell and PowerShell installers do
not install an uninstaller; remove the installed binary manually from
`~/.cargo/bin/cageforge-cli` on Linux/macOS or
`%USERPROFILE%\.cargo\bin\cageforge-cli.exe` on Windows.

The Linux and macOS release binaries embed their native helper entry points, so
a separate helper executable is not installed. macOS registers an unprivileged
per-launch service and requires no administrative setup. Windows requires the
explicit first-time `cageforge-cli setup install` step described in the
[CLI README](crates/cageforge-cli/README.md#windows-first-time-setup).

For the CLI command reference, see the [`cageforge-cli` README](crates/cageforge-cli/README.md).

## Workspace packages

The workspace currently contains 17 Cargo packages: 16 reusable library,
resource, binding, or CLI packages and one internal upstream-review tool.

| Package | Role | Native target or feature |
| --- | --- | --- |
| [`cageforge`](crates/cageforge/README.md) | Unified application-facing crate | Native backend selected from `target_os` |
| [`cageforge-cli`](crates/cageforge-cli/README.md) | Explicit command-line adapter over the `cageforge` crate | Native backend selected from `target_os` |
| [`cageforge-permissions`](crates/cageforge-permissions/README.md) | Typed preflight requests, grants, and host-owned permission store | Portable |
| [`cageforge-java`](crates/bindings/cageforge-java/README.md) | Internal JNI implementation for the JVM binding | Linux, macOS, or Windows |
| [`cageforge-python`](crates/bindings/cageforge-python/README.md) | PyO3 implementation for the Python binding published through maturin | Linux, macOS, or Windows |
| [`cageforge-backend-api`](crates/cageforge-backend-api/README.md) | Capability preflight and backend-bound handoff | Portable |
| [`cageforge-command`](crates/cageforge-command/README.md) | Validated command, environment, stdio, and timeout values | Portable |
| [`cageforge-config`](crates/cageforge-config/README.md) | TOML profiles and inheritance resolution | Portable, optional `cageforge` feature `config` |
| [`cageforge-network-proxy`](crates/cageforge-network-proxy/README.md) | Policy-enforcing HTTP/SOCKS gateway | Portable; runtime feature is optional |
| [`cageforge-path`](crates/cageforge-path/README.md) | Native lexical path identity and containment | Portable |
| [`cageforge-policy`](crates/cageforge-policy/README.md) | Filesystem and network policy model | Portable |
| [`cageforge-policy-compose`](crates/cageforge-policy-compose/README.md) | Requested-policy and ceiling intersection | Portable |
| [`cageforge-linux`](crates/cageforge-linux/README.md) | Linux native process sandbox | Linux |
| [`cageforge-macos`](crates/cageforge-macos/README.md) | macOS native process sandbox | macOS |
| [`cageforge-windows`](crates/cageforge-windows/README.md) | Windows native process sandbox | Windows |
| [`cageforge-bwrap`](crates/cageforge-bwrap/README.md) | Builds and stages the pinned Bubblewrap resource | Linux build/release support |
| `cageforge-upstream-review` | Read-only internal upstream comparison tool | `publish = false` |

The native backend README files are the platform-specific guides. The
`cageforge-java` and `cageforge-python` READMEs cover their language
bindings and Maven/PyPI artifacts. The
`cageforge-bwrap` README covers the separately licensed Bubblewrap build
component.

## Policy and command boundaries

Filesystem and network restrictions are explicit. Restricted policies start
from denial and add only validated scopes or destinations. An outer
`PolicyCeiling` can narrow a request further; native lowering consumes the
complete effective result rather than reconstructing a broader request.

Network authorization is bound to the exact resolved `SocketAddr` that a
backend is about to connect to. Filesystem policy is combined with native
symlink, mount, reparse-point, and TOCTOU-safe enforcement by the selected
backend. Unsupported native requirements become typed errors before launch.

Commands launched outside an application’s Cageforge integration are not
automatically sandboxed. A CLI can wrap the `cageforge` crate, for example:

```text
my-tool cargo test --workspace
```

The wrapper constructs a `CommandRequest`, applies its policy, and starts
Cargo through `spawn`.

## Isolation model and references

At runtime, the application supplies the command and policy to `prepare`,
which validates the request and narrows it with the optional safety ceiling.
`spawn` then asks the selected native backend to create the boundary around the
root process and every descendant it creates.

Unlike a virtual machine, Cageforge uses the host kernel rather than booting a
guest operating system. Unlike a Docker container, it starts no container
daemon and builds no image. The library uses the host's process, filesystem,
and network controls, so the host OS and its security configuration remain part
of the trust boundary. A program must be started through Cageforge for the
boundary to apply.

Cageforge's sandbox model was reviewed against the open-source
[Codex](https://github.com/openai/codex) sandbox and the native enforcement
mechanisms described in OpenAI's [Windows sandbox article](https://openai.com/index/building-codex-windows-sandbox/).
The Linux, macOS, and Windows backends implement the model independently for
their respective operating systems. Cageforge has its own public API and does
not expose Codex product protocols or runtime integrations.

The protection is layered:

| Protection layer | What the sandbox enforces |
| --- | --- |
| Command boundary | One explicitly launched root command and its complete descendant process tree share the selected boundary. |
| Filesystem | The effective policy grants only declared scopes and modes, with native checks for symlinks, mounts, reparse points, and TOCTOU-sensitive operations. |
| Environment | The command receives the validated environment selected for the instance; it cannot use environment changes to widen native permissions. |
| Network | Direct, disabled, and routed access are lowered by the selected backend, with authorization tied to the exact resolved destination where applicable. |
| Local IPC | The portable policy distinguishes absolute Unix sockets from Windows named pipes; each backend must prove endpoint enforcement before advertising the capability. |
| Lifecycle | Timeouts and termination apply to the complete process tree, and native resources are released only after the boundary reaches a confirmed terminal state. |
| Descriptors and handles | Only explicitly authorized standard streams and other transport handles cross the launch boundary. |
| Native enforcement | Linux uses namespaces, mounts, seccomp, and Bubblewrap; Windows uses restricted tokens, ACLs, Job Objects, and firewall/WFP; macOS uses Seatbelt profiles and native process controls. |

This is an OS-enforced library boundary, not a promise that every possible
host or application failure is harmless. Its guarantees depend on a correct
host OS, functioning native mechanisms, and a correct Cageforge
implementation.

The TOML examples are in
[`crates/cageforge-config/examples`](crates/cageforge-config/examples/README.md).
The [configuration guide](crates/cageforge-config/examples/CONFIGURATION_GUIDE.md)
shows which profile to run on Linux, macOS, or Windows and how `minimal` maps
to each native runtime.
The [`local-ipc-platforms.toml`](crates/cageforge-config/examples/local-ipc-platforms.toml)
example shows one profile with Linux/macOS Unix-socket overrides and a
Windows named-pipe override. Windows does not silently fall back to TCP or an
unsandboxed launch when named-pipe isolation is unsupported.
The main package is published on [crates.io](https://crates.io/crates/cageforge).
and in the package README files linked above.
The legal and provenance records are maintained in
[`specs/0001-project-charter-and-licensing.md`](specs/0001-project-charter-and-licensing.md),
[`specs/0023-local-ipc-capability.md`](specs/0023-local-ipc-capability.md),
[`specs/0024-macos-executable-runtime-roots.md`](specs/0024-macos-executable-runtime-roots.md),
[`specs/0025-dynamic-permission-escalation.md`](specs/0025-dynamic-permission-escalation.md),
[`NOTICE`](NOTICE), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and
[`UPSTREAM.md`](UPSTREAM.md).

## License

Cageforge's Rust code is Apache-2.0. The separately maintained Bubblewrap
component retains its LGPL-2.1-or-later license; see the
[`cageforge-bwrap` README](crates/cageforge-bwrap/README.md) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
