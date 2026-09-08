# Cageforge

> **Independent project:** Cageforge is not affiliated with, sponsored by, or
> endorsed by OpenAI.

**[What Cageforge is](#what-cageforge-is) · [Use it as a library](#start-with-the-facade) ·
[Install the CLI](#install-the-command-line-adapter) · [Workspace packages](#workspace-packages) ·
[Portable layers](#portable-layers) · [Isolation model](#isolation-model-and-references) ·
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

## Start with the facade

Most applications should begin with [`cageforge`](https://docs.rs/cageforge/latest/cageforge/).
Supported operating systems are:

- Linux — enable the `linux` feature;
- Windows — enable the `windows` feature; and
- macOS — enable the `macos` feature.

Choose the feature that matches the target operating system:

```toml
[dependencies]
cageforge = { version = "0.1.0", features = ["linux"] }
```

Add `config` when profiles should come from TOML.

On Linux, `linux-bundled-bubblewrap` is an optional alternative when you do
not want to build or provide Bubblewrap separately. It includes Cageforge's
verified, fixed Bubblewrap `v0.11.2` resource; the embedded version is not
selected dynamically.

The normal flow is explicit:

```text
CommandRequest + SandboxPolicy
             │
             ▼
  optional policy composition
             │
             ▼
       prepare(request)
             │
             ▼
          spawn()
             │
             ▼
  one boundary for the command
  and all of its descendants
```

Each `spawn` creates an independent sandbox instance. A reusable backend and
policy can prepare several commands, while every instance owns its own native
process boundary, timeout, lifecycle, and network state. If Cargo starts
`rustc`, `build.rs`, or a linker, those descendants remain inside the same
boundary as Cargo.

The facade is synchronous. An application with an async runtime can execute
blocking preparation, spawning, and waiting in its blocking-task facility.

## Install the command-line adapter

Applications can embed the `cageforge` facade directly, or install
`cageforge-cli` when a standalone wrapper is more convenient. The CLI accepts a
TOML profile that names the files, environment, network destinations, and
timeout a program needs, then runs one explicit argv command inside the
matching OS sandbox.

CLI releases cover Linux, macOS, and Windows on x86_64 and ARM64. On macOS or
Linux, install the Homebrew formula with:

```sh
brew tap m62624/cageforge
brew install m62624/cageforge/cageforge-cli
```

The [latest release](https://github.com/m62624/cageforge/releases/latest) also
contains target-labelled archives, checksums, shell and PowerShell installers,
and Windows `.msi` packages. The CLI README contains the exact installer
commands and source-build alternative.

## Workspace packages

The workspace currently contains 14 Cargo packages: 13 reusable library,
resource, or CLI packages and one internal upstream-review tool.

| Package | Role | Native target or feature |
| --- | --- | --- |
| [`cageforge`](crates/cageforge/README.md) | Unified application-facing facade | `linux`, `windows`, or `macos` |
| [`cageforge-cli`](crates/cageforge-cli/README.md) | Explicit command-line adapter over the facade | Matching OS feature |
| [`cageforge-backend-api`](crates/cageforge-backend-api/README.md) | Capability preflight and backend-bound handoff | Portable |
| [`cageforge-command`](crates/cageforge-command/README.md) | Validated command, environment, stdio, and timeout values | Portable |
| [`cageforge-config`](crates/cageforge-config/README.md) | TOML profiles and inheritance resolution | Portable, optional facade feature `config` |
| [`cageforge-network-proxy`](crates/cageforge-network-proxy/README.md) | Policy-enforcing HTTP/SOCKS gateway | Portable; runtime feature is optional |
| [`cageforge-path`](crates/cageforge-path/README.md) | Native lexical path identity and containment | Portable |
| [`cageforge-policy`](crates/cageforge-policy/README.md) | Filesystem and network policy model | Portable |
| [`cageforge-policy-compose`](crates/cageforge-policy-compose/README.md) | Requested-policy and ceiling intersection | Portable |
| [`cageforge-linux`](crates/cageforge-linux/README.md) | Linux native process sandbox | Linux |
| [`cageforge-macos`](crates/cageforge-macos/README.md) | macOS native process sandbox | macOS |
| [`cageforge-windows`](crates/cageforge-windows/README.md) | Windows native process sandbox | Windows |
| [`cageforge-bwrap`](crates/cageforge-bwrap/README.md) | Builds and stages the pinned Bubblewrap resource | Linux build/release support |
| `cageforge-upstream-review` | Read-only internal upstream comparison tool | `publish = false` |

The three native backend README files are the platform-specific guides. The
other package README files describe the portable layers and their handoff
relationships. The `cageforge-bwrap` README covers the separately licensed
Bubblewrap build component.

## Portable layers

Applications can use the smaller packages independently:

1. `cageforge-path` provides shared lexical path equality, containment, native
   case handling, and parent-traversal decisions.
2. `cageforge-command` validates executable, arguments, working directory,
   environment, standard streams, and timeout intent.
3. `cageforge-policy` validates filesystem and network rules and evaluates
   portable decisions.
4. `cageforge-config` can resolve those values from named TOML profiles.
5. `cageforge-policy-compose` can narrow requested values with an outer
   `PolicyCeiling`.
6. `cageforge-backend-api` performs common capability preflight and creates a
   backend-bound prepared handoff.
7. A native backend lowers that complete handoff to the OS enforcement API.

The portable packages do not launch processes or silently select an OS
sandbox. They provide validated values for an application or the `cageforge`
facade to pass to a selected native backend.

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
automatically sandboxed. A CLI can wrap the facade, for example:

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

This is different from a virtual machine: Cageforge does not boot a guest
kernel or provide a second operating system. It is also different from a
Docker container: the library does not build an image or require a container
daemon; it uses the host's native process, filesystem, and network controls.
That makes startup and integration lightweight for an embedding application,
while the protection necessarily depends on the host OS, its native security
mechanisms, and a correct Cageforge implementation. A program must be started
through Cageforge for the boundary to apply.

The idea for Cageforge's common command-sandbox API grew from studying the
security model and protection mechanisms used by the open-source
[Codex](https://github.com/openai/codex) sandbox, including the process-boundary
design described in OpenAI's [Building a safe, effective sandbox to enable
Codex on Windows](https://openai.com/index/building-codex-windows-sandbox/)
article. Cageforge takes those sandbox principles and the corresponding
mechanism inventory as its behavioral foundation, then realizes each part with
the native enforcement facilities of Linux, Windows, and macOS. The backends
are separate implementations for their operating systems, not one Windows
mechanism transplanted unchanged to the others.

Cageforge remains an independent library with its own public API and adapts
that shared security model for multiple independent sandbox instances; Codex
product protocols, runtime integrations, and source files are not part of this
API.

The protection is layered:

| Protection layer | What the sandbox enforces |
| --- | --- |
| Command boundary | One explicitly launched root command and its complete descendant process tree share the selected boundary. |
| Filesystem | The effective policy grants only declared scopes and modes, with native checks for symlinks, mounts, reparse points, and TOCTOU-sensitive operations. |
| Environment | The command receives the validated environment selected for the instance; it cannot use environment changes to widen native permissions. |
| Network | Direct, disabled, and routed access are lowered by the selected backend, with authorization tied to the exact resolved destination where applicable. |
| Lifecycle | Timeouts and termination apply to the complete process tree, and native resources are released only after the boundary reaches a confirmed terminal state. |
| Descriptors and handles | Only explicitly authorized standard streams and other transport handles cross the launch boundary. |
| Native enforcement | Linux uses namespaces, mounts, seccomp, and Bubblewrap; Windows uses restricted tokens, ACLs, Job Objects, and firewall/WFP; macOS uses Seatbelt profiles and native process controls. |

This is an OS-enforced library boundary, not a promise that every possible
host or application failure is harmless. Its guarantees depend on a correct
host OS, functioning native mechanisms, and a correct Cageforge
implementation.

The TOML examples are in
[`crates/cageforge-config/examples`](crates/cageforge-config/examples/README.md).
The complete public API is available on [docs.rs](https://docs.rs/cageforge/latest/cageforge/)
and in the package README files linked above.
The legal and provenance records are maintained in
[`specs/0001-project-charter-and-licensing.md`](specs/0001-project-charter-and-licensing.md),
[`NOTICE`](NOTICE), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and
[`UPSTREAM.md`](UPSTREAM.md).

## License

Cageforge's Rust code is Apache-2.0. The separately maintained Bubblewrap
component retains its LGPL-2.0-or-later license; see the
[`cageforge-bwrap` README](crates/cageforge-bwrap/README.md) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
