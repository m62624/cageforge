# Cageforge

> **Independent project:** Cageforge is not affiliated with, sponsored by, or
> endorsed by OpenAI.

> **Development status:** Cageforge is under active development and has not
> published its first `0.1.0` release yet.

Cageforge is a reusable Rust toolkit for running potentially untrusted
commands, agents, plugins, build scripts, and mods inside an OS-enforced
process boundary. It describes and validates command, filesystem, environment,
and network intent, narrows that intent with an optional safety ceiling, and
hands the result to a native Linux, macOS, or Windows backend.

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

## Workspace packages

The workspace currently contains 13 Cargo packages: 12 reusable library or
resource packages and one internal upstream-review tool.

| Package | Role | Native target or feature |
| --- | --- | --- |
| [`cageforge`](crates/cageforge/README.md) | Unified application-facing facade | `linux`, `windows`, or `macos` |
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

## Configuration and references

The TOML examples are in
[`crates/cageforge-config/examples`](crates/cageforge-config/examples/README.md).
The complete public API is available on [docs.rs](https://docs.rs/cageforge/latest/cageforge/)
and in the package README files linked above.

Cageforge is independently implemented. Its design and security boundaries
are reviewed against relevant open-source sandboxing code in
[OpenAI Codex](https://github.com/openai/codex), without exposing Codex
protocols or making Codex a runtime dependency. The legal and provenance
records are maintained in [`specs/0001-project-charter-and-licensing.md`](specs/0001-project-charter-and-licensing.md),
[`NOTICE`](NOTICE), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and
[`UPSTREAM.md`](UPSTREAM.md).
