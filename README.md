# Cageforge

> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

> 🚧 **Development status**
>
> Cageforge is under active development and is not ready for production use.
> The 0.1.0 release is not yet available.

Cageforge is a reusable Rust toolkit for describing, validating, narrowing,
and handing off sandboxed process execution. It is designed for agent
harnesses, build tools, developer tools, and other applications that need an
explicit boundary around commands, files, environment variables, and network
destinations.

The workspace is split into small libraries so an application can use only the
layer it needs. The portable crates do not choose an operating-system sandbox
for the caller and do not contain a process runner. A native backend consumes
their validated values and applies the corresponding Linux, macOS, or Windows
enforcement mechanism.

## Start here

Choose the smallest entry point that matches your application:

| You need to… | Start with | What it gives you |
| --- | --- | --- |
| Compare paths using consistent POSIX/Windows rules | [`cageforge-path`](https://docs.rs/cageforge-path/latest/cageforge_path/) | Lexical equality, containment, native path keys, and parent-traversal checks |
| Describe a command without launching it | [`cageforge-command`](https://docs.rs/cageforge-command/latest/cageforge_command/) | Validated argv, working directory, environment, stdio, and timeout intent |
| Describe filesystem and network permissions | [`cageforge-policy`](https://docs.rs/cageforge-policy/latest/cageforge_policy/) | Portable policy values, validation, and access decisions |
| Load named profiles from TOML | [`cageforge-config`](https://docs.rs/cageforge-config/latest/cageforge_config/) | Strict parsing, inheritance, diagnostics, schema, and resolved policy/command values |
| Apply an outer safety limit | [`cageforge-policy-compose`](https://docs.rs/cageforge-policy-compose/latest/cageforge_policy_compose/) | Monotonic intersection of requested permissions and a policy ceiling |
| Check a request against a backend contract | [`cageforge-backend-api`](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/) | Typed capability negotiation and side-effect-free preflight for a native backend |
| Integrate a native process sandbox | Future backend integration | OS-specific enforcement and safe process/file/network operations |

Most applications use the crates in this order:

```text
configuration source       Rust builders
        │                       │
        └──────────┬────────────┘
                   ▼
       cageforge-config or direct values
                   │
                   ▼
       cageforge-policy + cageforge-command
                   │
                   ▼
       cageforge-policy-compose (optional outer limit)
                   │
                   ▼
       cageforge-backend-api (capability preflight)
                   │
                   ▼
       native backend / application-owned executor
```

`cageforge-path` is the shared path-semantics layer used by the other crates.
Most users receive it through those crates and do not need to call it
directly. Use it directly when your own configuration or backend code must
make the same native path comparisons.

## The normal application flow

### 1. Choose a configuration boundary

Use `cageforge-config` when operators should write named TOML profiles. Use
the `cageforge-policy` and `cageforge-command` builders directly when the
caller already has a typed configuration system or wants compile-time Rust
construction.

### 2. Build or resolve the portable values

The result is a `SandboxPolicy` plus an optional `CommandRequest`. These are
validated values, not an instruction to launch a process. Special filesystem
selectors such as `workspace-root` are resolved later from a runtime context
owned by the application or backend.

### 3. Narrow with an outer ceiling when needed

If an application has a system, tenant, workspace, or harness-wide limit,
construct a `PolicyCeiling` and call `cageforge_policy_compose::compose`.
The resulting `EffectiveSandbox` is the value a backend must enforce. It is
never safe for a backend to replace it with the original requested policy.

### 4. Apply native enforcement

A backend selects its platform-specific capabilities and performs the actual
enforcement. In particular:

- filesystem access must be combined with native symlink, junction/reparse,
  mount, and TOCTOU-safe operations;
- network connections must use the exact `SocketAddr` authorized from a
  `ResolvedNetworkTarget` immediately before connecting;
- the backend chooses the actual platform-specific variables for the
  `EnvironmentBase::Core` request;
- unsupported native capabilities must produce typed errors rather than being
  silently widened or ignored.

The portable crates deliberately keep these responsibilities outside their
APIs so the same values can be integrated with different execution systems.

## Use the crates independently

The crates are libraries, not a mandatory monolith:

- `cageforge-path` can be used without any sandbox policy.
- `cageforge-command` can describe ordinary or sandboxed process requests and
  can be paired with a custom configuration format.
- `cageforge-policy` can be built from Rust, JSON, another config language,
  or an application-specific API without using TOML.
- `cageforge-config` depends on the validated policy and command models but
  does not depend on a backend.
- `cageforge-policy-compose` can narrow values produced by TOML, JSON, Rust,
  or another configuration source; it does not require `cageforge-config`.
- `cageforge-backend-api` can validate a composed request before any native
  backend or application-owned executor performs process, filesystem, or
  network operations.

The individual crate pages contain copyable examples and explain the handoff
to the next layer:

- [`cageforge-path` API guide](https://docs.rs/cageforge-path/latest/cageforge_path/)
- [`cageforge-command` API guide](https://docs.rs/cageforge-command/latest/cageforge_command/)
- [`cageforge-policy` API guide](https://docs.rs/cageforge-policy/latest/cageforge_policy/)
- [`cageforge-config` API guide](https://docs.rs/cageforge-config/latest/cageforge_config/)
- [`cageforge-policy-compose` API guide](https://docs.rs/cageforge-policy-compose/latest/cageforge_policy_compose/)
- [`cageforge-backend-api` API guide](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/)

## Configuration examples

The [`cageforge-config/examples`](crates/cageforge-config/examples/README.md)
directory contains complete TOML scenarios, including minimal read-only
profiles, inheritance, environment filtering, protected metadata, and native
Unix/macOS and Windows path spellings. Start with
[`minimal-policy.toml`](crates/cageforge-config/examples/minimal-policy.toml),
then compare it with
[`workspace-development.toml`](crates/cageforge-config/examples/workspace-development.toml).

## Project relationship and provenance

Cageforge is independently implemented. Its portable sandbox design and
security boundaries are informed by relevant open-source sandboxing code in
[OpenAI Codex](https://github.com/openai/codex), without copying Codex source
into the current crates. This project is not a Codex fork and does not expose
Codex protocols, telemetry, PTY types, or product-specific process APIs.

The legal, provenance, and upstream-review rules are maintained in:

- [`specs/0001-project-charter-and-licensing.md`](specs/0001-project-charter-and-licensing.md)
- [`NOTICE`](NOTICE)
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- [`UPSTREAM.md`](UPSTREAM.md)

The current workspace contains the portable layers described above. Native
backend crates and the ergonomic facade are separate architectural layers and
should consume these APIs rather than move platform enforcement into them.
