> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-macos

`cageforge-macos` is the macOS-native backend for Cageforge's library API. It
provides a Seatbelt-enforced sandbox for potentially untrusted commands,
agents, plugins, build scripts, and mods. The backend accepts the portable
Cageforge command and effective-policy models and creates one independent
OS-enforced boundary for each command tree.

The backend object is reusable: callers may prepare and run multiple commands
concurrently with different policies. Each instance has its own native policy,
process lifecycle, timeout, and network enforcement state.

## Workspace role

| Crate | Role |
|---|---|
| `cageforge-command` | Validated program, arguments, working directory, stdio, timeout, and environment intent. |
| `cageforge-policy` | Portable filesystem and network policy declarations. |
| `cageforge-policy-compose` | Requested-policy and safety-ceiling intersection. |
| `cageforge-backend-api` | Backend-bound preflight and capability contract. |
| `cageforge-network-proxy` | Exact-target gateway for restricted network modes. |
| `cageforge-macos` | Seatbelt process and native lifecycle enforcement. |

The final `cageforge-core` facade will select this backend together with the
Linux and Windows backends. Applications can use this crate directly while
that facade is developed.

## Public API flow

Construct a reusable `MacosBackend`, compose a requested policy with its
`PolicyCeiling`, create a `CommandRequest`, and provide a
`PathResolutionContext` for symbolic paths. `MacosBackend::prepare` validates
the complete portable request and binds it to that backend. `spawn` then turns
the prepared request into one Seatbelt boundary; `MacosChild::wait` or
`try_wait` returns the native command status.

Each call to `spawn` protects one command and its complete descendant tree.
The backend can be shared between threads and several independent instances
can run concurrently with different filesystem, network, environment, and
timeout policies. A policy may therefore be reused for a sequence of separate
commands, while a shell that launches several commands creates one boundary
around that shell and its descendants.

The backend lowers filesystem scopes, read-only carve-outs, protected paths,
deny globs, network mode, exact local IPC rules, environment state, and the
prepared timeout into the native profile. Restricted network policies use a
private per-instance gateway and permit only its authenticated ingress port;
the gateway applies the complete effective network policy before connecting.

```rust,no_run
use std::path::PathBuf;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_macos::{MacosBackend, MacosBackendConfig};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{compose, CompositionRequest, PolicyCeiling};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = std::env::current_dir()?;
    let environment = EnvironmentSpec::inherit_core();
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), environment.clone())
        .with_workspace_roots([workspace.clone()])?;
    let effective = compose(
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_workspace_roots([workspace.clone()])?,
    )?;
    let command = CommandRequest::new(CommandSpec::new("/bin/echo")?.with_arg("ready")?)
        .with_working_directory(workspace.clone())?
        .with_environment(environment);
    let context = PathResolutionContext::new()
        .with_root(PathBuf::from("/"))?
        .with_workspace_root(workspace.clone())?
        .with_minimal_path(PathBuf::from("/usr"))?
        .with_tmpdir(PathBuf::from("/tmp"))?
        .with_slash_tmp(PathBuf::from("/tmp"))?
        .with_current_directory(workspace)?;
    let backend = MacosBackend::new(MacosBackendConfig::new())?;
    let prepared = backend.prepare(BackendRequest::new(&command, &effective), &context)?;
    let status = backend.spawn(prepared)?.wait()?;
    assert!(status.success());
    Ok(())
}
```

The configured Seatbelt executable must be an absolute trusted path. macOS
enforcement is performed by the operating system; cross-target compilation
checks the API surface, while native execution is verified on a macOS runner.

The exact native enforcement correspondence and completion requirements are in
[`specs/0017-macos-backend-implementation.md`](../../specs/0017-macos-backend-implementation.md).
