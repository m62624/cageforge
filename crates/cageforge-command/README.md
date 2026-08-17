> **Provenance and independence**
>
> Cageforge is an independent project. It is not affiliated with, sponsored by,
> or endorsed by OpenAI. This crate was independently implemented in Cageforge.
> Its behavior was reviewed against the open-source OpenAI Codex execution
> boundary at commit `c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc`; it contains no
> copied or source-derived Codex code.

# cageforge-command

`cageforge-command` is a small, platform-independent command request model for
Cageforge. It describes argv, the working directory, environment construction,
standard stream routing, and timeout intent. A backend or harness adapter
consumes the request and decides how to execute it.

The crate does not spawn processes, parse TOML, apply a sandbox, allocate a
PTY, manage process sessions, configure a network proxy, or depend on an agent
protocol.

## Workspace role

| Crate | Role | Runtime dependencies | Used by |
|---|---|---|---|
| `cageforge-command` | Portable command and process-launch intent | None beyond Rust's standard library | Current black-box tests; planned `cageforge-config`, `cageforge-backend-api`, and harness adapters |

`cageforge-command` intentionally does not depend on `cageforge-policy`. A
future `cageforge-backend-api` will compose both values so callers can choose a
policy and a command without putting enforcement or process-launch code into
either portable model.

## Library API and ownership

Command fields are private. Queries return shared references or copyable values,
while `with_*` methods consume and return updated values. The API does not
expose mutable argv or environment collections, so callers cannot bypass NUL
and environment-name validation. `CommandSpec::into_parts` is the explicit
owned handoff for a process backend.

## Public API

| Type | Purpose |
|---|---|
| `CommandRequest` | Complete portable request passed to a future execution backend. |
| `CommandSpec` | Native argv vector with a non-empty executable. |
| `EnvironmentSpec` | Inherited or empty base environment plus explicit set/remove overrides. |
| `StdioSpec` and `StdioMode` | Independent routing for stdin, stdout, and stderr. |
| `TimeoutPolicy` | Backend default, explicit duration limit, or disabled automatic timeout. |
| `CommandError` | Construction errors for invalid programs, paths, and environment values. |

## Quick start

The crate preserves native command-line values with `OsString` and never parses
shell syntax. To run a shell, put the shell executable and its arguments in the
command explicitly:

```rust
use cageforge_command::{
    CommandRequest, CommandSpec, EnvironmentSpec, StdioSpec, TimeoutPolicy,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = CommandSpec::new("cargo")?.with_args(["test", "--workspace"]);
    let environment = EnvironmentSpec::empty().with_var("RUST_BACKTRACE", "1")?;
    let request = CommandRequest::new(command)
        .with_working_directory(std::env::current_dir()?)?
        .with_environment(environment)
        .with_stdio(StdioSpec::captured())
        .with_timeout_policy(TimeoutPolicy::Limit(Duration::from_secs(60)));

    assert_eq!(request.timeout_policy(), TimeoutPolicy::Limit(Duration::from_secs(60)));
    Ok(())
}
```

`CommandSpec::with_arg` and `with_args` append argv values without changing
them. An empty program or a NUL-containing program is rejected. Empty argv
arguments are valid.

## Environment

`EnvironmentSpec::inherit_all` starts with the launching process environment.
`EnvironmentSpec::empty` starts with no inherited variables. Both forms accept
explicit `with_var` and `without_var` overrides. Setting a variable to an empty
value is different from removing it. Names reject empty strings, `=`, and NUL;
values reject NUL.

The type does not reproduce Codex's product-specific environment filtering.
Filtering, if needed, belongs in a future config or backend layer and must
produce this canonical request model.

## Standard streams and timeout

`StdioSpec::captured()` is the default: stdin is connected to the null device,
while stdout and stderr are piped for the caller. `StdioSpec::inherited()`
passes all three streams through. `StdioSpec::new` and the three `with_*`
methods support independent routing with `Inherit`, `Null`, or `Pipe`.

`TimeoutPolicy` has three states:

- `BackendDefault` uses the timeout selected by the backend or resolved profile;
- `Limit(Duration)` imposes an explicit maximum duration;
- `Disabled` removes the automatic timeout.

Cancellation is a separate lifecycle signal and can still terminate a request
in any timeout state. PTY allocation, output caps, streaming, and process
handles belong to a backend or harness adapter.

## Codex relationship

The request boundary was checked against Codex's `command/exec` and
`process/spawn` protocol models, sandbox spawn inputs, environment overrides,
stdio setup, and execution expiration. This review established the portable
fields that belong in this crate and the concerns that stay outside it.

The review is not a source import. The exact audit and keep/remove decisions
are recorded in
[`specs/0003-crate-api-audit.md`](https://github.com/m62624/cageforge/blob/main/specs/0003-crate-api-audit.md).

If a future Cageforge crate contains copied or materially adapted upstream
source, its README and source headers will name the exact upstream repository,
commit, and path and will retain the applicable copyright and license notices.
The current crate does not require a source-derived header.

## Tests and API documentation

The black-box integration suite lives in
`crates/cageforge-command/tests/command.rs`. It covers native argv values,
validation, environment bases and overrides, stdio routing, cwd handling,
timeout states, and error display.

API reference: [`cageforge-command` on docs.rs](https://docs.rs/cageforge-command/latest/cageforge_command/).

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
