> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-command

`cageforge-command` is a small, platform-independent command request model for
Cageforge. It describes argv, the working directory, environment construction,
standard stream routing, and timeout intent. Other crates can use the same
validated request model when they need to prepare a command for a sandboxed or
ordinary process launch.

## When to use it

Use this crate when one part of an application describes a process and another
part launches it. It is also suitable for ordinary process execution: the
request model does not require a sandbox backend or a particular harness.

The usual handoff is:

```text
CommandSpec + EnvironmentSpec + StdioSpec + TimeoutPolicy
                              │
                              ▼
                       CommandRequest
                              │
                              ▼
                 application-owned process adapter
```

The adapter chooses how to map stdio and timeout intent to its process API.
The command crate validates the request but does not spawn a process, allocate
a PTY, stream output, or terminate a process.

## Workspace role

`cageforge-command` is the command-intent layer.

| Crate | Role in the relationship |
|---|---|
| `cageforge-config` | Builds validated `CommandRequest` and `EnvironmentSpec` values from TOML. |
| `cageforge-policy-compose` | Composes `EnvironmentSpec` with an outer policy ceiling. |
| Backend integrations | Consume the request alongside policy values before process launch. |

The crate is also useful on its own in projects that need validated command
inputs without using Cageforge's configuration format.

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
| `EnvironmentSpec` | All/core/none base environment plus validated filters and explicit set/remove overrides. |
| `EnvironmentInput` | A validated backend-selected environment snapshot tagged as `All`, `Core`, or `None`. |
| `CoreEnvironment` | The validated core-variable snapshot selected by a platform adapter. |
| `EnvironmentNameKey` | Case-insensitive map/set identity for native environment names without lossy collisions. |
| `StdioSpec` and `StdioMode` | Independent routing for stdin, stdout, and stderr. |
| `TimeoutPolicy` | Backend default, explicit duration limit, or disabled automatic timeout. |
| `CommandError` | Construction errors for invalid programs, paths, and environment values. |

`CommandError` is a dedicated library error enum. Callers can match invalid
programs, arguments, working directories, and environment values directly.

Working-directory parent traversal uses the shared `cageforge-path` semantics,
so command requests, policy scopes, workspace ceilings, and review paths agree
about Windows case handling without making this crate depend on a policy or
backend.

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
    let command = CommandSpec::new("cargo")?.with_args(["test", "--workspace"])?;
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
them and reject NUL-containing arguments. An empty program or a NUL-containing
program is rejected; empty argv arguments are valid. Working-directory input
also rejects empty, NUL-containing, and lexically escaping parent-traversal
paths at the request boundary. Relative paths that do not contain parent
traversal are still preserved for backend resolution.

## Environment

`EnvironmentSpec::inherit_all` starts with the launching process environment,
`EnvironmentSpec::inherit_core` requests the backend's conservative
platform-specific core set, and `EnvironmentSpec::empty` starts with no
inherited variables. All forms accept explicit `with_var` and `without_var`
overrides. Setting a variable to an empty value is different from removing it.
Names reject empty strings, `=`, and NUL; values and filter patterns reject NUL.

`with_filter` accepts an explicit `Include` or `Exclude` action and portable `*`
and `?` wildcards. The convenience methods `with_include_pattern` and
`with_exclude_pattern` remain available for readable Rust call sites. Matching
is case-insensitive, including explicit variable names and duplicate filter
patterns. `EnvironmentPattern` equality, hashing, and ordering use that same
case-insensitive identity; `as_str()` preserves the declared spelling for
diagnostics and serialization. A later case variant replaces the same logical override. Excludes
have precedence when a variable matches both actions. `apply_to` applies the
portable stages in this order: `inherit → exclude → set/remove → include`. A
variable removed by an exclude is not restored by an include, while an explicit
set can intentionally restore it at the later set stage. The backend still
selects the platform-specific `Core` variables
and supplies the selected base map. This keeps process-environment discovery
out of the platform-independent crate.

Native environment names that are not valid Unicode remain distinct for
explicit storage and lookup. When any wildcard filter is active they are
removed conservatively, because a Unicode pattern cannot identify such a name
without a lossy conversion.

The `Core` set is not a hidden global constant. A backend explicitly selects
the platform-specific core variables, passes that map to `apply_to`, and then
enforces the resulting environment. This keeps Linux, macOS, and Windows
differences in the backend that owns them.

Construct `EnvironmentInput::all` and `CoreEnvironment::from_selected` through
their fallible constructors; they validate native names and values before the
snapshot reaches a backend. `EnvironmentSpec::apply_to` accepts an
`EnvironmentInput` and returns another validated `EnvironmentInput`. The input tag is checked before any filtering or
override is applied: an `All` snapshot cannot be supplied to a `Core` or
`None` specification. This makes it impossible for a caller to label a broad
process environment as a narrower base by accident. The returned snapshot can
be passed to `into_variables()` at the process boundary.

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
in any timeout state. A process adapter can add PTY allocation, output caps,
streaming, and process handles around this request model.

## Using it with a sandbox project

Build the command request in the layer that owns configuration, then pass it to
the layer that owns process execution. Pair it with `cageforge-policy` when the
same execution needs filesystem and network restrictions; use
`cageforge-policy-compose` when an outer policy must narrow those restrictions.

The command crate remains the shared data model between these layers, so a
different project can reuse it with its own configuration format and backend.

For a TOML-driven application, resolve the command through
`cageforge-config`. For a typed application, construct `CommandSpec` and
`EnvironmentSpec` directly and pass the resulting `CommandRequest` to the
same adapter. This keeps the process boundary independent from the choice of
configuration format.

API reference: [`cageforge-command` on docs.rs](https://docs.rs/cageforge-command/latest/cageforge_command/).

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
