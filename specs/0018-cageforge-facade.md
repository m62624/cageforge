# Specification 0018: Cageforge Facade Crate

Status: accepted

## Purpose

The final public crate is named `cageforge`. It is the ergonomic entry point
for applications that need to describe and launch sandboxed commands. It
re-exports the portable Cageforge model crates, exposes one common execution
trait over the native backends, and keeps each operating-system implementation
behind an opt-in Cargo feature.

The facade is a library for agent harnesses, build tools, developer tools,
plugin hosts, and mod systems. It is not a system-wide command interceptor.
An application launches a command through the facade; that command and every
descendant it creates remain inside the same native sandbox boundary.

## Package and migration

The workspace placeholder package is renamed to the package and library crate
`cageforge`. The source directory, package metadata, README, workspace member,
dependency keys, documentation links, and repository references must use
`cageforge`. No compatibility package or legacy alias is retained before
publication.

## Cargo features and dependency boundaries

The package exposes these features:

| Feature | Enables | Target |
| --- | --- | --- |
| `linux` | `cageforge-linux` | Linux |
| `linux-bundled-bubblewrap` | `cageforge-linux` with its embedded Bubblewrap resource | Linux |
| `windows` | `cageforge-windows` | Windows |
| `macos` | `cageforge-macos` | macOS |
| `config` | `cageforge-config` and TOML profile re-exports | all targets |
| `network-runtime` | `cageforge-network-proxy` runtime | all targets |

The default feature set is empty. Portable model crates are always available;
the config and native backend crates are optional. Native dependencies remain
inside target-specific dependency sections, so enabling one OS feature does
not pull native libraries for another operating system. The facade must not
compile a native backend module on a different target, and CI must check each
supported OS with only its matching native feature plus the portable feature
combinations relevant to that target.

The facade must not depend on Bubblewrap source or compile third-party native
source. Linux's optional dependency consumes the staged resource according to
Specification 0015.

The package metadata for docs.rs must build the facade with all features for
the supported x86_64 and AArch64 Linux, Windows, and macOS targets. Each
target still receives only its matching native re-export; the other native
features remain inactive through target-specific dependencies and guards.

## Public re-exports

The root module re-exports the public items of these portable crates under the
same names:

- `cageforge-path`;
- `cageforge-command`;
- `cageforge-policy`;
- `cageforge-policy-compose`;
- `cageforge-backend-api`; and
- the configuration-only public API of `cageforge-network-proxy`.

When `config` is enabled, it also re-exports the public `cageforge-config`
types. When `network-runtime` is enabled, it re-exports the complete public
network gateway API. Selecting a native backend does not implicitly make the
standalone gateway API part of the facade's public feature surface. Native
backend types, configuration, child types, and typed errors are
re-exported only when their matching feature and target are active. The root
documentation links to each native crate README and docs.rs page for the
platform-specific setup and enforcement details instead of repeating those
implementation inventories.

`cageforge-bwrap` remains a separate Linux build and resource crate. It is not
part of the application-facing facade API; `linux-bundled-bubblewrap` enables
the Linux backend to consume its verified resource without exposing the
third-party build surface through `cageforge`.

## Unified execution contract

The facade defines `Sandbox`, a high-level trait implemented by each native
backend. It extends the portable capability-discovery contract and provides
the same `prepare` and `spawn` operation shape for Linux, Windows, and macOS.
The associated child and error types remain native, so the facade does not
erase useful platform-specific diagnostics or force incompatible OS process
models into one fake type.

The facade also defines `SandboxChild` for the common lifecycle operations:
process identifier, standard streams, non-blocking status, blocking wait, and
termination. All operations return the native backend's typed error.

Preparation remains a separate, synchronous, side-effect-free step. It takes
`BackendRequest` and the runtime `PathResolutionContext`, returns a
backend-bound prepared request, and must not bypass the effective policy or
backend capability checks from Specification 0011. Native `spawn` performs
the actual OS setup and creates one independent boundary.

The public facade is synchronous. Native network gateways may use hidden
Tokio tasks or helper threads, but the caller does not need a particular async
runtime. Async applications may run the blocking facade calls in their own
blocking-task facility.

## Ergonomic usage

The README must present a short practical flow:

1. enable the matching OS feature (and `config` only when TOML profiles are
   needed);
2. create one reusable native backend;
3. construct or load a command and policy;
4. compose the requested policy with its ceiling;
5. prepare and spawn the command; and
6. wait for or poll the returned child.

The example must use `cargo build` or `cargo test` to show that Cargo's
`rustc`, build scripts, linker, and other descendants inherit the same
boundary. It must explain that command-line options remain available, while
filesystem, environment, and network access are limited by the effective
policy. It must also explain that separate top-level `spawn` calls create
separate instances, while several commands inside one explicitly launched
shell share one instance.

The README must describe the facade in plain technical language and link to
the Linux, Windows, and macOS crate documentation. It must not reproduce the
platform security inventories or discuss internal locks and synchronization.

## CI contract

The existing sandbox CI jobs remain the authoritative native checks. After
their platform-specific backend checks, each job runs the facade crate with
the matching feature:

- Linux native VM: `cageforge --features linux`;
- Windows Server 2025 runner: `cageforge --features windows`; and
- macOS runner: `cageforge --features macos`.

Portable checks also run the facade with `config` and its supported portable
feature combinations, including `network-runtime`. The Linux Bubblewrap source
build remains in its existing dedicated job and is not duplicated by the
facade check.

## Security and compatibility invariants

The facade is only an ergonomic layer. It must preserve the existing native
backend invariants: complete effective policy lowering, backend-bound
preparation, exact network target authorization, native filesystem race
handling, typed helper transport, complete descendant termination, and
independent concurrent instances. Re-exporting an API must not expose a
mutable representation or a constructor that bypasses those checks.

The facade is not a transparent system-wide hook. Commands launched outside
the facade are not automatically sandboxed. A program may use all of its
normal command-line options inside the sandbox, but those options cannot
expand the OS-enforced permissions granted by the effective policy.

## Relationship to upstream

The facade's boundaries are behaviorally informed by the execution boundary
and process consumers reviewed from the frozen Codex baseline. The facade
does not expose Codex product types, protocols, telemetry, PTY integration,
or network-proxy implementation types.
