# Specification 0019: Cageforge CLI

Status: proposed; implementation begins on the dedicated CLI branch

## Purpose

`cageforge-cli` is a small executable adapter over the public `cageforge`
facade. It lets a user run one explicitly named program through the native
sandbox without writing a new launcher. It is useful for untrusted tools,
agents, plugins, build scripts, mod loaders, and ordinary applications whose
filesystem and network permissions can be stated in advance.

The CLI is not another sandbox implementation. It must not duplicate policy
evaluation, path handling, native setup, process ownership, or network
enforcement. Those remain in the existing model, composition, facade, and
native backend crates.

## User contract

The user supplies a TOML profile and an explicit command:

```text
cageforge-cli run --config cageforge.toml --profile isolated -- untrusted-program --safe-mode
```

The profile enumerates the filesystem scopes, network rules, environment,
workspace roots, gateway bounds, and timeout. The command after `--` is argv,
not shell text; shell syntax is not interpreted. If a profile contains a
command, it can be used when the command after `--` is omitted. A run without
an explicit profile command is rejected rather than inferred from the host.

One `run` invocation creates one sandbox instance around the top-level
program and all descendants. A caller can invoke the CLI repeatedly or an
integrating program can reuse one backend and create several independent
instances. The CLI does not intercept programs started outside it.

## Backend selection and features

The crate has no default native backend. The release binary is built with
exactly one matching OS feature:

| Feature | Native backend | Target |
|---|---|---|
| `linux` | `cageforge-linux` | Linux |
| `linux-bundled-bubblewrap` | Linux plus verified embedded Bubblewrap | Linux |
| `windows` | `cageforge-windows` | Windows |
| `macos` | `cageforge-macos` | macOS |

Each native feature enables the CLI's `config` feature because a usable CLI
must load profiles. A build without a matching feature remains cross-target
compilable and returns a typed configuration error when `run` is requested;
it never launches an unsandboxed fallback.

The CLI uses the platform-native backend only when its feature and target
match. A Windows build does not compile Linux or macOS enforcement, and a
Linux build does not compile Windows or macOS enforcement. Linux's bundled
Bubblewrap option is explicit and keeps the same fixed verified resource
contract as `cageforge-linux`.

## Execution sequence

The adapter performs this sequence:

1. read and resolve the selected `cageforge-config` profile;
2. construct the runtime path context from the process directory, the
   platform's declared runtime roots, and the profile's explicitly declared
   workspace roots;
3. compose the requested profile with an equal outer ceiling owned by this
   CLI invocation;
4. construct the matching native backend with `native_sandbox_with` and pass
   its gateway configuration (and the CLI helper identity on Linux);
5. call `DynSandbox::launch` with `BackendRequest`, which performs native
   preparation and spawn on the same instance; and
6. wait for the common child result with the native error preserved as a source.

The CLI reports configuration, composition, missing-feature, and native
backend failures to stderr and returns a nonzero exit code. A child that
exits normally returns its exit code; a signal or native lifecycle failure is
reported without parsing human display strings as a protocol.

The CLI uses inherited standard streams so interactive tools and build output
remain visible. Applications needing captured output should use
`CommandRequest` and `SandboxChild` directly.

On Windows, the CLI exposes `setup install`, `setup status`, and
`setup uninstall` only when built with the `windows` feature for a Windows
target. `setup install` is the explicit administrator-approved provisioning
step and may request UAC; it creates or reconciles the persistent
owner-scoped Windows accounts, ACLs, firewall/WFP state, protected resources,
and setup marker. `run` verifies that setup but never provisions it implicitly.
When setup is missing or stale, `run` prints a warning and returns the typed
Windows setup error. `setup uninstall` removes only Cageforge-owned setup
objects after active backends and children have been released; it does not
uninstall the CLI executable. Linux and macOS builds do not expose these
subcommands.

## Resource and compatibility boundary

The CLI can enforce the existing command timeout and network gateway bounds,
but the current portable API does not expose a general CPU, RAM, process-count,
thread-count, write-byte, disk-quota, or direct-network-bandwidth quota. A
program may therefore consume resources available to its allowed filesystem
and process boundary until the timeout or native lifecycle policy terminates
it. Adding such quotas requires a separate cross-platform specification and
native implementation; the CLI must not pretend that access control is a
resource quota.

Programs that need kernel drivers, raw devices, mount/namespace administration,
host IPC, unrestricted filesystem access, or permissions outside the profile
may fail by design. Ordinary command-line programs, Cargo and its descendants,
GUI applications where the native desktop permits them, plugins, and mod
loaders can run when their declared dependencies fit the selected OS policy.

## Release and CI

The CLI is a workspace crate and is checked with all supported feature
combinations. Common checks build the portable no-native surface and each
target-specific feature. Native sandbox jobs remain responsible for native
black-box enforcement and run the CLI check after the relevant backend check.
On `main`, all target lanes run. On pull requests, the changes job selects the
CLI when `cageforge-cli` or any crate in its dependency closure changes; a
native sandbox is selected independently when its own implementation or
dependency closure changes. Workflow concurrency cancels superseded runs for
the same PR or ref.

The release workflow follows the workspace release sequence: it prepares a
versioned RC branch, runs reusable CI against that branch, creates the final
tag only after CI succeeds, builds the CLI artifacts, creates and publishes the
GitHub release, publishes the workspace's publishable crates, and opens a PR
that synchronizes the RC version back to `main`. It has no skill, npm, or
Python-package stages because this workspace does not ship those artifacts.

Release artifacts are built by a tag-driven workflow from the CLI package only.
The release workflow uses these six target/runner pairs:

| Target | Release runner | CLI feature |
|---|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` | `linux-bundled-bubblewrap` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04` plus Zig cross-build | `linux-bundled-bubblewrap` |
| `x86_64-pc-windows-msvc` | `windows-2025` | `windows` |
| `aarch64-pc-windows-msvc` | `windows-2025` | `windows` |
| `x86_64-apple-darwin` | `macos-26-intel` | `macos` |
| `aarch64-apple-darwin` | `macos-26` | `macos` |

The Rust target triple, not the runner label, determines the artifact
architecture. Each artifact name includes its target triple. Normal feature
work does not bump workspace or protocol versions; release preparation owns
deliberate version changes.

The release workflow is the stable cargo-dist orchestration kept in
`.github/workflows/bin-release.yml`. It is based on the reviewed plugmem
workflow shape and is intentionally maintained as a checked-in workflow rather
than regenerated during ordinary changes. It contains only the Cageforge CLI
release: target archives, checksums, shell and PowerShell installers, Windows
MSI packages, and the Homebrew formula for `m62624/homebrew-cageforge`.
There are no MCP, Skill, npm, Python, or native companion-binary release
stages. The WiX template uses Cageforge-owned stable product and PATH-component
GUIDs; these identifiers must not be copied from another project or changed
between compatible MSI releases.

The first crates.io publication is a one-time bootstrap. Trusted Publishing
cannot be registered until a crate has an initial release. For that bootstrap,
the release publisher temporarily adds a GitHub Actions secret named
`CARGO_REGISTRY_TOKEN`, containing a narrowly scoped crates.io API token. The
workflow detects that secret without exposing it and uses it only for the
bootstrap publication. After each crate has its Trusted Publisher configured
for repository `m62624/cageforge` and workflow `release.yml`, the bootstrap
secret is removed; subsequent runs then use
`rust-lang/crates-io-auth-action` with GitHub OIDC. `HOMEBREW_TAP_TOKEN` is a
separate secret used only to push the generated formula to the Cageforge tap.

## Testing requirements

Black-box CLI tests must cover profile loading, explicit command and argv
handling, missing profile/command failures, unsupported feature behavior,
child exit-code propagation, and the no-shell-parsing boundary. Native CI
must exercise the CLI with the matching backend feature on each supported OS.
Tests must not weaken the backend API or add test-only public escape hatches.

## Relationship to upstream

The CLI's thin-adapter shape follows the reviewed `plugmem-cli` pattern and
the process-boundary behavior is informed by the frozen Codex review baseline.
No Codex CLI protocol, product type, telemetry, PTY, or network-proxy API is
copied into this crate. Cageforge's public API and TOML schema remain the
source of truth.
