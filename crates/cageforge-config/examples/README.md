# `cageforge-config` examples

> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

Start with the [configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md). It explains the
full TOML-to-native-launch flow, the platform meaning of `minimal`, and how to
choose the configuration for Linux, macOS, or Windows.

The [`runnable/`](https://github.com/m62624/cageforge/tree/main/crates/cageforge-config/examples/runnable) directory contains one native smoke profile per
operating system. Use only the file for the host where the command will run:

| Host | Runnable profile | Command |
|---|---|---|
| Linux | [`runnable/linux/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/linux/smoke.toml) | `/bin/echo` |
| macOS | [`runnable/macos/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/macos/smoke.toml) | `/bin/echo` |
| Windows | [`runnable/windows/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/windows/smoke.toml) | `C:/Windows/System32/cmd.exe` |

Each smoke profile includes `minimal` read access, a writable workspace root,
and disabled networking. The three files are deliberately separate: Windows
paths and `cmd.exe` are not Linux/macOS input, while POSIX `/bin/echo` is not a
Windows command. The platform backend still supplies the absolute runtime
paths represented by the symbolic selectors.

The files in this directory are resolution fixtures for the portable
configuration layer. They can be loaded with `Config::from_file` or embedded
with `Config::from_toml`, then resolved through `resolve_default` or
`resolve`. Use the host-specific `platform-targets-*` file when a fixture must
contain native absolute path syntax; do not use it as a cross-platform launch
profile.

| File | Scenario | Main concepts |
|---|---|---|
| [`minimal-policy.toml`](minimal-policy.toml) | Read-only policy without a command | Platform-minimal runtime, safe defaults, disabled network |
| [`workspace-development.toml`](workspace-development.toml) | Normal writable development profile | Workspace roots, protected paths, command argv, environment, stdio, timeout |
| [`profile-inheritance.toml`](profile-inheritance.toml) | Parent profile refined by a child | Inheritance, exact target replacement, environment filter replacement |
| [`environment-order.toml`](environment-order.toml) | Explicit environment processing | `inherit → exclude → set/remove → include` |
| [`trusted-metadata-write.toml`](trusted-metadata-write.toml) | Deliberate repository metadata opt-out | Additional protection and `dangerously_allow_git_write` |
| [`network-gateway.toml`](network-gateway.toml) | Restricted outbound gateway runtime | Timeouts, resource bounds, inheritance, explicit unlimited relay mode |
| [`permission-preflight.toml`](permission-preflight.toml) | One cross-platform approval profile | Persistent preflight, shared policy, and Linux/macOS/Windows native paths |
| [`permission-session.toml`](permission-session.toml) | Session-only approval | Preflight without a persistent store record |
| [`permission-inheritance.toml`](permission-inheritance.toml) | Approval merge and platform override | Scalar inheritance, child overrides, and Windows approval overlay |
| [`platform-targets-unix.toml`](platform-targets-unix.toml) | Linux/macOS path and socket syntax | All portable filesystem and network rule fields |
| [`platform-targets-windows.toml`](platform-targets-windows.toml) | Windows-native equivalent | Drive-qualified paths and the same portable policy fields |
| [`local-ipc-platforms.toml`](local-ipc-platforms.toml) | Portable local IPC declaration | Unix sockets on Linux/macOS and named-pipe validation on Windows |

Local IPC endpoint syntax is platform-specific inside one portable document:
`local_ipc.unix_sockets` contains absolute POSIX paths for Linux/macOS, while
`local_ipc.named_pipes` contains names from the Windows `\\.\pipe\` namespace.
Rust callers use `LocalIpcEndpoint`; Python and Java/Kotlin permission requests
expose the same endpoint kinds as typed values.
The selected native backend must prove enforcement before launch; unsupported
endpoint types fail closed.

The configuration test suite parses and resolves every checked-in TOML file on
every host. Only the three files under `runnable/` are native launch fixtures:
the Linux QEMU job, the macOS native job, and the Windows native job execute
the matching profile through `cageforge-cli`. The other files intentionally
describe policy, inheritance, platform syntax, or external services; their
contract is parse-and-resolve validation, not an implicit host launch.

### What a first launch must declare

An endpoint declaration is not a general permission grant. A command still
needs the resources it uses to start and run:

- `minimal` read access for the platform runtime and executable loader;
- `workspace-root` write access when the command's working directory is the
  workspace or it creates output there; and
- `network.mode = "disabled"` unless the application explicitly needs a different
  network mode.

The local-IPC rule is then added separately for the exact endpoint. On Linux
and macOS that endpoint is an absolute Unix-socket path. On Windows it is a
local `\\.\pipe\...` named pipe. Allowing an IPC endpoint does not grant the
working directory, arbitrary files, TCP loopback, or other sockets. A missing
resource must be added to the appropriate policy section and profile; it is
not inferred from the IPC rule.

The [`local-ipc-platforms.toml`](local-ipc-platforms.toml) file is the
complete minimal policy shape: its common filesystem section makes the command
launchable, and its three platform overlays select only the native endpoint
syntax for the current OS. Use the overlay for the host that will run the
command; the other endpoint kinds are not translated or silently widened.

The environment order applies to a command environment, not to filesystem
permissions or profile inheritance. `cageforge-config` parses and resolves the
TOML into `EnvironmentSpec`; `cageforge-command` applies the portable stages
after a backend has selected the `all`, `core`, or `none` base environment.
The `root` and `minimal` targets are symbolic: the backend supplies their
concrete platform paths through its validated runtime context.

Suggested reading order:

1. The [configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md) for the platform model.
2. `minimal-policy.toml` for the smallest policy-only profile.
3. `workspace-development.toml` for a command plus filesystem declarations.
4. `profile-inheritance.toml` for parent/child overrides.
5. `environment-order.toml` for environment filtering stages.
6. `network-gateway.toml` for proxy runtime limits and inheritance.
7. `permission-preflight.toml` for persistent approval and host-selected store paths.
8. `permission-session.toml` for in-memory session approval.
9. `permission-inheritance.toml` for approval-field merge and platform overlay.
10. The matching platform fixture for native path spelling.

Domain entries accept host-like inputs such as `Example.com:443` and
`[2001:db8::1]:443`; the resolved policy stores their normalized host form.
Working-directory values may be relative, but parent traversal such as
`../outside` is rejected by `cageforge-command`.
