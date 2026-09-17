# `cageforge-config` examples

Start with the [configuration guide](CONFIGURATION_GUIDE.md). It explains the
full TOML-to-native-launch flow, the platform meaning of `minimal`, and how to
choose the configuration for Linux, macOS, or Windows.

The [`runnable/`](runnable/) directory contains one native smoke profile per
operating system. Use only the file for the host where the command will run:

| Host | Runnable profile | Command |
|---|---|---|
| Linux | [`runnable/linux/smoke.toml`](runnable/linux/smoke.toml) | `/bin/echo` |
| macOS | [`runnable/macos/smoke.toml`](runnable/macos/smoke.toml) | `/bin/echo` |
| Windows | [`runnable/windows/smoke.toml`](runnable/windows/smoke.toml) | `C:/Windows/System32/cmd.exe` |

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
| [`platform-targets-unix.toml`](platform-targets-unix.toml) | Linux/macOS path and socket syntax | All portable filesystem and network rule fields |
| [`platform-targets-windows.toml`](platform-targets-windows.toml) | Windows-native equivalent | Drive-qualified paths and the same portable policy fields |

The environment order applies to a command environment, not to filesystem
permissions or profile inheritance. `cageforge-config` parses and resolves the
TOML into `EnvironmentSpec`; `cageforge-command` applies the portable stages
after a backend has selected the `all`, `core`, or `none` base environment.
The `root` and `minimal` targets are symbolic: the backend supplies their
concrete platform paths through its validated runtime context.

Suggested reading order:

1. The [configuration guide](CONFIGURATION_GUIDE.md) for the platform model.
2. `minimal-policy.toml` for the smallest policy-only profile.
3. `workspace-development.toml` for a command plus filesystem declarations.
4. `profile-inheritance.toml` for parent/child overrides.
5. `environment-order.toml` for environment filtering stages.
6. `network-gateway.toml` for proxy runtime limits and inheritance.
7. The matching platform fixture for native path spelling.

Domain entries accept host-like inputs such as `Example.com:443` and
`[2001:db8::1]:443`; the resolved policy stores their normalized host form.
Working-directory values may be relative, but parent traversal such as
`../outside` is rejected by `cageforge-command`.
