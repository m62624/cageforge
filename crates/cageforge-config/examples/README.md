# `cageforge-config` examples

These TOML files are executable documentation. The integration tests load them
with `include_str!`, parse them through `Config::from_toml`, resolve their
default profile, and check the important resulting values. If the schema or
resolution rules change, the examples fail with the tests instead of silently
becoming stale.

| File | Scenario | Main concepts |
|---|---|---|
| [`minimal-policy.toml`](minimal-policy.toml) | Read-only policy without a command | Safe defaults, restricted filesystem, disabled network |
| [`workspace-development.toml`](workspace-development.toml) | Normal writable development profile | Workspace roots, protected paths, command argv, environment, stdio, timeout |
| [`profile-inheritance.toml`](profile-inheritance.toml) | Parent profile refined by a child | Inheritance, exact target replacement, environment filter replacement |
| [`environment-order.toml`](environment-order.toml) | Explicit environment processing | `inherit → exclude → set/remove → include` |
| [`trusted-metadata-write.toml`](trusted-metadata-write.toml) | Deliberate repository metadata opt-out | Additional protection and `dangerously_allow_git_write` |
| [`platform-targets-unix.toml`](platform-targets-unix.toml) | Unix/macOS path and socket syntax | All filesystem targets and network rule fields |
| [`platform-targets-windows.toml`](platform-targets-windows.toml) | Windows-native equivalent | Drive-qualified paths and the same portable policy fields |

The two `platform-targets-*` files contain the same logical scenario with
native absolute paths. The test suite selects the matching file for the host;
the other file remains available as a copyable reference for cross-platform
configuration.

The environment order applies to a command environment, not to filesystem
permissions or profile inheritance. `cageforge-config` parses and resolves the
TOML into `EnvironmentSpec`; `cageforge-command` applies the portable stages
after a backend has selected the `all`, `core`, or `none` base environment.
