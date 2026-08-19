# `cageforge-config` examples

These TOML files are copyable documentation for the configuration boundary.
Each one can be loaded with `Config::from_file` or embedded with
`Config::from_toml`, then resolved through `resolve_default` or `resolve`.
They are kept alongside the crate's integration coverage so the documented
syntax remains a real configuration surface.

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
The `root` target is symbolic: the backend supplies its concrete POSIX root or
Windows drive/UNC roots.

Suggested reading order:

1. `minimal-policy.toml` for safe defaults and the smallest profile.
2. `workspace-development.toml` for a command plus filesystem and network
   declarations.
3. `profile-inheritance.toml` for parent/child overrides.
4. `environment-order.toml` for environment filtering stages.
5. The platform examples for native path spelling and all supported target
   forms.

Domain entries accept host-like inputs such as `Example.com:443` and
`[2001:db8::1]:443`; the resolved policy stores their normalized host form.
Working-directory values may be relative, but parent traversal such as
`../outside` is rejected by `cageforge-command`.
