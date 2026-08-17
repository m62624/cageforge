# cageforge-command

Portable command invocation types for Cageforge.

This crate describes a command that a backend may execute. It does not spawn
processes, parse TOML, apply a sandbox, allocate a PTY, or depend on an agent
protocol. A future backend API will combine these requests with
`cageforge-policy` and platform-specific capabilities.

The request model has explicit types for:

- an argv vector with a non-empty program;
- an optional working directory;
- inherited or empty environments with explicit set/unset overrides;
- stdin, stdout, and stderr routing;
- an optional execution timeout.

The crate is intentionally independent from product-specific command names and
legacy configuration formats.
