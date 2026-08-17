# `cageforge-command`

This crate owns portable command invocation intent only.

- Do not spawn processes or import OS-specific process APIs here.
- Do not add TOML, sandbox enforcement, PTY implementation, telemetry, or
  harness protocol types here.
- Keep the public API explicit with enums and named builder methods.
- Put behavior tests in `tests/` and prefer the public API over private unit
  tests.
- A backend will compose `CommandRequest` with `cageforge-policy`; this crate
  must remain independently reusable.
