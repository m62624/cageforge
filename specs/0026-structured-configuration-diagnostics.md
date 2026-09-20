# Specification 0026: Structured Configuration Diagnostics

Status: active implementation contract

## Purpose

Cageforge configuration failures must be useful to both a human invoking the
CLI and a host language binding. A display string is not the API contract.
Rust exposes the typed error; the CLI renders one concise diagnostic; Python
and Java preserve the same category and source metadata in their exception
types.

## Configuration boundary

`cageforge-config` parses TOML, selects the requested platform overlay, merges
profiles, and validates portable configuration invariants. It does not decide
which paths a native backend treats as system runtime paths or how a native
policy is lowered. Backend-specific checks belong to the selected backend and
must return that backend's typed error before spawn.

Each `ConfigError` may carry `ConfigErrorContext` containing:

- the configuration path, when the source came from a file;
- the selected `PlatformId`;
- the source line, column, byte offset, and span length;
- the profile and logical field identified by the error.

`ConfigDiagnostic` exposes a stable code, severity, message, profile, field,
platform, path, and source location. `to_json()` is for machines; the CLI
uses `render_human()` and must not require callers to parse a display string.

## Native boundary

The selected backend performs native capability checks after composition and
before process creation. For macOS, Seatbelt owns the fixed executable
baseline and checks absolute custom programs against effective read access and
explicit `runtime.executable_roots`. It returns typed errors such as
`ProgramRequiresRead` and `ProgramRequiresExecutableRoot`; config does not
duplicate the Seatbelt baseline.

## Foreign bindings

Python raises `CageforgeConfigurationError` with stable attributes:
`code`, `config_path`, `profile`, `platform`, `field`, `line`, and `column`.
Java raises `CageforgeConfigurationException` with the equivalent properties.
Bindings must preserve the error category and nested native cause, never let a
Rust panic cross FFI, and never use raw stderr or a sentinel success value as
the public error protocol.

## Verification

Rust tests cover typed variants, source context, platform overlays, and native
preflight failures. CLI tests use snapshots for the human rendering. Python
and Java tests verify the stable exception category and metadata. Native jobs
remain responsible for executing the backend-specific checks on their actual
operating system.
