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
platform, command, path, and source location. `to_json()` is for machines; the
CLI uses `render_human()` and must not require callers to parse a display
string. A resolved profile retains source metadata separately from its
semantic policy value. Native adapters use that metadata to attach the
selected profile, effective command, logical field, and TOML line/column to a
backend failure without making the backend parse TOML.

## Native boundary

The selected backend performs native capability checks after composition and
before process creation. For macOS, Seatbelt owns the fixed executable
baseline and checks absolute custom programs against effective read access and
explicit `runtime.executable_roots`. It returns typed errors such as
`ProgramRequiresRead` and `ProgramRequiresExecutableRoot`; config does not
duplicate the Seatbelt baseline. The CLI and host-language adapters may wrap
the typed native cause in a source-aware diagnostic, but must retain the
original typed error for programmatic inspection.

## Foreign bindings

Python raises `CageforgeConfigurationError` for config failures and
`CageforgeLaunchError` for source-aware native launch failures. Java raises
`CageforgeConfigurationException` and `CageforgeLaunchException` respectively.
Both pairs expose the stable attributes `code`, `config_path`, `profile`,
`platform`, `field`, `line`, `column`, and `command` where available.
Bindings must preserve the error category and nested native cause, use the same
platform-specific native diagnostic codes and logical fields as the CLI, never
let a Rust panic cross FFI, and never use raw stderr or a sentinel success value
as the public error protocol.

## Verification

Rust tests cover typed variants, shared native-code classification, source
context, platform overlays, and native preflight failures. CLI snapshots cover
generic Linux/Windows failures and every macOS runtime/read variant, including
the platform, command, profile, field, and source location. Python and Java
tests verify the stable exception category and metadata; their launch adapters
reuse the same native-code classifier. Native jobs remain responsible for
executing the backend-specific checks on their actual operating system.
