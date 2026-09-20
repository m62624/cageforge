# Specification 0024: macOS Executable Runtime Roots

Status: active implementation contract

## Purpose

macOS Seatbelt separates filesystem reads from `file-map-executable`. A
restricted process that needs to start a Mach-O executable from a user-owned
runtime directory must therefore declare both permissions explicitly. This
specification defines the portable configuration and permission contract for
that case while keeping native enforcement macOS-specific.

## Configuration

The selected profile may declare validated runtime roots in a platform overlay:

```toml
[profiles.tool.platforms.macos.filesystem]
rules = [
  { target = "minimal", access = "read" },
  { target = "absolute", path = "/opt/example-runtime", access = "read" },
]

[profiles.tool.platforms.macos.runtime]
executable_roots = ["/opt/example-runtime"]
```

`runtime.executable_roots` contains existing absolute directories. The config
layer rejects empty, NUL-containing, relative, parent-traversing, and duplicate
paths. The macOS backend additionally rejects missing roots, symlinked
ancestors, non-directories, and roots not covered by effective read or write
filesystem access. The root is canonicalized before native policy generation.

Platform overlays validate path syntax for their declared target platform, so
one portable TOML document may contain all three operating-system overlays.
Only the selected overlay is resolved into the runtime context. This
capability remains macOS-specific: Linux and Windows reject a direct
executable-root context with a typed unsupported-capability error.

The runtime declaration never grants read or write access. Those permissions
remain ordinary filesystem rules and must be declared separately. A runtime
root is not inferred from `command.program`, `minimal`, or any other readable
path.

## Native enforcement

`PathResolutionContext` carries executable roots separately from root,
workspace, minimal, temporary, and current-directory inputs. Composition copies
them into the effective context without widening workspace roots. The backend
advertises `FilesystemExecutableMapping` only on macOS; Linux and Windows
reject a non-empty executable-root context with the typed unsupported
capability error rather than ignoring it.

The macOS filesystem plan validates every root before spawn. Seatbelt first
denies `file-map-executable` and then receives one allowlist for the fixed
system runtime roots plus the caller's canonical directories. The caller's
allowlist is separate from the normal `file-read*` and `file-write*` rules and
is narrowed by the effective deny paths and deny globs. The prepared request is
immutable after validation and every descendant inherits the same profile.

System runtime paths retain the fixed Seatbelt baseline. This capability is for
non-system runtime roots and must not be implemented by granting executable
mapping to all readable paths or the whole filesystem.

## Permission and binding contract

The host-facing permission model represents the additional operation as the
stable filesystem capability label `map-executable`. A restricted request for
one runtime root contains both `read` and `map-executable` capabilities for
that root. A partial grant cannot remove either capability independently; the
launch fails closed instead of using an unapproved mapping.

Rust callers add roots with `PathResolutionContext::with_executable_root`.
Python and Java callers use the same TOML platform overlay through
`permission_request`/`permissionRequest`; their existing filesystem capability
accessors expose the same `map-executable` operation label. No binding adds a
macOS-specific launch method or path convention.

## Verification

The config tests cover parsing, platform selection, duplicate rejection, and
unsafe-path rejection. The backend API verifies unsupported capability
negotiation. The macOS native integration test builds a small Mach-O program
and a dynamic library in a temporary user runtime directory. The program
explicitly maps a sibling Mach-O executable payload with executable
permissions, proving that the child fails without `runtime.executable_roots`
and prints its marker successfully when the mapping capability is present. The
test runs inside the existing native macOS backend job; it is not a config-only
fixture.
