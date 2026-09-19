# Specification 0023: Portable Local IPC Capability

## Status

Active implementation contract.

This is the cross-platform capability contract, not a Windows-only
specification. The native details are recorded in
[Specification 0014](0014-linux-backend-implementation.md),
[Specification 0017](0017-macos-backend-implementation.md), and
[Specification 0016](0016-windows-backend-implementation.md). Those backend
specifications must implement this model without changing its public endpoint
or fail-closed semantics.

## Purpose

`LocalIpcEndpoint` is Cageforge's platform-neutral description of one local
IPC endpoint. It keeps the high-level policy and permission model identical
while allowing each native backend to use its own endpoint primitive.

The public endpoint variants are:

- `UnixSocket(AbsolutePath)` on Linux and macOS;
- `WindowsNamedPipe(NamedPipeName)` on Windows.

A Windows named pipe is never represented as a Unix path and is never silently
converted into TCP loopback.

## Configuration

Platform overlays use the following shape:

```toml
[profiles.tool.platforms.linux.local_ipc]
unix_sockets = ["/run/tool/service.sock"]

[profiles.tool.platforms.macos.local_ipc]
unix_sockets = ["/var/run/tool/service.sock"]

[profiles.tool.platforms.windows.local_ipc]
named_pipes = ['\\.\pipe\tool-service']
```

Endpoint declarations are explicit, validated, deduplicated during profile
merge, and immutable after native launch preparation. Unix-socket declarations
enable the local network boundary needed by pathname socket enforcement;
Windows named pipes remain compatible with `network = "disabled"` because they
are enforced as kernel object capabilities, while external access remains
governed by the ordinary network policy.

## Validation

The policy layer rejects empty values, NULs, relative or parent-traversing Unix
paths, remote named-pipe namespaces, malformed pipe names, duplicate endpoints,
and names exceeding the backend-supported bound. Invalid values fail before
composition or process creation.

## Native enforcement

Linux and macOS lower Unix-socket endpoints through their existing native
enforcement paths. Their existing closed-by-default and exact pathname rules
remain authoritative; the new typed model is an additional common entry point
to those paths.

Windows named-pipe enforcement combines strict host/sandbox DACLs, local-only
pipe policy, a launch-unique capability SID, and a write-restricted token that
does not restore broad user or Everyone access. The authenticated logon SID is
retained where Windows session initialization requires it, including the
session `ApiPort`; it is not an approval for any named pipe. The capability
SID remains the narrow authorization for the explicitly approved pipe, and is
also authorized on the private desktop and token default DACL. The DACL for an
approved pipe additionally grants the selected dedicated runner-account SID,
which supplies the normal-token side of Windows restricted-token access
checking; the launch capability SID remains the second, launch-specific
condition. This lets the child complete startup without widening pipe access.
Neighboring unauthorized
endpoints remain denied, descendants inherit the restriction, and cleanup is
durable and deterministic. The original and intended DACLs are journaled
before mutation and restored only after exact read-back; unexpected drift
fails closed. A Windows Unix-socket endpoint is unsupported and receives the
typed capability error before spawn. There is no unrestricted, TCP, or
unsandboxed fallback.

The Windows ACL transaction holds one host-side handle for each approved pipe
from original-state capture through DACL activation, read-back verification,
restoration, and final restoration verification. All security operations for
that transaction address the retained handle; launch enforcement does not
depend on repeatedly opening fresh named-pipe instances between transaction
steps. The handle is released only after the journal is resolved. Recovery of
an interrupted transaction opens and validates a replacement handle because no
live launch transaction handle exists.

## Foreign-language contract

Rust, Python, and Java expose the same endpoint kinds, endpoint values,
configuration behavior, and structured error categories. Python exposes frozen
`LocalIpcEndpoint` values with a `kind` and validated `value`; Kotlin exposes
the corresponding sealed `UnixSocket` and `WindowsNamedPipe` types. The
ordinary network-capability list remains available for generic network rules,
but LocalIpc consumers do not need to parse transport-prefixed strings.
FFI boundaries must not return raw error strings, cross-language panics, or
platform-specific path hacks. Python stubs and Java API documentation are
generated/updated with the corresponding binding changes.

## Verification

The implementation requires policy/config parsing tests, platform-overlay
tests, Linux and macOS native allow/deny tests, Windows named-pipe allow/deny,
descendant and ACL-recovery tests, typed unsupported Unix-socket tests, and
binding success/error parity tests. The required native process scenario is
host endpoint creation, an approved child connection, denial of a neighboring
endpoint, restriction of a spawned descendant, and cleanup with no surviving
helper or temporary enforcement state. Windows additionally verifies that an
approved named pipe succeeds, another named pipe and loopback remain denied by
the effective policy, and ACL drift or setup failure returns a typed error
before spawn. Native tests run only in their matching CI environments; missing
native prerequisites are failures, not skips.

The three checked-in runnable configuration profiles are executed through the
shared CLI smoke runner after the platform backend checks. All other TOML
examples are parse-and-resolve fixtures because some intentionally describe a
policy without a command, a placeholder executable, an external service, or
host paths that must not be created by CI.
