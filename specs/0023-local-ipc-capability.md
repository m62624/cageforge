# Specification 0023: Portable Local IPC Capability

## Status

Active implementation contract.

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
pipe policy, a launch-unique capability SID, a restricted token without broad
restricting SIDs, denial of neighboring unauthorized endpoints, descendant
inheritance, and durable deterministic cleanup. The original and intended
DACLs are journaled before mutation and restored only after exact read-back;
unexpected drift fails closed. A Windows Unix-socket endpoint is unsupported
and receives the typed capability error before spawn. There is no unrestricted,
TCP, or unsandboxed fallback.

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
binding success/error parity tests. Native tests run only in their matching CI
environments; missing native prerequisites are failures, not skips.
