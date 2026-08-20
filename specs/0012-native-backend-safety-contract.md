# Specification 0012: Native Backend Safety Contract

Status: accepted; required before native backend implementation

## Purpose

The portable crates make lexical policy decisions. They do not have enough
information or operating-system authority to enforce filesystem object
identity, mount boundaries, or connection races. Every native backend must
close those gaps before it launches a restricted process or performs a
restricted file operation.

## Filesystem contract

`FilesystemPolicy::access_for_path` and
`EffectiveFilesystemPolicy::access_for_path` are lexical decisions only. A
backend must not treat `Write` or `Read` from either method as authorization to
call `std::fs::write`, `File::open`, or an equivalent operation directly.

Before handing a path to an operating-system API, the backend must:

1. establish the native enforcement boundary before the restricted process can
   access the filesystem;
2. resolve or constrain symlinks on POSIX systems and junctions/reparse points
   on Windows according to the selected policy;
3. account for mount, bind-mount, drive, and other filesystem-root escapes;
4. use descriptor- or handle-relative operations, or an equivalent OS-native
   mechanism, so validation and use cannot be separated by a TOCTOU race; and
5. return a typed unsupported-capability error when the selected backend cannot
   prove these properties for a requested rule.

The portable layer deliberately does not canonicalize paths or inspect the
filesystem. A backend may reject a path conservatively, but it must never
convert a lexical `Allow` into an unrestricted direct host operation.

## Network contract

A domain decision is declarative policy inspection. It is not permission to
open a socket. The backend must resolve the host once, construct one
`ResolvedNetworkTarget` containing every result, and use only an address from
that snapshot. Immediately before connecting it must check the exact
`SocketAddr` with `authorize_connection` and connect only through the returned
`AuthorizedSocketAddr`. A second DNS lookup, an unverified address, or a
changed target is denied. Hostname-only decision methods are inspection APIs,
not connection authorization.

External enforcement values and `ExternalOwner` identify a caller-declared
boundary only. They do not prove that an OS sandbox, firewall, proxy, or DNS
policy exists. The backend or embedding application must provide that proof
through its own trusted setup and must fail closed when it cannot do so.

## Required verification

Each native backend must add tests on its own operating-system runner for:

- symlink, junction, and reparse-point escapes;
- mount or drive-root escapes;
- validation/use races and safe handle-relative operations;
- exact resolved-address enforcement and DNS-rebinding attempts; and
- unsupported capability paths returning typed errors.

These tests cannot be replaced by portable lexical unit tests.
