# Specification 0006: Cageforge Policy Model

Status: accepted; portable implementation complete

## Purpose

`cageforge-policy` is the first implementation crate in the workspace. It is
a platform-independent Rust library that describes and resolves filesystem and
network boundaries for a sandbox. It is not a process launcher and does not
know which agent harness or operating-system backend will consume the policy.

The model is Cageforge's own API. It does not reproduce Codex configuration
names, aliases, legacy compatibility behavior, `PermissionProfile`, or
product-specific protocol types.

## Crate boundary

```text
cageforge-path
    shared native path comparison and lexical validation

cageforge-policy
    pure policy semantics and validation; consumes cageforge-path

cageforge-config
    future TOML loader and named-profile composition

cageforge-command
    future command, environment, cwd, and stdio description

cageforge-backend-api
    future backend capability and preparation contract

cageforge-linux / cageforge-macos / cageforge-windows
    future native enforcement implementations
```

`cageforge-policy` must not depend on TOML, Starlark, Codex, network proxy,
PTY, telemetry, or a platform sandbox API.

## Public model

The first crate exposes:

- `AccessMode`: `Read`, `Write`, and `Deny`;
- `PathSelector`: native absolute paths, workspace-relative paths, and
  platform-defined scopes for minimal runtime files, the platform temporary
  directory, and `/tmp`;
- `PathPattern` and `PathResolutionContext` for validated globs, runtime path
  expansion, and the absolute directory used to resolve or validate command
  cwd;
- `FilesystemRule`, `FilesystemTarget`, `FilesystemMode`,
  `MissingPathBehavior`, and `FilesystemPolicy`;
- `DomainRule`, `DomainAccess`, `DomainMode`, `UnixSocketRule`,
  `UnixSocketMode`, `NetworkMode`, `LocalNetworkAccess`, and `NetworkPolicy`;
- `SandboxPolicy`, which combines filesystem and network policy.

The crate provides built-in constructors named `read_only`, `workspace`, and
`full_access`; `NetworkPolicy` also provides the explicit `unrestricted` network
preset. These are Cageforge concepts, not Codex compatibility aliases. They are
initial policy presets; future named TOML profiles will resolve to the same
policy types.

Restricted filesystem policies also carry protected metadata paths by default.
The initial default is the relative path `.git`, applied below every writable
scope. Callers may add more relative protected paths through an additive API,
and an explicitly named `dangerously_allow_git_write` operation can request
removal of the default. A later policy composer or backend may reject that
dangerous request.

## Security invariants

- Workspace-relative selectors cannot contain NUL characters, parent traversal,
  or become absolute.
- Absolute selectors and concrete access lookups reject NUL characters and
  parent traversal. They are validated lexically without filesystem access or
  symlink resolution; native backends must enforce the same boundary when
  resolving filesystem objects.
- Filesystem access is recursive. Any matching deny rule wins; among read/write
  rules the most-specific resolved target wins. Exact profile overrides and
  capability intersection are separate operations; an inherited policy must
  not accidentally widen a granted capability.
- Specificity counts logical path components, excluding the native root or
  drive prefix. This lets a workspace-relative deny glob such as
  `Secrets/**` override the writable workspace-root rule it narrows.
- Capability intersection is conservative: `Deny` over `Read` over `Write`.
  A profile may explicitly override an equal canonical target while resolving a
  requested policy, but the later backend grant intersection may only narrow
  it.
- Glob patterns support component wildcards, recursive `**` matching, and
  `globset`-compatible character classes, ranges, negative classes, and
  alternates. They reject parent traversal and malformed syntax and carry an
  explicit scan depth for backend expansion.
- Writable rules may carry read-only subpath carve-outs, and concrete targets
  may explicitly request skip-on-missing behavior.
- `.git` is protected as read-only below every writable scope in a restricted
  policy by default. Additional protected relative paths are additive and are
  evaluated after ordinary rules, so a later write rule cannot bypass them.
  The library exposes only the explicitly named
  `dangerously_allow_git_write` opt-out; a later composer or backend may still
  reject it. Protection means that the path remains readable but is not
  writable.
- Protected relative paths must be non-empty, relative, free of NUL and parent
  traversal components, and matched as path components (`.git` must not match
  `.gitignore`). Native backends must also prevent symlink-based escapes.
- Concrete path matching follows host filesystem conventions: POSIX path
  components and glob segments are case-sensitive, while Windows components,
  drive prefixes, and glob segments are case-insensitive. Protected metadata
  uses the same native comparison rules. Supported Windows drive and UNC
  verbatim/device aliases share one identity, and malformed UTF-16 does not
  collapse through lossy conversion. Symlink resolution remains a native
  backend responsibility.
- Unrestricted and externally enforced filesystem policies cannot carry local
  filesystem rules. Restriction-only builders reject those combinations at
  construction time.
- Domain inputs use host-boundary normalization: matching is case-insensitive,
  trailing dots and host ports are ignored, bracketed IPv6 literals are
  unwrapped, and IPv4/IPv6 literals are canonicalized. Missing, non-numeric,
  and out-of-range ports are rejected. Schemes, paths, whitespace, empty
  labels, malformed bracketed hosts, and unsupported wildcard syntax are
  rejected.
- Domain patterns support `*`, `?`, character classes, ranges, and negative
  classes within labels, including mid-label patterns such as
  `region*.example.com`; the `*.` and `**.` prefixes retain their explicit
  subdomain-only and apex-plus-subdomains semantics.
- Domain glob matchers are compiled when `DomainRule` is constructed rather
  than during each lookup. The stored matcher is an implementation detail;
  public equality and serialization identity remain the normalized pattern and
  access decision.
- `*.example.com` matches subdomains but not the apex; `**.example.com`
  matches the apex and subdomains.
- Deny wins when multiple matching domain rules apply.
- Domain and Unix-socket defaults are explicit: disabled, enabled, or
  restricted allowlist; backends never infer a default from rule presence.
- Resolved domain targets use `LocalNetworkAccess::Deny` by default. Backends
  pass all DNS results to the typed resolved-target query; empty resolution and
  any non-public result are denied for ordinary hostnames even when the
  hostname is explicitly allowlisted, preventing DNS rebinding. An IP literal
  does not require DNS results, so an empty result is valid for the literal
  itself; non-public literals still require an exact IP rule or
  `LocalNetworkAccess::Allow`. An exact `localhost` rule permits only loopback
  among non-public addresses. Broader private, link-local, reserved, or other
  special-purpose non-global access requires `LocalNetworkAccess::Allow`. The
  policy crate never performs DNS or connection I/O.
- Disabled network mode always denies even when inert rules are retained for
  inspection. External network policy cannot carry local domain or socket
  rules; its rule builders reject the combination at construction time.
- `NetworkPolicy::decision_for_domain` and
  `NetworkPolicy::decision_for_unix_socket` return typed `Allow`, `Deny`, or
  `ExternallyEnforced` results. The public API does not expose boolean
  authorization helpers, so callers cannot accidentally collapse local denial
  and externally enforced policy into the same `bool` result. Backends must
  handle the typed decision explicitly and use `authorize_connection` for
  actual network authorization.
- A network backend must use `authorize_connection`; it is the only network
  API that can return an `AuthorizedSocketAddr` bound to the resolution
  snapshot and exact connected address.
- Unrestricted and external enforcement are explicit ownership transfers. A
  backend or policy composer may reject them when its grant does not permit the
  transfer.
- The policy crate never silently broadens an effective policy. Requested
  profile resolution and effective capability composition remain separate.

The comparison against the current Codex sandbox crates and the intentionally
deferred semantics are recorded in `specs/0007-codex-policy-audit.md`.

## Testing policy

The crate is tested as a library through black-box integration tests in
`crates/cageforge-policy/tests/`. The suite covers native absolute paths,
relative paths, NUL and parent traversal rejection, special scopes, context
expansion, POSIX and Windows-native path forms, path patterns, recursive
resolution, access precedence, duplicate normalization, filesystem modes,
carve-outs, missing-path behavior, domain normalization and wildcard
semantics, Unix socket validation, external-policy validation, and built-in
policies. Network tests also cover host ports, bracketed IPv6, typed external
decisions, and malformed paths under an external policy.

Unit tests should be added only when private implementation logic cannot be
meaningfully exercised through the public API.

## Documentation and coverage gates

`src/lib.rs` uses `#![deny(missing_docs)]`. Every public item must have a Rust
doc comment or the crate fails to compile.

The workspace `tarpaulin.toml` sets a hard 90% line-coverage floor. Native
platform backends will later be excluded from the aggregate Tarpaulin metric
because their enforcement tests must run on their respective operating systems;
they remain required in the native CI matrix.

## Native enforcement boundary

Portable filesystem evaluation is lexical. It does not resolve symlinks or
Windows junction/reparse points and cannot close mount or TOCTOU races. Native
backends must apply OS-level enforcement and safe file-opening rules instead of
treating `access_for_path` as sufficient authorization.

Network host evaluation has the same boundary. `decision_for_domain` is a
declarative policy query, not a connection authorization. Backends use
`ResolvedNetworkTarget`, check all resolution results, and verify the exact
connected `SocketAddr` immediately before connecting.

Restricted policies protect `.git` below writable scopes by default. Additional
protected paths are generic. `dangerously_allow_git_write` is a trusted opt-in
that a stricter ceiling or backend may reject.
