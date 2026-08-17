# Specification 0005: Cageforge Policy Model

Status: accepted for the first implementation milestone

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
cageforge-policy
    pure policy semantics and validation

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
- `PathPattern` and `PathResolutionContext` for validated globs and runtime
  path expansion;
- `FilesystemRule`, `FilesystemTarget`, `FilesystemMode`,
  `MissingPathBehavior`, and `FilesystemPolicy`;
- `DomainRule`, `DomainAccess`, `DomainMode`, `UnixSocketRule`,
  `UnixSocketMode`, `NetworkMode`, and `NetworkPolicy`;
- `SandboxPolicy`, which combines filesystem and network policy.

The crate provides built-in constructors named `read_only`, `workspace`, and
`full_access`. These are Cageforge concepts, not Codex compatibility aliases.
They are initial policy presets; future named TOML profiles will resolve to the
same `SandboxPolicy` type.

## Security invariants

- Workspace-relative selectors cannot contain NUL characters, parent traversal,
  or become absolute.
- Absolute selectors and concrete access lookups reject NUL characters and
  parent traversal. They are validated lexically without filesystem access or
  symlink resolution; native backends must enforce the same boundary when
  resolving filesystem objects.
- Filesystem access is recursive and the most-specific matching target wins;
  equal targets use deterministic access precedence: `Deny` over `Write` over
  `Read`, matching the audited Codex behavior.
- Duplicate filesystem entries are normalized conservatively: the strongest
  access decision wins, with `Deny` stronger than `Write`, and `Write` stronger
  than `Read`.
- Glob patterns support component wildcards and recursive `**` matching,
  reject parent traversal and unsupported syntax, and carry an explicit scan
  depth for backend expansion.
- Writable rules may carry read-only subpath carve-outs, and concrete targets
  may explicitly request skip-on-missing behavior.
- Unrestricted and externally enforced filesystem policies cannot carry local
  filesystem rules. Restriction-only builders reject those combinations at
  construction time.
- Domain patterns are normalized to lowercase and reject schemes, paths,
  whitespace, and unsupported wildcard shapes.
- `*.example.com` matches subdomains but not the apex; `**.example.com`
  matches the apex and subdomains.
- Deny wins when multiple matching domain rules apply.
- Domain and Unix-socket defaults are explicit: disabled, enabled, or
  restricted allowlist; backends never infer a default from rule presence.
- Disabled network mode always denies even when inert rules are retained for
  inspection. External network policy cannot carry local domain or socket
  rules; its rule builders reject the combination at construction time.
- The policy crate never silently downgrades or broadens a requested policy.

The comparison against the current Codex sandbox crates and the intentionally
deferred semantics are recorded in `specs/0006-codex-policy-audit.md`.

## Testing policy

The crate is tested as a library through black-box integration tests in
`crates/cageforge-policy/tests/`. The suite covers native absolute paths,
relative paths, NUL and parent traversal rejection, special scopes, context
expansion, POSIX and Windows-native path forms, path patterns, recursive
resolution, access precedence, duplicate normalization, filesystem modes,
carve-outs, missing-path behavior, domain normalization and wildcard
semantics, Unix socket validation, external-policy validation, and built-in
policies.

Unit tests should be added only when private implementation logic cannot be
meaningfully exercised through the public API.

## Documentation and coverage gates

`src/lib.rs` uses `#![deny(missing_docs)]`. Every public item must have a Rust
doc comment or the crate fails to compile.

The workspace `tarpaulin.toml` sets a hard 90% line-coverage floor. Native
platform backends will later be excluded from the aggregate Tarpaulin metric
because their enforcement tests must run on their respective operating systems;
they remain required in the native CI matrix.
