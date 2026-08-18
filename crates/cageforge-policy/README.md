> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-policy

`cageforge-policy` is the platform-independent policy model for Cageforge. It
describes filesystem and network boundaries, validates them, resolves symbolic
path scopes against a caller-provided runtime context, and evaluates access for
concrete paths and network destinations.

The crate does not read the filesystem, launch processes, parse TOML, allocate
PTYs, configure a network proxy, or call a native sandbox API. A future backend
uses its values to prepare Linux, macOS, or Windows enforcement.

## Workspace role

| Crate | Role | Runtime dependencies | Used by |
|---|---|---|---|
| `cageforge-policy` | Portable filesystem and network policy semantics | None beyond Rust's standard library | Current black-box tests; planned `cageforge-config`, `cageforge-backend-api`, and native backend crates |

Use this crate when a harness needs a policy value that can cross an operating
system backend boundary. Use `cageforge-config` to parse TOML and resolve
named profiles. Use a native backend crate to enforce the resolved policy.

## Library API and ownership

Policy fields are private. Queries return shared references, slices,
`Option<&T>`, or copyable enum values. Constructors and `with_*` methods build
new values and validate input. Builders that could otherwise create
contradictory policy states are fallible, and path inputs reject NUL characters
and parent traversal before backend compilation. The API does not expose
mutable collections or public fields that could bypass policy invariants. This
keeps both direct library use and backend compilation on the same validated API.

`PathSelector` is opaque. Create it with `absolute`, `workspace`,
`workspace_root`, `root`, `minimal`, `tmpdir`, or `slash_tmp`; callers cannot construct
an unchecked path selector by writing a public enum payload.

## Public API

| Type | Purpose |
|---|---|
| `SandboxPolicy` | Combines filesystem and network policy. |
| `FilesystemPolicy` and `FilesystemRule` | Describes restricted, unrestricted, or externally enforced filesystem access. |
| `FilesystemDecision` | Distinguishes local read/write/deny results from an externally enforced boundary. |
| `PathSelector` and `PathResolutionContext` | Represents absolute, system-root, workspace, minimal-runtime, and temporary-directory scopes. |
| `PathPattern` | Represents validated absolute or workspace-relative globs. |
| `AccessMode` | Expresses `Read`, `Write`, or `Deny`. |
| `NetworkPolicy` | Describes network enforcement ownership and domain/socket defaults. |
| `NetworkDecision` | Distinguishes local allow/deny from externally owned network enforcement. |
| `DomainRule` and `UnixSocketRule` | Adds validated network destinations and decisions. |
| `PolicyError` | Reports invalid paths, patterns, domains, contexts, and policy combinations. |

`PolicyError` is a dedicated library error enum. Callers can match path,
pattern, context, and policy-rule failures without parsing display strings.

The built-in `SandboxPolicy::read_only`, `SandboxPolicy::workspace`, and
`SandboxPolicy::full_access` constructors are Cageforge presets. They are not
legacy configuration aliases and do not preserve a second policy system.

## Quick start

The policy model is independent of path discovery. The harness or backend
provides the paths that special selectors should resolve to:

```rust
use cageforge_policy::{
    AccessMode, FilesystemDecision, FilesystemPolicy, FilesystemRule, NetworkPolicy,
    PathResolutionContext, PathSelector, SandboxPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = std::env::current_dir()?;
    let context = PathResolutionContext::new().with_workspace_root(workspace.clone())?;
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([FilesystemRule::new(
            PathSelector::workspace_root(),
            AccessMode::Write,
        )]),
        NetworkPolicy::disabled(),
    );

    policy.validate()?;
    let access = policy
        .filesystem()
        .access_for_path(&workspace.join("src/lib.rs"), &context)?;
    assert_eq!(access, FilesystemDecision::Write);
    Ok(())
}
```

`access_for_path` requires an absolute path and rejects NUL characters and
parent traversal. Rules are recursive. The most-specific matching rule wins;
ties use deterministic precedence, with `Deny` stronger than `Read`, and
`Read` stronger than `Write`. Restricted policies protect `.git` below every
writable scope by default. Add more protected relative paths with
`with_additional_protected_relative_path`; the explicit
`dangerously_allow_git_write` method is available only for trusted callers and
may still be rejected by a future policy composer or backend. Call
`normalized` before handing duplicate rules to a backend when a canonical rule
list is needed. Concrete path and glob comparisons follow native filesystem
case rules: POSIX matching is case-sensitive, while Windows matching is
case-insensitive. The portable crate does not resolve symlinks; that remains a
native backend decision. The built-in protected-metadata check is deliberately
conservative and remains case-insensitive on every host.

`PathSelector::root()` is a symbolic request for every system root supplied in
`PathResolutionContext`. POSIX callers normally provide `/`; Windows callers
may provide multiple drive or UNC roots. The policy crate never discovers
these roots itself. Glob rules are portable deny rules only. Read/write globs
are rejected with `PolicyError::UnsupportedGlobAccess` until a backend
capability contract can prove support on every target platform.

A read-only carve-out must be below its writable scope. Concrete absolute and
workspace-relative selectors that are visibly outside the parent are rejected
when the rule is built. Symbolic selectors are retained when their relationship
can only be determined after a backend resolves its runtime paths.

## Filesystem model

`PathSelector` supports native absolute paths, system roots, paths relative to
every workspace root, a minimal runtime scope, the platform temporary directory,
and the conventional `/tmp` scope. Special selectors are resolved only from
`PathResolutionContext`; the crate never guesses a workspace or touches a
symlink.

`FilesystemRule` can target a selector or a validated deny glob. A writable rule can
carry read-only subpaths. A concrete target can use
`MissingPathBehavior::Skip` when a backend should ignore an absent path rather
than create it or fail preparation. `FilesystemPolicy::external` records that
another trusted sandbox owns the filesystem boundary. Its queries return
`FilesystemDecision::ExternallyEnforced`, never local `Deny`, so a backend
cannot silently apply the wrong interpretation.

## Network model

`NetworkPolicy` separates enforcement ownership from the default behavior for
domains and Unix socket paths. Domain inputs are normalized like the upstream
host boundary: case is folded, trailing dots are removed, host ports are
ignored, bracketed IPv6 literals are unwrapped, and IPv4/IPv6 literals are
canonicalized. `*.example.com` matches subdomains but not the apex, while
`**.example.com` matches the apex and its subdomains. Domain patterns also
support `*` and `?` within a host label, such as
`region*.example.com`; wildcard characters never change host normalization or
the explicit apex semantics of the prefixed forms.

Use `decision_for_domain` and `decision_for_unix_socket` when a backend needs
the complete result. They return `NetworkDecision::Allow`,
`NetworkDecision::Deny`, or `NetworkDecision::ExternallyEnforced`. The
`allows_domain` and `allows_unix_socket` helpers remain as local boolean
queries and return `true` only for `Allow`; they intentionally do not collapse
external ownership into permission.

Network policy is independent from filesystem policy. Disabled mode always
denies, even if rules are retained for inspection; external mode delegates the
boundary and rejects local rules. A future backend may enforce domains through
a proxy, firewall, or another native mechanism; this crate does not select or
configure that mechanism.

## Tests and API documentation

The black-box integration suite lives in
`crates/cageforge-policy/tests/policy.rs`. It covers validation, path
resolution, matching precedence, normalization, filesystem modes, network
rules, and built-in policies. Unit tests are reserved for private logic that
cannot be exercised through the public API.

API reference: [`cageforge-policy` on docs.rs](https://docs.rs/cageforge-policy/latest/cageforge_policy/).

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
