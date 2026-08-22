# Cageforge Agent Rules

Before making any change, read:

- `specs/0001-project-charter-and-licensing.md`
- `NOTICE`
- `THIRD_PARTY_NOTICES.md`
- `UPSTREAM.md`

These rules are mandatory:

1. Cageforge is an independent project, not affiliated with, sponsored by, or
   endorsed by OpenAI. Its public crates, APIs, and branding must not use
   `Codex` or `OpenAI` except for accurate provenance and attribution.
2. The implementation is derived from open-source sandboxing code in OpenAI
   Codex. Never remove upstream copyright, attribution, NOTICE, or license
   information.
3. Every source-derived file must record its upstream repository path and
   commit, retain applicable original copyright, and identify material changes
   made for Cageforge.
   Use the exact header and classification rules in
   `specs/0002-source-provenance-and-file-headers.md`. Do not mark
   independently authored files as Codex-derived merely because they implement
   similar behavior.
   Cageforge-authored Rust files use the SPDX-only header defined in that
   specification; do not add a personal or collective copyright line to them.
4. Cageforge-authored code is Apache-2.0. Third-party code keeps its own
   license: bundled bubblewrap is LGPL-2.0-or-later; do not relabel it as
   Apache-2.0.
5. Do not import source-derived implementation code until provenance and
   license records are prepared. Do not create the first Git commit until the
   licensing scaffold has been reviewed.
6. Keep the public API independent from Codex protocols, telemetry, PTY,
   network-proxy, and product-specific types. Harness integrations belong in
   adapters, not in `cageforge-core`.
7. Do not preserve Codex legacy configuration names, aliases, or compatibility
   layers merely for compatibility. Design Cageforge's generalized capability
   and profile model as the canonical API and default behavior. Any compatibility
   layer requires an explicit project specification decision.
8. Prefer black-box integration tests in each crate's `tests/` directory. Add
   unit tests only for internal logic that cannot be meaningfully covered through
   the crate's public API. Do not expand the public API or add test-only helpers
   solely to make unit tests possible.
9. Keep crate README files focused on the library's role, public API, practical
   usage, and place in the workspace or an integrating project. Start with a
   direct positive statement of what the crate provides, then explain its
   inputs, outputs, and integration sequence. Show a small example when the
   API benefits from one. Do not write the main description as a list of
   exclusions or repeated "does not ..." statements; implementation boundaries
   belong in the API docs and specs. Avoid implementation history, audit notes,
   and test/coverage inventories. Tests belong in the crate and CI, not in the
   README. If upstream work informed a crate's design, mention that provenance
   once in a concise top banner. Keep exact commits, paths, license details,
   and audit history in the project specs and provenance records instead of
   repeating them throughout the README.
10. Treat public policy and command constructors/builders as security boundaries.
    Keep representations private, validate NUL/parent-traversal and mode
    invariants before backend handoff, and cover native POSIX and Windows path
    forms through black-box tests before widening the API.
    Use `cageforge-path` for shared lexical path equality, containment, and
    parent-traversal decisions; platform-specific path comparison code belongs
    there, while other crates may keep only platform-specific test fixtures.
    Path-pattern compilation belongs to `cageforge-policy`: `cageforge-path`
    must remain independent of policy, glob access modes, domain rules, and
    backend semantics. A dependency such as `globset` belongs in the crate that
    interprets the pattern as a policy rule, not automatically in the shared
    path crate.
    Audit every alternate public constructor, accessor, and convenience query
    for the same invariant as the primary path. Authorization queries must
    evaluate complete mode and ownership state, not only a matched rule;
    do not add boolean authorization shortcuts when the result can be denied,
    malformed, or externally enforced;
    runtime-dependent queries must require a validated runtime context; and
    environment transformations must accept a typed base rather than an
    unlabelled map.
11. Treat Rust trait derivations as part of each type's security contract.
    Collection identity (`Eq`, `Hash`, and `Ord`) must use the same canonical
    semantics as matching; declaration aggregates may remain structural when
    their spelling or order is public. Opaque composition and authorization
    identities must use identity semantics and must not gain `Copy` or `Clone`
    when copying could detach a value from its checked boundary. Authorization
    modes and results must not expose an arbitrary `Ord`; use an explicit
    narrowing operation such as `most_restrictive` and handle external
    ownership as a separate state. An `Ord` implementation is appropriate for
    canonical collection keys or deterministic diagnostic labels only when it
    is not presented as an enforcement precedence.
    Types that define a logical case-insensitive namespace must canonicalize
    duplicate inputs before exposing snapshots, and their `Eq` must compare
    that logical identity rather than diagnostic spelling. Preserved spelling
    is presentation data, not a second authorization identity.
    Prepared backend handoffs must be type-bound to the backend whose
    capabilities were checked; native lowering should accept
    `PreparedBackendRequest<'_, Self>` rather than an unbound prepared value.
    Native lowering must consume the complete immutable filesystem and network
    lowering views; it must not reconstruct enforcement from only one side of
    a policy composition.
12. A network backend must use `ResolvedNetworkTarget` and verify the exact
    `SocketAddr` immediately before connecting. `decision_for_domain` and
    `decision_for_domain_with_resolved_ips` are policy queries, not proof that
    a later connection uses the checked address. A filesystem backend must
    combine policy evaluation with native symlink, reparse-point, mount, and
    TOCTOU-safe enforcement.
13. `ExternalOwner` is an identity token supplied by a trusted caller. It is
    not evidence that an external sandbox exists or is enforcing anything.
    `CoreEnvironment` likewise requires a backend-selected core environment;
    the label must never be applied to the complete process environment.
14. Keep the Codex baseline in `upstream-review.toml` frozen until a deliberate
    review approves an advance. Never pull or fetch Codex automatically; the
    upstream-review tool is read-only and only compares an externally updated
    checkout.
15. Configuration files are trusted application input, not an untrusted wire
    format. Keep resolution efficient for large files and shared inheritance
    graphs through one iterative inheritance linearization and indexed
    canonical merges. Do not add
    arbitrary resource limits or silently truncate valid configuration without
    a separate specification decision.
16. When several imports belong to one crate or responsibility domain, prefer
    one grouped `use` declaration. Split imports only when they represent
    genuinely different responsibility zones or the split materially improves
    readability.

## Specification ordering

Keep specifications ordered from broad contracts to narrow implementation
contracts. The current order is project charter, provenance, cross-crate API,
upstream tooling, shared semantics, then crate-specific and boundary-specific
contracts in dependency order. When adding or renumbering a specification,
update its filename, title, and every repository reference, then verify that
no stale links or mentions remain before committing.

When in doubt, stop and update the specification or provenance records before
changing source code.
