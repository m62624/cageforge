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
9. Keep crate README files focused on the library's role, public API, and usage.
   If upstream work informed a crate's design, mention that provenance once in
   a concise top banner. Keep exact commits, paths, license details, and audit
   history in the project specs and provenance records instead of repeating them
   throughout the README.
10. Treat public policy and command constructors/builders as security boundaries.
    Keep representations private, validate NUL/parent-traversal and mode
    invariants before backend handoff, and cover native POSIX and Windows path
    forms through black-box tests before widening the API.

When in doubt, stop and update the specification or provenance records before
changing source code.
