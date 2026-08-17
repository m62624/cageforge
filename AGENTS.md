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
4. Cageforge-authored code is Apache-2.0. Third-party code keeps its own
   license: bundled bubblewrap is LGPL-2.0-or-later; do not relabel it as
   Apache-2.0.
5. Do not import source-derived implementation code until provenance and
   license records are prepared. Do not create the first Git commit until the
   licensing scaffold has been reviewed.
6. Keep the public API independent from Codex protocols, telemetry, PTY,
   network-proxy, and product-specific types. Harness integrations belong in
   adapters, not in `cageforge-core`.

When in doubt, stop and update the specification or provenance records before
changing source code.
