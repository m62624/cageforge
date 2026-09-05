# Cageforge Bubblewrap Crate Rules

These rules apply to every file under `crates/cageforge-bwrap/` and extend the
repository-level `AGENTS.md`.

`vendor/bubblewrap/` is an immutable third-party zone. Do not refactor,
reformat, patch, or otherwise modify its C sources or headers as part of a Rust
change. They are retained solely to compile the original Bubblewrap binary.
Only surrounding Cageforge build integration may change, subject to the
repository provenance and licensing rules.

The `build-from-source` feature is the explicit source-builder mode used by
native CI and release tooling. The `embedded` feature is the dependency-facing
resource mode: it selects a reviewed `x86_64` or `aarch64` asset with
`cfg(target_arch)` and must not compile C source or require a target sysroot.
Every supported architecture must have its generated binary and digest
manifest before the feature is published. The Linux backend enables this mode
through its single `bundled-bubblewrap` feature.
