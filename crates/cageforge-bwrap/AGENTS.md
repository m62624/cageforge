# Cageforge Bubblewrap Crate Rules

These rules apply to every file under `crates/cageforge-bwrap/` and extend the
repository-level `AGENTS.md`.

`vendor/bubblewrap/` is an immutable third-party zone. Do not refactor,
reformat, patch, or otherwise modify its C sources or headers as part of a Rust
change. They are retained solely to compile the original Bubblewrap binary.
Only surrounding Cageforge build integration may change, subject to the
repository provenance and licensing rules.
