# Upstream Provenance

## Source repository

- Repository: <https://github.com/openai/codex>
- Tracking remote: `upstream`
- Baseline commit: not selected yet

The machine-readable tracking configuration is upstream-review.toml. It stores
only the upstream location, configured source scopes, and the last adapted
commit SHA. It does not store an upstream source snapshot in the Cageforge
repository. The external checkout is updated manually before review.

## Planned source areas

| Upstream path | Cageforge destination | Status |
| --- | --- | --- |
| `codex-rs/sandboxing` | `crates/cageforge-core` and platform crates | Not imported |
| `codex-rs/linux-sandbox` | `crates/cageforge-linux` | Not imported |
| `codex-rs/windows-sandbox-rs` | `crates/cageforge-windows` | Not imported |
| `codex-rs/bwrap` | `crates/cageforge-linux` or separate helper | Not imported |
| `codex-rs/vendor/bubblewrap` | Linux third-party component | Not imported |

This mapping must be updated with the exact upstream commit, reviewed date,
and material changes whenever source-derived code is added or updated.
