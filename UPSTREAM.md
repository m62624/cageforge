# Upstream Provenance

## Source repository

- Repository: <https://github.com/openai/codex>
- Tracking mechanism: `upstream-review.toml` and an externally maintained
  Codex checkout; no automatic pull or fetch is performed
- Baseline commit: `c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc`
- Baseline date: 2026-08-17
- Baseline state: frozen; future Codex updates require a deliberate manual review

The machine-readable tracking configuration is upstream-review.toml. It stores
only the upstream location, configured source scopes, and the last adapted
commit SHA. It does not store an upstream source snapshot in the Cageforge
repository. The external checkout is updated manually before review.

## Planned source areas

| Upstream path | Cageforge destination | Status |
| --- | --- | --- |
| `codex-rs/protocol/src/permissions.rs` | `crates/cageforge-policy` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/models.rs` | `crates/cageforge-policy`, `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/protocol.rs` | `crates/cageforge-policy` | Behavior-tracked; independently implemented |
| `codex-rs/sandboxing/src/policy_transforms.rs` | `crates/cageforge-policy` | Behavior-tracked; independently implemented |
| `codex-rs/app-server-protocol/src/protocol/v2/command_exec.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/app-server-protocol/src/protocol/v2/process.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/config_types.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/sandboxing/src/spawn.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/core/src/exec.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/sandboxing`, `codex-rs/linux-sandbox`, `codex-rs/windows-sandbox-rs`, `codex-rs/bwrap` | Future native backend crates | Planned; not imported |
| `codex-rs/vendor/bubblewrap` | Future Linux third-party component | Planned; not imported |

The two current crates are candidates for future upstream review, not source
imports. Their APIs and implementations were written independently in
Cageforge. The configured paths identify the Codex behavior that should be
rechecked when the frozen baseline is manually advanced.

This mapping must be updated with the exact upstream commit, reviewed date,
and material changes whenever source-derived code is added or updated.
