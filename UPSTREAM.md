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
| `codex-rs/core/src/sandboxing/mod.rs` | `crates/cageforge-command` | Execution-boundary inputs audited; independently implemented |
| `codex-rs/core/src/spawn.rs` | `crates/cageforge-command` | Execution-boundary inputs audited; independently implemented |
| `codex-rs/core/src/exec.rs` | `crates/cageforge-command` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/shell_environment.rs` | `crates/cageforge-command` | Environment order and core-set behavior audited; Codex-only variables excluded |
| `codex-rs/core/src/exec_env.rs` | `crates/cageforge-command` | Runtime environment application audited; Codex session/profile injection excluded |
| `codex-rs/config/src/permissions_toml.rs` | `crates/cageforge-config` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/config_types.rs` | `crates/cageforge-config` | Behavior-tracked; independently implemented |
| `codex-rs/core/src/config/permissions.rs` | `crates/cageforge-config` | Behavior-tracked; independently implemented |
| `codex-rs/core/src/config/resolved_permission_profile.rs` | `crates/cageforge-config` | Profile-root state audited; Codex profile types excluded |
| `codex-rs/core/src/exec_env.rs` | `crates/cageforge-config` | Behavior-tracked; independently implemented |
| `codex-rs/config/src/config_toml.rs` | `crates/cageforge-config` | Behavior-tracked; product wiring audited, Codex-only fields excluded |
| `codex-rs/config/src/merge.rs` | `crates/cageforge-config` | Profile inheritance merge behavior audited |
| `codex-rs/config/src/shell_environment_policy.rs` | `crates/cageforge-config` | Behavior-tracked; independently implemented |
| `codex-rs/protocol/src/shell_environment.rs` | `crates/cageforge-config`, `crates/cageforge-command` | Behavior-tracked; platform environment semantics audited |
| `codex-rs/core/src/config/mod.rs` | `crates/cageforge-config` | Behavior-tracked; profile selection audited, product trust excluded |
| `codex-rs/core/src/environment_selection.rs` | `crates/cageforge-config` | Behavior-tracked; runtime workspace-root consumption audited |
| `codex-rs/sandboxing`, `codex-rs/linux-sandbox`, `codex-rs/windows-sandbox-rs`, `codex-rs/bwrap` | Future native backend crates | Planned; not imported |
| `codex-rs/vendor/bubblewrap` | Future Linux third-party component | Planned; not imported |

The current Cageforge crates are candidates for future upstream review, not
source imports. Their APIs and implementations were written independently in
Cageforge. The configured paths identify the Codex behavior that should be
rechecked when the frozen baseline is manually advanced. Native backend paths
are deliberately listed separately as planned work and are not part of the
current crate tracking scope.

This mapping must be updated with the exact upstream commit, reviewed date,
and material changes whenever source-derived code is added or updated.
