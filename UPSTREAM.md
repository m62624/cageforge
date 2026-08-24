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
| `codex-rs/network-proxy/src/policy.rs` | `crates/cageforge-policy` | Host and domain normalization behavior tracked; proxy enforcement excluded |
| `codex-rs/network-proxy/src/runtime.rs` | `crates/cageforge-policy`, future network backends | Resolved-address local-network protection generalized without importing proxy or DNS runtime code |
| `codex-rs/sandboxing/src/policy_transforms.rs` | `crates/cageforge-policy-compose` | Portable intersection behavior audited; independently implemented |
| `codex-rs/protocol/src/permissions.rs` | `crates/cageforge-policy-compose` | Decision and ownership concepts audited; independently implemented |
| `codex-rs/protocol/src/models.rs` | `crates/cageforge-policy-compose` | Portable policy request usage audited; product types excluded |
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
| `codex-rs/config/src/schema.rs` | `crates/cageforge-config` | Upstream schema concepts are tracked while Cageforge keeps an independent schema |
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
| `codex-rs/sandboxing/src/lib.rs` | `crates/cageforge-backend-api` | Backend boundary and capability families audited; implementation remains independent |
| `codex-rs/sandboxing/src/manager.rs` | `crates/cageforge-backend-api` | Sandbox preparation inputs and platform selection audited; Codex product types excluded |
| `codex-rs/sandboxing/src/spawn.rs` | `crates/cageforge-backend-api` | Spawn handoff responsibilities audited; process and PTY APIs remain outside the portable contract |
| `codex-rs/sandboxing/src/policy_transforms.rs` | `crates/cageforge-backend-api` | Effective-policy handoff audited; the Cageforge API accepts only `EffectiveSandbox` |
| `codex-rs/core/src/exec.rs` | `crates/cageforge-backend-api` | Execution boundary consumers audited; process lifecycle remains backend-owned |
| `codex-rs/exec-server/src/process_sandbox.rs` | `crates/cageforge-backend-api` | Prepared sandbox request flow audited; JSON-RPC and Codex protocol types excluded |
| `codex-rs/exec-server/src/local_process.rs` | `crates/cageforge-backend-api` | Local process lifecycle consumer audited; PTY, telemetry, and session state excluded |
| `codex-rs/sandboxing`, `codex-rs/linux-sandbox`, `codex-rs/windows-sandbox-rs`, `codex-rs/bwrap` | Future native backend crates | Planned; not imported |
| `codex-rs/vendor/bubblewrap` | `crates/cageforge-bwrap/vendor/bubblewrap` | Behavior comparison only; not the source of the bundled component |

## Bundled third-party source

The bundled Bubblewrap source is taken directly from the upstream project, not
from the Codex repository:

| Component | Repository | Tag | Commit | License |
| --- | --- | --- | --- | --- |
| Bubblewrap | <https://github.com/containers/bubblewrap> | `v0.11.2` | `1b80120ef26a28e065e67f89bfef873f13bdd317` | LGPL-2.0-or-later |

The current Cageforge crates are candidates for future upstream review, not
source imports. Their APIs and implementations were written independently in
Cageforge. The configured paths identify the Codex behavior that should be
rechecked when the frozen baseline is manually advanced. Native backend paths
are deliberately listed separately as planned work and are not part of the
current crate tracking scope.

This mapping must be updated with the exact upstream commit, reviewed date,
and material changes whenever source-derived code is added or updated.
