# Specification 0006: Codex Policy Audit

Status: accepted audit baseline

## Reviewed upstream baseline

The audit was performed against the local Codex checkout at commit
`c6058ccaa91ab17159cf805bf4d6d4edd87fe5fc` on 2026-08-17. The reviewed
areas are:

- `codex-rs/protocol/src/permissions.rs`;
- `codex-rs/protocol/src/models.rs`;
- `codex-rs/sandboxing`;
- `codex-rs/linux-sandbox`;
- `codex-rs/windows-sandbox-rs`;
- `codex-rs/bwrap`.

This is an audit record, not a source import. No Codex implementation code is
included in Cageforge by this specification.

## Details that must not be lost

The policy and backend design must account for these upstream behaviors:

- filesystem access is recursive and resolves the most-specific matching
  entry, with deny/write/read precedence for equal targets;
- a policy can distinguish managed enforcement, no outer sandbox, and an
  externally owned sandbox;
- filesystem entries can target absolute paths, workspace/project roots,
  platform-minimal paths, the platform temporary directory, and `/tmp`;
- writable roots may carry read-only subpaths and protected metadata roots;
- deny-read entries may be exact subtree roots or validated glob patterns;
- glob expansion has an explicit maximum depth and malformed patterns must
  fail closed;
- missing filesystem entries can be skipped instead of materialized;
- network restriction is a separate capability from filesystem restriction;
  domain and Unix-socket defaults must be explicit rather than inferred;
  Linux additionally needs process and socket syscall restrictions, while
  macOS has explicit Unix-socket policy generation;
- Linux backend selection must account for system bubblewrap capabilities,
  bundled bubblewrap fallback, Landlock/seccomp behavior, and unsupported
  architectures;
- Windows enforcement has separate ACL, token, deny-read, firewall, and
  process-launch concerns and cannot be represented as a Unix-only path list.

The final `cageforge-policy` implementation now owns the portable parts of
these semantics: runtime path context, recursive most-specific filesystem
resolution, validated path globs, scan depth, missing-path behavior,
read-only carve-outs, domain defaults, and Unix-socket defaults. The remaining
OS-specific behavior stays below the policy boundary.

These are design inputs for the future `cageforge-config`,
`cageforge-backend-api`, and native backend crates. The portable command
intent boundary is now implemented in `cageforge-command`; it remains free of
operating-system and process-launch dependencies. None of these details
justify adding operating-system or process-launch dependencies to
`cageforge-policy`.

## Deliberate non-porting decisions

Cageforge does not expose Codex's `PermissionProfile`, `SandboxPolicy`, or
legacy `sandbox_workspace_write`/`sandbox_mode` configuration names. The
canonical model is a generalized policy plus named user-defined profiles.

The old Codex workspace mode is not a compatibility alias and is not a second
policy system. Its useful semantics belong in a user-defined profile composed
from filesystem entries, network settings, and future backend capabilities.
The profile resolver may provide an ergonomic Cageforge preset, but it must
resolve to the same canonical policy model and must not preserve Codex field
names or legacy serialization.

The following Codex-specific concerns remain outside the policy crate:

- approval prompts and per-command permission escalation;
- network proxy routing and proxy attribution;
- PTY and stdio bridging;
- telemetry, rollout formats, and agent protocol types;
- Codex metadata names such as `.codex`.

## Remaining follow-up order

1. Add TOML profile resolution with inheritance and cycle/unknown-profile
   errors in `cageforge-config`.
2. Define capability negotiation and explicit unsupported-policy errors in
   `cageforge-backend-api`.
3. Implement and integration-test Linux, macOS, and Windows backends on their
   native CI runners.

Every follow-up must retain the black-box integration-test rule and the hard
90% coverage floor for portable policy/config logic. Native enforcement tests
remain mandatory even when excluded from the aggregate Tarpaulin percentage.
