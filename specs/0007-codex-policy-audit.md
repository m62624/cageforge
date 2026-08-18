# Specification 0007: Portable Sandbox Policy Boundary

Status: accepted

## Upstream reference

The policy boundary is compared with the Codex commit recorded in
`upstream-review.toml`. The relevant areas are:

- `codex-rs/protocol/src/permissions.rs`;
- `codex-rs/protocol/src/models.rs`;
- `codex-rs/sandboxing`;
- `codex-rs/linux-sandbox`;
- `codex-rs/windows-sandbox-rs`;
- `codex-rs/bwrap`.
- `codex-rs/network-proxy/src/policy.rs` for host and domain normalization;
- `codex-rs/network-proxy/src/runtime.rs` for resolved-address loopback,
  private-network, and DNS-rebinding protection.

This is a design boundary, not a source import. No Codex implementation code
is included in Cageforge by this specification.

## Details that must not be lost

The policy and backend design must account for these upstream behaviors:

- filesystem access is recursive and resolves the most-specific matching
  entry, with deny/write/read precedence for equal targets;
- a policy can distinguish managed enforcement, no outer sandbox, and an
  externally owned sandbox;
- filesystem entries can target absolute paths, workspace/project roots,
  system roots, platform-minimal paths, the platform temporary directory, and
  `/tmp`;
- writable roots may carry read-only subpaths and protected metadata roots;
- deny-read entries may be exact subtree roots or validated glob patterns;
- glob expansion has an explicit maximum depth and malformed patterns must
  fail closed;
- missing filesystem entries can be skipped instead of materialized;
- network restriction is a separate capability from filesystem restriction;
  domain and Unix-socket defaults must be explicit rather than inferred;
  host matching must normalize case, trailing dots, ports, and bracketed IP
  literals before policy evaluation;
  resolved hostnames must not silently reach loopback or private addresses,
  and failed DNS resolution must fail closed;
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
read-only carve-outs, mandatory `.git` metadata protection, additive custom
protected relative paths, explicit external-enforcement decisions, domain
defaults, host normalization, and Unix-socket defaults. `NetworkDecision`
preserves `Allow`, `Deny`, and `ExternallyEnforced` for domain and socket
queries; the boolean helpers intentionally expose only local `Allow`.
`LocalNetworkAccess` and the resolved-address query provide the portable
decision boundary for loopback/private/DNS-rebinding protection without adding
DNS or proxy dependencies; a native backend supplies the resolver results.
Portable glob rules are deny-only; a read/write glob is rejected as
unsupported rather than silently delegated.
The remaining OS-specific behavior stays below the policy boundary. Codex's
product-specific `.agents` and `.codex` names are not copied into the public
API; callers can add generic protected relative paths when they need them.

These are design inputs for the current `cageforge-config`,
`cageforge-command`, and `cageforge-policy-compose` crates, and for the future
`cageforge-backend-api` and native backend crates. The portable command intent
boundary is now implemented in `cageforge-command`; it remains free of
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

The requested profile and the effective backend policy are separate stages.
Profile inheritance may express an explicit requested override, but capability
intersection in `cageforge-policy-compose` is monotonic and may only narrow
filesystem, network, roots, and environment access. Mandatory `.git` protection
survives both stages.

The following Codex-specific concerns remain outside the policy crate:

- approval prompts and per-command permission escalation;
- network proxy routing and proxy attribution;
- PTY and stdio bridging;
- telemetry, rollout formats, and agent protocol types;
- Codex metadata names such as `.codex`.

## Future boundaries

1. Maintain the completed `cageforge-config` and `cageforge-command`
   integration coverage when the portable policy API changes. Their current
   profile, environment, host-normalization, and cwd-validation behavior is
   implemented and tested; it is not a deferred feature.
2. Use `cageforge-policy-compose` for pure intersection against a neutral
   `PolicyCeiling`. Define native capability negotiation and typed unsupported
   policy errors in `cageforge-backend-api`; the composer deliberately does not
   know which OS backend will consume the result.
3. Implement and integration-test Linux, macOS, and Windows backends on their
   native CI runners.

Every follow-up must retain the black-box integration-test rule and the hard
90% coverage floor for portable policy/config logic. Native enforcement tests
remain mandatory even when excluded from the aggregate Tarpaulin percentage.
