# Specification 0025: Dynamic Permission Escalation

Status: active implementation contract

## 1. Purpose

Cageforge may allow a trusted host to request additional capabilities for a
new launch when a running tool needs a resource that was not part of its
original sandbox. This is an orchestration API, not an in-place mutation of a
native sandbox.

The public model is independent of Codex protocols. Codex's dynamic
permission flow is a behavioral reference only; Cageforge uses its own
request, grant, error, and relaunch types.

## 2. Security contract

- A `PermissionEscalationRequest` names the immutable base request, the new
  capabilities, and a human-readable reason.
- The additional capabilities are merged with the base request to produce a
  new exact `PermissionRequest` and therefore a new grant identity.
- A trusted host approves all or a subset of the additional capabilities. The
  existing base capabilities remain in the relaunch grant.
- The current native sandbox is never widened. It must be stopped or
  terminated before the approved relaunch is created.
- The relaunch receives a newly composed immutable policy and a newly
  authorized grant. A failed approval or preflight never starts the child.
- The effective policy remains bounded by the configured environment and
  workspace ceiling; dynamic filesystem and network additions are explicit
  and validated before composition.
- Dynamic escalation is available only for `on-demand` and
  `preflight-and-on-demand` approval modes. `disabled` and `preflight` do not
  enable it.

## 3. Capability scope

The first implementation supports explicit filesystem read/write and
map-executable roots, plus explicit domain and local-IPC endpoints. It rejects
unrestricted sentinels, deny-only additions, malformed paths, and child
process changes that cannot be represented by the relaunch policy. The
rejected request is reported through a typed error.

Dynamic requests do not contain credentials, bearer tokens, or authentication
material. A reason is diagnostic metadata and must not be used as an
authorization decision.

## 4. Binding contract

Rust, Python, and Java expose the same lifecycle:

1. create a typed escalation request from the active runtime;
2. send its structured representation to a trusted host;
3. approve all or a subset through the existing grant authority;
4. stop/close the old process;
5. launch the new immutable sandbox with the escalation grant.

Bindings map expected failures to stable typed error categories and keep the
native process lifecycle owned by Rust. The foreign-language objects are
handles to the same request, grant, and relaunch model; they do not implement
a second permission engine. Blocking native work is performed outside
language-runtime synchronization, and Rust panics never cross an FFI boundary.
