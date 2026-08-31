# Cageforge Windows Backend Agent Rules

These rules apply to every file under `crates/cageforge-windows/` and extend
the repository-level `AGENTS.md`. Read the root rules and
`specs/0016-windows-backend-implementation.md` before changing this crate.

## Objective and completion boundary

Finish a native Windows sandbox with the same public backend integration model
as `cageforge-linux`, retaining every relevant security property from the
frozen Codex Windows sandbox and strengthening it where Cageforge has a safer
general-purpose contract. Setup-only code, an authenticated runner, or a
cross-compiled library are not completion. Completion requires native
filesystem, process, and network enforcement to be reached through the public
`WindowsBackend` API and exercised by black-box tests on Windows Server 2025.

Do not describe the backend as complete until all of the following are true:

- `WindowsBackend::prepare` consumes the complete backend-bound lowering views;
- `WindowsBackend::spawn` launches through the authenticated installed runner;
- `WindowsChild` owns and terminates the complete sandbox process tree;
- restricted filesystem policies are enforced with handle-pinned ACL changes;
- missing protected and read-only paths are enforced without a creation race;
- disabled, direct, and exactly routed network modes are enforced natively;
- concurrent sandboxes cannot use one another's route policy or setup objects;
- timeout, drop, signal, stdio, environment, and exit-status behavior match the
  common Cageforge backend contract;
- native Windows black-box tests and every crate feature combination pass.

## Current continuation point

The crate already contains setup state and verification, sandbox-account
provisioning, firewall and WFP setup contracts, installed-helper identity
verification, authenticated runner transport, restricted-token construction,
Job Object and private-desktop preparation, explicit inherited-handle lists,
filesystem lowering, handle-pinned path identity, a write-ahead ACL mutation
journal, and transactional creation of missing protected paths. The public
`WindowsBackend` and `WindowsChild` now reach the authenticated runner. The
network checkpoint contains fixed exclusive IPv4 ingress listeners, bounded
exact reversed-four-tuple PID attribution, process-handle pinning, one random
route SID per routed launch, exact one-route selection, and the independent
`cageforge-network-proxy` gateway. Standard streams are now prepared by the
trusted parent, duplicated into the pinned runner process, and passed to the
user process only through its explicit handle list; `WindowsChild` owns direct
pipe endpoints and the lifecycle protocol carries no stream data. These paths
now have native Windows Server 2025 evidence: the black-box suite exercises
setup recovery, filesystem enforcement and cleanup, restricted-token and Job
lifecycle, direct and proxy-routed networking, HTTP and SOCKS ingress, and two
simultaneous `WindowsBackend` instances with distinct route policies. The
cross-target build remains a development check, not a replacement for that
native boundary.

The remaining work is the completion audit, not a fallback implementation:

1. Re-read every affected frozen Codex Windows boundary and map it to the
   independent Cageforge implementation, Specification 0016, and native
   evidence. Resolve any missing retained invariant with a test and, where
   required, implementation before declaring the crate complete.
2. Audit cleanup recovery, token/HANDLE ownership, Job termination, WFP and
   firewall read-back, route attribution, and all `Eq`/`Hash`/`Clone` derives
   as security boundaries. Expand native black-box coverage for any uncovered
   case; do not mistake the current green smoke and end-to-end paths for a
   complete proof.
3. Once the audit is green, update `README.md` to the same library-focused
   standard as `cageforge-linux`: explain setup, public integration sequence,
   and every actually enforced protection. Do not describe unverified work as
   available, and do not write the README before this audit is complete.

## Required implementation order

### 1. Transactional ACL and materialization cleanup (implemented; preserve and audit)

Creation and recovery are connected to filesystem enforcement. Retain and
audit the inverse lifecycle without weakening its identity contract.

1. Coordinate uninstall and runtime enforcement with the same protected
   cross-process lock and an explicit active-child lifecycle record. Uninstall
   must not revoke an ACL or delete a materialized path while any child still
   depends on it.
2. Recover and complete interrupted ACL restoration before deleting any setup
   identity, helper, firewall rule, or WFP object.
3. For every managed ACL object, reopen without following reparse points and
   verify canonical final path, volume serial, 128-bit file identity, current
   descriptor bytes, and protection bit before restoring the journaled original
   descriptor through that same handle.
4. Restore managed ACLs in dependency-safe order and durably remove each state
   record only after exact read-back of the original descriptor.
5. Remove materialized markers and directories deepest-first only after exact
   path, identity, owner, descriptor, nonce, and non-reparse verification.
   Delete the marker through its pinned identity, then remove only an empty
   directory with the recorded identity.
6. Treat replacement, third-state descriptor drift, a missing marker, a changed
   nonce, unexpected descendants, or an active child as a typed fail-closed
   cleanup result. Never force-delete or adopt a lookalike object.
7. Make interrupted cleanup resumable from the durable state and verify that a
   second uninstall converges without touching unrelated host objects.
8. Add state-model and native tests for active-child exclusion, partial ACL
   restoration, process interruption at every cleanup checkpoint, marker and
   directory replacement, non-empty directories, reparse substitution, and
   idempotent retry.
Update the materialization section of specification 0016 before considering
this phase complete. The state version, setup-created initial state, decoder,
recovery, and cleanup must advance atomically; do not leave a version bump that
the installed setup lifecycle cannot safely recover or remove.

### 2. Public backend and child lifecycle (implemented; preserve and audit)

Keep `WindowsBackend`, the backend-bound prepared request handoff, and
`WindowsChild` in the same integration shape as `cageforge-linux`.

- `prepare` must validate every capability and complete filesystem/network
  lowering before privileged mutation.
- `spawn` must verify installed setup state and helper digests, acquire the
  required setup/capability coordination, apply filesystem enforcement, create
  one random route SID when exact proxy routing is required, and send one
  authenticated bounded request to the installed command runner.
- The runner must use the verified sandbox account, restricted token, private
  desktop, Job Object, explicit handle list, and parent-process constraints
  already implemented in this crate.
- The authenticated runner creates and owns each launch-unique private desktop
  in its own sandbox-account logon session, after it has constructed and
  verified the restricted token. It grants only SYSTEM, Administrators, the
  runner account, and that launch logon SID full access, reads the descriptor
  back, and holds the desktop through child supervision. Do not trim this ACL
  below the Windows initialization contract or broaden it to the host default
  desktop: the desktop DACL and Job UI restrictions are independent controls.
- The explicit child HANDLE list contains only the three validated standard
  stream endpoints. Do not pass a parent `WinSta0` or desktop handle through
  the runner: cross-session station inheritance can stall Windows process
  initialization before `main`. The runner-owned private desktop follows the
  frozen Codex session model without granting the untrusted child a station
  handle.
- Keep the completed standard-stream boundary intact: prepare handles in the
  parent, duplicate only into the pinned authenticated runner process, reject
  malformed or aliased values in the runner, and expose only direct pipe
  endpoints from `WindowsChild`. Do not restore framed stdio forwarding.
- Treat every duplicated HANDLE as a linear ownership transfer. For piped
  stdin the parent retains the writer; for piped stdout/stderr it retains the
  readers. The runner owns each duplicated child endpoint and its assign-only
  Job handle only inside the narrow
  `CreateProcessAsUserW` scope, then closes those copies immediately after the
  explicit handle and Job lists have been consumed. Keep the parent endpoints
  alive in `WindowsChild` until their documented close/drop boundary. Do not
  rely on a broad function scope or an
  incidental destructor order for this transition; a late runner-held writer
  prevents EOF, while an early close invalidates the child launch.
- `WindowsChild` must retain the process, Job Object, ACL/materialization
  handles, runner session, desktop, proxy route, and every other enforcement
  resource. `kill`, timeout, wait, and `Drop` must terminate the complete Job
  Object tree and reconcile persistent state deterministically.
- Return typed library errors. Printing belongs only in binaries. Avoid
  `expect` and `unwrap` outside tests; a recoverable per-launch failure must not
  panic the host application.

This wiring must make the existing native modules genuinely reachable and
eliminate their `dead_code` warnings without lint suppression.

Before changing this wiring, compare both reference sides. Read the affected
frozen `../codex` Windows implementation line by line for native security
invariants, then read `cageforge-linux` and the shared Cageforge crates for the
independent backend API, ownership model, typed errors, and child lifecycle.
Retain or strengthen the former while presenting the latter. Never copy Codex
CLI request schemas, permission profiles, telemetry, product environment
variables, ConPTY integration, or other product-only coupling into the public
Windows library.

### 3. Exact network enforcement (implemented; preserve and audit)

Codex parity requires per-process route ownership, not only a firewall port.

1. Generate a fresh restricting SID for every routed sandbox launch and add it
   only to that launch's restricted token.
2. Keep the firewall/WFP deny boundary active for sandbox accounts. Direct
   sockets from a routed or disabled sandbox must remain blocked, including
   direct loopback and access to the private gateway endpoint.
3. Implement the stable proxy ingress and TCP attribution contract by reviewing
   the frozen upstream files line by line:
   `network-proxy/src/windows_proxy_ingress.rs`,
   `network-proxy/src/windows_tcp_attribution.rs`, and their tests.
4. Resolve the accepted TCP connection's four-tuple to the owning PID, inspect
   that process token, and select the route only when the exact restricting SID
   is present. PID alone, source port alone, account SID alone, or a
   user-supplied route identifier is insufficient.
5. Pin process identity against PID reuse while authorizing a route. Bound all
   handshakes, lookups, frame sizes, and connection counts.
6. Use `ResolvedNetworkTarget` and re-check the exact `SocketAddr` immediately
   before every outbound connect. A domain decision is not connection proof.
7. Keep concurrent routes isolated. One sandbox must never inherit, discover,
   or use another sandbox's allowlist or gateway authority.
8. Cover disabled, unrestricted direct, HTTP proxy, SOCKS proxy, denied target,
   DNS/address substitution, route-SID mismatch, PID reuse, direct gateway,
   direct loopback, concurrent profiles, timeout, and cleanup behavior.

Do not weaken the model to a shared proxy credential or firewall-only routing
because that is easier to implement.

### 4. Native verification and final parity audit

Use the Windows Server 2025 GitHub runner as the authoritative native boundary.
Cross-compilation on Linux proves only compilation and linting; it cannot prove
ACL, token, Job Object, desktop, WFP, firewall, named-pipe, or process-tree
enforcement.

- Keep `tests/windows_backend.rs` black-box and guarded with
  `cfg(target_os = "windows")`; a non-Windows no-op pass is not evidence.
- Test each feature separately, with no optional features, and with all
  features together. Run fmt, check, Clippy, tests, doctests, and docs for every
  supported x86_64 and ARM64 Windows target that the relevant gate can build.
- On `main`, all target builds and every sandbox job run. On pull requests, the
  Windows sandbox job runs when this crate or one of its actual workspace
  dependencies changes, and it can also be requested through the repository's
  manual sandbox label.
- Compare every affected API and invariant against the frozen upstream checkout
  before changing native behavior. Record retained behavior and intentional
  Cageforge differences in specification 0016. Never fetch or advance upstream
  automatically.
- Review at least upstream `acl.rs`, `allow.rs`, `cap.rs`, `deny_read_acl.rs`,
  `deny_read_resolver.rs`, `deny_read_state.rs`, `desktop.rs`, `elevated/`,
  `process.rs`, `proc_thread_attr.rs`, `resolved_permissions.rs`, `setup.rs`,
  `spawn_prep.rs`, `stdio_bridge.rs`, `token.rs`, `wfp.rs`,
  `workspace_acl.rs`, `wrapper.rs`, and the corresponding tests. Product-only
  telemetry, PTY, and Codex protocol types must not leak into the public API.
- Audit all derives and ownership boundaries after wiring. Live authority,
  checked composition, process, token, handle, journal session, and child
  lifetime types must not gain `Copy` or `Clone`. Add `Eq`/`Hash` only when
  identity exactly matches enforcement semantics; do not add arbitrary `Ord`
  to authorization modes.

The final completion audit must map every contract in specification 0016 to a
native test or direct current-state evidence. Green setup tests or successful
cross-compilation alone do not prove sandbox parity.
