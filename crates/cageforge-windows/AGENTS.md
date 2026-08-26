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
filesystem lowering, handle-pinned path identity, and a write-ahead ACL
mutation journal.

The active unfinished filesystem work is the missing-path materialization
journal. `capability_state.rs` and `capability_store.rs` contain the version-3
state-model checkpoint. `filesystem_acl.rs` contains imports, types, and typed
error variants for its runtime implementation, but the runtime methods are not
yet connected. Continue from that checkpoint; do not replace it with a polling
monitor or an unjournaled `create_dir_all` implementation.

Some native implementation modules remain unreachable from the public backend
and therefore currently emit `dead_code` warnings. Remove those warnings by
finishing and using the implementation. Never hide them with
`allow(dead_code)`, a dummy type alias, or artificial calls. Do not commit new
unused imports or placeholder types unless they are part of this explicitly
recorded continuation checkpoint.

## Required implementation order

### 1. Finish transactional missing-path materialization

Complete this before applying ACL operations or wiring the public backend.

1. Recover any pending ACL mutation while holding `CapabilityStateSession`.
2. Recover any pending materialization before beginning another mutation.
3. Build an owner-only, protected security descriptor for the setup owner,
   Administrators, and SYSTEM. Attach it atomically at object creation; never
   create a permissive object and tighten it afterwards.
4. For each missing `ReadOnly` or `Protected` target, walk from its validated
   existing anchor one path component at a time. Reject parent traversal,
   reparse points, replacement, and an unexpected pre-existing component.
5. Before creating a component, durably record the target path, exact expected
   DACL, fixed marker path, marker DACL, and a cryptographically random 32-byte
   nonce in the capability-state write-ahead journal.
6. Create the directory with `CreateDirectoryW` and the protected creation
   descriptor. Create `.cageforge-materialized-path` with `CreateFileW` and
   `CREATE_NEW`, write the nonce, and durably flush it.
7. Reopen and pin both directory and marker without delete sharing. Verify the
   final path, absence of a reparse point, stable file identities, owner SID,
   exact DACL bytes and protection bit, and exact marker contents.
8. Commit `MaterializationEvidence` only after all checks pass. If the target is
   absent during recovery, clear the pending entry. If it is present and every
   recorded property matches, commit it. Any third state is drift and must fail
   closed with a typed error.
9. Reuse an existing component only when capability state already records the
   same path and the live object and marker still match. Never adopt an
   arbitrary lookalike directory.
10. Retain the pinned target and marker handles for the whole child lifetime.
    This prevents deletion or replacement and keeps the marker directory
    non-empty.
11. Add the materialized targets to ACL planning: missing read-only targets get
    the profile write deny and missing protected targets get the full deny.
    Preserve foundation and deny continuation across protected descendants.
12. Add state-model tests for absent recovery, matching recovery, nonce drift,
    descriptor drift, duplicate identity, noncanonical order, and overlapping
    nested targets. Add native tests for creation races, marker replacement,
    reparse-point replacement, and crash recovery.
13. Implement uninstall/cleanup only with the same recorded identities. Restore
    managed ACLs first, then remove markers and empty materialized directories
    deepest-first. Never delete an object whose identity or current descriptor
    differs from the journal.

Update the materialization section of specification 0016 before considering
this phase complete. The state version, setup-created initial state, decoder,
recovery, and cleanup must advance atomically; do not leave a version bump that
the installed setup lifecycle cannot safely recover or remove.

### 2. Wire the public backend and child lifecycle

Implement `WindowsBackend`, the backend-bound prepared request handoff, and
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
- Standard input/output/error handles must be duplicated only into the verified
  runner PID and passed to the user process only through the explicit handle
  list. Do not put secrets or authentication material in argv or environment.
- `WindowsChild` must retain the process, Job Object, ACL/materialization
  handles, runner session, desktop, proxy route, and every other enforcement
  resource. `kill`, timeout, wait, and `Drop` must terminate the complete Job
  Object tree and reconcile persistent state deterministically.
- Return typed library errors. Printing belongs only in binaries. Avoid
  `expect` and `unwrap` outside tests; a recoverable per-launch failure must not
  panic the host application.

This wiring must make the existing native modules genuinely reachable and
eliminate their `dead_code` warnings without lint suppression.

### 3. Finish exact network enforcement

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
