# Specification 0016: Windows Backend Implementation

Status: accepted for implementation; native verification pending

## 1. Purpose

`cageforge-windows` is the Windows-native execution backend for Cageforge. It
accepts only a backend-bound `PreparedBackendRequest<'_, WindowsBackend>` and
lowers the complete effective command, filesystem, network, environment, stdio,
and timeout contract into a Windows restricted-process boundary.

The backend implements one security level: the administrator-provisioned native
boundary corresponding to the stronger Windows sandbox described by the frozen
Codex baseline. Cageforge does not provide or silently select an unelevated
restricted-token fallback. Missing, stale, or ineffective setup is a typed
failure before command launch.

The crate is an independent implementation. It contains no Codex protocol,
telemetry, PTY, product configuration, or copied source files.

## 2. Platform and dependency boundary

The crate is compiled only under `cfg(target_os = "windows")`. Its native
integration tests use the same exact guard and must execute the Windows APIs;
they may not pass on another target through a stub implementation.

The crate may depend on:

- `cageforge-backend-api` for backend-bound preflight;
- `cageforge-command` for environment, stdio, and timeout values;
- `cageforge-path` and `cageforge-policy` for Windows path identity and policy
  values;
- `cageforge-policy-compose` for complete immutable lowering views;
- `cageforge-network-proxy` for exact resolved-target HTTP and SOCKS5
  enforcement;
- focused Windows bindings, serialization, cryptography, and runtime support.

It must not depend on Codex crates or expose product-specific values. Setup and
command-runner binaries are implementation resources of `cageforge-windows`,
not portable backend API concepts.

## 3. Public API

The public crate surface consists of:

- `WindowsBackend`;
- `WindowsBackendConfig`;
- `WindowsSetup` and `WindowsSetupConfig`;
- `WindowsSetupStatus`;
- `WindowsChild`;
- typed configuration, setup, lowering, process, network, and lifecycle errors.

`WindowsBackend::prepare` runs common Cageforge preflight and then validates
Windows-specific policy combinations. `WindowsBackend::spawn` consumes a
prepared request bound to the same backend identity. It never accepts a raw
policy or reconstructs a working directory or environment from the original
request.

Library APIs return errors and never print diagnostics. The setup helper and
command-runner binaries may render a typed failure for direct human use, but
their machine-to-machine protocols remain structured and versioned.

## 4. Provisioned identities and setup

The strong Windows boundary requires one administrator-approved setup. Setup
creates two ordinary local users scoped to the signed-in host identity:

- an offline user for disabled or proxy-routed networking;
- an online user for unrestricted direct networking.

The account names are deterministic functions of the real user's SID and use a
Cageforge prefix, so installations for different real users do not reset one
another's passwords. Both users belong to one Cageforge-managed local group and
must not belong to Administrators or another privileged local group.

Setup also:

1. creates versioned setup and secret directories;
2. generates independent cryptographically random account passwords;
3. protects the credential record with Windows DPAPI and ACLs the record to the
   real user, Administrators, and SYSTEM;
4. grants the required batch-logon right and removes incompatible interactive
   account state when Windows permits it;
5. installs offline-user firewall rules;
6. installs the required WFP defense-in-depth filters;
7. creates and protects capability-SID state;
8. writes a versioned marker only after every mandatory step succeeds; and
9. verifies the effective account, ACL, firewall, and WFP state by reading it
   back.

WFP installation is mandatory in Cageforge. The frozen Codex baseline logs WFP
failure and continues setup; Cageforge intentionally fails closed because its
backend advertises the complete elevated network boundary.

Setup is idempotent. It reconciles stale state without silently deleting
unrelated accounts, rules, ACLs, or files. Destructive uninstall is a separate
explicit operation and is not performed by backend construction.

Capability state consists of a protected state record and a separate protected
cross-process lock file. Setup generates one random installation SID namespace;
runtime entries append random subauthorities and are keyed by the SHA-256 of the
complete resolved filesystem enforcement profile, authority role, and canonical
root identity. One profile-guard SID owns every deny ACE for that immutable
profile, while separate write-root SIDs own only their corresponding allow
ACEs. Every update holds an exclusive `LockFileEx` range lock, writes and
flushes a sibling replacement, atomically installs it with
`ReplaceFileW(REPLACEFILE_WRITE_THROUGH)`, then validates the retained owner and
DACL plus the schema, canonical ordering, SID namespace, and exact contents
again. Replacement keeps a sibling backup until that validation succeeds. If
Windows reports an interrupted replacement with the primary name absent,
Cageforge accepts only a regular non-reparse backup with the exact protected
owner/DACL and a valid canonical state, moves it back with write-through, and
validates it again. The original record therefore remains complete if
interruption happens before replacement, while a completed replacement is
durable before its journalled native mutation begins. A missing, malformed,
non-canonical, foreign-namespace, or unlocked record fails closed; setup never
silently rotates a damaged record because existing ACLs may still refer to its
authorities.

The protected lock file has two independent one-byte ranges. Byte zero is the
exclusive capability-state mutation lock. Byte one is shared by every live
`WindowsChild` and acquired before byte zero; uninstall requests byte one
exclusively and without waiting before it may acquire byte zero. Parallel
sandboxes therefore remain concurrent, while uninstall returns a typed active-
child error without touching ACLs, materialized paths, accounts, firewall, or
WFP state. A completed child releases pinned filesystem handles before its
shared lifetime lock.

Every persistent ACL mutation uses the same record as a write-ahead journal.
Before `SetSecurityInfo`, Cageforge stores the canonical path, volume serial,
128-bit file identity, complete DACL bytes and protection bit both before and
after the intended mutation, together with the prior and next managed-object
records. The journal is flushed before mutation and cleared only after the same
handle reads back the exact after state. Recovery accepts exactly two outcomes:
the object still matches `before`, so the prior record remains, or it matches
`after`, so the next record is committed. A replaced object or any third DACL
state is typed drift and fails closed; recovery never guesses which descriptor
to restore and never overwrites an unrelated owner change.

This is an intentional strengthening over the per-root capability identity in
the frozen implementation recorded by [the upstream baseline](../UPSTREAM.md).
Two concurrent requests that name the same writable root but have different
deny, glob, protected-path, or read-only constraints receive different
restricting SIDs, so reconciliation for one profile cannot remove or reuse the
other profile's ACL boundary.

`WindowsBackend::new` performs read-only setup verification. It does not launch
UAC automatically. `WindowsSetup::install` may launch the signed sibling setup
helper with `runas`; UAC cancellation and every helper stage remain distinct
typed errors.

The helper records a non-secret native-operation checkpoint beside its
structured response before entering each setup boundary. If Windows terminates
the helper before it can encode a response, the caller reports both the native
exit code and the last checkpoint. Checkpoints contain stage and operation
labels only; account SIDs, credentials, request contents, and policy data are
never written to this diagnostic channel.

## 5. Token and process boundary

Restricted launches use a primary token derived from the selected dedicated
sandbox account. The token:

- disables maximum privileges and applies the LUA restriction;
- applies restricting-SID access checks to reads and writes rather than using
  the upstream `WRITE_RESTRICTED` optimization;
- retains only `SeChangeNotifyPrivilege` when Windows requires traversal;
- includes only the capability SIDs required by this request;
- includes one random network-route restricting SID when proxy routing is
  active;
- keeps the logon SID and request capability SIDs as the complete default
  object DACL, excluding both the route SID and `Everyone`; and
- cannot inherit an administrator token or the real user's identity.

The runner reads the completed token back before process creation. Token user,
canonical restricting-SID set, default-DACL ACE set and masks, and enabled
privileges must exactly match the requested boundary. `Everyone` remains a
restricting SID because Windows restricted-token access checks require the
normal and restricting passes to retain operating-system compatibility; it is
not an object-creation grant. Any extra enabled privilege, duplicate canonical
SID, route/default-DACL overlap, or Windows-canonicalized ACL difference fails
before the child starts.

Every restricted process is assigned atomically at creation to a fresh Job
Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and every
`JOB_OBJECT_UILIMIT_*` isolation flag. The parent reads both classes back
exactly before launching the runner. These UI limits prevent the child from
using USER handles owned outside its job, installing cross-job hooks, sending
broadcast messages outside the job, reading or writing the clipboard, creating
or switching desktops, sharing global atoms, changing display or system UI
settings, or exiting the Windows session. This defense remains authoritative
even if the host's default desktop has an unexpectedly permissive DACL.
Cageforge does not enable breakaway. If Windows cannot apply the job-list
process attribute, the spawn fails before the primary thread runs.

The parent creates and retains that fresh Job Object before launching the
runner. Only after the runner process is created suspended does the parent
duplicate a handle granting only `JOB_OBJECT_ASSIGN_PROCESS` into that exact
process; no pre-existing parent handle is exposed. The runner uses the limited
copy only for `PROC_THREAD_ATTRIBUTE_JOB_LIST` and closes it after child
creation. `WindowsChild` retains the original handle with termination rights and
can therefore kill the complete user-command tree without trusting a control
response from the runner.

The process starts on a private desktop by default. Disabling private-desktop
is not part of the first public API because it would weaken the declared
boundary. After learning the runner's unique logon SID, the trusted parent
creates and retains the desktop, gives that SID only the access required to
start and use the child, and verifies the protected owner/Admin/SYSTEM/logon-SID
descriptor before resuming the runner. The runner receives only the desktop
name. A desktop created by the sandbox account would be unsafe because another
logon of the same file owner retains implicit descriptor-control rights. The
desktop, token, process, thread, pipe, and job handles use owned RAII wrappers
and are never inherited unless explicitly present in the process handle list.

The parent launches the command runner with `CreateProcessWithLogonW`, which
does not provide a safe inherited-handle request channel. The runner therefore
receives a versioned authenticated request over one random private named-pipe
pair. Both directions are identity-bound: the parent verifies that both pipe
clients have the exact PID returned for the launched runner, while the runner
verifies that both pipe servers have the same PID and that the server process
`TokenUser` is the setup owner recorded in a protected runner manifest. The
runner also verifies the exact owner and DACL of its own executable and
manifest, its executable digest, its own `TokenUser` against the selected
manifest account SID, and the deterministic relation between that account name
and the setup-owner SID. No one check is treated as a root of trust by itself.
The staged runner and manifest are readable and executable, but not writable,
by the managed sandbox group. A copied runner with a forged adjacent manifest
can imitate file contents, but it cannot simultaneously run as the provisioned
owner-derived sandbox identity and authenticate a pipe server whose token is
the real setup owner. Direct invocation therefore cannot acquire the backend's
prepared state.

The runner is initially created with `CREATE_SUSPENDED`. Before its first
instruction executes, the parent reads the new token's unique logon SID, creates
both named-pipe DACLs for exactly that logon SID rather than the shared account
SID, and replaces the runner process and primary-thread DACLs with protected
owner/Admin/SYSTEM descriptors. The parent creates each pipe with
`FILE_FLAG_FIRST_PIPE_INSTANCE`, rejects remote clients, and grants the runner
only `FILE_READ_DATA` on the request pipe and `FILE_WRITE_DATA` on the response
pipe. It intentionally does not grant `FILE_GENERIC_WRITE`, because that mask
also contains `FILE_CREATE_PIPE_INSTANCE` for named pipes. Pipe owner and DACL
are read back before the runner resumes. The parent then duplicates the
assign-only Job handle and resumes the primary thread. Exact client-PID checks
remain mandatory after connection. An older process using the same dedicated
account therefore cannot race a pipe connection, create another instance, open
the new runner for injection, steal handles, or reuse another launch's
authenticated channel.

Only the user command's explicit standard handles cross the second process
boundary. The runner supplies those handles through the process handle-list
attribute; no transport, token, job, desktop, setup, or unrelated inheritable
handle reaches the user command.

The trusted parent prepares all three standard streams only after the exact
runner process has connected to both identity-bound pipes. Pipe mode creates an
anonymous pipe with no inheritable parent handle and retains only the caller's
endpoint. Null mode opens `NUL` in the required direction. Inherit mode reads
the current process's exact standard handle and fails if none is associated.
For every mode the parent duplicates only the child endpoint into its pinned
runner-process handle with `bInheritHandle=TRUE`; the authenticated request
contains the three target-process handle values but never stream bytes. The
runner rejects null, invalid, repeated, non-inheritable, unexpectedly flagged,
or Job-aliasing values before taking ownership, then places exactly those three
handles in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Runner exit closes every
duplicate on a failed request, while `WindowsChild` owns pipe endpoints directly
and therefore has no unbounded output queue or blocking stdio-forwarder thread.

`WindowsChild` owns the Job Object and every runtime resource. `kill`, timeout,
drop, and failed setup terminate the complete job and reap the primary process.
Timeout enforcement belongs to the trusted parent and is not delegated to a
runner request field or runner-side timer. The runner closes its assign-only Job
handle immediately after atomic child creation, so parent death also closes the
last Job handle and activates `KILL_ON_JOB_CLOSE`.
Exit status, signal-equivalent termination, timeout, and setup failure remain
distinguishable.

## 6. Filesystem lowering

The backend consumes both layers returned by
`PreparedBackendRequest::filesystem_lowering`. It resolves each selector only
through the prepared effective path context and preserves the conjunction of
requested policy and ceiling.

Windows filesystem enforcement combines:

- dedicated sandbox identities;
- request-scoped restricting capability SIDs;
- handle-based DACL inspection and mutation;
- allow ACEs for readable and writable roots;
- deny ACEs for explicit deny rules, read-only descendants, deny-glob
  snapshots, and protected relative paths;
- persistent state reconciliation for ACEs that must survive descendants; and
- reparse-point and final-handle validation before a path can participate in
  an ACL plan.

A deny ACE for the profile-guard SID must not remain effective inside a
more-specific writable carve-out. Windows evaluates a matching deny before an
allow from another restricting SID, so a writable child cannot override an
inherited deny by ACE ordering. A finite snapshot that makes the deny
non-inheriting on ancestors is also insufficient: another concurrent sandbox
could create a sibling after enumeration and before launch.

The backend therefore keeps each deny and read-only ACE inheritable across its
complete subtree and turns every nested writable root into a protected-DACL
inheritance boundary. The protected DACL is built from the handle-read effective
DACL, removes only the current profile-guard SID, converts retained inherited
ACEs to explicit ACEs without changing their masks, and installs the writable
group and write-root capability ACEs. New descendants then inherit from the
protected writable root while new siblings outside it continue to inherit the
deny. Unknown or malformed ACE forms, a failed protected-DACL read-back, or a
descendant on which the effective deny did not propagate fails before launch.

All capability-state and ACL reconciliation uses the same protected
cross-process lock. A later profile may preserve another profile's capability
ACEs but must never revoke or rewrite them as its own. Persistent state records
every Cageforge-created protected inheritance boundary and the descriptor it
replaced so uninstall or a future no-longer-needed reconciliation can restore
host inheritance only after no active profile depends on the boundary.

The filesystem profile digest is computed only after both mandatory lowering
layers have been resolved, deny globs have been expanded, and every native path
has passed final-handle validation. Its canonical input contains each final
read root, write root, deny target, read-only target, protected target, and
missing-path outcome. Declaration order and diagnostic spelling are not
authority identity. A profile digest therefore cannot be reused when any
effective native constraint differs.

All path opens used for validation set the reparse-point and backup-semantics
flags as appropriate. The backend compares normalized final paths obtained from
handles, rejects cross-volume or out-of-root targets, and applies security
information through the validated handle. A lexical check followed by a
path-based ACL mutation is not sufficient.

Rules with `MissingPathBehavior::Error` fail before launch. `Skip` does not
create the target. Missing exact read-only and protected paths are materialized
component by component below their nearest handle-validated existing ancestor.
Each directory is created atomically with a protected owner/Admin/SYSTEM DACL;
Cageforge never creates a permissive directory and tightens it afterwards.

Materialization uses the capability-state record as a second write-ahead
journal, mutually exclusive with an ACL mutation journal. Before creating one
component, Cageforge durably stores its canonical path, exact creation DACL, a
fixed marker path, the marker DACL, and a random 32-byte nonce. It then creates
the directory, creates `.cageforge-materialized-path` with `CREATE_NEW`, writes
and flushes the nonce, and reopens both objects without delete sharing. Commit
requires the expected owner SID, exact DACL bytes and protection bit, distinct
stable file identities, exact marker contents, non-reparse final paths, and
pinned directory and marker handles.

Recovery accepts exactly three observable states. An absent target means the
native create never became visible, so the pending journal is cleared without
recording an object. A target and marker matching every recorded property are
committed and retained. Any present lookalike, missing or replaced marker,
different nonce, owner, DACL, identity, final path, or reparse state is typed
drift; the journal remains pending and launch fails closed. An existing
component is reusable only when a previously committed materialization record
still verifies exactly. Cageforge never adopts an arbitrary pre-existing
directory after planning observed it as missing.

Committed marker and directory handles remain owned by `WindowsChild`, which
prevents replacement and keeps the materialized directory non-empty while the
command runs. Cleanup restores managed ACLs first and then removes only verified
markers and empty materialized directories in deepest-first order. Identity or
descriptor drift blocks cleanup rather than deleting an unrelated object. A
junction, symlink, crash, or replacement race therefore never turns an absent
protected target into an external writable path.

Uninstall uses a second durable materialization-removal journal. After exact
directory and marker verification through non-reparse handles, it persists
`marker_delete_armed` before setting deletion disposition on the pinned marker
handle. Exact marker absence is recoverable only in that armed phase. It then
persists `directory_delete_armed`, rejects every unexpected descendant, sets
deletion disposition on the same pinned empty-directory handle, verifies path
absence, and only then removes the committed object record. Recovery may repeat
either armed operation or commit an already absent directory; an unarmed
absence, replacement identity, changed owner, DACL, nonce, reparse state, or
non-empty directory remains typed drift. The elevated helper refuses to remove
accounts or network setup while any ACL, materialization, or cleanup journal
remains.

Glob expansion starts at the deepest literal root. A recursive root glob with
no configured depth is rejected rather than scanning the complete machine or
silently truncating the rule. Directory enumeration does not follow reparse
points and detects object-identity cycles.

The first implementation supports the elevated Codex filesystem shape: a
restricted policy must provide readable platform or root scopes and may narrow
them with exact denies and deny globs. A policy that requires a true
default-deny read namespace without a readable Windows platform base is rejected
with `UnsupportedFilesystemShape`; the backend must not advertise enforcement
for that request. This is an operating-system contract difference from the
Linux mount namespace, not a silent widening.

Unrestricted filesystem execution is allowed only when network policy is also
unrestricted and the backend can launch the current identity directly without
claiming a restricted boundary. Mixed unrestricted-filesystem and restricted-
network requests fail as an unsupported combination.

## 7. Network lowering

Disabled and proxy-routed requests use the offline sandbox identity. Direct
unrestricted networking uses the online identity. External ownership is not
advertised.

Offline setup must prove all of the following:

- non-loopback outbound traffic is blocked for every active firewall profile;
- UDP loopback is blocked;
- TCP loopback is blocked except for the configured Cageforge ingress ports;
- ICMP, DNS ports 53 and 853, and SMB ports 139 and 445 are blocked by the
  Cageforge WFP provider for IPv4 and IPv6; and
- local policy is effective rather than overridden or partially applied by
  Group Policy.

Proxy routing uses one process-wide IPv4-loopback HTTP listener and one SOCKS5
listener, both bound specifically to `127.0.0.1`. The frozen implementation's
owner-PID attribution is IPv4-only, so Cageforge does not expose an IPv6
listener whose clients it cannot attribute; the offline boundary continues to
block direct IPv6 loopback. Each execution receives a random restricting SID
that is added to its token and registered to exactly one immutable
`NetworkGateway` route. For every accepted connection, ingress:

1. reads the accepted local and peer addresses;
2. queries the exact reversed TCP four-tuple in the Windows owner-PID table;
3. opens that PID and reads its `TokenRestrictedSids`;
4. requires exactly one currently registered route SID;
5. prepends the private `GatewayIngressKey` proof; and
6. hands the stream to the route's Cageforge gateway.

Missing, duplicate, stale, or unattributable routes fail closed. This prevents
two concurrent sandboxes using different policies from selecting one another's
gateway route. PID lookup, token lookup, and route registration are bounded and
never fall back to an unauthenticated listener.

The Cageforge ingress strengthens the frozen implementation by requiring
`SO_EXCLUSIVEADDRUSE` before binding each fixed setup port, bounding owner-table
resize retries and token buffers, pinning the attributed process while the
owner row and restricted token are rechecked, and generating route SIDs from
operating-system cryptographic randomness with a bounded collision loop. These
are native enforcement details; the public API remains the generalized
effective network policy and gateway configuration used by other Cageforge
backends.

The gateway still performs one DNS snapshot and exact `SocketAddr`
authorization immediately before connect. Firewall and route attribution are
native ingress boundaries, not replacements for portable policy checks.

Windows pathname Unix-socket capabilities are not advertised in the first
backend. Named pipes are separate Windows objects and must be isolated by token,
desktop, object DACL, and handle inheritance. A Unix-socket request receives the
typed unsupported capability error from common preflight.

## 8. Environment and standard streams

The backend selects a conservative Windows core environment containing only
the platform variables required for executable lookup, user profile, locale,
system directories, and temporary paths. The complete host environment is
never relabelled as `CoreEnvironment`.

The final environment comes only from
`PreparedBackendRequest::apply_environment`. Environment blocks are sorted by
case-insensitive Windows identity, contain no NUL values, and end with the
required double NUL. Proxy variables are backend-owned overrides applied after
portable transformation and cannot be removed by the user command request.

Inherited, null, and piped stdio use an explicit handle list. No unrelated
inheritable handle may cross the boundary. Pipe readers and writers are owned
by `WindowsChild` and close deterministically on timeout and drop. Standard
stream content is not part of the authenticated runner protocol: the protocol
reports only spawn, typed failure, and exit lifecycle state.

## 9. Capabilities and native validation

The backend advertises command execution, checked working directories, all
three standard-stream modes, all timeout modes, the supported elevated
filesystem scope/glob/protection families, disabled and enabled networking,
domain/local-address/exact-target enforcement, and all portable environment
modes and transformations.

It does not advertise:

- external filesystem or network ownership;
- pathname Unix-socket isolation or per-path Unix-socket rules; or
- a capability whose setup read-back or runtime mechanism is unavailable.

Capability preflight is followed by native combination validation. In
particular, proxy routing requires verified offline firewall and WFP state,
restricted filesystem ownership, and a registered route SID. Any mismatch is a
typed error before process launch.

## 10. Required tests

Portable and cross-target tests cover deterministic plans, capability
declarations, setup-marker parsing, protocol framing, path planning, error
typing, and every feature combination.

Windows-native black-box tests must cover at least:

- setup is required, versioned, idempotent, and read back;
- sandbox users are non-administrative and offline/online identities differ;
- disabled network blocks direct public, private, loopback, DNS, ICMP, SMB,
  WinHTTP, WinINet, PowerShell, and process-broker attempts;
- HTTP and SOCKS reach only exact authorized targets;
- a process cannot use another execution's route SID or ingress;
- direct invocation of helpers and forged protocols fail;
- writes outside roots, reads outside the supported readable base, protected
  paths, read-only descendants, alternate data streams, device paths, drive
  aliases, junctions, symlinks, and reparse replacements fail;
- missing-path and glob-depth behavior is deterministic;
- private-desktop GUI and shell-activation escapes fail;
- unrelated handles and named objects do not cross the boundary;
- timeout, kill, drop, and parent death terminate the complete process tree;
- simultaneous backends keep identities, ACL state, routes, and jobs separate;
  and
- typed setup failures identify UAC cancellation, ineffective firewall policy,
  WFP failure, ACL failure, token failure, desktop failure, job failure, and
  process start failure separately.

Tests that require administrator provisioning run only in the dedicated
Windows native CI job on an ephemeral runner. They must not use repository
secrets and must clean Cageforge-created users, rules, WFP objects, ACL state,
and processes even after a failed assertion.

## 11. CI contract

The common-component lane runs independently on Linux, macOS, and Windows and
must not compile or test an OS sandbox crate. It checks every feature
combination exposed by the platform-independent crates on each target.

The separate Windows sandbox lane performs formatting and Clippy, all
`cageforge-windows` feature combinations, native tests, setup-helper tests,
command-runner tests, and a machine-readable test report. It runs on an
explicit Windows Server 2025 runner. `main` always runs this lane. Pull requests
run it for shared dependencies, Windows crate changes, workflow changes, a
manual `sandbox-windows` label, or manual workflow dispatch.

The native security job runs on an ephemeral Windows runner and provisions
only the runner VM. It receives read-only repository permissions, does not run
with repository secrets, and is superseded when a newer commit reaches the same
PR or branch.

## 12. Frozen Codex correspondence

The behavioral baseline is the commit recorded in `UPSTREAM.md`. The required
review includes:

| Frozen Codex area | Retained behavior | Cageforge difference |
| --- | --- | --- |
| `windows-sandbox-rs/src/resolved_permissions.rs` | Resolve native roots and choose read-only/write capability families | Consume Cageforge lowering views and reject unsupported shapes explicitly |
| `windows-sandbox-rs/src/token.rs` | Dedicated-user restricted token and per-route restricting SID | No unelevated current-user path; no job breakaway |
| `windows-sandbox-rs/src/process.rs` and `proc_thread_attr.rs` | `CreateProcessAsUserW`, explicit handles, atomic job assignment | Backend-owned child API and typed errors |
| `windows-sandbox-rs/src/desktop.rs` | Private desktop for each launch | Private desktop is mandatory initially |
| `windows-sandbox-rs/src/identity.rs`, `setup.rs`, and setup helper | Versioned users, protected credentials, ACL/firewall reconciliation | Upstream fixed account names become user-SID-scoped Cageforge identities; library does not silently launch weaker fallback |
| `windows-sandbox-rs/src/acl.rs`, `deny_read_*`, `allow.rs`, and `audit.rs` | Capability ACEs, deny-read/write and persistent reconciliation | Handle-based reparse/TOCTOU validation; profile-scoped identities; protected-DACL writable boundaries preserve inheritable denies without deny/allow ordering or finite branch snapshots; no time-bounded best-effort security scan |
| `windows-sandbox-rs/src/wfp.rs` and setup firewall module | Offline-account firewall and WFP filters | WFP failure is fatal and all configured policy is read back |
| `network-proxy/src/windows_tcp_attribution.rs` and `windows_proxy_ingress.rs` | IPv4 four-tuple PID attribution and random restricting-SID routing | IPv4-only ingress is explicit and the route feeds the independent Cageforge gateway authentication contract |
| `windows-sandbox-rs/src/elevated/*` and command runner | Dedicated-user helper transport and lifecycle | Versioned minimal protocol with no Codex command/profile types |

Product logging, metrics, ConPTY, Git-specific injection, profile aliases,
automatic fallback, and Codex home conventions are intentionally excluded.

### 12.1 Provisioning review record

The setup implementation was reviewed line by line against the frozen versions
of `src/setup.rs`, `src/setup_error.rs`, `src/identity.rs`, `src/dpapi.rs`,
`src/wfp.rs`, `src/wfp/filter_specs.rs`, `src/wfp_setup.rs`,
`src/bin/setup_main/win.rs`, `src/bin/setup_main/win/sandbox_users.rs`, and
`src/bin/setup_main/win/firewall.rs` under `codex-rs/windows-sandbox-rs`.
The Cageforge setup protocol retains the following boundaries:

- setup state is per signed-in owner and cannot be shared merely because two
  callers choose the same directory;
- an incomplete or malformed marker is never readiness evidence;
- independent random credentials are rotated on every successful reconcile,
  protected with machine-scope DPAPI, and stored behind an explicit protected
  DACL;
- local users are ordinary users, belong to the managed group, and are rejected
  if disabled, locked, or directly or indirectly administrative;
- firewall changes must apply to every active profile and each installed rule
  is read back by its stable Cageforge name and complete enforcement fields;
- firewall address and port read-back compares canonical interval sets rather
  than COM-preserved spelling, and the local-user scope must contain exactly
  one `COM_RIGHTS_EXECUTE` allow ACE for the offline account SID. The frozen
  baseline checks only that the returned user-scope string contains the SID;
  Cageforge intentionally rejects extra principals and semantically different
  scopes while accepting equivalent Windows canonicalization;
- the firewall COM apartment outlives every policy, rule-collection, and rule
  interface acquired from it; teardown never calls `CoUninitialize` while a
  dependent COM interface can still execute `Release`;
- WFP provider, sublayer, and every account-scoped filter are persistent,
  stable Cageforge objects and are read back before marker commit; and
- setup is committed only after all native state is effective.

Intentional differences are exact typed errors instead of product error codes,
owner-SID-derived account and object identities instead of machine-global Codex
names, checked group-membership updates, a required `SeBatchLogonRight`, fatal
WFP failure, and no telemetry or product directory conventions. The
Cageforge-authored implementation uses the Windows APIs directly and does not
copy the reviewed source files.

### 12.2 Token, runner, process, and lifecycle review record

The process-boundary design was reviewed line by line against the frozen
versions of `src/token.rs`, `src/token_tests.rs`, `src/process.rs`,
`src/proc_thread_attr.rs`, `src/desktop.rs`, `src/stdio_bridge.rs`,
`src/elevated/ipc_framed.rs`, `src/elevated/runner_pipe.rs`,
`src/elevated/runner_client.rs`,
`src/elevated_impl.rs`, and `src/bin/command_runner/win.rs` under
`codex-rs/windows-sandbox-rs`, plus `src/win/job.rs` under
`codex-rs/utils/pty`.

The Cageforge boundary retains the dedicated-account runner, bounded framed
transport, exact runner-PID pipe attribution, `CreateRestrictedToken` with
maximum privileges disabled and the LUA restriction, capability and token-
user restricting SIDs, route SIDs excluded from the default object DACL,
`SeChangeNotifyPrivilege` as the sole re-enabled privilege,
`CreateProcessAsUserW`, an explicit handle list, a private desktop, atomic Job
Object assignment through `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and complete tree
termination on startup failure, timeout, explicit kill, or owner drop.

Cageforge intentionally adds runner-side owner-PID and token verification,
uses a protected owner manifest, forbids Job Object breakaway and descendant
preservation, enables and verifies all Job Object UI restrictions, keeps private
desktop mandatory, and returns stage-specific typed
protocol, token, desktop, job, process, wait, and termination failures. It does
not set `WRITE_RESTRICTED`: the full restricting set participates in read and
write checks, which permits profile-scoped deny-read ACLs instead of the frozen
implementation's shared sandbox-group deny-read state. It also does not retain
Codex permission profiles, command schemas, logging, credential
refresh fallback, ConPTY, filesystem-helper aliases, or cloned secret-bearing
protocol requests.

The frozen direct-process path supplies standard streams with
`STARTF_USESTDHANDLES` and an explicit process handle list; Cageforge retains
that native boundary. The frozen elevated unified-exec path instead transports
stdin and output as framed messages and includes PTY and product request state.
Cageforge intentionally does not retain that transport. Parent-prepared HANDLE
duplication gives the reusable library the same direct `Read`/`Write` child
surface as `cageforge-linux`, prevents undrained output from accumulating in an
unbounded runner channel, and keeps slow inherited output outside the trusted
lifecycle-response dispatcher.

The installed runner manifest is versioned and binds the setup owner SID,
managed-group name and SID, both dedicated account names and SIDs, and the
staged runner digest. Its digest is committed in the final setup marker. The
runner directory and executable grant the managed group exactly read/execute
access, while the manifest grants that group exactly read access; owner,
Administrators, and SYSTEM retain full control. Every one of these protected
DACLs and manifest fields is read back before setup is accepted. The runner
obtains the manifest
only from the protected directory containing its own verified executable, so a
copied binary and attacker-selected manifest cannot establish a trusted
endpoint.

Each protected setup directory and file also has the real setup owner SID as
its Windows object owner, and read-back verifies that owner together with the
protected DACL. Matching only the ACE list is insufficient because a sandbox
account that owns an attacker-created lookalike retains implicit DACL-control
rights even if it writes visually equivalent ACEs.

### 12.3 Filesystem ACL review record

Filesystem lowering and ACL reconciliation were reviewed line by line against
the frozen versions of `src/acl.rs`, `src/allow.rs`, `src/workspace_acl.rs`,
`src/deny_read_acl.rs`, `src/deny_read_state.rs`, `src/deny_read_resolver.rs`,
`src/spawn_prep.rs`, and the ACL portions of `src/bin/setup_main/win.rs` under
`codex-rs/windows-sandbox-rs`.

Cageforge retains separate normal-pass group grants and restricting-pass
capability grants, a write-root mask that excludes `FILE_DELETE_CHILD`,
inheritable deny-read and deny-write ACEs, durable capability identity, and
read-back before launch. It intentionally replaces path-based
`SetNamedSecurityInfoW` mutation with `GetSecurityInfo` and `SetSecurityInfo` on
the same validated handle, rejects reparse-point and final-path changes, and
uses profile-scoped guards rather than a machine-global deny-read principal.
Writable descendants below a deny use protected-DACL inheritance boundaries;
the frozen implementation instead materializes deny targets and relies on
separate capability SIDs and ACL ordering without representing this nested
composition as one transactional plan.

Unlike the frozen deny-read state, which records only principal-to-path lists,
Cageforge journals the complete before/after descriptor and stable file
identity before every mutation. This closes the crash interval between state
write and ACL application and makes a path replacement distinguishable from a
recoverable interrupted operation.

The frozen `revoke_ace` cleanup is path-based, best-effort, and does not report
failure. Cageforge instead restores the complete original descriptor through
the same identity-checked handle and requires exact read-back before deleting
the state record. Its child-owned resource release follows the independent
`cageforge-linux` lifecycle shape, while Windows lifetime exclusion uses shared
and exclusive byte-range locks because ACL state is host-persistent rather than
mount-namespace-local.

The frozen `deny_read_acl.rs` materializes missing paths with path-based
`create_dir_all` before adding an ACE. Cageforge intentionally does not retain
that creation interval. Its materialization journal records a random marker and
exact creation descriptor before the first native object appears, creates each
component with that descriptor, and accepts only absent or exact verified
recovery states. Marker and directory identities are pinned through the child
lifetime, and uninstall removes them only after exact state reconciliation.
