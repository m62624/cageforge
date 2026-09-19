> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

This crate is a supporting component of the
[`cageforge`](https://crates.io/crates/cageforge) crate, a cross-platform Rust
sandbox for AI agents and untrusted code.

# cageforge-permissions

`cageforge-permissions` provides the typed, platform-neutral preflight contract
used by Cageforge hosts and language bindings. It turns a concrete launch
request into an auditable capability description, lets a trusted approver
create an opaque grant, and persists approved grants in a versioned host-owned
store.

## Add the crate

```toml
[dependencies]
cageforge-permissions = "x.y.z"
```

The crate is intentionally independent from the native Linux, macOS, and
Windows enforcement crates. This makes the same request, grant, digest, and
error model available to Rust, Python, Java, and interactive CLI hosts.

## Preflight flow

Create a request from the immutable launch identity and requested capabilities.
The request includes the tool and version, executable and manifest digests,
target platform and architecture, and the exact filesystem, network, and
child-process capabilities.

```rust
use cageforge_permissions::{GrantAuthority, PermissionRequest, PermissionSet};

let request = PermissionRequest::new(
    "example-tool",
    "1.2.3",
    manifest_digest,
    config_digest,
    platform,
    architecture,
    PermissionSet::default(),
)?;

// Only trusted host code should hold the authority used to approve requests.
let grant = GrantAuthority::new().approve(&request);
```

`PermissionRequest` is descriptive input. `PermissionGrant` has private
fields and can only be created by `GrantAuthority`; callers cannot forge a
grant by deserializing or reconstructing its representation. A grant is bound
to the complete request identity and can be narrowed to a subset of the
requested capabilities before launch.

`PermissionRequest` is intentionally different from a launch request. A
`CommandRequest` describes the executable and its argv, while a backend
request carries the composed policy into one OS implementation. This crate's
request is the host-facing capability declaration that connects those two
steps before native launch.

The host performs this sequence before starting a process:

1. construct the request from the exact launch inputs;
2. load a matching grant, or ask the trusted approver;
3. validate expiry, platform, architecture, digests, and capability scope;
4. compose the approved scope with the immutable policy ceiling; and
5. pass the resulting authorization to the native Cageforge crate.

There is no permission escalation inside a running process. A request that
cannot be approved before launch is rejected with a typed error.

`PermissionScope::Launch` and `PermissionScope::Session` remain in memory.
`PermissionScope::Persistent` may be written to the store only after the
trusted host approves it. The store path is always selected by the host: the
CLI accepts `--permission-store PATH`, which takes priority over its OS-native
per-user default. Without an explicit path, Linux uses
`$XDG_STATE_HOME/cageforge/permissions.json` (falling back to
`~/.local/state/cageforge/permissions.json`), macOS uses
`~/Library/Application Support/Cageforge/permissions.json`, and Windows uses
`%LOCALAPPDATA%\\Cageforge\\permissions.json`. A trusted host may deliberately
share one path across projects or choose separate stores. Rust callers pass an
absolute path to `PermissionStore::open`, and the Python and Java bindings
enforce the same rule with a language-native typed store-path error.

Persistence is revocable host state, not an undeletable system database. The
owner may remove the file to revoke all saved approvals, and the next launch
will require approval again. A host should keep the store outside any
workspace or directory that it grants to the sandbox with write access.

## Persistent grant store

`PermissionStore` stores grants in one versioned `permissions.json` document.
It validates the document when the store is opened, then loads and indexes the
current file for each operation. The stored audit metadata is checked against
each request. An absent file is always treated as an empty store. Updates use
a temporary file, sync, and atomic rename. A writer refreshes the latest
document while holding the OS lock before replacing it. Unix stores are
restricted to the owner; the Windows implementation applies and verifies an
owner-only ACL. A persistent OS advisory lock serializes concurrent writers
without a fixed retry budget.

The document contains host audit state, not executable policy:

```json
{
  "schema_version": 2,
  "grants": {
    "<request-digest>": {
      "request_digest": "<request-digest>",
      "tool_id": "example-tool",
      "tool_version": "1.2.3",
      "manifest_digest": "<sha256>",
      "config_digest": "<sha256>",
      "platform": "linux",
      "architecture": "x86_64",
      "approved": {
        "filesystem": [],
        "network": [],
        "child_processes": []
      },
      "scope": "persistent",
      "expires_at": null,
      "issued_at": 1780000000
    }
  }
}
```

The digest key and the repeated identity fields bind the persisted approval to
the exact tool, executable/manifest identity, configuration, platform,
architecture, and requested capabilities. Editing a record does not grant new
authority: the next lookup revalidates its digest, subset, expiry, schema, and
owner-only file protection. A changed TOML profile or executable therefore
requires a new approval.

Every `get` for an existing store and every `put` takes the kernel lock and
refreshes the latest document before evaluating or replacing it. A not-yet-
persisted store is treated as empty without creating a sidecar file. `put`
then performs one durable atomic replacement; there is no userspace polling
delay or fixed retry loop. The store does not use a userspace mutex for
cross-process coordination; the OS lock is the authority. The durable JSON
path is intentionally appropriate for relatively infrequent persistent
approvals.

## Inspecting and revoking grants

The store exposes bounded, metadata-only pages. A request gets the same stable
ID in every language binding:

```rust
let page = store.list_page(GrantPageRequest::new(50, None)?)?;
for grant in page.entries() {
    println!("{} {}", grant.id, grant.tool_id);
}
if let Some(cursor) = page.next_cursor() {
    let _next = store.list_page(GrantPageRequest::new(50, Some(cursor.clone()))?)?;
}
store.revoke(request.grant_id())?;
```

`GrantSummary` contains only tool identity, target, scope, and timestamps. It
does not expose the approved capability set or secret material. A cursor is
opaque and becomes invalid when the JSON document changes. `revoke` affects
future launches only; `revoke_all` retains the owner-protected file and is
intended for an explicit host-management action.
High-frequency hosts should keep session grants in memory or replace this
host-owned storage behind the same API with a transactional backend such as
SQLite.

The store is host state, not application policy. Keep it in a host-controlled
location and pass its path explicitly when the launch environment requires a
non-default location.

## Integration

The `cageforge` crate builds requests from resolved profiles and combines an
approved grant with the effective policy before invoking the selected native
backend. The Python and Java bindings expose the same request identity,
approval scope, expiry, and structured permission-error semantics. The CLI
uses the same flow when a profile selects preflight approval.

See the [`cageforge` crate](https://crates.io/crates/cageforge) and the
[configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md)
for the complete profile-to-launch flow.
