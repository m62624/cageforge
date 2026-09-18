# Specification 0022: Persistent Grant Management

Status: draft

## Purpose

The host-owned persistent permission store provides bounded inspection and
addressed revocation without exposing the stored capability payload or
changing an already-running sandbox.

## Stable identities

`PermissionRequest::grant_id()` is the SHA-256 digest of the canonical complete
request. It is rendered as lowercase hexadecimal. A changed tool identity,
version, manifest/config digest, target, architecture, or capability set
therefore selects a different grant. Random and sequential identifiers are not
used.

`GrantSummary` exposes only the safe audit metadata needed to identify a grant:
ID, tool identity, platform, architecture, scope, issuance, and expiration. It
does not expose approved capabilities, credentials, tokens, or authentication
material.

## Storage

The canonical format remains one versioned, owner-protected JSON document.
Opening it validates the schema, canonical grant keys, and repeated request
digests, then indexes records by their digest in a `BTreeMap`. Lookup and
pagination operate on that index; no binary search over raw JSON is used.

JSONL is intentionally not the canonical format. An append-only journal would
still require replay, an index, revoke tombstones, partial-tail recovery, and
compaction. If the control-plane store ever becomes large or high-frequency,
`PermissionStore` may gain a transactional backend behind the same API; that
is a separate storage decision.

Writes and revokes acquire the operating-system lock, reread the latest
document, and atomically replace it through a synced temporary file. The
current JSON document is indexed in memory only for the duration of the
operation; the OS lock is the cross-process coordination mechanism. The lock
is never held between page calls, and no userspace retry loop is used.

## Listing and revocation

`GrantPageRequest` requires a non-zero page size bounded by
`GrantPageRequest::MAX_PAGE_SIZE`. `GrantPageCursor` is opaque and contains a
document snapshot digest plus the last returned ID. A changed document makes
the cursor stale and returns `StoreError::ListingSnapshotExpired`.

`revoke(GrantId)` removes exactly one future approval and returns
`RevokeResult`. `revoke_all` is an explicit host operation that retains the
store file. Neither operation changes a grant already held in memory or a
process that has already launched.

Rust, the CLI, Python, and Java expose the same ID, cursor, page, result, and
error semantics. Bindings add only language-native immutable DTOs and stable
exception categories; Rust remains the validation and storage authority.
