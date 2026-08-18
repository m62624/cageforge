# Specification 0005: Shared Path and Network Target Semantics

Status: accepted; portable implementation complete

## Purpose

Several Cageforge crates accept paths, but none of them should invent its own
Windows comparison rules. `cageforge-path` is the small shared crate for those
lexical operations. It is intentionally independent of policy, configuration,
process launching, DNS, and native enforcement.

## Shared path contract

`cageforge-path` owns:

- component-aware `is_within` checks;
- complete-path `paths_equal` checks;
- platform-aware component and string comparisons;
- lexical `contains_parent_traversal` validation.

On POSIX targets comparisons are case-sensitive. On Windows they are
case-insensitive, including drive-prefix and component comparisons. The helpers
never use filesystem I/O, canonicalization, or symlink resolution. A backend
must perform those operations when it prepares a native enforcement boundary.

The shared helpers are used by policy filesystem matching, Unix-socket rules,
command working-directory validation, config rule merging, policy-composition
workspace ceilings, and upstream-review path validation. This keeps a path
that is equal or inside another path under the same native semantics in every
layer.

`PathSelector` delegates its equality, hashing, and ordering identity to the
same native component rules. Config profile inheritance applies those rules to
`workspace_roots`, so a child cannot leave a semantically duplicate inherited
root active by changing only Windows path case or equivalent lexical spelling.

`PathPattern` follows the same contract for its public `Eq`, `Hash`, and `Ord`
implementations. Its absolute/workspace root kind, native prefix, and path
components form the collection identity; the original pattern text remains
available through `as_str()` for diagnostics and serialization. This prevents a
Windows case variant from becoming a second policy key while preserving the
declared spelling at the API boundary.

## Resolved network target contract

Domain rules alone cannot prevent a hostname from resolving to loopback,
private, link-local, multicast, or other non-public addresses. The portable
network model therefore exposes `LocalNetworkAccess` and the resolved-target
API (`ResolvedNetworkTarget` plus `decision_for_resolved_target`). The older
slice-based query remains available for inspection, but it does not bind the
result to a future socket connection.

The policy crate does not perform DNS or network I/O. A consuming backend must
resolve the hostname and pass every result to the target. It passes an empty
address snapshot when resolution fails or times out. With the default
`LocalNetworkAccess::Deny`:

- a hostname resolving to any non-public address is denied, even when its
  hostname rule is explicitly allowlisted;
- a hostname with no resolved addresses is denied;
- the `localhost` hostname is denied before trusting a public DNS result;
- a literal IP is denied when it is non-public unless an exact literal allow
  rule exists;
- public results remain subject to the ordinary domain rules, and an exact
  `localhost` allow rule is an explicit local-literal opt-in that may also
  accept its loopback resolution;
- `LocalNetworkAccess::Allow` is an explicit opt-in after the ordinary domain
  policy has allowed the destination.

The same check is exposed by `cageforge-policy-compose`, which evaluates both
the requested policy and the ceiling with the same resolved address set. The
composer does not resolve DNS, select a proxy, or implement firewall rules.

This boundary captures the portable safety decision while leaving DNS
configuration, resolver choice, connection races, socket enforcement, and
platform capability errors to the future network backend.

## Configuration

`cageforge-config` maps the TOML field
`[profiles.<name>.network].local_network_access` to this typed policy value.
The field defaults to `deny`; `allow` must be an explicit profile choice.
Profile inheritance treats it as a scalar child override.

## Verification

Black-box tests cover component-aware containment, Windows case behavior,
parent-traversal rejection, path deduplication, native protected-metadata case
behavior, character-class and range globs, public/private/mixed/empty DNS
results, IPv4/IPv6 targets, `localhost` DNS spoofing resistance, exact literal
opt-in, explicit local-network opt-in, composition narrowing, config mapping,
and config inheritance.
Bounded property tests exercise these combinations without performing DNS or
network I/O, so CI remains deterministic and short.

## Responsibility boundaries

`globset` belongs to `cageforge-policy`, not to `cageforge-path`. A glob is
interpreted there as a filesystem or domain policy rule with access modes,
deny precedence, and portability restrictions. `cageforge-path` owns only
native path identity and containment, so it remains reusable by projects that
do not use policy globs.

`cageforge-policy` exposes `ResolvedNetworkTarget` for a normalized host and
one exact resolution snapshot. A native backend must evaluate that target,
connect only to one of its `SocketAddr` values, and call
`decision_for_connected_address` immediately before connecting. A second DNS
lookup or an address outside the snapshot is denied.
