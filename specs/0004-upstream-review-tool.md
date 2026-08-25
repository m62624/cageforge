# Specification 0004: Upstream Review Tool

Status: accepted

## Purpose

The cageforge-upstream-review tool is an internal, read-only tool for tracking
the exact OpenAI Codex commit used as a behavioral reference by Cageforge's
independent implementation.

The tool does not vendor the Codex repository, add Codex as a Rust dependency,
copy source files, create branches, create pull requests, or update the
tracked commit. Porting remains a manual change to the independent Cageforge
workspace.

## Configuration

The repository root contains upstream-review.toml. It records:

- upstream repository, checkout path, and branch;
- the external upstream checkout used for local Git operations;
- the full commit SHA represented by the current Cageforge adaptation;
- explicit upstream scopes and their local Cageforge destinations.

Scope paths are validated in two places: local destinations must exist in the
Cageforge checkout, and configured upstream paths must exist at the recorded
baseline when an external checkout is available. For each tracked Rust file,
the tool also watches the same path without `.rs`. For example, it watches both
`permissions.rs` and `permissions/`. A tracked `mod.rs` is special: the tool
watches the containing directory, such as both `sandboxing/mod.rs` and
`sandboxing/`, because Rust module children are added next to `mod.rs`. This
catches module splits without widening the review to an unrelated source
directory. Additional directory paths can still be listed explicitly when a
broader review boundary is intentional.

The current configuration records the frozen baseline documented in
[UPSTREAM.md](../UPSTREAM.md) for the current portable policy, command, and
config crates. The policy scope also tracks Codex's
`network-proxy/src/policy.rs` because host normalization is part of the
portable network boundary. This baseline is frozen: the tool never pulls
Codex, changes the commit, or imports source. Advancing it requires a manual
review and an explicit configuration change.

## Commands

- status prints the configuration and locally available upstream ref;
- check validates configuration and local path scopes without an upstream checkout;
- diff prints a Git stat, changed-file list, and patch for configured scopes.

The tool never fetches automatically. The caller updates the external Codex
checkout manually. Status and diff use the path from the configuration, or an
override supplied through --upstream-path or CAGEFORGE_UPSTREAM_PATH. The
external checkout is not copied into Cageforge. The check command does not
require the external checkout to exist.

## Review boundary

The tool compares upstream commit A to upstream commit B. The configured
`cageforge-policy` and `cageforge-command` scopes are behavioral review scopes;
they do not claim that a rewritten Cageforge implementation is textually
equivalent to Codex or source-derived from it.
The manual provenance mapping in UPSTREAM.md remains authoritative for
source-derived files and must record each imported path, commit, local path,
license, and material adaptation.

## Safety properties

- Only configured repository-relative upstream paths are passed to Git.
- Possible Rust module-directory splits next to a tracked `.rs` file are also
  passed as narrow pathspecs.
- Diff targets and the configured upstream ref used by `status` are resolved
  to full commit IDs with Git's end-of-options marker before any Git operation
  uses them as revisions.
- Diff execution disables external diff and text-conversion hooks and treats
  configured pathspecs literally. Diff output is streamed instead of being
  buffered in memory as one unbounded command result.
- Unknown fields in the tracking TOML are rejected instead of being ignored.
- Baseline upstream files and local Cageforge destinations are checked before
  a review is shown.
- The tracked commit must be a full commit SHA.
- No shell is invoked by the tool.
- No network, filesystem mutation, Git ref mutation, or source import occurs.
