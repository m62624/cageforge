# Specification 0002: Upstream Review Tool

Status: draft

## Purpose

The cageforge-upstream-review tool is an internal, read-only tool for tracking
the exact OpenAI Codex commit represented by Cageforge's adapted
implementation.

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

The initial pre-port configuration may leave last_adapted_commit empty. A diff
is not allowed until an audited commit has been selected.

## Commands

- status prints the configuration and locally available upstream ref;
- check validates configuration and path scopes;
- diff prints a Git stat, changed-file list, and patch for configured scopes.

The tool never fetches automatically. The caller updates the external Codex
checkout manually and then supplies a commit or uses the configured branch.
The external checkout is not copied into Cageforge.

## Review boundary

The tool compares upstream commit A to upstream commit B. It does not claim
that a rewritten Cageforge implementation is textually equivalent to Codex.
The manual provenance mapping in UPSTREAM.md remains authoritative for
source-derived files and must record each imported path, commit, local path,
license, and material adaptation.

## Safety properties

- Only configured repository-relative upstream paths are passed to Git.
- The tracked commit must be a full commit SHA.
- No shell is invoked by the tool.
- No network, filesystem mutation, Git ref mutation, or source import occurs.
