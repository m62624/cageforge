# cageforge-upstream-review

This is an internal, read-only repository tool. It tracks the exact upstream
Codex commit represented by the current Cageforge adaptation and limits diffs
to explicitly configured upstream scopes.

Rules:

- Do not copy upstream source into the Cageforge repository.
- Do not fetch automatically.
- Do not update last_adapted_commit.
- Do not create branches, commits, pull requests, or review bundles.
- check must work without an upstream checkout.
- status and diff may require an external checkout from config,
  --upstream-path, or CAGEFORGE_UPSTREAM_PATH.
- Use Git arguments directly through Command; never invoke a shell.
- Keep output deterministic and suitable for CI logs.

The tool reports upstream changes. It does not decide whether a change should
be ported and is not an automatic merge or license review.
