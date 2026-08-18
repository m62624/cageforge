# Specification 0001: Cageforge Project Charter and Licensing

Status: draft

## 1. Purpose

Cageforge is an independent Rust workspace for reusable process sandboxing.
It is intended for agent harnesses, build systems, developer tools, and other
programs that need to execute untrusted or semi-trusted commands with explicit
filesystem, process, and network restrictions.

Cageforge must provide a small, platform-neutral public API with native
implementations for Linux, macOS, and Windows. A harness should be able to
depend on Cageforge without depending on an agent product, an LLM protocol,
Codex-specific telemetry, or a particular process orchestration framework.

## 2. Relationship to OpenAI Codex

The current implementation is independently authored in Cageforge. Its
portable sandbox design and security boundaries are reviewed against relevant
open-source code in the OpenAI Codex repository:

<https://github.com/openai/codex>

The behavioral reference areas include:

- `codex-rs/sandboxing`
- `codex-rs/linux-sandbox`
- `codex-rs/windows-sandbox-rs`
- `codex-rs/bwrap`
- `codex-rs/vendor/bubblewrap` for a possible future bundled Linux component

**Cageforge is not a fork of the Codex product and must not expose Codex as a
runtime dependency or as part of its public API. The current crates are
independent reimplementations with their own APIs and boundaries; they do not
contain copied Codex source. If a future crate copies or substantially adapts
an upstream file, the provenance and license rules in `specs/0002` become
mandatory for that file.

Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.**

## 3. Public naming and trademark policy

The public project and crate names are Cageforge. New public symbols should
not use `codex_`, `Codex`, or OpenAI product names unless a compatibility or
provenance reference is genuinely required.

References to OpenAI Codex are allowed and required in provenance and legal
documentation where they accurately describe the origin of derived code. They
must not be used as Cageforge branding or in a way that implies endorsement.

The following locations may contain the origin reference:

- `NOTICE`;
- `UPSTREAM.md`;
- `THIRD_PARTY_NOTICES.md`;
- source-file provenance headers for derived files;
- documentation sections that explain the project's origin.

## 4. Provenance and upstream tracking

Every imported or substantially adapted source file must be traceable to an
upstream repository path and commit. The repository will maintain an
`UPSTREAM.md` file containing:

- the upstream repository URL;
- the imported baseline commit;
- a mapping from upstream paths to Cageforge paths;
- the date of each reviewed upstream update;
- notes about material changes made during porting.

The Git repository should keep an `upstream` remote pointing at the original
Codex repository. Upstream updates are reviewed with Git diffs and then
ported manually into the independent Cageforge architecture. Automatic merges
must not be treated as a security or licensing review.

When a file is copied or substantially adapted, it must carry the applicable
upstream copyright and a prominent provenance notice. The exact required
templates and the distinction from independently authored code are defined in
`specs/0002-source-provenance-and-file-headers.md`. The adapted Apache-2.0
form is:

```text
Copyright 2025 OpenAI
Copyright 2026 Mansur Azatbek
SPDX-License-Identifier: Apache-2.0

Originally derived from OpenAI Codex.
Upstream repository: https://github.com/openai/codex
Upstream path: codex-rs/<exact/path>
Upstream commit: <full 40-character commit SHA>
Modified and reorganized for Cageforge.
```

New Cageforge code that is not source-derived should use only its Cageforge
SPDX header. The header must not claim Apache-2.0 for a file that contains
third-party code under a different license.

## 5. Licensing policy

The intended license for Cageforge-authored code is Apache-2.0. Before the
first source-derived release, the repository must contain:

- a complete `LICENSE` file containing Apache License 2.0;
- a complete and accurate `NOTICE` file;
- `THIRD_PARTY_NOTICES.md` with attribution and license information for every
  bundled or source-derived third-party component;
- a `licenses/` directory for full third-party license texts when required;
- package-level `license`, `description`, `repository`, and `readme` metadata.

The Apache-2.0 obligations for derived Codex code include preserving relevant
copyright, patent, trademark, attribution, and NOTICE information, and marking
files that have been changed. Cageforge may add its own copyright notices and
may license its original additions under additional compatible terms, but it
must not remove or rewrite the applicable terms for derived portions.

If a release contains source-derived files, the root `NOTICE` must include an
attribution similar to:

```text
This project contains code derived from OpenAI Codex:
https://github.com/openai/codex

Copyright 2025 OpenAI.
The original code is licensed under the Apache License, Version 2.0.
The derived portions have been substantially refactored, renamed, and
reorganized for Cageforge.
This project is not affiliated with or endorsed by OpenAI.
```

The exact notice must be reviewed against the files actually included in each
release. Attribution that does not apply to a release should not be copied
into that release's notice.

## 6. Third-party components

Third-party components must remain separately identified. In particular:

- bundled bubblewrap code is LGPL-2.0-or-later and must retain its own
  license, copyright, source, and distribution obligations;
- Ratatui-derived code is MIT-licensed and must retain its attribution;
- transitive dependencies must be inventoried before producing binary
  distributions or vendored source archives.

The Linux backend should prefer a system bubblewrap when practical. If
Cageforge ships a bundled bubblewrap binary or compiles bubblewrap sources
into a helper, the release process must include the corresponding LGPL source
and notices. Cageforge must never represent bundled bubblewrap as wholly
Apache-2.0 code.

## 7. Architecture boundary

The workspace is planned as:

```text
cageforge-policy      platform-independent policy values and invariants
cageforge-config      TOML loading and named-profile resolution
cageforge-command     command, environment, and working-directory requests
cageforge-backend-api backend capability and execution contracts
cageforge-linux       bubblewrap, namespaces, seccomp, and Landlock support
cageforge-macos       Seatbelt policy generation and process launch
cageforge-windows     restricted tokens, ACLs, WFP, and Windows process launch
cageforge-core        ergonomic facade and backend selection
```

`cageforge-policy` is the first implementation crate. It is deliberately
smaller than the future facade and contains only platform-independent policy
semantics; it does not parse TOML or launch processes. The detailed first
policy model is specified in `specs/0006-policy-model.md`.

`cageforge-core` must not depend on Codex crates. The core API must not expose
Codex `PermissionProfile`, Codex network-proxy types, Codex PTY types, Codex
telemetry, or Codex-specific error and protocol structures.

Platform crates may depend on platform APIs and focused Rust dependencies, but
they must keep product-specific concerns out of the sandbox boundary. Network
proxying, PTY integration, telemetry, and harness-specific process lifecycle
should be optional adapters owned by the caller or separate integration crates.

## 8. Required policy model

The public API must make the security-relevant choices explicit. It should
model at least:

- command and working directory;
- readable, writable, and denied filesystem roots;
- network mode and explicit proxy endpoints, if supported;
- environment handling;
- TTY or pipe requirements as an integration concern;
- backend capability and unsupported-policy errors;
- process lifecycle and cancellation behavior.

Boolean or ambiguous positional options must be avoided in public APIs.
Configuration types should use named builders, enums, or dedicated option
types so call sites remain self-documenting.

## 9. Release and repository gates

No source-derived code should be published until all of the following are
complete:

1. The provenance mapping identifies the source path and baseline commit.
2. The applicable LICENSE, NOTICE, and third-party texts are present.
3. A license inventory has been reviewed for both source and binary releases.
4. Public APIs contain no accidental Codex-specific types or names.
5. Linux, macOS, and Windows CI cover the supported backend paths.
6. Security-sensitive changes have tests for both allowed and denied actions.
7. Package metadata and crate dependencies pass `cargo package --list` and
   `cargo publish --dry-run` when crates.io publication is intended.
8. The release notes identify material upstream-derived changes.

Git dependencies are acceptable during development. A crates.io release must
not rely on unpublished path-only or external Git dependencies; dependencies
intended for publication must have a publishable version strategy.

## 10. Initial decision

The project will begin as a separate `cageforge` Git repository beside the
Codex checkout. It will track upstream with Git, preserve provenance in
documentation and file headers, and implement a new independent public API.
The first implementation milestone is architecture and licensing scaffolding,
not bulk source copying.

## 11. First-commit policy

The first commit must be made only after the licensing scaffold has been
reviewed. Before that commit:

- the complete official Apache-2.0 text must be present in `LICENSE`;
- the applicable third-party license texts must be present under `licenses/`;
- `NOTICE`, `THIRD_PARTY_NOTICES.md`, and `UPSTREAM.md` must describe the
  intended provenance without claiming that unimported code is already
  included;
- the repository must contain no copied Codex or third-party implementation
  files;
- the project name and public API must remain independent from Codex and
  OpenAI branding.

Once source-derived files are imported, each import must be accompanied by an
upstream commit reference, a file-level modification notice where applicable,
and a review of the exact licenses that apply to that import. The project
must respect the original authors and licenses while remaining an independent
library with its own API, crate names, architecture, and documentation.
