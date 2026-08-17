# Specification 0005: Source Provenance and File Headers

Status: accepted

## Principle

License attribution follows actual code lineage, not architectural similarity.
The fact that Cageforge implements the same sandbox concepts as Codex does not
make every Cageforge file source-derived. New Cageforge implementations keep
the Cageforge copyright and SPDX header only. Codex is referenced in project
provenance documents and audit records, not artificially attached to unrelated
files.

This policy is an engineering provenance rule, not a substitute for a legal
review of a release.

## Header for new Cageforge-authored files

Use this for code designed and implemented in Cageforge without copying or
substantially adapting a specific upstream file:

```text
// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0
```

The year and copyright holder must be updated when appropriate. No OpenAI or
Codex reference belongs in this header.

## Header for adapted Apache-2.0 Codex files

When a file contains copied or substantially adapted Codex implementation,
retain every applicable upstream copyright and license notice, then add the
Cageforge modification and provenance record:

```text
// Copyright 2025 OpenAI
// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0
//
// Originally derived from OpenAI Codex.
// Upstream repository: https://github.com/openai/codex
// Upstream path: codex-rs/<exact/path>
// Upstream commit: <full 40-character commit SHA>
// Modified and reorganized for Cageforge.
```

If the upstream file has additional authors or copyright holders, preserve
those notices too. If the file combines several upstream files, list every
material upstream path. If the original contains a full license boilerplate,
do not replace it with this short header; preserve the original boilerplate and
add the provenance lines alongside it.

The phrase “OpenAI Codex” is used only to describe origin. It is not Cageforge
branding and must not imply affiliation, sponsorship, or endorsement.

## Header for other third-party code

Third-party code keeps its own license and copyright. For bundled bubblewrap,
retain the applicable LGPL-2.0-or-later notices and use a matching SPDX
identifier; never label that source as wholly Apache-2.0. The same rule applies
to any future MIT, BSD, or other third-party component.

## File classification before import

Before adding a source-derived file, record in `UPSTREAM.md`:

1. the exact upstream repository and commit;
2. the upstream path and Cageforge destination;
3. the applicable license and copyright holders;
4. whether the file is copied, substantially adapted, or independently
   reimplemented;
5. the material Cageforge changes.

Only copied or substantially adapted files receive the adapted-file header.
An independent reimplementation may cite the upstream audit in documentation,
but must not claim false line-level derivation.

## Release checks

Before distribution, verify that:

- every adapted file has a path and commit that resolve in `UPSTREAM.md`;
- all applicable upstream notices remain in the root `NOTICE` or the relevant
  package notice;
- the package license metadata matches the actual source composition;
- mixed-license crates identify their components separately;
- no source-derived attribution is included for files that do not contain
  source-derived code.
