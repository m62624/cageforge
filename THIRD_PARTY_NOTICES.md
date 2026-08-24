# Third-Party Notices

The workspace contains a separately identified Bubblewrap source component.
This file is a release gate and must be updated before additional
source-derived code or bundled binaries are distributed.

At minimum, the first source-derived release must account for:

- OpenAI Codex source-derived portions under the applicable Apache-2.0 terms;
- `crates/cageforge-bwrap/vendor/bubblewrap/` and binaries built from it under
  LGPL-2.0-or-later;
- all other bundled or vendored dependencies and their license texts.

Full third-party license texts should be stored under `licenses/` when they
are not already included with the corresponding source component.

The current repository includes the original LGPL-2.0 text at
`licenses/bubblewrap-COPYING`, and the source component retains its own
`COPYING`, `LICENSE`, copyright headers, README, and provenance record.

Bubblewrap upstream:
<https://github.com/containers/bubblewrap/tree/v0.11.2>
