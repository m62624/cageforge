# Third-Party Notices

The initial Cageforge workspace contains no copied third-party implementation
code. This file is a release gate and must be updated before source-derived
code or bundled binaries are distributed.

At minimum, the first source-derived release must account for:

- OpenAI Codex source-derived portions under the applicable Apache-2.0 terms;
- bundled bubblewrap source or binaries under LGPL-2.0-or-later;
- Ratatui-derived portions under MIT only if any are actually retained;
- all other bundled or vendored dependencies and their license texts.

Full third-party license texts should be stored under `licenses/` when they
are not already included with the corresponding source component.

The current repository includes the official LGPL-2.0 text at
`licenses/bubblewrap-COPYING` as a prepared notice for the planned bundled
bubblewrap component. It does not by itself mean that bubblewrap source is
already included in this scaffold.
