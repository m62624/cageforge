# Bubblewrap source provenance

This directory contains the unmodified source files required to build the
Bubblewrap executable used by Cageforge.

- Upstream repository: <https://github.com/containers/bubblewrap>
- Upstream tag: `v0.12.0`
- Upstream commit: `014a04330642e5c870418beb621532cb896e0002`
- License: LGPL-2.1-or-later
- Local changes: none

The source files retain their upstream copyright and SPDX headers. The source
snapshot includes `chroot_realpath.c` and `safe_openat.c`, which are required
by the v0.12.0 filesystem setup implementation. The full license text is
`COPYING`; `LICENSE` and `COPYING.LIB` are the corresponding upstream license
aliases. This third-party source is not Cageforge Apache-2.0 code.
