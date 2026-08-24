⚠️ **Independent project**

`cageforge-bwrap` builds the official upstream Bubblewrap executable used as
the optional bundled Linux resource for Cageforge. It keeps the Bubblewrap
implementation separate from Cageforge's Apache-2.0 Rust crates and produces
the `bwrap` binary for the target Linux architecture.

The source snapshot is Bubblewrap `0.11.2` at commit
`1b80120ef26a28e065e67f89bfef873f13bdd317`. Its original LGPL-2.0-or-later
notices are retained under `vendor/bubblewrap/` and the project license text is
recorded in `licenses/bubblewrap-COPYING`.

On Linux, the build requires a C compiler, `pkg-config`, and the development
files for `libcap`. Set `CAGEFORGE_BWRAP_SOURCE_DIR` to build from another
reviewed Bubblewrap source checkout; otherwise the pinned vendor snapshot is
used.

The resulting binary is staged by an application release builder into
`cageforge-resources/bwrap` next to the application. `cageforge-linux` then
validates the resource before using it as a fallback for a compatible system
Bubblewrap executable.
