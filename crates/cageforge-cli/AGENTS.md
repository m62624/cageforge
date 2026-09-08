# Cageforge CLI agent rules

Read the repository root `AGENTS.md` and all files it requires before making
changes. This crate is a thin command-line adapter over `cageforge`.

- Keep sandbox policy, path validation, composition, native lowering, process
  ownership, and network enforcement in the existing crates. Do not reimplement
  those mechanisms here.
- Require an explicit matching OS feature for native execution. Never fall
  back to an ordinary unsandboxed child when the feature or target is absent.
- Preserve native typed errors at the library boundary and keep CLI rendering
  separate from the execution protocol.
- Keep argv explicit after `--`; never parse shell strings or construct a
  shell implicitly.
- Keep `main.rs` a one-line adapter over testable library code, following the
  `plugmem-cli` shape.
- Prefer black-box tests in `tests/`; do not add public test-only helpers.
- Keep the README focused on practical CLI usage, explicit profile inputs,
  outputs, and links to the native backend READMEs. Do not add test inventories
  or implementation history there.
- Cageforge-authored Rust files use the SPDX-only header from the project
  provenance specification. This crate contains no Bubblewrap or other C
  source; those sources are build-only and must not be modified.
- Use conventional commits and do not bump versions for ordinary feature work.
