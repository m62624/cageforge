> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate provides independently authored native path semantics shared by
> Cageforge libraries.

# cageforge-path

`cageforge-path` centralizes the small set of path comparisons that must agree
across Cageforge crates. It treats path components case-sensitively on POSIX
systems and case-insensitively on Windows, while keeping parent traversal
checks lexical and platform-neutral.

The crate does not access the filesystem, resolve symlinks, or canonicalize
paths. Native backends remain responsible for those operations.

## API

- `is_within(path, root)` checks component-aware containment and does not treat
  `/work-other` as a child of `/work`.
- `paths_equal(left, right)` compares complete native path components.
- `strings_equal(left, right)` and `case_fold(value)` expose the same native
  comparison rule for path-derived glob matching.
- `contains_parent_traversal(path)` detects lexical `..` components.

The helpers are used by policy evaluation, command working-directory
validation, policy composition, and the upstream-review tool so those layers
cannot silently develop different Windows behavior.

API reference: [`cageforge-path` on docs.rs](https://docs.rs/cageforge-path/latest/cageforge_path/).

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
