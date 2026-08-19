> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate provides independently authored native path semantics shared by
> Cageforge libraries.

# cageforge-path

`cageforge-path` centralizes the small set of path comparisons that must agree
across Cageforge crates. It treats path components case-sensitively on POSIX
systems and case-insensitively on Windows. Windows drive, UNC, verbatim, and
supported device aliases share one lexical identity; malformed native strings
remain distinct instead of passing through lossy Unicode conversion.

The crate does not access the filesystem, resolve symlinks, or canonicalize
paths. Native backends remain responsible for those operations.

## When to use it

Use this crate when your own code stores, compares, or validates paths and must
agree with Cageforge's policy and configuration layers. It is especially
useful for workspace-root maps, protected metadata paths, and component-aware
containment checks.

Do not use it as a filesystem sandbox by itself. It answers lexical questions
such as “is this path below that path?”; it does not prove that a file can be
opened safely. A native executor must add symlink, junction/reparse-point,
mount, and TOCTOU-safe enforcement.

## Workspace role

`cageforge-path` is the shared lexical path-semantics layer.

| Crate | Role in the relationship |
|---|---|
| `cageforge-policy` | Uses component-aware equality, containment, and path-pattern comparison. |
| `cageforge-command` | Validates command working-directory traversal. |
| `cageforge-config` | Validates configured workspace-root declarations. |
| `cageforge-policy-compose` | Deduplicates and compares effective workspace roots. |
| `cageforge-upstream-review` | Validates repository-relative review paths. |

The helpers define lexical relationships only. A backend still owns filesystem
I/O, symlink resolution, canonicalization, and platform capability checks.

## Case semantics

The following table is the single path-identity rule shared by the workspace.
It is not configurable through TOML or the Rust API.

| Value or operation | POSIX (Linux/macOS) | Windows |
|---|---|---|
| Absolute and workspace paths | Case-sensitive | Case-insensitive |
| `workspace_roots` | Case-sensitive | Case-insensitive |
| Protected paths such as `.git` | Case-sensitive | Case-insensitive |
| Unix socket paths | Case-sensitive | Case-insensitive path comparison |
| Filesystem glob components | Case-sensitive | Case-insensitive |
| Environment variable names and filters | Case-insensitive by policy | Case-insensitive by policy |
| Domain names and domain globs | Case-insensitive by protocol | Case-insensitive by protocol |
| Profile names and ordinary strings | Exact comparison | Exact comparison |

Only the filesystem-related rows use this crate's native path helpers. The
environment and domain rows intentionally have their own portable semantics.

## API

- `is_within(path, root)` checks component-aware containment and does not treat
  `/work-other` as a child of `/work`.
- `contains_component_path(path, needle)` finds a complete relative component
  path such as `.git` without matching a partial component such as `.github`.
- `paths_equal(left, right)` compares complete native path components.
- `NativePathKey` supplies the same equality, hashing, and ordering identity
  for maps and sets.
- `normalize_lexical_path(path)` exposes supported native alias normalization
  without filesystem access.
- `strings_equal(left, right)` and `case_fold(value)` expose the same native
  comparison rule for path-derived glob matching.
- `contains_parent_traversal(path)` detects lexical `..` components.

The helpers are used by policy evaluation, command working-directory
validation, policy composition, and the upstream-review tool so those layers
cannot silently develop different Windows behavior.

## Smallest useful example

```rust
use cageforge_path::{is_within, paths_equal, NativePathKey};
use std::path::Path;

let workspace = Path::new("/work/project");
assert!(is_within(Path::new("/work/project/src/lib.rs"), workspace));
assert!(!is_within(Path::new("/work/project-old"), workspace));
assert!(paths_equal(workspace, Path::new("/work/project")));

let _map_key = NativePathKey::new(workspace);
```

Most applications do not need a direct dependency on this crate: the policy,
command, config, and composition crates already use it internally. Depend on
it directly when an integration layer has to build its own native path maps or
make a comparison before handing values to those crates.

API reference: [`cageforge-path` on docs.rs](https://docs.rs/cageforge-path/latest/cageforge_path/).

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
