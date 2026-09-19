# Specification 0021: Cageforge Python Binding and Version Contract

Status: implementation contract

## 1. Purpose and package boundary

The `cageforge-python` workspace package provides the published `cageforge`
CPython package. It is a PyO3 adapter over the public Cageforge facade and
uses the native backend selected by the installed target resource. Policy
parsing, composition, capability negotiation, and native enforcement remain
owned by the Cageforge crates; Python is not a second policy implementation.

The binding supports CPython on Linux, macOS, and Windows. PyPy, Jython,
IronPython, and non-CPython interpreter ABIs are outside this contract.

## 2. Interpreter and ABI contract

The package metadata declares `requires-python = ">=3.10"`. This is the
minimum supported interpreter for the public package and the lower bound used
by PyO3's stable `abi3-py310` extension ABI.

The release matrix produces two wheel forms for every supported operating
system and architecture:

| Wheel form | Supported interpreter contract | Purpose |
| --- | --- | --- |
| `abi3` | CPython 3.10 and newer | Stable limited-API wheel for ordinary CPython releases |
| `cp314t` | Free-threaded CPython 3.14t | Native free-threaded build without the GIL |

The free-threaded wheel is built from an explicitly installed CPython 3.14t
of the matrix architecture. It is not inferred from the runner's default
interpreter. A free-threaded build must not be presented as evidence that the
ordinary ABI3 wheel has no GIL; they are separate interpreter/ABI artifacts.

The binding must release the GIL around blocking native waits, process
termination, and standard-stream I/O. The native Rust implementation must
not retain a Python callback, Python lock, or GIL while waiting for a child,
performing blocking I/O, or entering another foreign-language boundary.

## 3. Version source and package identity

The Cargo workspace version is the single release version for
`cageforge-python`. `Cargo.toml` uses `version.workspace = true`, while
`pyproject.toml` declares a dynamic Python version so maturin reads the same
Cargo package version. The Python project name and import package are both
`cageforge`; the internal Cargo package remains `cageforge-python`.

The release workflow builds the sdist and all wheels from the tested release
tag. It must reject a missing or inconsistent version rather than introducing
a Python-only fallback. The wheel and sdist metadata therefore identify the
same version as the workspace release.

## 4. Native resource layout

Each wheel contains exactly one target-specific resource directory:

```text
cageforge/native/<os>-<architecture>/
```

Linux resources contain the JNI-independent Python extension, the Linux
helper, the reviewed Bubblewrap executable, its SHA-256 manifest, and the
Bubblewrap license notice. macOS resources contain the extension and Seatbelt
helper. Windows resources contain the extension and the owner-scoped setup
and command-runner helpers. A wheel must not contain resources for another
target or an accidental nested `native/native` directory.

The source distribution contains source, metadata, generated stubs, and
license/attribution files but no target-specific native resources. A clean
machine builds or installs the native artifact from the declared package
inputs; it does not depend on a development checkout's resource path.

## 5. Public error and lifecycle contract

Expected failures are exposed through the structured `CageforgeError`
hierarchy: configuration, initialization, launch, permission, process,
stream, Windows setup, and unsupported-platform failures retain stable Python
exception categories. A Rust panic must never cross the PyO3 boundary.

`PermissionRequest`, `PermissionGrant`, and `PermissionStore` preserve the
same identity, grant, persistence, and closed-handle semantics as the Rust
facade. `SandboxProcess` owns the native child boundary and exposes Pythonic
wait, status, termination, and stream operations; blocking methods release
the GIL. Async waiting delegates to a worker without polling from the Python
event loop, and cancellation terminates the native boundary.

Local IPC follows the shared contract in Specification 0023. Python receives
validated endpoint objects and the same platform-overlay behavior as Rust:
absolute Unix-socket paths on Linux/macOS and named-pipe names on Windows.
Unsupported endpoint kinds and native setup failures use stable exception
categories before child creation; Python does not encode transports as an
unvalidated string or widen a denied network policy.

## 6. Validation contract

Every target row runs Rust formatting, Clippy, stub generation, strict mypy,
Ruff, and Python tests. macOS and Windows rows execute native smoke tests
with the resources staged for that exact runner. Linux additionally passes
the tested wheel through the disposable QEMU/KVM consumer suite. Release
validation audits wheel members, target isolation, ABI tags, license files,
and the sdist member set before trusted PyPI publication.
The native smoke rows execute the matching checked-in runnable TOML profile;
the configuration crate separately parses and resolves every other example
without treating illustrative or host-specific profiles as universal launch
commands.

The generated `_cageforge.pyi` file is a checked-in release artifact. Any
public binding change must regenerate it and fail CI if the committed stub is
out of date.

## 7. Relationship to other specifications

This specification depends on the portable command, configuration, facade,
backend, native safety, and local IPC contracts in Specifications 0008-0019
and 0023. It defines the Python ABI and distribution boundary only; native
security behavior stays in the selected Linux, macOS, or Windows backend
specification.
