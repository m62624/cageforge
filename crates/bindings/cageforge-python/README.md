> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

# Cageforge Python binding

`cageforge` provides a typed Python API for the Cageforge sandbox on Linux,
macOS, and Windows. It loads the selected profile and uses the native backend
provided by the installed wheel.

The package is built with PyO3 and maturin. The published package name is
`cageforge`.

Use the published [cageforge crate](https://crates.io/crates/cageforge) as the
project-level reference for the sandbox API.
See the shared [configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md)
for the complete Linux/macOS/Windows profile shape, including the resources a
first restricted launch must declare separately from local IPC.

## Install

```bash
python -m pip install cageforge
```

Each wheel contains the Python extension and the native resources for one
operating-system and architecture target. Linux wheels include the pinned
Bubblewrap resource. Applications do not need to install a separate native
helper or provide a host-specific resource path.

The release also includes free-threaded CPython 3.14 wheels for each supported
operating-system and architecture target. Standard CPython 3.10 and newer
builds use the stable `abi3` wheel for their platform.

## Quick start with the repository smoke profile

The repository already contains one runnable profile for each supported OS.
This example selects the profile for the current host and uses
`Cageforge.from_toml_file` to run it. Run it from the repository root:

```python
import platform
from pathlib import Path

from cageforge import Cageforge, PermissionApprover, RuntimeContext

platform_name = platform.system().lower()
profile_name = {
    "linux": "linux",
    "darwin": "macos",
    "windows": "windows",
}[platform_name]
profile = (
    Path("crates")
    / "cageforge-config"
    / "examples"
    / "runnable"
    / profile_name
    / "smoke.toml"
).resolve()

context = RuntimeContext(profile.parent)
toml = profile.read_bytes().decode("utf-8")
Cageforge.check_toml(toml, context=context)
request = Cageforge.permission_request(toml, context=context)
grant = PermissionApprover().approve(request)
with Cageforge.from_toml_file(
    profile, context=context, grant=grant, request=request
) as runtime:
    with runtime.launch() as process:
        print(process.read_stdout(4096).decode().strip())
        assert process.wait().exit_code == 0
```

The three profiles are [`linux/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/linux/smoke.toml),
[`macos/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/macos/smoke.toml),
and [`windows/smoke.toml`](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/runnable/windows/smoke.toml).
They use the current Cageforge TOML schema, include `minimal` read access,
declare a workspace root, allow writes to `workspace-root`, and disable the
network. The Windows profile uses `cmd.exe`; the POSIX profiles use `/bin/echo`.

Profiles with `approval.mode = "preflight"` require a trusted host grant before
launch. `PermissionRequest` is descriptive; only `PermissionApprover` can
issue the opaque `PermissionGrant`. A grant never changes an already-running
process.
When `permission_request` is called with custom identity or digest arguments,
pass that same `PermissionRequest` to `from_toml` or `from_toml_file`; the
runtime then authorizes the grant against the exact identity that was approved.

`PermissionRequest.local_ipc()` returns frozen typed `LocalIpcEndpoint` values.
Their `kind` is `unix_socket` or `windows_named_pipe`, and `value` is the
validated native endpoint. The platform overlay selects which endpoint kind
is present; a Windows named-pipe request remains fail-closed if the native
backend cannot prove the required isolation.

### Persistent grants and store paths

The permission store is host state, not TOML policy. Choose its absolute path
explicitly and use a persistent grant when the approval should survive a new
process:

```python
from pathlib import Path

from cageforge import PermissionApprover, PermissionStore

store = PermissionStore.open(Path("/var/lib/my-tool/permissions.json"))
toml = profile.read_bytes().decode("utf-8")
request = Cageforge.permission_request(toml, context=context)
grant = PermissionApprover().approve(request, scope="persistent")
store.put(grant, request)

cached = store.get(request)
assert cached is not None
with Cageforge.from_toml_file(
    profile, context=context, grant=cached, request=request
) as runtime:
    ...
```

`PermissionStore` protects the file with owner-only permissions on Unix and an
owner-only DACL on Windows. It uses a versioned JSON document, a kernel file
lock, and atomic replacement. A missing store record is not an
approval; preflight remains deny-by-default.

Persistent grants can be inspected and revoked by stable ID without exposing
their approved capability payload:

```python
page = store.list_page(page_size=50)
for summary in page.entries:
    print(summary.id, summary.tool_id)
if page.next_cursor is not None:
    page = store.list_page(page_size=50, cursor=page.next_cursor)

result = store.revoke(request.grant_id())
assert str(result) in {"revoked", "not-found"}
```

`GrantPageCursor` is opaque and becomes stale when the store changes. The
binding exposes stable store exception subclasses for invalid IDs, invalid
cursors, page size, stale cursors, lock, read, write, and format failures. All
digest and store validation is performed by the shared Rust implementation.

When `profile_name` is omitted, `Cageforge.from_toml` and `check_toml` use the
TOML document's `default_profile`. `Cageforge.from_toml_file` reads a file and
uses its parent directory as the default current directory. `RuntimeContext()`
uses the Python process directory and lets the native adapter provide the
platform's default minimal paths. Passing a path in `RuntimeContext` does not
grant access unless the selected profile contains the corresponding rule.

The `minimal` selector is symbolic. Linux adapters supply the executable and
loader paths needed by the selected backend, macOS supplies its system runtime
paths, and Windows supplies the system root and `System32` paths. Use the
separate files under
[`cageforge-config/examples/runnable/`](https://github.com/m62624/cageforge/tree/main/crates/cageforge-config/examples/runnable/)
when the command or path syntax is OS-specific.
The macOS `runtime.executable_roots` overlay is passed through the same
preflight request; its filesystem capabilities expose `map-executable`
separately from `read`.

## Processes, asyncio, and errors

`SandboxProcess` provides `try_wait`, `wait`, `wait_for`, `kill`, and `close`,
as well as `read_stdout`, `read_stderr`, `write_stdin`, and `close_stdin`. The
`wait_for` method is a compatibility alias for `wait`. Blocking native waits
and stream operations release the GIL.

For asyncio applications, `wait_for_async(process)` waits in a worker thread
so the event loop remains responsive. Cancelling the coroutine terminates the
process boundary and then propagates `asyncio.CancelledError`.

Configuration, initialization, launch, process, stream, and Windows setup
failures use typed exceptions under `CageforgeError`, including
`CageforgeConfigurationError`, `CageforgeLaunchError`, and
`CageforgeProcessError`:

```python
from cageforge import Cageforge, CageforgeConfigurationError

try:
    Cageforge.check_toml("not valid = [")
except CageforgeConfigurationError as error:
    print(f"invalid Cageforge configuration: {error}")
```

## Windows setup and native resources

Windows provisioning is explicit because installation can require UAC. Before
launching on Windows, an application can reconcile and verify the owner-scoped
setup:

```python
from cageforge import WindowsSetup

if WindowsSetup.is_supported():
    if WindowsSetup.status() != "ready":
        WindowsSetup.install()
    WindowsSetup.verify()
```

`install()` is the only operation in this sequence that may request elevation.
Creating a runtime does not silently install Windows components. Linux wheels
prefer a compatible system Bubblewrap and fall back to the bundled Bubblewrap
resource shipped in the wheel. macOS uses the packaged native helper.

## Development

From this directory, install maturin and the Python development tools, then
use `maturin develop`, `pytest`, `mypy --strict`, and `ruff check`. The committed
`_cageforge.pyi` stub is generated by running `cargo run --bin stub_gen` from
this crate directory. The Java and Python bindings share the same native policy
contract; binding-specific contract checks live with their respective tests.
