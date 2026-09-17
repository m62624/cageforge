> **Independent project:** Cageforge is not affiliated with, sponsored by, or
> endorsed by OpenAI. Its implementation and public API are independently
> authored; repository notices document upstream behavioral references.

# Cageforge Python binding

`cageforge` provides a typed Python facade over the Cageforge sandbox on Linux,
macOS, and Windows. It resolves the same TOML profiles as the Rust and JVM
integrations and uses the native backend selected by the installed wheel.

The package is built with PyO3 and maturin. The published package name is
`cageforge`.

## Install

```bash
python -m pip install cageforge
```

Each wheel contains the Python extension and the native resources for one
operating-system and architecture target. Linux wheels include the pinned
Bubblewrap resource. Applications do not need to install a separate native
helper or provide a host-specific resource path.

## Quick start with the repository smoke profile

The repository already contains one runnable profile for each supported OS.
This example selects the profile for the current host and uses
`Cageforge.from_toml_file` to run it. Run it from the repository root:

```python
import platform
from pathlib import Path

from cageforge import Cageforge, RuntimeContext

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
Cageforge.check_toml(profile.read_text(), context=context)
with Cageforge.from_toml_file(profile, context=context) as runtime:
    with runtime.launch() as process:
        print(process.read_stdout(4096).decode().strip())
        assert process.wait().exit_code == 0
```

The three profiles are [`linux/smoke.toml`](../../cageforge-config/examples/runnable/linux/smoke.toml),
[`macos/smoke.toml`](../../cageforge-config/examples/runnable/macos/smoke.toml),
and [`windows/smoke.toml`](../../cageforge-config/examples/runnable/windows/smoke.toml).
They use the current Cageforge TOML schema, include `minimal` read access,
declare a workspace root, allow writes to `workspace-root`, and disable the
network. The Windows profile uses `cmd.exe`; the POSIX profiles use `/bin/echo`.

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
[`cageforge-config/examples/runnable/`](../../cageforge-config/examples/runnable/)
when the command or path syntax is OS-specific.

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
contract; their API parity checks live with the binding tests.
