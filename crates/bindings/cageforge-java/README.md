// SPDX-License-Identifier: Apache-2.0

> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> binding is an independent JVM adapter over Cageforge's public sandbox API.

# Cageforge Java binding

The Cageforge Java binding provides a JVM API for launching commands through
the same native sandbox boundary used by Cageforge applications. It supports
Java and Kotlin/JVM desktop applications on Linux, macOS, and Windows.

The public artifact is built from the `jvm` project and is intended for Maven
publication. The Rust package in this directory is an internal `publish =
false` JNI implementation; applications depend on the JVM artifact rather
than on this Cargo package.

The Maven coordinates are `io.github.m62624:cageforge-java:<version>`. The
Java package names remain `ai.cageforge`; the Maven group and Java package
namespace are independent concepts.

`Cageforge.profileNames(toml)` exposes the resolver's deterministic profile
list, and `Cageforge.checkToml(toml, profileName, context)` validates parsing,
inheritance resolution, path context, and policy composition without launching
a command. Both operations use the Rust Cageforge TOML implementation.

## Basic usage

```kotlin
val sandbox = Cageforge.fromTomlFile(configPath)
try {
    sandbox.launch(listOf("python", "task.py")).use { process ->
        process.stdout?.bufferedReader()?.useLines { lines -> lines.forEach(::println) }
        val result = process.waitFor()
        check(result.exitCode == 0)
    }
} finally {
    sandbox.close()
}
```

The TOML document remains the source of truth for detailed filesystem,
network, environment, timeout, inheritance, and profile policy. The JVM API
only supplies the selected profile, explicit argv, and runtime current
directory needed to resolve symbolic paths. Commands are passed as an argv
vector; shell syntax is not parsed implicitly.
The resolved `command.stdio` setting is preserved: `stdin`, `stdout`, and
`stderr` are non-null only when the corresponding stream is configured as
`pipe`; `inherit` and `null` intentionally expose no JVM stream.

The same classes are callable from Java. `Cageforge.fromToml`,
`Cageforge.fromTomlFile`, `Cageforge.launch`, and the `WindowsSetup`
`install`/`status`/`verify`/`uninstall` operations have
JVM-friendly static/bean-compatible entry points. Windows installation invokes
the native Cageforge setup path and may display the standard UAC prompt. The
explicit `WindowsSetup` operations are available on every JVM classpath. Use
`WindowsSetup.isSupported()` for a family-level platform check; it covers
Windows releases without enumerating version numbers. Calling `install` or
`uninstall` on Linux or macOS throws `UnsupportedPlatformException`
immediately, before native loading, and does not terminate the host process.

## Concurrency and blocking operations

Independent `Cageforge` runtimes and `SandboxProcess` instances can be used
concurrently. The binding does not install a JVM-wide execution monitor or a
GIL-equivalent lock. A short one-time loader lock may serialize native resource
extraction and `System.load`; it is released before runtime creation and never
surrounds launch, wait, stream, or kill operations. Synchronization after
loading is scoped to the individual native handle, so one runtime does not
serialize unrelated runtimes.

The JVM facade also serializes lifecycle access for one object while an
operation is in progress. This prevents `close` from reclaiming a raw JNI
handle during a native call; it does not serialize independent runtimes or
processes. Consequently, `kill` on the same process may wait for an already
running blocking operation to return, while `waitForAsync` keeps the caller's
thread responsive.

`waitFor`, and reads from `stdout` or `stderr`, are blocking operations. Do not
call them on a Swing or JavaFX event-dispatch thread. Use `waitForAsync` with
the common pool or an application-owned executor, and consume blocking streams
from a worker or coroutine dispatcher. `tryWait` is the non-blocking lifecycle
operation.

The native Cageforge backends may use short-lived internal mutexes, semaphores,
and helper threads for gateway, timeout, and boundary bookkeeping. Those are
implementation details of the native backend, not locks held by the JVM API;
they do not create a process-wide Java lock. Long native waits must still be
invoked from a worker when the caller needs a responsive UI.

Cageforge currently provides memory and IPC isolation as part of its native
boundaries, but it does not define a portable RAM, CPU, process-count,
thread-count, disk, or bandwidth quota. The JVM binding exposes every such
resource control that Cageforge actually provides and does not invent a
nonexistent `memoryLimit` API; adding quotas requires a separate native
cross-platform contract.

## Native packaging

The Maven artifact contains the JNI library and the native Cageforge helper
resources for the supported OS/architecture combinations. Linux entries also
contain Cageforge's reviewed Bubblewrap executable and its `bwrap.sha256`
manifest. At runtime Cageforge follows its normal `system-then-bundled`
selection: it uses a compatible system `bwrap` first and the verified JAR
resource only when needed. The JVM loader selects the current target, verifies
any existing cache entry against the resource digest, extracts the selected
files into a versioned cache, and loads the JNI library. The Rust layer
receives the explicit helper/resource directory, so it never mistakes the JVM
executable for a Cageforge helper.

The JAR also carries the project notice and third-party Bubblewrap license
files because the bundled Linux resource contains the reviewed Bubblewrap
implementation.

Build the native resources for the six target combinations, place them under
the `META-INF/native/<os>-<arch>/` layout, and run the Gradle
`verifyNativeBundle` task before publishing. The release workflow publishes
the signed publication to the Central Portal OSSRH Staging API after the
native bundle has passed CI. The release credential contract is defined in
Specification 0020; credentials must never be committed to this repository.
