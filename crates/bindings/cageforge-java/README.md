> **Independent project:** Cageforge is not affiliated with, sponsored by, or
> endorsed by OpenAI. Its implementation and public API are independently
> authored; repository notices document upstream behavioral references.

# Cageforge Java binding

`cageforge-java` exposes the Cageforge sandbox to Java and Kotlin/JVM desktop
applications on Linux, macOS, and Windows. It loads a TOML profile, supplies the
host paths that the profile leaves symbolic, launches a command, and manages
the complete descendant process boundary.

The binding uses the same policy and native backends as the Rust facade. The
platform-specific configuration files and the meaning of `minimal` are covered
in the shared [configuration guide](../../cageforge-config/examples/CONFIGURATION_GUIDE.md).

## Install

The published Maven coordinate is:

```text
io.github.m62624:cageforge-java:<version>
```

For Gradle Kotlin DSL:

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("io.github.m62624:cageforge-java:<version>")
}
```

The same artifact is available to Java and Kotlin/JVM applications. Android
and Kotlin/Native are outside this binding's supported runtime targets.

## Quick start with the repository smoke profile

The repository already contains one runnable profile for each supported OS.
This example selects the profile for the current host and uses
`Cageforge.fromTomlFile` to run it. Run it from the repository root:

```kotlin
import ai.cageforge.Cageforge
import ai.cageforge.RuntimeContext
import java.nio.file.Files
import java.nio.file.Path

val os = System.getProperty("os.name").lowercase()
val platform = when {
    os.contains("windows") -> "windows"
    os.contains("mac") -> "macos"
    else -> "linux"
}
val profile = Path.of(
    "crates", "cageforge-config", "examples", "runnable", platform, "smoke.toml",
).toAbsolutePath()

val config = Files.readString(profile)
val context = RuntimeContext(profile.parent)
Cageforge.checkToml(config, context = context)

Cageforge.fromTomlFile(profile, context = context).use { sandbox ->
    sandbox.launch().use { process ->
        process.stdout?.bufferedReader()?.use { reader ->
            print(reader.readText())
        }
        check(process.waitFor().exitCode == 0)
    }
}
```

The three profiles are [`linux/smoke.toml`](../../cageforge-config/examples/runnable/linux/smoke.toml),
[`macos/smoke.toml`](../../cageforge-config/examples/runnable/macos/smoke.toml),
and [`windows/smoke.toml`](../../cageforge-config/examples/runnable/windows/smoke.toml).
They use the current Cageforge TOML schema, include `minimal` read access,
declare a workspace root, allow writes to `workspace-root`, and disable the
network. The Windows profile uses `cmd.exe`; the POSIX profiles use `/bin/echo`.

`Cageforge.fromToml` uses the named `default_profile` when no profile name is
provided. Pass `profileName` when an application needs another profile.
`Cageforge.fromTomlFile` reads a TOML file and, by default, uses that file's
parent directory as the current directory. `RuntimeContext()` otherwise uses
the JVM process directory and lets the native adapter provide the platform's
default minimal paths.

The `minimal` selector is symbolic. It does not contain a universal path in
TOML; the native adapter supplies paths such as `/usr` and `/bin` on Linux or
the system runtime directories on Windows. A path in `RuntimeContext` does not
grant access unless the selected profile contains the matching filesystem rule.

## Process and error handling

`SandboxProcess` provides `tryWait`, `waitFor`, `waitForAsync`, `kill`, and
`close`, plus nullable `stdin`, `stdout`, and `stderr` streams. The standard
streams are captured by default. `waitForAsync()` uses the JVM common pool when
no executor is supplied; applications can pass a bounded executor of their own.
Cancelling the returned future terminates the process boundary.

Configuration, initialization, launch, process, stream, and Windows setup
failures use typed subclasses of `CageforgeException`, including
`CageforgeConfigurationException`, `CageforgeLaunchException`, and
`CageforgeProcessException`.

## Windows setup and native resources

Windows provisioning is explicit because installation can require UAC. An
application can inspect and reconcile the owner-scoped setup before launching:

```kotlin
import ai.cageforge.WindowsSetup
import ai.cageforge.WindowsSetupState

if (WindowsSetup.isSupported()) {
    if (WindowsSetup.status() != WindowsSetupState.READY) {
        WindowsSetup.install()
    }
    WindowsSetup.verify()
}
```

`install()` is the only operation in this sequence that may request elevation.
Runtime creation does not silently install Windows components. On Linux, the
binding prefers a compatible system Bubblewrap and can use the bundled
Bubblewrap resource included in the Linux native bundle. macOS uses the
packaged native helper.

The JAR contains the JNI library and native resources for each supported OS and
architecture under:

```text
META-INF/native/<os>-<arch>/
```

The loader selects the matching directory at runtime, verifies its resources,
and extracts them to a process-owned cache directory. Applications do not need
to hard-code a Linux, macOS, or Windows path.

The Gradle project is under [`jvm/`](jvm/). Its Java and Kotlin API uses the
same native policy contract as the Python binding while keeping each language's
normal naming and error conventions.
