> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> binding is an independent JVM adapter over Cageforge's public sandbox API.

# Cageforge Java binding

JVM binding for the [`cageforge`](https://crates.io/crates/cageforge) Rust crate.

The binding provides the Cageforge API to Java and Kotlin/JVM desktop
applications on Linux, macOS, and Windows. Detailed sandbox policy remains in
Cageforge TOML configuration; the JVM layer provides the API for loading a
profile, launching a command, and managing its process.

The shared [configuration guide](../../cageforge-config/examples/CONFIGURATION_GUIDE.md)
shows the separate runnable TOML profiles and explains how `minimal` is
resolved on each operating system.

## Maven artifact

```text
io.github.m62624:cageforge-java:<version>
```

The same artifact can be used from Java and Kotlin/JVM. Android and Kotlin/
Native are not supported by this binding.

## Kotlin example

```kotlin
val sandbox = Cageforge.fromTomlFile(configPath)
try {
    sandbox.launch(listOf("python", "task.py")).use { process ->
        process.stdout?.bufferedReader()?.useLines { lines ->
            lines.forEach(::println)
        }
        check(process.waitFor().exitCode == 0)
    }
} finally {
    sandbox.close()
}
```

The same JVM-compatible classes are available from Java. Commands are passed
as an argument list, and the selected TOML profile controls filesystem,
network, environment, timeout, and standard-stream policy.

The profile must explicitly allow the symbolic `minimal` read scope when the
command needs the platform runtime. The binding supplies the platform path in
its `RuntimeContext`; passing a path without the corresponding TOML rule does
not grant access. Use the host-specific file under
`cageforge-config/examples/runnable/` rather than copying a Windows command
into a POSIX application or vice versa.

## Native resources

The JAR contains the JNI library and Cageforge native resources for the
supported OS and architecture combinations under:

```text
META-INF/native/<os>-<arch>/
```

At runtime the loader selects the current platform, verifies the extracted
resources, and loads the matching native library. Linux resources include the
reviewed Bubblewrap asset used by Cageforge when a compatible system binary is
not available.

The Gradle project is under [`jvm/`](jvm/). Run `gradle check ktlintCheck` for
the JVM checks and `gradle verifyNativeBundle` after assembling native
resources.
