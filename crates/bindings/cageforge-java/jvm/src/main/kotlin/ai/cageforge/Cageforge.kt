// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.io.Closeable
import java.nio.file.Files
import java.nio.file.Path

/** JVM facade over one reusable native Cageforge backend and resolved profile. */
class Cageforge private constructor(
    private var handle: Long,
    private val nativeDirectory: Path,
) : Closeable {
    private val lifecycleLock = Any()

    /** Launches the profile command, or an explicit argv when supplied. */
    @JvmOverloads
    fun launch(argv: List<String> = emptyList()): SandboxProcess =
        synchronized(lifecycleLock) {
            checkOpen()
            val process = NativeBridge.nativeLaunch(handle, argv.toTypedArray())
            if (process == 0L) throw CageforgeException("Cageforge returned an invalid process handle")
            SandboxProcess.fromHandle(process)
        }

    /** Releases the native backend. Active processes must be closed first. */
    override fun close() =
        synchronized(lifecycleLock) {
            if (handle != 0L) {
                val value = handle
                handle = 0L
                NativeBridge.nativeCloseRuntime(value)
            }
        }

    private fun checkOpen() {
        if (handle == 0L) throw CageforgeException("Cageforge runtime is closed")
    }

    companion object {
        init {
            // Loading happens lazily in factory methods so applications that
            // only inspect configuration do not load an OS-specific library.
        }

        /** Creates a runtime from TOML and the selected profile. */
        @JvmStatic
        @JvmOverloads
        fun fromToml(
            toml: String,
            profileName: String? = null,
            context: RuntimeContext = RuntimeContext(),
        ): Cageforge {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            val directory = NativeLoader.load()
            val handle =
                NativeBridge.nativeCreate(
                    toml,
                    profileName,
                    context.currentDirectory.toString(),
                    directory.toString(),
                )
            if (handle == 0L) throw CageforgeException("Cageforge runtime creation failed")
            return Cageforge(handle, directory)
        }

        /** Returns the native resource target selected by this JVM. */
        @JvmStatic
        fun nativeTarget(): String = NativeLoader.targetId()

        /** Creates a runtime by reading a TOML file through the JVM. */
        @JvmStatic
        @JvmOverloads
        fun fromTomlFile(
            file: Path,
            profileName: String? = null,
            context: RuntimeContext = RuntimeContext(file.toAbsolutePath().parent ?: Path.of(".")),
        ): Cageforge = fromToml(Files.readString(file), profileName, context)
    }
}
