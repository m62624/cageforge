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
        /** Returns validated profile names in deterministic lexical order. */
        @JvmStatic
        fun profileNames(toml: String): List<String> {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            NativeLoader.load()
            return NativeBridge.nativeProfileNames(toml).toList()
        }

        /** Checks TOML parsing, profile resolution, and policy composition. */
        @JvmStatic
        @JvmOverloads
        fun checkToml(
            toml: String,
            profileName: String? = null,
            context: RuntimeContext = RuntimeContext(),
        ) {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            NativeLoader.load()
            NativeBridge.nativeCheckToml(
                toml,
                profileName,
                context.currentDirectory.toString(),
                context.minimalPath?.toString(),
            )
        }

        /** Returns the shared typed preflight request for a TOML profile. */
        @JvmStatic
        @JvmOverloads
        fun permissionRequest(
            toml: String,
            profileName: String? = null,
            context: RuntimeContext = RuntimeContext(),
            toolId: String = "cageforge-java",
            toolVersion: String? = null,
            manifestDigest: String? = null,
            configDigest: String? = null,
        ): PermissionRequest {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            val handle =
                NativeBridge.nativePermissionRequest(
                    toml,
                    profileName,
                    context.currentDirectory.toString(),
                    context.minimalPath?.toString(),
                    toolId,
                    toolVersion,
                    manifestDigest,
                    configDigest,
                )
            if (handle == 0L) throw CageforgeException("Cageforge permission request failed")
            try {
                return PermissionRequest(
                    handle = handle,
                    json = NativeBridge.nativePermissionRequestJson(handle),
                    toolId = NativeBridge.nativePermissionRequestToolId(handle),
                    toolVersion = NativeBridge.nativePermissionRequestToolVersion(handle),
                    platform = NativeBridge.nativePermissionRequestPlatform(handle),
                    digest = NativeBridge.nativePermissionRequestDigest(handle),
                    filesystemValues = NativeBridge.nativePermissionRequestFilesystem(handle),
                    network = NativeBridge.nativePermissionRequestNetwork(handle).toList(),
                )
            } catch (error: Throwable) {
                NativeBridge.nativeClosePermissionRequest(handle)
                throw error
            }
        }

        /** Creates a runtime from TOML and the selected profile. */
        @JvmStatic
        @JvmOverloads
        fun fromToml(
            toml: String,
            profileName: String? = null,
            context: RuntimeContext = RuntimeContext(),
            grant: PermissionGrant? = null,
        ): Cageforge {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            val directory = NativeLoader.load()
            val handle =
                NativeBridge.nativeCreate(
                    toml,
                    profileName,
                    context.currentDirectory.toString(),
                    directory.toString(),
                    context.minimalPath?.toString(),
                    grant?.handle ?: 0L,
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
            grant: PermissionGrant? = null,
        ): Cageforge = fromToml(Files.readString(file), profileName, context, grant)
    }
}
