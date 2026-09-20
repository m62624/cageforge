// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.io.Closeable
import java.nio.file.Files
import java.nio.file.Path

/** JVM facade over one reusable native Cageforge backend and resolved profile. */
class Cageforge private constructor(
    handle: Long,
    private val nativeDirectory: Path,
) : Closeable {
    private val native =
        NativeHandle(
            handle,
            NativeBridge::nativeCloseRuntime,
            { CageforgeException("Cageforge runtime is closed") },
        )

    /** Launches the profile command, or an explicit argv when supplied. */
    @JvmOverloads
    fun launch(argv: List<String> = emptyList()): SandboxProcess =
        native.use { handle ->
            val process = NativeBridge.nativeLaunch(handle, argv.toTypedArray())
            if (process == 0L) throw CageforgeException("Cageforge returned an invalid process handle")
            SandboxProcess.fromHandle(process)
        }

    /** Launches a native sandbox child through the standard Java `Process` API. */
    @JvmOverloads
    fun launchProcess(argv: List<String> = emptyList()): CageforgeProcess = launch(argv).asJavaProcess()

    /** Creates additional permissions for a future sandbox relaunch. */
    fun requestEscalation(
        filesystem: List<Pair<String, String>>,
        network: List<String>,
        reason: String,
    ): PermissionEscalationRequest {
        val handle =
            native.use { runtime ->
                NativeBridge.nativeRequestPermissionEscalation(
                    runtime,
                    filesystem.flatMap { listOf(it.first, it.second) }.toTypedArray(),
                    network.toTypedArray(),
                    reason,
                )
            }
        if (handle == 0L) throw CageforgeEscalationException("Cageforge escalation request failed")
        return try {
            PermissionEscalationRequest(
                handle = handle,
                json = NativeBridge.nativePermissionEscalationJson(handle),
                reason = NativeBridge.nativePermissionEscalationReason(handle),
                filesystemValues = NativeBridge.nativePermissionEscalationFilesystem(handle),
                network = NativeBridge.nativePermissionEscalationNetwork(handle).toList(),
            )
        } catch (error: Throwable) {
            NativeBridge.nativeClosePermissionEscalation(handle)
            throw error
        }
    }

    /** Relaunches the profile in a new sandbox authorized by an escalation. */
    @JvmOverloads
    fun launchEscalated(
        escalation: PermissionEscalationRequest,
        grant: PermissionGrant,
        argv: List<String> = emptyList(),
    ): SandboxProcess {
        val process =
            native.use { runtime ->
                escalation.useNative { escalationHandle ->
                    grant.useNative { grantHandle ->
                        NativeBridge.nativeLaunchEscalated(
                            runtime,
                            escalationHandle,
                            grantHandle,
                            argv.toTypedArray(),
                        )
                    }
                }
            }
        if (process == 0L) throw CageforgeEscalationException("Cageforge escalated launch failed")
        return SandboxProcess.fromHandle(process)
    }

    /** Releases the native backend. Active processes must be closed first. */
    override fun close() = native.close()

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
                    grantId = GrantId.fromHex(NativeBridge.nativePermissionRequestGrantId(handle)),
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
            request: PermissionRequest? = null,
        ): Cageforge {
            require(toml.isNotEmpty()) { "TOML must not be empty" }
            val directory = NativeLoader.load()

            fun create(
                grantHandle: Long,
                requestHandle: Long,
            ): Long =
                NativeBridge.nativeCreate(
                    toml,
                    profileName,
                    context.currentDirectory.toString(),
                    directory.toString(),
                    context.minimalPath?.toString(),
                    grantHandle,
                    requestHandle,
                )
            val handle =
                grant?.useNative { grantHandle ->
                    request?.useNative { requestHandle ->
                        create(grantHandle, requestHandle)
                    } ?: create(grantHandle, 0L)
                } ?: request?.useNative { requestHandle ->
                    create(0L, requestHandle)
                } ?: create(0L, 0L)
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
            request: PermissionRequest? = null,
        ): Cageforge {
            try {
                return fromToml(Files.readString(file), profileName, context, grant, request)
            } catch (error: CageforgeConfigurationException) {
                if (error.configPath != null) throw error
                throw CageforgeConfigurationException(
                    error.message ?: "configuration error",
                    error.code,
                    file.toAbsolutePath().toString(),
                    error.profile,
                    error.platform,
                    error.field,
                    error.line,
                    error.column,
                )
            }
        }
    }
}
