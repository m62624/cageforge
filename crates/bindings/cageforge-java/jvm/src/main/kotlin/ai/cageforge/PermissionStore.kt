// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.nio.file.Path

/** Host-owned persistent store for exact preflight grants. */
class PermissionStore private constructor(
    handle: Long,
    val path: Path,
) : AutoCloseable {
    private val native =
        NativeHandle(
            handle,
            NativeBridge::nativeClosePermissionStore,
            { CageforgePermissionException("Cageforge permission store is closed") },
        )

    /** Returns a persisted grant for the exact request, or null when absent. */
    fun get(request: PermissionRequest): PermissionGrant? {
        val grant =
            native.use { storeHandle ->
                request.useNative { requestHandle ->
                    NativeBridge.nativePermissionStoreGet(storeHandle, requestHandle)
                }
            }
        if (grant == 0L) return null
        return try {
            PermissionGrant(
                handle = grant,
                requestDigest = NativeBridge.nativePermissionGrantRequestDigest(grant),
                scope = NativeBridge.nativePermissionGrantScope(grant),
                expiresAt = NativeBridge.nativePermissionGrantExpiresAt(grant).takeUnless { it < 0 },
            )
        } catch (error: Throwable) {
            NativeBridge.nativeClosePermissionGrant(grant)
            throw error
        }
    }

    /** Persists a grant after native validation against the exact request. */
    fun put(
        grant: PermissionGrant,
        request: PermissionRequest,
    ) {
        native.use { storeHandle ->
            grant.useNative { grantHandle ->
                request.useNative { requestHandle ->
                    NativeBridge.nativePermissionStorePut(storeHandle, grantHandle, requestHandle)
                }
            }
        }
    }

    override fun close() = native.close()

    companion object {
        /** Opens or creates a host-owned store at an absolute path. */
        @JvmStatic
        fun open(path: Path): PermissionStore {
            if (!path.isAbsolute) {
                throw CageforgeConfigurationException("permission store path must be absolute: $path")
            }
            NativeLoader.load()
            val handle = NativeBridge.nativeOpenPermissionStore(path.toString())
            if (handle == 0L) throw CageforgePermissionException("Cageforge permission store failed to open")
            return PermissionStore(handle, path)
        }
    }
}
