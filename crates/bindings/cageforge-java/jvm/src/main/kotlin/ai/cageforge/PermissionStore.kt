// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.nio.file.Path

/** Host-owned persistent store for exact preflight grants. */
class PermissionStore private constructor(
    private var handle: Long,
    val path: Path,
) : AutoCloseable {
    /** Returns a persisted grant for the exact request, or null when absent. */
    fun get(request: PermissionRequest): PermissionGrant? {
        checkOpen()
        val grant = NativeBridge.nativePermissionStoreGet(handle, request.handle)
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
        checkOpen()
        NativeBridge.nativePermissionStorePut(handle, grant.handle, request.handle)
    }

    override fun close() {
        if (handle != 0L) {
            val value = handle
            handle = 0L
            NativeBridge.nativeClosePermissionStore(value)
        }
    }

    private fun checkOpen() {
        if (handle == 0L) throw CageforgePermissionException("Cageforge permission store is closed")
    }

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
