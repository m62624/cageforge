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

    /** Lists one bounded page of safe persistent-grant summaries. */
    @JvmOverloads
    fun listPage(
        pageSize: Int = 50,
        cursor: GrantPageCursor? = null,
    ): GrantPage {
        val values =
            native.use { storeHandle ->
                NativeBridge.nativePermissionStoreListPage(storeHandle, pageSize, cursor?.token)
            }
        if (values.isEmpty() || (values.size - 1) % SUMMARY_WIDTH != 0) {
            throw CageforgePermissionStoreException("Cageforge returned a malformed permission page")
        }
        val entries =
            values.drop(1).chunked(SUMMARY_WIDTH).map { fields ->
                GrantSummary(
                    id = GrantId.fromHex(fields[0]),
                    toolId = fields[1],
                    toolVersion = fields[2],
                    platform = fields[3],
                    architecture = fields[4],
                    scope = fields[5],
                    issuedAt = fields[6].toLongOrThrow("issued-at"),
                    expiresAt = fields[7].toLongOrThrow("expiration").takeUnless { it < 0 },
                )
            }
        return GrantPage(
            entries = entries,
            nextCursor = values[0].takeUnless { it.isEmpty() }?.let(GrantPageCursor::fromToken),
        )
    }

    /** Revokes one persistent grant for future launches. */
    fun revoke(id: GrantId): RevokeResult {
        return when (
            native.use { storeHandle ->
                NativeBridge.nativePermissionStoreRevoke(storeHandle, id.value)
            }
        ) {
            "revoked" -> RevokeResult.REVOKED
            "not-found" -> RevokeResult.NOT_FOUND
            else -> throw CageforgePermissionStoreException("Cageforge returned an invalid revoke result")
        }
    }

    /** Revokes all persistent grants while retaining the store file. */
    fun revokeAll() {
        native.use { storeHandle -> NativeBridge.nativePermissionStoreRevokeAll(storeHandle) }
    }

    override fun close() = native.close()

    companion object {
        private const val SUMMARY_WIDTH = 8

        private fun String.toLongOrThrow(field: String): Long =
            toLongOrNull() ?: throw CageforgePermissionStoreException("invalid permission page $field")

        /** Opens or creates a host-owned store at an absolute path. */
        @JvmStatic
        fun open(path: Path): PermissionStore {
            if (!path.isAbsolute) {
                throw CageforgeStorePathException("permission store path must be absolute: $path")
            }
            NativeLoader.load()
            val handle = NativeBridge.nativeOpenPermissionStore(path.toString())
            if (handle == 0L) throw CageforgePermissionException("Cageforge permission store failed to open")
            return PermissionStore(handle, path)
        }
    }
}
