package ai.cageforge

/** Structured preflight request emitted by the shared Rust permission layer. */
class PermissionRequest internal constructor(
    internal var handle: Long,
    val json: String,
    val toolId: String,
    val toolVersion: String,
    val platform: String,
    val digest: String,
    filesystemValues: Array<String>,
    val network: List<String>,
) : AutoCloseable {
    /** Requested filesystem capabilities as `(operation, path)` pairs. */
    val filesystem: List<Pair<String, String>> =
        filesystemValues.toList().chunked(2).map { values ->
            require(values.size == 2) { "Cageforge returned malformed filesystem capabilities" }
            values[0] to values[1]
        }

    /** Issues a session-scoped grant through the native trusted host adapter. */
    fun approve(): PermissionGrant {
        val grant = NativeBridge.nativeApprovePermissionRequest(handle)
        if (grant == 0L) throw CageforgeException("Cageforge permission approval failed")
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

    override fun close() {
        if (handle != 0L) {
            val value = handle
            handle = 0L
            NativeBridge.nativeClosePermissionRequest(value)
        }
    }
}

/** Opaque JVM handle to a trusted permission grant. */
class PermissionGrant internal constructor(
    internal var handle: Long,
    val requestDigest: String,
    val scope: String,
    val expiresAt: Long?,
) : AutoCloseable {
    override fun close() {
        if (handle != 0L) {
            val value = handle
            handle = 0L
            NativeBridge.nativeClosePermissionGrant(value)
        }
    }
}
