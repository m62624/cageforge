package ai.cageforge

/** Trusted host capability that issues an opaque grant for a request. */
class PermissionApprover {
    /** Approves the complete request with the selected lifetime. */
    @JvmOverloads
    fun approve(
        request: PermissionRequest,
        scope: String = "session",
        expiresAt: Long? = null,
    ): PermissionGrant {
        val grant =
            request.useNative { handle ->
                NativeBridge.nativeApprovePermissionRequest(handle, scope, expiresAt ?: -1L)
            }
        if (grant == 0L) throw CageforgePermissionException("Cageforge permission approval failed")
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

    /** Approves all or an explicit subset of capabilities for a new sandbox. */
    @JvmOverloads
    fun approveEscalation(
        request: PermissionEscalationRequest,
        filesystem: List<Pair<String, String>> = request.filesystem,
        network: List<String> = request.network,
        scope: String = "session",
        expiresAt: Long? = null,
    ): PermissionGrant {
        val grant =
            request.useNative { handle ->
                NativeBridge.nativeApprovePermissionEscalation(
                    handle,
                    filesystem.flatMap { listOf(it.first, it.second) }.toTypedArray(),
                    network.toTypedArray(),
                    scope,
                    expiresAt ?: -1L,
                )
            }
        if (grant == 0L) throw CageforgeEscalationException("Cageforge escalation approval failed")
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
}
