package ai.cageforge

/** Structured preflight request emitted by the shared Rust permission layer. */
class PermissionRequest internal constructor(
    handle: Long,
    val json: String,
    val toolId: String,
    val toolVersion: String,
    val platform: String,
    val digest: String,
    val grantId: GrantId,
    filesystemValues: Array<String>,
    val network: List<String>,
) : AutoCloseable {
    private val native =
        NativeHandle(
            handle,
            NativeBridge::nativeClosePermissionRequest,
            { CageforgePermissionException("Cageforge permission request is closed") },
        )

    /** Requested filesystem capabilities as `(operation, path)` pairs. */
    val filesystem: List<Pair<String, String>> =
        filesystemValues.toList().chunked(2).map { values ->
            require(values.size == 2) { "Cageforge returned malformed filesystem capabilities" }
            values[0] to values[1]
        }

    /** Returns typed local-IPC endpoint declarations. */
    val localIpc: List<LocalIpcEndpoint> =
        network.mapNotNull { value ->
            when {
                value.startsWith("unix:") -> LocalIpcEndpoint.UnixSocket(value.removePrefix("unix:"))
                value.startsWith("pipe:") -> LocalIpcEndpoint.WindowsNamedPipe(value.removePrefix("pipe:"))
                else -> null
            }
        }

    override fun close() {
        native.close()
    }

    internal fun <T> useNative(block: (Long) -> T): T = native.use(block)
}

/** Opaque JVM handle to a trusted permission grant. */
class PermissionGrant internal constructor(
    handle: Long,
    val requestDigest: String,
    val scope: String,
    val expiresAt: Long?,
) : AutoCloseable {
    private val native =
        NativeHandle(
            handle,
            NativeBridge::nativeClosePermissionGrant,
            { CageforgePermissionException("Cageforge permission grant is closed") },
        )

    override fun close() {
        native.close()
    }

    internal fun <T> useNative(block: (Long) -> T): T = native.use(block)
}
