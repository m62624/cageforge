// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

/** Additional capabilities that require a new approved sandbox launch. */
class PermissionEscalationRequest internal constructor(
    handle: Long,
    val json: String,
    val reason: String,
    filesystemValues: Array<String>,
    val network: List<String>,
) : AutoCloseable {
    private val native =
        NativeHandle(
            handle,
            NativeBridge::nativeClosePermissionEscalation,
            { CageforgeEscalationException("Cageforge permission escalation is closed") },
        )

    /** Additional filesystem capabilities as `(operation, path)` pairs. */
    val filesystem: List<Pair<String, String>> = parseFilesystem(filesystemValues)

    private fun parseFilesystem(values: Array<String>): List<Pair<String, String>> {
        if (values.size % 2 != 0) {
            throw CageforgeEscalationException("Cageforge returned malformed escalation capabilities")
        }
        return values.toList().chunked(2).map { pair -> pair[0] to pair[1] }
    }

    override fun close() = native.close()

    internal fun <T> useNative(block: (Long) -> T): T = native.use(block)
}
