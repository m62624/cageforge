// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

/** Stable identity of one exact permission request. */
class GrantId private constructor(
    val value: String,
) {
    override fun toString(): String = value

    override fun equals(other: Any?): Boolean = other is GrantId && other.value == value

    override fun hashCode(): Int = value.hashCode()

    companion object {
        /** Parses a 64-character hexadecimal grant ID. */
        @JvmStatic
        fun fromHex(value: String): GrantId {
            if (!value.matches(HEX_PATTERN)) throw CageforgeInvalidGrantIdException("invalid grant id")
            return GrantId(value.lowercase())
        }

        private val HEX_PATTERN = Regex("[0-9a-fA-F]{64}")
    }
}

/** Opaque continuation token for one permission-store snapshot. */
class GrantPageCursor internal constructor(
    val token: String,
) {
    companion object {
        /** Parses a cursor returned by a previous page. */
        @JvmStatic
        fun fromToken(token: String): GrantPageCursor {
            val parts = token.split('.', limit = 3)
            if (parts.size != 3 || parts[0] != "v1") {
                throw CageforgeInvalidCursorException("invalid permission listing cursor")
            }
            try {
                GrantId.fromHex(parts[1])
                GrantId.fromHex(parts[2])
            } catch (_: CageforgeInvalidGrantIdException) {
                throw CageforgeInvalidCursorException("invalid permission listing cursor")
            }
            return GrantPageCursor(token)
        }
    }
}

/** Safe metadata for one persistent permission grant. */
data class GrantSummary(
    val id: GrantId,
    val toolId: String,
    val toolVersion: String,
    val platform: String,
    val architecture: String,
    val scope: String,
    val issuedAt: Long,
    val expiresAt: Long?,
)

/** One bounded page of persistent-grant metadata. */
data class GrantPage(
    val entries: List<GrantSummary>,
    val nextCursor: GrantPageCursor?,
)

/** Result of removing one persistent grant. */
enum class RevokeResult {
    REVOKED,
    NOT_FOUND,
}
