// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

/** Base exception raised by the Cageforge JVM binding. */
open class CageforgeException
    @JvmOverloads
    constructor(
        message: String,
        cause: Throwable? = null,
    ) : RuntimeException(message, cause)

/** Raised when an explicitly OS-specific Cageforge operation targets another host OS. */
class UnsupportedPlatformException(message: String) : CageforgeException(message)
