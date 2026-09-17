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

/** Raised when TOML configuration cannot be parsed or resolved. */
class CageforgeConfigurationException(message: String) : CageforgeException(message)

/** Raised when the native Cageforge runtime cannot be initialized. */
class CageforgeInitializationException(message: String) : CageforgeException(message)

/** Raised when a command cannot be launched through the native sandbox. */
class CageforgeLaunchException(message: String) : CageforgeException(message)

/** Raised when a trusted preflight grant is missing, invalid, or insufficient. */
class CageforgePermissionException(message: String) : CageforgeException(message)

/** Raised when a native process lifecycle operation fails. */
class CageforgeProcessException(message: String) : CageforgeException(message)

/** Raised when a native standard-stream operation fails. */
class CageforgeStreamException(message: String) : CageforgeException(message)

/** Raised when Windows setup or its verification fails. */
class CageforgeWindowsSetupException(message: String) : CageforgeException(message)
