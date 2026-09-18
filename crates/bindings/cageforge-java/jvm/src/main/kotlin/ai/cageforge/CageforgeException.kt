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
open class CageforgePermissionException(message: String) : CageforgeException(message)

/** Raised when persistent permission-store I/O or format validation fails. */
open class CageforgePermissionStoreException(message: String) : CageforgePermissionException(message)

/** Raised when a persistent grant ID is not present in the store. */
class CageforgeGrantNotFoundException(message: String) : CageforgePermissionStoreException(message)

/** Raised when a page cursor refers to an old store snapshot. */
class CageforgeListingSnapshotExpiredException(message: String) : CageforgePermissionStoreException(message)

/** Raised when a grant ID is malformed. */
class CageforgeInvalidGrantIdException(message: String) : CageforgePermissionStoreException(message)

/** Raised when a persistent grant page cursor is malformed. */
class CageforgeInvalidCursorException(message: String) : CageforgePermissionStoreException(message)

/** Raised when a persistent grant page size is invalid. */
class CageforgeInvalidPageSizeException(message: String) : CageforgePermissionStoreException(message)

/** Raised when the persistent permission store lock fails. */
class CageforgeStoreLockedException(message: String) : CageforgePermissionStoreException(message)

/** Raised when the persistent permission store cannot be read. */
class CageforgeStoreReadException(message: String) : CageforgePermissionStoreException(message)

/** Raised when the persistent permission store cannot be written. */
class CageforgeStoreWriteException(message: String) : CageforgePermissionStoreException(message)

/** Raised when the persistent permission store format is invalid. */
class CageforgeStoreFormatException(message: String) : CageforgePermissionStoreException(message)

/** Raised when a native process lifecycle operation fails. */
class CageforgeProcessException
    @JvmOverloads
    constructor(
        message: String,
        cause: Throwable? = null,
    ) : CageforgeException(message, cause)

/** Raised when a native standard-stream operation fails. */
class CageforgeStreamException(message: String) : CageforgeException(message)

/** Raised when Windows setup or its verification fails. */
class CageforgeWindowsSetupException(message: String) : CageforgeException(message)
