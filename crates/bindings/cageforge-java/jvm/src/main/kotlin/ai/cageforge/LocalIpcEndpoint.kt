// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

/** A typed endpoint in the common local-IPC capability model. */
sealed interface LocalIpcEndpoint {
    /** The validated native endpoint value. */
    val value: String

    /** A Unix-domain socket pathname. */
    data class UnixSocket internal constructor(override val value: String) : LocalIpcEndpoint {
        /** The absolute Unix socket pathname. */
        val path: String get() = value
    }

    /** A Windows local named-pipe name. */
    data class WindowsNamedPipe internal constructor(override val value: String) : LocalIpcEndpoint {
        /** The validated `\\.\pipe\` namespace name. */
        val name: String get() = value
    }
}
