// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.nio.file.Path
import java.nio.file.Paths

/** Runtime paths that a TOML profile intentionally leaves to the host. */
data class RuntimeContext
    @JvmOverloads
    constructor(
        val currentDirectory: Path = Paths.get("").toAbsolutePath().normalize(),
    ) {
        init {
            require(currentDirectory.isAbsolute) { "currentDirectory must be absolute" }
        }
    }
