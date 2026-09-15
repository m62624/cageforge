// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RuntimeContextTest {
    @Test
    fun keepsAbsoluteRuntimeDirectory() {
        val runtimeDirectory = Path.of(System.getProperty("java.io.tmpdir"), "workspace")
        val context = RuntimeContext(runtimeDirectory)
        assertEquals(runtimeDirectory, context.currentDirectory)
    }

    @Test
    fun rejectsRelativeRuntimeDirectory() {
        assertFailsWith<IllegalArgumentException> { RuntimeContext(Path.of("relative")) }
    }

    @Test
    fun windowsSetupIsTypedAndNonDestructiveOnNonWindows() {
        if (WindowsSetup.isSupported()) return
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.install() }
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.status() }
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.verify() }
    }
}
