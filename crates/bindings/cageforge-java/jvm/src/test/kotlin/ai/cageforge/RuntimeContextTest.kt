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
        val minimalDirectory = runtimeDirectory.resolve("minimal")
        val context = RuntimeContext(runtimeDirectory, minimalDirectory)
        assertEquals(runtimeDirectory, context.currentDirectory)
        assertEquals(minimalDirectory, context.minimalPath)
    }

    @Test
    fun rejectsRelativeRuntimeDirectory() {
        assertFailsWith<IllegalArgumentException> { RuntimeContext(Path.of("relative")) }
    }

    @Test
    fun configurationExceptionKeepsStructuredDiagnosticFields() {
        val error =
            CageforgeConfigurationException(
                "invalid configuration",
                "invalid_value",
                "/tmp/tool.toml",
                "broken",
                "macos",
                "command.program",
                12,
                3,
            )
        assertEquals("invalid_value", error.code)
        assertEquals("/tmp/tool.toml", error.configPath)
        assertEquals("broken", error.profile)
        assertEquals("macos", error.platform)
        assertEquals("command.program", error.field)
        assertEquals(12, error.line)
        assertEquals(3, error.column)
    }

    @Test
    fun windowsSetupIsTypedAndNonDestructiveOnNonWindows() {
        if (WindowsSetup.isSupported()) return
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.install() }
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.status() }
        assertFailsWith<UnsupportedPlatformException> { WindowsSetup.verify() }
    }
}
