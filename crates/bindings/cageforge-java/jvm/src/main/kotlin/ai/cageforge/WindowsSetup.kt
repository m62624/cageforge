// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.util.Locale

/** Explicit Windows provisioning operations. Installation may display UAC. */
object WindowsSetup {
    /** Returns whether the current JVM belongs to the Windows OS family. */
    @JvmStatic
    fun isSupported(): Boolean = System.getProperty("os.name")
        .lowercase(Locale.ROOT)
        .contains("windows")

    /** Installs or reconciles the owner-scoped Windows Cageforge boundary. */
    @JvmStatic
    fun install() {
        requireWindows()
        NativeBridge.nativeWindowsInstall(NativeLoader.load().toString())
    }

    /** Returns the verified owner-scoped setup state without provisioning it. */
    @JvmStatic
    fun status(): WindowsSetupState {
        requireWindows()
        return when (NativeBridge.nativeWindowsStatus(NativeLoader.load().toString())) {
            0 -> WindowsSetupState.MISSING
            1 -> WindowsSetupState.STALE
            2 -> WindowsSetupState.READY
            else -> throw CageforgeException("Cageforge returned an invalid Windows setup state")
        }
    }

    /** Verifies the complete owner-scoped setup or throws a typed native error. */
    @JvmStatic
    fun verify() {
        requireWindows()
        NativeBridge.nativeWindowsVerify(NativeLoader.load().toString())
    }

    /** Removes the owner-scoped Windows Cageforge boundary. */
    @JvmStatic
    fun uninstall() {
        requireWindows()
        NativeBridge.nativeWindowsUninstall(NativeLoader.load().toString())
    }

    private fun requireWindows() {
        if (!isSupported()) {
            throw UnsupportedPlatformException("Windows setup is available only on Windows")
        }
    }
}

/** Read-back state of the owner-scoped Windows Cageforge setup. */
enum class WindowsSetupState {
    MISSING,
    STALE,
    READY,
}
