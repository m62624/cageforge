// SPDX-License-Identifier: Apache-2.0

package ai.cageforge;

final class NativeBridge {
    private NativeBridge() {}

    static native long nativeCreate(
            String toml,
            String profile,
            String currentDirectory,
            String nativeDirectory);

    static native String[] nativeProfileNames(String toml);

    static native void nativeCheckToml(
            String toml,
            String profile,
            String currentDirectory);

    static native long nativeLaunch(long runtime, String[] argv);

    static native int nativeId(long process);

    static native boolean nativeHasStdin(long process);

    static native boolean nativeHasStdout(long process);

    static native boolean nativeHasStderr(long process);

    static native int nativeTryWait(long process);

    static native int nativeWait(long process);

    static native void nativeKill(long process);

    static native byte[] nativeReadStdout(long process, int size);

    static native byte[] nativeReadStderr(long process, int size);

    static native int nativeWriteStdin(long process, byte[] data);

    static native void nativeCloseRuntime(long runtime);

    static native void nativeCloseProcess(long process);

    static native void nativeWindowsInstall(String nativeDirectory);

    static native int nativeWindowsStatus(String nativeDirectory);

    static native void nativeWindowsVerify(String nativeDirectory);

    static native void nativeWindowsUninstall(String nativeDirectory);
}
