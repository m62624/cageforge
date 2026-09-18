// SPDX-License-Identifier: Apache-2.0

package ai.cageforge;

final class NativeBridge {
    private NativeBridge() {}

    static native long nativeCreate(
            String toml,
            String profile,
            String currentDirectory,
            String nativeDirectory,
            String minimalDirectory,
            long grant,
            long request);

    static native String[] nativeProfileNames(String toml);

    static native void nativeCheckToml(
            String toml,
            String profile,
            String currentDirectory,
            String minimalDirectory);

    static native long nativePermissionRequest(
            String toml,
            String profile,
            String currentDirectory,
            String minimalDirectory,
            String toolId,
            String toolVersion,
            String manifestDigest,
            String configDigest);

    static native String nativePermissionRequestJson(long request);

    static native String nativePermissionRequestToolId(long request);

    static native String nativePermissionRequestToolVersion(long request);

    static native String nativePermissionRequestPlatform(long request);

    static native String nativePermissionRequestDigest(long request);

    static native String[] nativePermissionRequestFilesystem(long request);

    static native String[] nativePermissionRequestNetwork(long request);

    static native void nativeClosePermissionRequest(long request);

    static native long nativeApprovePermissionRequest(long request, String scope, long expiresAt);

    static native String nativePermissionGrantRequestDigest(long grant);

    static native String nativePermissionGrantScope(long grant);

    static native long nativePermissionGrantExpiresAt(long grant);

    static native void nativeClosePermissionGrant(long grant);

    static native long nativeOpenPermissionStore(String path);

    static native long nativePermissionStoreGet(long store, long request);

    static native void nativePermissionStorePut(long store, long grant, long request);

    static native void nativeClosePermissionStore(long store);

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

    static native void nativeCloseStdin(long process);

    static native void nativeCloseRuntime(long runtime);

    static native void nativeCloseProcess(long process);

    static native void nativeWindowsInstall(String nativeDirectory);

    static native int nativeWindowsStatus(String nativeDirectory);

    static native void nativeWindowsVerify(String nativeDirectory);

    static native void nativeWindowsUninstall(String nativeDirectory);
}
