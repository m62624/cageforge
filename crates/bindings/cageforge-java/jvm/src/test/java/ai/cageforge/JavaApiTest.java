// SPDX-License-Identifier: Apache-2.0

package ai.cageforge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class JavaApiTest {
    @Test
    void javaCanConstructTheKotlinRuntimeContext() {
        Path runtimeDirectory = Path.of(System.getProperty("java.io.tmpdir"), "cageforge-java");
        Path minimalDirectory = runtimeDirectory.resolve("minimal");
        RuntimeContext context = new RuntimeContext(runtimeDirectory, minimalDirectory);
        assertEquals(runtimeDirectory, context.getCurrentDirectory());
        assertEquals(minimalDirectory, context.getMinimalPath());
    }

    @Test
    void javaSeesTheCompleteKotlinFacade() {
        Function<String, List<String>> profileNames = Cageforge::profileNames;
        TriFunction<String, String, RuntimeContext, Cageforge> fromToml = Cageforge::fromToml;
        TriConsumer<String, String, RuntimeContext> checkToml = Cageforge::checkToml;
        TriFunction<String, String, RuntimeContext, PermissionRequest> permissionRequest =
                Cageforge::permissionRequest;
        Function<Path, Cageforge> fromTomlFile = Cageforge::fromTomlFile;
        Supplier<String> nativeTarget = Cageforge::nativeTarget;
        Function<Cageforge, SandboxProcess> launch = Cageforge::launch;
        BiFunction<Cageforge, List<String>, SandboxProcess> launchArgv = Cageforge::launch;
        Function<Cageforge, Process> launchProcess = Cageforge::launchProcess;
        Function<SandboxProcess, Process> asJavaProcess = SandboxProcess::asJavaProcess;
        Consumer<Cageforge> closeRuntime = Cageforge::close;
        Function<PermissionRequest, PermissionGrant> approve = new PermissionApprover()::approve;
        Function<Path, PermissionStore> openStore = PermissionStore::open;
        BiFunction<PermissionStore, PermissionRequest, PermissionGrant> getGrant =
                PermissionStore::get;
        TriConsumer<PermissionStore, PermissionGrant, PermissionRequest> putGrant =
                PermissionStore::put;
        Consumer<PermissionStore> closeStore = PermissionStore::close;
        Function<SandboxProcess, Integer> processId = SandboxProcess::getId;
        Function<SandboxProcess, InputStream> stdout = SandboxProcess::getStdout;
        Function<SandboxProcess, InputStream> stderr = SandboxProcess::getStderr;
        Function<SandboxProcess, OutputStream> stdin = SandboxProcess::getStdin;
        Function<SandboxProcess, ProcessResult> waitFor = SandboxProcess::waitFor;
        Function<SandboxProcess, ProcessResult> tryWait = process -> process.tryWait();
        Function<SandboxProcess, CompletableFuture<ProcessResult>> waitForAsync =
                SandboxProcess::waitForAsync;
        Consumer<SandboxProcess> kill = SandboxProcess::kill;
        Consumer<SandboxProcess> closeProcess = SandboxProcess::close;
        Supplier<Boolean> windows = WindowsSetup::isSupported;
        Runnable install = WindowsSetup::install;
        Supplier<WindowsSetupState> status = WindowsSetup::status;
        Runnable verify = WindowsSetup::verify;
        Runnable uninstall = WindowsSetup::uninstall;

        assertNotNull(profileNames);
        assertNotNull(fromToml);
        assertNotNull(checkToml);
        assertNotNull(permissionRequest);
        assertNotNull(fromTomlFile);
        assertNotNull(nativeTarget);
        assertNotNull(launch);
        assertNotNull(launchArgv);
        assertNotNull(launchProcess);
        assertNotNull(asJavaProcess);
        assertNotNull(closeRuntime);
        assertNotNull(approve);
        assertNotNull(openStore);
        assertNotNull(getGrant);
        assertNotNull(putGrant);
        assertNotNull(closeStore);
        assertNotNull(processId);
        assertNotNull(stdout);
        assertNotNull(stderr);
        assertNotNull(stdin);
        assertNotNull(waitFor);
        assertNotNull(tryWait);
        assertNotNull(waitForAsync);
        assertNotNull(kill);
        assertNotNull(closeProcess);
        assertNotNull(windows);
        assertNotNull(install);
        assertNotNull(status);
        assertNotNull(verify);
        assertNotNull(uninstall);
    }

    @FunctionalInterface
    private interface TriFunction<A, B, C, R> {
        R apply(A first, B second, C third);
    }

    @FunctionalInterface
    private interface TriConsumer<A, B, C> {
        void accept(A first, B second, C third);
    }
}
