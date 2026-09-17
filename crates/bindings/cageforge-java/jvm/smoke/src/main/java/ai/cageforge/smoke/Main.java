// SPDX-License-Identifier: Apache-2.0

package ai.cageforge.smoke;

import ai.cageforge.Cageforge;
import ai.cageforge.CageforgeConfigurationException;
import ai.cageforge.CageforgeException;
import ai.cageforge.PermissionApprover;
import ai.cageforge.RuntimeContext;
import ai.cageforge.SandboxProcess;
import ai.cageforge.WindowsSetup;
import ai.cageforge.WindowsSetupState;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Minimal Java consumer used by CI to exercise the locally assembled JAR. */
public final class Main {
    private static final String SMOKE_OUTPUT = "cageforge-java-local-consumer";
    private static final String MINIMAL_DIRECTORY = ".cageforge-test-runtime";
    private static final String WORKSPACE_ROOT = "workspace-root";
    private static final String WINDOWS_SYSTEM_ROOT = "SystemRoot";
    private static final String WINDOWS_SYSTEM32 = "System32";
    private static final String WINDOWS_CMD = "cmd.exe";
    private static final String WINDOWS_POWERSHELL = "WindowsPowerShell";
    private static final String WINDOWS_POWERSHELL_VERSION = "v1.0";
    private static final String POWERSHELL = "powershell.exe";
    private static final int WAIT_TIMEOUT_SECONDS = 15;

    private Main() {}

    public static void main(String[] args) throws Exception {
        Path currentDirectory = Files.createTempDirectory("cageforge-java-smoke-")
                .toAbsolutePath().normalize();
        Path minimalPath = Files.createDirectory(currentDirectory.resolve(MINIMAL_DIRECTORY));
        RuntimeContext context = new RuntimeContext(currentDirectory, minimalPath);
        boolean windows = WindowsSetup.isSupported();
        Path command = windows
                ? windowsSystemPath(WINDOWS_CMD)
                : Path.of("/bin/echo");
        String filesystemRule = "{ target = \"minimal\", access = \"read\" }";
        String toml = """
                default_profile = "smoke"

                [profiles.base.command]
                program = "inherited-placeholder"

                [profiles.base.command.stdio]
                stdin = "pipe"
                stdout = "pipe"
                stderr = "pipe"

                [profiles.smoke]
                inherits = ["base"]
                workspace_roots = { "%s" = true }

                [profiles.smoke.filesystem]
                mode = "restricted"
                rules = [
                %s,
                  { target = "%s", access = "write" },
                ]

                [profiles.smoke.network]
                mode = "disabled"
                """.formatted(tomlString(currentDirectory), filesystemRule, WORKSPACE_ROOT);

        List<String> profileNames = Cageforge.profileNames(toml);
        if (!List.of("base", "smoke").equals(profileNames)) {
            throw new CageforgeException("unexpected profile names: " + profileNames);
        }
        try {
            Cageforge.profileNames("default_profile = [");
            throw new CageforgeException("invalid TOML was accepted");
        } catch (CageforgeConfigurationException expected) {
            System.out.println("typed-errors=ok");
        }
        Cageforge.checkToml(toml, "smoke", context);
        System.out.println("toml-validation=ok");
        System.out.println("native-target=" + Cageforge.nativeTarget());
        boolean cleanupWindowsSetup = false;
        try {
            if (windows) {
                cleanupWindowsSetup = WindowsSetup.status() != WindowsSetupState.READY;
                WindowsSetup.install();
                if (WindowsSetup.status() != WindowsSetupState.READY) {
                    throw new CageforgeException("Windows setup did not become ready");
                }
                WindowsSetup.verify();
            }
            System.out.println("stage=concurrent-instances");
            List<String> argv = windows
                    ? List.of(command.toString(), "/d", "/c", "echo", SMOKE_OUTPUT)
                    : List.of(command.toString(), SMOKE_OUTPUT);
            try (Cageforge warmupRuntime = openRuntime(toml, context)) {
                runCommand(warmupRuntime, argv);
            }
            try (Cageforge firstRuntime = openRuntime(toml, context);
                 Cageforge secondRuntime = openRuntime(toml, context)) {
                var first = java.util.concurrent.CompletableFuture.runAsync(
                        () -> runCommand(firstRuntime, argv));
                var second = java.util.concurrent.CompletableFuture.runAsync(
                        () -> runCommand(secondRuntime, argv));
                java.util.concurrent.CompletableFuture.allOf(first, second).join();
                firstRuntime.close();
                firstRuntime.close();
                secondRuntime.close();
                secondRuntime.close();
                System.out.println("concurrent-instances=ok");
            }
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(argv)) {
                String stdout = new String(
                        process.getStdout().readAllBytes(), StandardCharsets.UTF_8);
                if (!stdout.contains(SMOKE_OUTPUT)) {
                    throw new CageforgeException("unexpected sandbox stdout: " + stdout);
                }
                if (!Integer.valueOf(0).equals(process.waitForAsync().join().getExitCode())) {
                    throw new CageforgeException("sandbox command did not exit successfully");
                }
                System.out.println("consumer-smoke=ok");
            }
            System.out.println("stage=closed-handles");
            Cageforge closedRuntime = openRuntime(toml, context);
            closedRuntime.close();
            closedRuntime.close();
            boolean runtimeRejected = false;
            try {
                closedRuntime.launch(argv);
            } catch (CageforgeException expected) {
                // A closed runtime must reject new native operations.
                runtimeRejected = true;
            }
            if (!runtimeRejected) {
                throw new CageforgeException("closed runtime accepted a launch");
            }
            Cageforge processOwner = openRuntime(toml, context);
            SandboxProcess closedProcess = processOwner.launch(argv);
            closedProcess.close();
            closedProcess.close();
            processOwner.close();
            boolean processRejected = false;
            try {
                closedProcess.tryWait();
            } catch (CageforgeException expected) {
                // A closed process must reject new native operations.
                processRejected = true;
            }
            if (!processRejected) {
                throw new CageforgeException("closed process accepted a status query");
            }
            System.out.println("closed-handles=ok");
            List<String> longRunningArgv = windows
                    ? List.of(
                            windowsSystemPath(WINDOWS_POWERSHELL,
                                    WINDOWS_POWERSHELL_VERSION, POWERSHELL).toString(),
                            "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                            "Start-Sleep -Seconds 30")
                    : List.of(Path.of("/bin/sh").toString(), "-c", "sleep 30");
            System.out.println("stage=wait-kill");
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var wait = process.waitForAsync();
                boolean running = false;
                for (int attempt = 0; attempt < 40; attempt++) {
                    if (process.tryWait() == null) {
                        running = true;
                        break;
                    }
                    Thread.sleep(50);
                }
                if (!running) {
                    throw new CageforgeException("long-running sandbox command exited too early");
                }
                process.kill();
                wait.get(WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                System.out.println("wait-kill=ok");
            }
            System.out.println("stage=stream-kill");
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var blockedRead = java.util.concurrent.CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                return process.getStdout().read();
                            } catch (java.io.IOException error) {
                                throw new java.util.concurrent.CompletionException(error);
                            }
                        });
                Thread.sleep(100);
                process.kill();
                blockedRead.get(WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                System.out.println("stream-kill=ok");
            }
            System.out.println("stage=write-kill");
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var blockedWrite = java.util.concurrent.CompletableFuture.runAsync(
                        () -> {
                            try {
                                process.getStdin().write(new byte[16 * 1024 * 1024]);
                            } catch (java.io.IOException | CageforgeException expected) {
                                // Killing the boundary closes the pipe peer.
                            }
                        });
                Thread.sleep(100);
                if (blockedWrite.isDone()) {
                    throw new CageforgeException("stdin write did not block as expected");
                }
                process.kill();
                blockedWrite.get(WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                System.out.println("write-kill=ok");
            }
            System.out.println("stage=close-kill");
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var wait = process.waitForAsync();
                Thread.sleep(100);
                process.close();
                wait.get(WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                System.out.println("close-kill=ok");
            }
            System.out.println("stage=async-cancel");
            try (Cageforge runtime = openRuntime(toml, context);
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var wait = process.waitForAsync();
                Thread.sleep(100);
                if (!wait.cancel(true)) {
                    throw new CageforgeException("wait future could not be cancelled");
                }
                if (process.tryWait() == null) {
                    throw new CageforgeException("future cancellation did not terminate process");
                }
                System.out.println("async-cancel=ok");
            }
            System.out.println("stage=stdin-eof");
            String eofToml = toml + """

                    [profiles.smoke.command.stdio]
                    stdin = "pipe"
                    stdout = "null"
                    stderr = "null"
                    """;
            List<String> eofArgv = windows
                    ? List.of(command.toString(), "/d", "/c", "more > nul")
                    : List.of(Path.of("/bin/sh").toString(), "-c", "cat >/dev/null");
            try (Cageforge runtime = openRuntime(eofToml, context);
                 SandboxProcess process = runtime.launch(eofArgv)) {
                process.getStdin().write("eof".getBytes(StandardCharsets.UTF_8));
                process.getStdin().close();
                if (!Integer.valueOf(0).equals(process.waitForAsync().get(WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .getExitCode())) {
                    throw new CageforgeException("stdin EOF command failed");
                }
                System.out.println("stdin-eof=ok");
            }
            System.out.println("stage=stdio-routing");
            String nonPipedToml = toml + """

                    [profiles.smoke.command.stdio]
                    stdin = "null"
                    stdout = "null"
                    stderr = "null"
                    """;
            try (Cageforge runtime = openRuntime(nonPipedToml, context);
                 SandboxProcess process = runtime.launch(argv)) {
                if (process.getStdin() != null || process.getStdout() != null
                        || process.getStderr() != null) {
                    throw new CageforgeException("TOML stdio routing was not preserved");
                }
                if (!Integer.valueOf(0).equals(process.waitForAsync().join().getExitCode())) {
                    throw new CageforgeException("non-piped sandbox command failed");
                }
                System.out.println("stdio-routing=ok");
            }
        } finally {
            if (windows && cleanupWindowsSetup) {
                WindowsSetup.uninstall();
                if (WindowsSetup.status() != WindowsSetupState.MISSING) {
                    throw new CageforgeException("Windows setup was not removed");
                }
            }
        }
    }

    private static Cageforge openRuntime(String toml, RuntimeContext context) {
        try (PermissionRequest request = Cageforge.permissionRequest(toml, null, context);
                PermissionGrant grant = new PermissionApprover().approve(request)) {
            return Cageforge.fromToml(toml, null, context, grant);
        }
    }

    private static void runCommand(Cageforge runtime, List<String> argv) {
        try (SandboxProcess process = runtime.launch(argv)) {
            if (!Integer.valueOf(0).equals(process.waitForAsync().join().getExitCode())) {
                throw new CageforgeException("concurrent sandbox command failed");
            }
        }
    }

    private static String tomlString(Path path) {
        return path.toString().replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static Path windowsSystemPath(String... components) {
        Path path = Path.of(System.getenv(WINDOWS_SYSTEM_ROOT), WINDOWS_SYSTEM32);
        for (String component : components) {
            path = path.resolve(component);
        }
        return path;
    }
}
