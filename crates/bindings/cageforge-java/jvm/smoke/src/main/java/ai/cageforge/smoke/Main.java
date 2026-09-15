// SPDX-License-Identifier: Apache-2.0

package ai.cageforge.smoke;

import ai.cageforge.Cageforge;
import ai.cageforge.CageforgeConfigurationException;
import ai.cageforge.CageforgeException;
import ai.cageforge.RuntimeContext;
import ai.cageforge.SandboxProcess;
import ai.cageforge.WindowsSetup;
import ai.cageforge.WindowsSetupState;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Minimal Java consumer used by CI to exercise the locally assembled JAR. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Path currentDirectory = Path.of(System.getProperty("user.dir"));
        boolean windows = WindowsSetup.isSupported();
        Path command = windows
                ? Path.of(System.getenv("SystemRoot"), "System32", "cmd.exe")
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
                  { target = "workspace-root", access = "write" },
                ]

                [profiles.smoke.network]
                mode = "disabled"
                """.formatted(tomlString(currentDirectory), filesystemRule);

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
        Cageforge.checkToml(toml, "smoke", new RuntimeContext(currentDirectory));
        System.out.println("toml-validation=ok");
        System.out.println("native-target=" + Cageforge.nativeTarget());
        if (windows) {
            WindowsSetup.install();
            if (WindowsSetup.status() != WindowsSetupState.READY) {
                throw new CageforgeException("Windows setup did not become ready");
            }
            WindowsSetup.verify();
        }
        try {
            List<String> argv = windows
                    ? List.of(command.toString(), "/d", "/c", "echo", "cageforge-java-local-consumer")
                    : List.of(command.toString(), "cageforge-java-local-consumer");
            try (Cageforge firstRuntime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
                 Cageforge secondRuntime = Cageforge.fromToml(
                         toml, null, new RuntimeContext(currentDirectory))) {
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
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
                 SandboxProcess process = runtime.launch(argv)) {
                String stdout = new String(
                        process.getStdout().readAllBytes(), StandardCharsets.UTF_8);
                if (!stdout.contains("cageforge-java-local-consumer")) {
                    throw new CageforgeException("unexpected sandbox stdout: " + stdout);
                }
                if (!Integer.valueOf(0).equals(process.waitForAsync().join().getExitCode())) {
                    throw new CageforgeException("sandbox command did not exit successfully");
                }
                System.out.println("consumer-smoke=ok");
            }
            Cageforge closedRuntime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
            Cageforge processOwner = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
                    ? List.of(command.toString(), "/d", "/c", "timeout", "/t", "30", "/nobreak")
                    : List.of(Path.of("/bin/sh").toString(), "-c", "sleep 30");
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
                wait.get(15, TimeUnit.SECONDS);
                System.out.println("wait-kill=ok");
            }
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
                blockedRead.get(15, TimeUnit.SECONDS);
                System.out.println("stream-kill=ok");
            }
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
                blockedWrite.get(15, TimeUnit.SECONDS);
                System.out.println("write-kill=ok");
            }
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
                 SandboxProcess process = runtime.launch(longRunningArgv)) {
                var wait = process.waitForAsync();
                Thread.sleep(100);
                process.close();
                wait.get(15, TimeUnit.SECONDS);
                System.out.println("close-kill=ok");
            }
            try (Cageforge runtime = Cageforge.fromToml(
                    toml, null, new RuntimeContext(currentDirectory));
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
            String eofToml = toml + """

                    [profiles.smoke.command.stdio]
                    stdin = "pipe"
                    stdout = "null"
                    stderr = "null"
                    """;
            List<String> eofArgv = windows
                    ? List.of(command.toString(), "/d", "/c", "more > nul")
                    : List.of(Path.of("/bin/sh").toString(), "-c", "cat >/dev/null");
            try (Cageforge runtime = Cageforge.fromToml(
                    eofToml, null, new RuntimeContext(currentDirectory));
                 SandboxProcess process = runtime.launch(eofArgv)) {
                process.getStdin().write("eof".getBytes(StandardCharsets.UTF_8));
                process.getStdin().close();
                if (!Integer.valueOf(0).equals(process.waitForAsync().get(15, TimeUnit.SECONDS)
                        .getExitCode())) {
                    throw new CageforgeException("stdin EOF command failed");
                }
                System.out.println("stdin-eof=ok");
            }
            String nonPipedToml = toml + """

                    [profiles.smoke.command.stdio]
                    stdin = "null"
                    stdout = "null"
                    stderr = "null"
                    """;
            try (Cageforge runtime = Cageforge.fromToml(
                    nonPipedToml, null, new RuntimeContext(currentDirectory));
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
            if (windows) {
                WindowsSetup.uninstall();
                if (WindowsSetup.status() != WindowsSetupState.MISSING) {
                    throw new CageforgeException("Windows setup was not removed");
                }
            }
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
}
