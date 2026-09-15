// SPDX-License-Identifier: Apache-2.0

package ai.cageforge.smoke;

import ai.cageforge.Cageforge;
import ai.cageforge.CageforgeException;
import ai.cageforge.RuntimeContext;
import ai.cageforge.SandboxProcess;
import ai.cageforge.WindowsSetup;
import ai.cageforge.WindowsSetupState;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/** Minimal Java consumer used by CI to exercise the locally assembled JAR. */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        Path currentDirectory = Path.of(System.getProperty("user.dir"));
        boolean windows = WindowsSetup.isSupported();
        Path command = windows
                ? Path.of(System.getenv("SystemRoot"), "System32", "cmd.exe")
                : Path.of("/bin/echo");
        Path readableDirectory = windows ? command.getParent() : Path.of("/bin");
        String filesystemRule = windows
                ? "{ target = \"absolute\", path = \"%s\", access = \"read\" }"
                        .formatted(tomlString(readableDirectory))
                : "{ target = \"minimal\", access = \"read\" }";
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
