// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.io.InputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.atomic.AtomicReference

internal object NativeLoader {
    private val loaded = AtomicReference<CompletableFuture<Loaded>?>(null)

    fun load(): Path {
        val target = target()
        while (true) {
            val existing = loaded.get()
            if (existing != null) {
                val value = await(existing)
                check(value.target == target) {
                    "Cageforge native target changed after the JVM library was loaded"
                }
                verify(value.directory, target)
                return value.directory
            }

            val candidate = CompletableFuture<Loaded>()
            if (!loaded.compareAndSet(null, candidate)) continue
            try {
                val directory = loadInitial(target)
                val value = Loaded(target, directory)
                candidate.complete(value)
                return directory
            } catch (error: Throwable) {
                candidate.completeExceptionally(error)
                loaded.compareAndSet(candidate, null)
                throw error
            }
        }
    }

    /** Returns the resource target selected from the current JVM platform. */
    fun targetId(): String = "${target().os}-${target().arch}"

    private fun loadInitial(target: Target): Path {
        val directory = cacheDirectory(target)
        Files.createDirectories(directory)
        val library = extract(directory, target.library)
        target.resources.forEach { extract(directory, it) }
        System.load(library.toAbsolutePath().toString())
        return directory
    }

    private fun verify(
        directory: Path,
        target: Target,
    ) {
        // Helpers are executed by later runtime launches, so verify the
        // cached bytes on every access, not only on first load.
        extract(directory, target.library)
        target.resources.forEach { extract(directory, it) }
    }

    private fun await(future: CompletableFuture<Loaded>): Loaded =
        try {
            future.get()
        } catch (error: ExecutionException) {
            throw error.cause ?: error
        }

    private fun target(): Target {
        val os = System.getProperty("os.name").lowercase(Locale.ROOT)
        val architecture = System.getProperty("os.arch").lowercase(Locale.ROOT)
        val osName =
            when {
                os.contains("linux") -> "linux"
                os.contains("mac") || os.contains("darwin") -> "macos"
                os.contains("win") -> "windows"
                else -> throw CageforgeException("Unsupported operating system: $os")
            }
        val archName =
            when (architecture) {
                "amd64", "x86_64" -> "x86_64"
                "aarch64", "arm64" -> "aarch64"
                else -> throw CageforgeException("Unsupported architecture: $architecture")
            }
        val prefix = "META-INF/native/$osName-$archName/"
        val library =
            when (osName) {
                "linux" -> prefix + "libcageforge_java.so"
                "macos" -> prefix + "libcageforge_java.dylib"
                else -> prefix + "cageforge_java.dll"
            }
        val resources =
            when (osName) {
                "linux" ->
                    listOf(
                        prefix + "bwrap",
                        prefix + "bwrap.sha256",
                        prefix + "cageforge-linux-helper",
                    )
                "macos" -> listOf(prefix + "cageforge-macos-helper")
                else ->
                    listOf(
                        prefix + "cageforge-windows-setup.exe",
                        prefix + "cageforge-windows-command-runner.exe",
                    )
            }
        return Target(osName, archName, library, resources)
    }

    private fun cacheDirectory(target: Target): Path {
        val version = NativeLoader::class.java.getPackage()?.implementationVersion ?: "development"
        val base =
            System.getProperty("cageforge.native.cache")?.let { Path.of(it) }
                ?: Path.of(System.getProperty("user.home"), ".cache", "cageforge-java")
        return base.resolve(version).resolve("${target.os}-${target.arch}").toAbsolutePath().normalize()
    }

    private fun extract(
        directory: Path,
        resource: String,
    ): Path {
        val name = resource.substringAfterLast('/')
        val destination = directory.resolve(name)
        val stream =
            NativeLoader::class.java.classLoader.getResourceAsStream(resource)
                ?: throw CageforgeException("Missing Cageforge native resource: $resource")
        stream.use { input ->
            val bytes = input.readBytes()
            if (Files.exists(destination)) {
                verifyCached(destination, bytes)
            } else {
                val temporary = Files.createTempFile(directory, ".cageforge-", ".tmp")
                try {
                    Files.write(temporary, bytes)
                    installCached(destination, temporary, bytes)
                } finally {
                    Files.deleteIfExists(temporary)
                }
            }
        }
        if (!name.endsWith(".dll") && !name.endsWith(".json") && !name.endsWith(".sha256")) {
            destination.toFile().setExecutable(true, true)
        }
        return destination
    }

    private fun installCached(
        destination: Path,
        temporary: Path,
        expected: ByteArray,
    ) {
        try {
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: FileAlreadyExistsException) {
            verifyCached(destination, expected)
        } catch (_: AtomicMoveNotSupportedException) {
            try {
                Files.move(temporary, destination)
            } catch (_: FileAlreadyExistsException) {
                verifyCached(destination, expected)
            }
        }
    }

    private fun verifyCached(
        destination: Path,
        expected: ByteArray,
    ) {
        if (!sameDigest(destination, expected)) {
            throw CageforgeException("Cageforge native resource cache mismatch: $destination")
        }
    }

    private fun sameDigest(
        path: Path,
        expected: ByteArray,
    ): Boolean {
        return digest(Files.newInputStream(path)) == digest(expected.inputStream())
    }

    private fun digest(input: InputStream): String =
        input.use {
            MessageDigest.getInstance("SHA-256").digest(it.readBytes())
                .joinToString("") { byte -> "%02x".format(byte) }
        }

    private data class Target(
        val os: String,
        val arch: String,
        val library: String,
        val resources: List<String>,
    )

    private data class Loaded(
        val target: Target,
        val directory: Path,
    )
}
