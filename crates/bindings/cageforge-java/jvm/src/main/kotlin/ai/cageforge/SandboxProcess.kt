// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.ForkJoinPool
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Process and complete descendant-boundary lifecycle for one sandbox launch. */
class SandboxProcess internal constructor(private var handle: Long) : Closeable {
    private val lifecycleLock = ReentrantLock()
    private val noActiveOperations: Condition = lifecycleLock.newCondition()
    private val waitLock = Any()
    private var activeOperations = 0
    private var closing = false

    val id: Int
        get() = withHandle { NativeBridge.nativeId(it) }

    /** A readable pipe when TOML configured stdout as `pipe`, otherwise null. */
    val stdout: InputStream? =
        if (hasStdout()) {
            stream(true)
        } else {
            null
        }

    /** A readable pipe when TOML configured stderr as `pipe`, otherwise null. */
    val stderr: InputStream? =
        if (hasStderr()) {
            stream(false)
        } else {
            null
        }

    /** A writable pipe when TOML configured stdin as `pipe`, otherwise null. */
    val stdin: OutputStream? =
        if (hasStdin()) {
            object : OutputStream() {
                override fun write(b: Int) = write(byteArrayOf(b.toByte()))

                override fun write(
                    b: ByteArray,
                    off: Int,
                    len: Int,
                ) {
                    require(off >= 0 && len >= 0 && off <= b.size - len) { "invalid byte range" }
                    withHandle {
                        if (len == 0) return
                        val written =
                            NativeBridge.nativeWriteStdin(
                                it,
                                b.copyOfRange(off, off + len),
                            )
                        if (written != len) {
                            throw CageforgeException("Cageforge wrote only $written stdin bytes")
                        }
                    }
                }
            }
        } else {
            null
        }

    /** Returns null while running, otherwise the completed process result. */
    fun tryWait(): ProcessResult? = withHandle { decode(NativeBridge.nativeTryWait(it)) }

    /** Waits until the process exits or Cageforge's configured timeout fires. */
    fun waitFor(): ProcessResult =
        synchronized(waitLock) {
            withHandle {
                val status = NativeBridge.nativeWait(it)
                if (status == -1) {
                    throw CageforgeException("Cageforge returned a running status from wait")
                }
                decode(status) ?: throw CageforgeException("Cageforge returned no process result from wait")
            }
        }

    /**
     * Waits without occupying the caller's thread.
     *
     * The native wait is synchronous by design, so this method dispatches it
     * to the supplied executor. It is safe to call from Swing, JavaFX, or
     * another application main thread. The default executor is the JVM common
     * pool; applications with their own lifecycle may provide a bounded one.
     */
    @JvmOverloads
    fun waitForAsync(executor: Executor = ForkJoinPool.commonPool()): CompletableFuture<ProcessResult> =
        CompletableFuture.supplyAsync({ waitFor() }, executor)

    /** Terminates and confirms the complete sandbox boundary. */
    fun kill() = withHandle { NativeBridge.nativeKill(it) }

    override fun close() =
        run {
            val value =
                lifecycleLock.withLock {
                    if (handle == 0L) return@withLock 0L
                    closing = true
                    while (activeOperations != 0) {
                        noActiveOperations.awaitUninterruptibly()
                    }
                    handle.also { handle = 0L }
                }
            if (value != 0L) NativeBridge.nativeCloseProcess(value)
        }

    private fun stream(stdout: Boolean): InputStream =
        object : InputStream() {
            override fun read(): Int {
                val bytes = readBytes(1)
                return if (bytes.isEmpty()) -1 else bytes[0].toInt() and 0xff
            }

            override fun read(
                b: ByteArray,
                off: Int,
                len: Int,
            ): Int {
                require(off >= 0 && len >= 0 && off <= b.size - len) { "invalid byte range" }
                if (len == 0) return 0
                val bytes = readBytes(len)
                bytes.copyInto(b, off)
                return if (bytes.isEmpty()) -1 else bytes.size
            }

            private fun readBytes(size: Int): ByteArray =
                withHandle {
                    if (stdout) {
                        NativeBridge.nativeReadStdout(it, size)
                    } else {
                        NativeBridge.nativeReadStderr(it, size)
                    }
                }
        }

    private fun hasStdin(): Boolean = withHandle { NativeBridge.nativeHasStdin(it) }

    private fun hasStdout(): Boolean = withHandle { NativeBridge.nativeHasStdout(it) }

    private fun hasStderr(): Boolean = withHandle { NativeBridge.nativeHasStderr(it) }

    private inline fun <T> withHandle(block: (Long) -> T): T {
        val value =
            lifecycleLock.withLock {
                checkOpen()
                activeOperations += 1
                handle
            }
        return try {
            block(value)
        } finally {
            lifecycleLock.withLock {
                activeOperations -= 1
                if (activeOperations == 0) noActiveOperations.signalAll()
            }
        }
    }

    private fun decode(status: Int): ProcessResult? =
        when {
            status == -1 -> null
            status == -2 -> ProcessResult(null)
            status >= 0 -> ProcessResult(status)
            else -> throw CageforgeException("invalid native process status: $status")
        }

    private fun checkOpen() {
        if (handle == 0L || closing) throw CageforgeException("sandbox process is closed")
    }

    internal companion object {
        fun fromHandle(handle: Long): SandboxProcess =
            try {
                SandboxProcess(handle)
            } catch (error: Throwable) {
                NativeBridge.nativeCloseProcess(handle)
                throw error
            }
    }
}

/** Completed process status; null exitCode means the OS reported termination without an exit code. */
data class ProcessResult(val exitCode: Int?)
