// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * A `java.lang.Process` facade over a Cageforge-native sandbox child.
 *
 * The wrapped child is always created by the Rust native backend. This class
 * never starts a second process and never uses `ProcessBuilder`.
 */
class CageforgeProcess internal constructor(
    private val delegate: SandboxProcess,
) : Process(), AutoCloseable {
    override fun getInputStream(): InputStream = delegate.stdout ?: InputStream.nullInputStream()

    override fun getErrorStream(): InputStream = delegate.stderr ?: InputStream.nullInputStream()

    override fun getOutputStream(): OutputStream = delegate.stdin ?: OutputStream.nullOutputStream()

    override fun waitFor(): Int = exitCode(delegate.waitFor())

    @Throws(InterruptedException::class)
    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        require(timeout >= 0) { "timeout must not be negative" }
        if (delegate.tryWait() != null) return true
        if (timeout == 0L) return false
        return try {
            delegate.waitForAsync().get(timeout, unit)
            true
        } catch (_: TimeoutException) {
            false
        } catch (error: ExecutionException) {
            throw rethrow(error.cause ?: error)
        }
    }

    override fun exitValue(): Int =
        delegate.tryWait()?.let(::exitCode)
            ?: throw IllegalThreadStateException("Cageforge process is still running")

    override fun destroy() {
        delegate.kill()
    }

    override fun destroyForcibly(): Process {
        delegate.kill()
        return this
    }

    override fun isAlive(): Boolean = delegate.tryWait() == null

    override fun pid(): Long = delegate.id.toLong()

    override fun onExit(): CompletableFuture<Process> = delegate.waitForAsync().thenApply { this }

    override fun supportsNormalTermination(): Boolean = false

    /** Closes the native sandbox boundary and its detached streams. */
    override fun close() {
        delegate.close()
    }

    private fun exitCode(result: ProcessResult): Int = result.exitCode ?: -1

    private fun rethrow(error: Throwable): RuntimeException =
        when (error) {
            is RuntimeException -> error
            is Error -> throw error
            else -> CageforgeProcessException("Cageforge process wait failed", error)
        }
}
