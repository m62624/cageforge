// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Owns one native handle without holding a JVM lock during native work. */
internal class NativeHandle(
    initial: Long,
    private val closeNative: (Long) -> Unit,
    private val closedError: () -> CageforgeException,
) : AutoCloseable {
    private val lifecycleLock = ReentrantLock()
    private val noActiveOperations: Condition = lifecycleLock.newCondition()
    private var handle = initial
    private var activeOperations = 0
    private var closing = false

    init {
        require(initial != 0L) { "native handle must not be zero" }
    }

    fun <T> use(block: (Long) -> T): T {
        val value =
            lifecycleLock.withLock {
                if (handle == 0L || closing) throw closedError()
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

    override fun close() {
        val value =
            lifecycleLock.withLock {
                while (closing && handle != 0L) {
                    noActiveOperations.awaitUninterruptibly()
                }
                if (handle == 0L) return
                closing = true
                handle
            }

        lifecycleLock.withLock {
            while (activeOperations != 0) {
                noActiveOperations.awaitUninterruptibly()
            }
            handle = 0L
            closing = false
            noActiveOperations.signalAll()
        }
        closeNative(value)
    }
}
