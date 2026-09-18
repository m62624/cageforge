// SPDX-License-Identifier: Apache-2.0

package ai.cageforge

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeHandleTest {
    @Test
    fun closeWaitsForNativeWorkAndRejectsLaterUse() {
        val operationStarted = CountDownLatch(1)
        val releaseOperation = CountDownLatch(1)
        val closeFinished = CountDownLatch(1)
        val nativeClosed = CountDownLatch(1)
        val handle =
            NativeHandle(
                1L,
                { nativeClosed.countDown() },
                { CageforgeException("closed") },
            )

        val worker =
            Thread {
                handle.use {
                    operationStarted.countDown()
                    assertTrue(releaseOperation.await(1, TimeUnit.SECONDS))
                }
            }
        worker.start()
        assertTrue(operationStarted.await(1, TimeUnit.SECONDS))

        Thread {
            handle.close()
            closeFinished.countDown()
        }.start()
        assertFalse(closeFinished.await(100, TimeUnit.MILLISECONDS))

        releaseOperation.countDown()
        assertTrue(closeFinished.await(1, TimeUnit.SECONDS))
        assertTrue(nativeClosed.await(1, TimeUnit.SECONDS))
        worker.join(1_000)
        assertFailsWith<CageforgeException> { handle.use {} }
    }
}
