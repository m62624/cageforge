// SPDX-License-Identifier: Apache-2.0

package ai.cageforge;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class JavaApiTest {
    @Test
    void javaCanConstructTheKotlinRuntimeContext() {
        Path runtimeDirectory = Path.of(System.getProperty("java.io.tmpdir"), "cageforge-java");
        RuntimeContext context = new RuntimeContext(runtimeDirectory);
        assertEquals(runtimeDirectory, context.getCurrentDirectory());
    }
}
