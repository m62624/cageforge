// SPDX-License-Identifier: Apache-2.0

package ai.cageforge;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class JavaApiTest {
    @Test
    void javaCanConstructTheKotlinRuntimeContext() {
        RuntimeContext context = new RuntimeContext(Path.of("/tmp/cageforge-java"));
        assertEquals(Path.of("/tmp/cageforge-java"), context.getCurrentDirectory());
    }
}
