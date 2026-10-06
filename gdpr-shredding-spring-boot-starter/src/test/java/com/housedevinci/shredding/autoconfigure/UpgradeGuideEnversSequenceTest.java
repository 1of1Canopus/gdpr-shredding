package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Security review C-25-3: the upgrade guide gives the Envers refusal sequence in the order startup
 * meets it as a running 0.1.1 install meets it (RC2-1): the schema-less mapping, the audited blind
 * index, mapping admission, the catalogue in one message, then a trigger alone.
 */
class UpgradeGuideEnversSequenceTest {

  @Test
  void the_envers_sequence_is_in_startup_order() throws Exception {
    String guide = Files.readString(Path.of("..", "docs", "upgrading-0.2.0.md"));
    int start = guide.indexOf("**A 0.1.1 installation with Hibernate Envers meets these refusals");
    assertThat(start).isPositive();
    String paragraph = guide.substring(start, guide.indexOf("\n\n", start)).replaceAll("\\s+", " ");

    assertThat(paragraph)
        .containsSubsequence(
            "1. `SHRED-CONFIG-001`, a mapping that names no schema",
            "2. `SHRED-SCHEMA-010` from the mapping",
            "3. `SHRED-SCHEMA-009`",
            "4. `SHRED-SCHEMA-010` from the catalogue",
            "_aud",
            "planner statistics",
            "5. `SHRED-SCHEMA-010` for a trigger alone");
  }
}
