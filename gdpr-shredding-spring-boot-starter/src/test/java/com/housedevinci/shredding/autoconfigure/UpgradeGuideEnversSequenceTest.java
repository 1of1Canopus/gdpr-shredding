package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Security review C-25-3: the upgrade guide gives the Envers refusal sequence in the order startup
 * meets it (model scan: audited ciphertext, then audited blind index; then the listener check; then
 * mapping admission; then the catalogue copies with the statistics).
 */
class UpgradeGuideEnversSequenceTest {

  @Test
  void the_envers_sequence_is_in_startup_order() throws Exception {
    String guide = Files.readString(Path.of("..", "docs", "upgrading-0.2.0.md"));
    int start = guide.indexOf("**A 0.1.x installation with Hibernate Envers meets these refusals");
    assertThat(start).isPositive();
    String paragraph = guide.substring(start, guide.indexOf("\n\n", start));

    assertThat(paragraph)
        .containsSubsequence(
            "1. `SHRED-CONFIG-001`, Envers audits a `@Shredded`",
            "2. `SHRED-SCHEMA-010` from the mapping",
            "3. `SHRED-CONFIG-001`,",
            "autoRegisterListeners=false",
            "4. `SHRED-SCHEMA-009`",
            "5. `SHRED-SCHEMA-010` from the catalogue",
            "_aud",
            "planner statistics");
  }
}
