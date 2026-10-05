package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Security review, PR 18 (feat/read-back-bracket), second pass. RED on 1bf1d52.
 *
 * <p>Copy into gdpr-shredding-core/src/test/java/com/housedevinci/shredding/adapter/jdbc/ before
 * touching anything else. No production code changes for this finding.
 */
class CipherProbePr18SecondPassTest {

  /** The module root, wherever surefire runs from (module dir or reactor root). */
  private static Path moduleRoot() {
    Path here = Path.of("").toAbsolutePath();
    return Files.exists(here.resolve("SECURITY-NOTES.md")) ? here : here.getParent();
  }

  private static String read(String relative) throws IOException {
    return Files.readString(moduleRoot().resolve(relative), StandardCharsets.UTF_8);
  }

  /**
   * C-18-7 (INFO). C-18-6 took the cross-tenant WARN count out of the window, and C-A-6 had already
   * removed its IS DISTINCT FROM spelling. Two window probes still describe both as the current
   * production statement: one says its SQL shape "is the one verifyCleared builds", the other that
   * the count "gets its own window" and that "the second window" must not change the erasure. A
   * reader of the suite is told a statement is covered by a control it no longer runs under. The
   * production side is checked first, so this probe stays meaningful if the code moves again.
   */
  @Test
  void probe_no_window_probe_describes_the_removed_cross_tenant_window_as_current()
      throws IOException {
    String store =
        read(
            "gdpr-shredding-core/src/main/java/com/housedevinci/shredding/adapter/jdbc/JdbcErasureStore.java");
    assertThat(store)
        .describedAs(
            "precondition: production holds exactly one window, around the framework count")
        .containsOnlyOnce("inOneStatementWindow(");

    String core =
        read(
            "gdpr-shredding-core/src/test/java/com/housedevinci/shredding/adapter/jdbc/CipherProbeWindowPr14Test.java");
    String starter =
        read(
            "gdpr-shredding-spring-boot-starter/src/test/java/com/housedevinci/shredding/autoconfigure/CipherProbeWindowPr14StarterTest.java");

    assertThat(core.replaceAll("\\s*\\*\\s*", " "))
        .describedAs(
            "CipherProbeWindowPr14Test: the IS DISTINCT FROM shape is a historical statement measured"
                + " for the window's own property, not the one verifyCleared builds (C-A-6, C-18-6)")
        .doesNotContain("The shape below is the one {@code verifyCleared} builds")
        .doesNotContain("cross-tenant WARN count's {@code IS DISTINCT FROM} reaches");
    assertThat(starter.replaceAll("\\s*\\*\\s*", " "))
        .describedAs(
            "CipherProbeWindowPr14StarterTest: the cross-tenant WARN count runs outside any window"
                + " since C-18-6")
        .doesNotContain("which gets its own window")
        .doesNotContain("the second window must not change");
  }
}
