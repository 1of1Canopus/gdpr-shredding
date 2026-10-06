package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Release-candidate pass 2 (0.2.0, head 333a4a1), finding RC2-2: the open point of PR 26. C-26-3
 * moved every remedy statement the core prints to {@code JdbcSupport.sqlIdentifier} (exact, one
 * line, {@code U&"..."} for a control character). The starter's mapping leg still prints its "clear
 * and drop" statement through {@code LogText.escape}: a quoted mapping name holding a line break is
 * printed as {@code "a\u000Ab_aud"}, which PostgreSQL reads as a different identifier, the literal
 * backslash sequence. Run as printed, the UPDATE and the DROP COLUMN address another relation (a
 * decoy if one exists) or fail; the real audit table keeps the copies. Startup refuses again, so no
 * erasure runs over the copy: fail closed, LOW, same class and fix as C-26-3.
 */
class CipherProbeRc2PrintedStatementTest {

  @Test
  void probe_mapping_leg_clear_statement_prints_a_quoted_name_as_log_text() {
    String printed = HibernateCopyCheck.clear("public.\"a\nb_aud\"", "email_idx");
    assertThat(printed).doesNotContain("\n");
    assertThat(printed)
        .as("the statement must name the mapped relation exactly, in U&\"...\" form")
        .doesNotContain("\"a\\u000Ab_aud\"")
        .contains("U&\"a\\000Ab_aud\"");
  }
}
