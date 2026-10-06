package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * C-26-2 for leg M: the remedy a mapping-derived {@code SHRED-SCHEMA-010} prints names the audit or
 * history table and column as the mapping renders them, which is free text; both are escaped where
 * they are inserted, so the message stays one line; the statement itself is spelled as SQL (RC2-2).
 */
class CopyMessageEscapeTest {

  @Test
  void clear_remedy_escapes_the_rendered_table_and_column() {
    assertThat(HibernateCopyCheck.clear("public.\"note\naud\"", "\"idx x\""))
        .isEqualTo(
            "UPDATE public.U&\"note\\000Aaud\" SET U&\"idx\\2028x\" = NULL; ALTER TABLE"
                + " public.U&\"note\\000Aaud\" DROP COLUMN U&\"idx\\2028x\".");
    assertThat(HibernateCopyCheck.clear("public.note_aud", "email_idx"))
        .isEqualTo(
            "UPDATE public.note_aud SET email_idx = NULL; ALTER TABLE public.note_aud DROP COLUMN"
                + " email_idx.");
  }
}
