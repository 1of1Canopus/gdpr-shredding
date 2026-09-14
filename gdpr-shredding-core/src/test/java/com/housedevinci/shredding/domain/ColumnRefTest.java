package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** Design addendum 4, §4.1: the record reproduces the mapping's quoting and invents none. */
class ColumnRefTest {

  @Test
  void an_unquoted_column_renders_bare_so_postgresql_folds_it() {
    assertThat(ColumnRef.unquoted("OWNER_ID").sql()).isEqualTo("OWNER_ID");
    assertThat(ColumnRef.unquoted("owner_id").sql()).isEqualTo("owner_id");
  }

  @Test
  void a_quoted_column_renders_quoted_so_its_case_stays_significant() {
    assertThat(ColumnRef.quoted("Owner").sql()).isEqualTo("\"Owner\"");
    assertThat(ColumnRef.quoted("user").sql()).isEqualTo("\"user\"");
  }

  @Test
  void a_quoted_name_containing_a_dot_stays_whole() {
    assertThat(ColumnRef.quoted("a.b").sql()).isEqualTo("\"a.b\"");
  }

  @Test
  void a_quote_character_in_the_name_is_refused_rather_than_escaped() {
    assertThatThrownBy(() -> ColumnRef.quoted("Ow\"ner"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("double-quote");
  }

  @Test
  void an_unquoted_expression_that_is_not_an_identifier_is_refused() {
    assertThatThrownBy(() -> ColumnRef.unquoted("owner_id || 'x'"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("not a SQL identifier");
    assertThatThrownBy(() -> ColumnRef.unquoted("a.b"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("not a SQL identifier");
  }

  @Test
  void an_empty_or_null_name_is_refused() {
    assertThatThrownBy(() -> ColumnRef.unquoted("")).isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> ColumnRef.unquoted(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void a_control_character_is_refused() {
    assertThatThrownBy(() -> ColumnRef.quoted("own\ner"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("control character");
  }

  @Test
  void a_name_postgresql_would_silently_truncate_is_refused() {
    assertThatThrownBy(() -> ColumnRef.unquoted("a".repeat(64)))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("truncates");
    assertThat(ColumnRef.unquoted("a".repeat(63)).sql()).hasSize(63);
  }

  @Test
  void to_string_shows_the_quoting_so_a_listing_can_be_compared_by_eye() {
    assertThat(ColumnRef.quoted("Owner")).hasToString("\"Owner\"");
    assertThat(ColumnRef.unquoted("owner")).hasToString("owner");
  }
}
