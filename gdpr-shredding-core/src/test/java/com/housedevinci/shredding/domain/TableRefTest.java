package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Design addendum 3, change 9 (§3.9a). The table one statement names, parsed from Hibernate's own
 * table expression and rendered qualified, so what a statement hits is the mapping's decision and
 * not the runtime connection's {@code search_path} (S-21).
 */
class TableRefTest {

  @Test
  void an_unqualified_expression_parses_to_a_name_with_no_schema() {
    TableRef ref = TableRef.parse("owned_note");

    assertThat(ref.schema()).isEmpty();
    assertThat(ref.name()).isEqualTo("owned_note");
    assertThat(ref.sql()).isEqualTo("\"owned_note\"");
    assertThat(ref).hasToString("owned_note");
  }

  @Test
  void a_schema_qualified_expression_is_rendered_quoted_per_part() {
    TableRef ref = TableRef.parse("app2.schema_note");

    assertThat(ref.schema()).contains("app2");
    assertThat(ref.sql()).isEqualTo("\"app2\".\"schema_note\"");
    assertThat(ref).hasToString("app2.schema_note");
  }

  @Test
  void quoted_parts_are_unquoted_before_they_are_rendered_again() {
    assertThat(TableRef.parse("\"app2\".\"schema_note\"").sql())
        .isEqualTo("\"app2\".\"schema_note\"");
    assertThat(TableRef.parse("`app2`.`schema_note`").sql()).isEqualTo("\"app2\".\"schema_note\"");
  }

  /**
   * The K1 failure mode this type exists to make impossible, at the level of one value: two tables
   * of the same name in different schemas are two different {@code TableRef}s and two different
   * statements.
   */
  @Test
  void a_same_named_table_in_another_schema_is_a_different_reference() {
    assertThat(TableRef.parse("app2.schema_note")).isNotEqualTo(TableRef.parse("schema_note"));
    assertThat(TableRef.parse("app2.schema_note"))
        .isNotEqualTo(TableRef.parse("public.schema_note"));
  }

  /**
   * Refused rather than lowercased: in PostgreSQL a quoted mixed-case name and its folded form are
   * two different tables, and this module renders every identifier quoted.
   */
  @Test
  void a_mixed_case_identifier_is_refused_and_says_why() {
    assertThatThrownBy(() -> TableRef.parse("\"Order\""))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("not folded lowercase")
        .hasMessageContaining("order");
  }

  @Test
  void a_catalog_qualified_expression_is_refused_rather_than_reduced() {
    assertThatThrownBy(() -> TableRef.parse("cat.app2.schema_note"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("3 parts");
  }

  @Test
  void a_name_outside_the_identifier_pattern_is_refused() {
    assertThatThrownBy(() -> TableRef.parse("note; drop table shredding_erasure"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("SQL identifier");
    assertThatThrownBy(() -> TableRef.parse("  "))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("null or blank");
    assertThatThrownBy(() -> new TableRef(Optional.of("bad-schema"), "note"))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("schema");
  }
}
