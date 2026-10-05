package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The stored-expression reader of the statistics check, without a database. The trees are the ones
 * PostgreSQL 16.15, 17.11 and 18.6 stored for the fixture's indexes ({@code pg_index.indexprs}),
 * trimmed to the nodes that matter.
 */
class PlannerStatisticsTest {

  private static final String PREFIX_16 =
      "({FUNCEXPR :funcid 2012 :funcresulttype 17 :args ({VAR :varno 1 :varattno 3 :vartype 17"
          + " :vartypmod -1 :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varnosyn 1"
          + " :varattnosyn 3 :location 30} {CONST :consttype 23}) :location 20})";

  private static final String WHOLE_ROW_18 =
      "({FUNCEXPR :funcid 16393 :args ({VAR :varno 1 :varattno 0 :vartype 16387 :vartypmod -1"
          + " :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1"
          + " :varattnosyn 0 :location -1}) :location -1})";

  @Test
  void a_column_reference_is_read_as_its_attnum() {
    assertThat(PlannerStatistics.referencedAttnums(PREFIX_16)).containsExactly(3);
  }

  @Test
  void a_whole_row_reference_is_read_as_zero() {
    assertThat(PlannerStatistics.referencedAttnums(WHOLE_ROW_18)).containsExactly(0);
  }

  @Test
  void an_expression_that_reads_no_column_reads_nothing() {
    assertThat(PlannerStatistics.referencedAttnums("({CONST :consttype 23 :constlen 4})"))
        .isEmpty();
  }

  @Test
  void a_var_node_the_pattern_cannot_read_is_unverifiable_not_an_empty_reference() {
    String moved = PREFIX_16.replace(":varno 1 :varattno 3", ":varattno 3 :varno 1");

    assertThatThrownBy(() -> PlannerStatistics.referencedAttnums(moved))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("1 Var nodes in a stored expression, 0 of them readable");
  }

  @Test
  void attnum_lists_parse_as_int2vector_and_string_agg_print_them() {
    assertThat(PlannerStatistics.attnums("2 3")).containsExactly(2, 3);
    assertThat(PlannerStatistics.attnums(" 4 ")).containsExactly(4);
    assertThat(PlannerStatistics.attnums(null)).isEmpty();
    assertThat(PlannerStatistics.attnums("")).isEmpty();
  }
}
