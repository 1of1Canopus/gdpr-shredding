package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The pure parts of the catalogue leg, without a database. */
class CopyCatalogueTest {

  /** S-7: a publication's NULL column list is every column (PostgreSQL 15's form). */
  @Test
  void a_null_column_list_carries_the_index() {
    assertThat(CopyCatalogue.carried(List.of(4), null)).isEqualTo(Optional.of(4));
  }

  @Test
  void a_column_list_without_the_index_carries_nothing() {
    assertThat(CopyCatalogue.carried(List.of(4), "1 2 3")).isEmpty();
  }

  @Test
  void a_column_list_with_the_index_carries_it() {
    assertThat(CopyCatalogue.carried(List.of(4, 7), "1 7")).isEqualTo(Optional.of(7));
  }

  @Test
  void array_and_int2vector_text_forms_parse() {
    assertThat(CopyCatalogue.attnums("{3,4}")).containsExactly(3, 4);
    assertThat(CopyCatalogue.attnums("3 4")).containsExactly(3, 4);
    assertThat(CopyCatalogue.attnums("")).isEmpty();
  }
}
