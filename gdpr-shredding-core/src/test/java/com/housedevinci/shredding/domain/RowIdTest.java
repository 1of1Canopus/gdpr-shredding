package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Design §3, Cipher item 7: the row identity bound into every header and every AAD comes from the
 * identifier's column value under a canonical, type-tagged encoding - never {@code toString()},
 * whose output for two different identifier types can coincide ({@code Long 1} and {@code String
 * "1"}), and never a guess for a type this module has not been taught.
 */
class RowIdTest {

  @Test
  void a_numeric_identifier_encodes_as_a_tagged_int64() {
    assertThat(RowId.ofIdentifier(1L).bytes())
        .containsExactly(0x01, 0, 0, 0, 0, 0, 0, 0, 1)
        .isEqualTo(RowId.ofIdentifier(1).bytes());
  }

  /** Cipher item 7: a {@code Long} 1 and a {@code String} "1" must not bind to the same row. */
  @Test
  void two_identifier_types_that_share_a_to_string_do_not_share_a_row_id() {
    assertThat(RowId.ofIdentifier(1L)).isNotEqualTo(RowId.ofIdentifier("1"));
  }

  @Test
  void a_uuid_identifier_encodes_as_its_sixteen_bytes() {
    UUID id = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");
    assertThat(RowId.ofIdentifier(id).bytes()).hasSize(17).startsWith((byte) 0x02);
    assertThat(RowId.ofIdentifier(id)).isEqualTo(RowId.ofIdentifier(id));
  }

  @Test
  void an_unsupported_identifier_type_is_refused_rather_than_guessed() {
    assertThatThrownBy(() -> RowId.ofIdentifier(new Object()))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.CONFIG);
    assertThatThrownBy(() -> RowId.ofIdentifier(null)).isInstanceOf(ShreddingException.class);
  }

  /** Design §3, Cipher item 5: no unbound header exists. */
  @Test
  void an_empty_or_all_zero_row_id_is_refused() {
    assertThatThrownBy(() -> new RowId(new byte[0])).isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new RowId(new byte[8])).isInstanceOf(ShreddingException.class);
    assertThatThrownBy(() -> new RowId(new byte[256])).isInstanceOf(ShreddingException.class);
  }

  /**
   * Design §3.1: the intermediate an {@code IDENTITY} insert binds before the generated key exists.
   * It is random, it is tagged as unbound, and it can never equal a real identifier's encoding, so
   * an intermediate captured by CDC, a trigger or a replica verifies against no row at all.
   */
  @Test
  void an_unbound_intermediate_is_random_tagged_and_matches_no_real_identifier() {
    RowId first = RowId.unboundIntermediate(RandomSource.secure());
    RowId second = RowId.unboundIntermediate(RandomSource.secure());
    assertThat(first.bytes()).hasSize(17).startsWith((byte) 0x7f);
    assertThat(first).isNotEqualTo(second);
    assertThat(first.isUnboundIntermediate()).isTrue();
    assertThat(RowId.ofIdentifier(1L).isUnboundIntermediate()).isFalse();
  }

  /** Never a copy of an identifier, which may itself be personal data. */
  @Test
  void to_string_never_echoes_the_identifier() {
    assertThat(RowId.ofIdentifier("customer-42").toString()).doesNotContain("customer-42");
  }
}
