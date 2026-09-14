package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.adapter.memory.InMemoryKeyProvider;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * C-34, design §3: the row is part of the AAD, so two rows of the <strong>same</strong> subject no
 * longer hold interchangeable ciphertexts. Every earlier version of this module decrypted and
 * displayed a value copied between two rows of one person, because tenant and subject were the
 * finest grain the AAD had.
 */
class FieldCipherRowBindingTest {

  private static final TenantId TENANT = TenantId.of("acme");
  private static final SubjectId SUBJECT = SubjectId.of("s-1");
  private static final RowId ROW_A = RowId.ofIdentifier(1L);
  private static final RowId ROW_B = RowId.ofIdentifier(2L);
  private static final byte[] PLAINTEXT = "alice@example.com".getBytes(StandardCharsets.UTF_8);

  private FieldCipher cipher;

  @BeforeEach
  void setUp() {
    cipher =
        new FieldCipher(
            new InMemoryKeyProvider(RandomSource.secure(), true),
            new DataKeyCache(Duration.ofSeconds(60), 100, Clock.systemUTC()),
            RandomSource.secure(),
            FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY);
  }

  @Test
  void a_value_decrypts_under_the_row_it_was_written_for() {
    byte[] stored = cipher.encrypt(TENANT, SUBJECT, ROW_A, "Customer", "email", PLAINTEXT);

    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL))
        .hasValueSatisfying(p -> assertThat(p).isEqualTo(PLAINTEXT));
    assertThat(EncryptedValue.decode(stored).rowId()).isEqualTo(ROW_A);
  }

  /**
   * The attack C-34 demonstrated: an attacker holding {@code UPDATE} copies row A's column into row
   * B. Both headers still name the same subject and the same tenant. The row id in the header - and
   * therefore in the AAD - is what makes the copy detectable at all; the row-level refusal that
   * uses it lives in {@code ShreddingEventListener.onPostLoad}, and the header itself is what it
   * reads.
   */
  @Test
  void a_ciphertext_copied_into_another_row_of_the_same_subject_is_visible_in_its_header() {
    byte[] storedForA = cipher.encrypt(TENANT, SUBJECT, ROW_A, "Customer", "email", PLAINTEXT);
    byte[] storedForB = cipher.encrypt(TENANT, SUBJECT, ROW_B, "Customer", "email", PLAINTEXT);

    assertThat(EncryptedValue.decode(storedForA).rowId())
        .isNotEqualTo(EncryptedValue.decode(storedForB).rowId());
  }

  /**
   * And the AAD binding, so relabelling the header to claim the other row - the only way to make
   * the copy pass a header comparison - breaks authentication instead.
   */
  @Test
  void relabelling_a_header_to_claim_another_row_fails_authentication() {
    byte[] storedForA = cipher.encrypt(TENANT, SUBJECT, ROW_A, "Customer", "email", PLAINTEXT);
    var a = EncryptedValue.decode(storedForA);
    byte[] relabelled =
        new EncryptedValue(
                a.formatVersion(),
                a.algId(),
                a.keyVersion(),
                a.tenant(),
                a.subject(),
                ROW_B,
                a.nonce(),
                a.ciphertext())
            .encode();

    assertThatThrownBy(
            () -> cipher.decrypt("Customer", "email", relabelled, ErasedValuePolicy.SENTINEL))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.DECRYPT);
  }

  /** Design §3.1: an {@code IDENTITY} intermediate authenticates, but names no row. */
  @Test
  void an_unbound_intermediate_authenticates_but_matches_no_real_identifier() {
    RowId intermediate = RowId.unboundIntermediate(RandomSource.secure());
    byte[] stored = cipher.encrypt(TENANT, SUBJECT, intermediate, "Customer", "email", PLAINTEXT);

    assertThat(cipher.decrypt("Customer", "email", stored, ErasedValuePolicy.SENTINEL)).isPresent();
    assertThat(EncryptedValue.decode(stored).rowId().isUnboundIntermediate()).isTrue();
    assertThat(EncryptedValue.decode(stored).rowId()).isNotEqualTo(ROW_A);
  }
}
