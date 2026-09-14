package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * The security review's probe: the stored format is strict, with no plaintext fallback (controls 4
 * and 17).
 */
class CipherProbeFormatTest {

  /**
   * A column that still holds plaintext, or a half-finished migration, must be a typed error. A
   * "decrypt, else return the column as it is" fallback is a downgrade oracle and the worst
   * possible half-state: the application keeps working and nothing is encrypted.
   */
  @Test
  void probe_core_reads_a_plaintext_column_as_plaintext() {
    byte[] plaintextColumn = "alice@example.com".getBytes(StandardCharsets.UTF_8);

    assertThatThrownBy(() -> EncryptedValue.decode(plaintextColumn))
        .isInstanceOf(InvalidCiphertextException.class)
        .hasMessageContaining("magic");
  }

  @Test
  void an_unknown_format_version_is_refused() {
    byte[] blob = validBlob();
    blob[3] = (byte) 0x7f;

    assertThatThrownBy(() -> EncryptedValue.decode(blob))
        .isInstanceOf(InvalidCiphertextException.class)
        .hasMessageContaining("format version");
  }

  @Test
  void a_truncated_blob_is_refused() {
    byte[] blob = validBlob();
    byte[] cut = java.util.Arrays.copyOf(blob, blob.length - 1);

    assertThatThrownBy(() -> EncryptedValue.decode(cut))
        .isInstanceOf(InvalidCiphertextException.class);
  }

  @Test
  void trailing_bytes_are_refused() {
    byte[] blob = validBlob();
    byte[] extended = java.util.Arrays.copyOf(blob, blob.length + 1);

    assertThatThrownBy(() -> EncryptedValue.decode(extended))
        .isInstanceOf(InvalidCiphertextException.class)
        .hasMessageContaining("trailing");
  }

  @Test
  void an_empty_column_is_refused() {
    assertThatThrownBy(() -> EncryptedValue.decode(new byte[0]))
        .isInstanceOf(InvalidCiphertextException.class);
  }

  @Test
  void a_well_formed_blob_round_trips() {
    EncryptedValue v = EncryptedValue.decode(validBlob());
    org.assertj.core.api.Assertions.assertThat(v.tenant()).isEqualTo(TenantId.of("acme"));
    org.assertj.core.api.Assertions.assertThat(v.subject()).isEqualTo(SubjectId.of("s-1"));
    org.assertj.core.api.Assertions.assertThat(v.keyVersion()).isEqualTo(3);
    org.assertj.core.api.Assertions.assertThat(v.encode()).isEqualTo(validBlob());
  }

  private static byte[] validBlob() {
    return new EncryptedValue(
            EncryptedValue.FORMAT_VERSION,
            EncryptedValue.ALG_AES_256_GCM,
            3,
            TenantId.of("acme"),
            SubjectId.of("s-1"),
            RowId.ofIdentifier(1L),
            new byte[12],
            new byte[20])
        .encode();
  }
}
