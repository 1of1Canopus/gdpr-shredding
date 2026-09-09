package com.housedevinci.shredding.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Design §3: format {@code SH1} v2 carries the row id, and a v1 header is refused rather than read
 * (Cipher item 12).
 */
class EncryptedValueV2Test {

  private static final TenantId TENANT = TenantId.of("acme");
  private static final SubjectId SUBJECT = SubjectId.of("s-1");

  @Test
  void a_v2_blob_round_trips_its_row_id() {
    RowId row = RowId.ofIdentifier(4242L);
    byte[] encoded = value(row).encode();

    var decoded = EncryptedValue.decode(encoded);

    assertThat(decoded.formatVersion()).isEqualTo((byte) 0x02);
    assertThat(decoded.rowId()).isEqualTo(row);
    assertThat(decoded.encode()).isEqualTo(encoded);
  }

  @Test
  void two_rows_of_one_subject_do_not_share_a_stored_header() {
    assertThat(value(RowId.ofIdentifier(1L)).encode())
        .isNotEqualTo(value(RowId.ofIdentifier(2L)).encode());
  }

  /**
   * Cipher item 12. There is no dual-format reader and no downgrade: either would let an attacker
   * holding {@code UPDATE} strip the row binding by writing a v1 blob over a v2 one.
   */
  @Test
  void a_v1_header_is_refused_not_ignored() {
    byte[] v1 = v1Blob();

    assertThatThrownBy(() -> EncryptedValue.decode(v1))
        .isInstanceOf(InvalidCiphertextException.class)
        .hasMessageContaining("v1")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.FORMAT);
  }

  @Test
  void a_header_whose_row_id_is_absent_or_zero_never_decodes() {
    assertThatThrownBy(() -> EncryptedValue.decode(blobWithRowIdBytes(new byte[0])))
        .isInstanceOf(InvalidCiphertextException.class);
    assertThatThrownBy(() -> EncryptedValue.decode(blobWithRowIdBytes(new byte[9])))
        .isInstanceOf(ShreddingException.class);
  }

  private static EncryptedValue value(RowId row) {
    return new EncryptedValue(
        EncryptedValue.FORMAT_VERSION,
        EncryptedValue.ALG_AES_256_GCM,
        3,
        TENANT,
        SUBJECT,
        row,
        new byte[12],
        new byte[20]);
  }

  /** The exact bytes the pre-v2 encoder produced: no row id section at all. */
  private static byte[] v1Blob() {
    byte[] t = "acme".getBytes(StandardCharsets.UTF_8);
    byte[] s = "s-1".getBytes(StandardCharsets.UTF_8);
    return ByteBuffer.allocate(9 + 1 + t.length + 1 + s.length + 12 + 4 + 20)
        .put(EncryptedValue.MAGIC)
        .put(EncryptedValue.FORMAT_VERSION_V1_UNBOUND)
        .put(EncryptedValue.ALG_AES_256_GCM)
        .putInt(3)
        .put((byte) t.length)
        .put(t)
        .put((byte) s.length)
        .put(s)
        .put(new byte[12])
        .putInt(20)
        .put(new byte[20])
        .array();
  }

  private static byte[] blobWithRowIdBytes(byte[] rowIdBytes) {
    byte[] t = "acme".getBytes(StandardCharsets.UTF_8);
    byte[] s = "s-1".getBytes(StandardCharsets.UTF_8);
    return ByteBuffer.allocate(
            9 + 1 + t.length + 1 + s.length + 1 + rowIdBytes.length + 12 + 4 + 20)
        .put(EncryptedValue.MAGIC)
        .put(EncryptedValue.FORMAT_VERSION)
        .put(EncryptedValue.ALG_AES_256_GCM)
        .putInt(3)
        .put((byte) t.length)
        .put(t)
        .put((byte) s.length)
        .put(s)
        .put((byte) rowIdBytes.length)
        .put(rowIdBytes)
        .put(new byte[12])
        .putInt(20)
        .put(new byte[20])
        .array();
  }
}
