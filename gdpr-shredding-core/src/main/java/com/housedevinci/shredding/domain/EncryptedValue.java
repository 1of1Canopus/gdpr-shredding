package com.housedevinci.shredding.domain;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * The self-describing binary format stored in the {@code bytea} column (control 4).
 *
 * <pre>
 * offset  len  field
 * 0       3    magic                       0x53 0x48 0x31, "SH1"
 * 3       1    format version              0x02 (v1, 0x01, is refused - see below)
 * 4       1    algorithm id                0x01 = AES-256-GCM, 96-bit nonce, 128-bit tag
 * 5       4    key version                 int32 big-endian, &gt;= 1
 * 9       1    tenant id length in bytes   1..255
 * 10      t    tenant id                   UTF-8
 * 10+t    1    subject id length in bytes  1..255
 * 11+t    s    subject id                  UTF-8
 * 11+t+s  1    row id length in bytes      1..255                        v2
 * 12+t+s  r    row id                      canonical, see {@link RowId}  v2
 * 12+t+s+r  12 nonce
 * 24+t+s+r  4  ciphertext length           int32 big-endian, &gt;= 16
 * 28+t+s+r  n  ciphertext || 16-byte tag
 * </pre>
 *
 * <p><strong>Format v2 (design §3, C-34, Cipher items 5, 7 and 12).</strong> The row id is what
 * stops a ciphertext being moved between two rows of the <em>same</em> subject, which v1 decrypted
 * and displayed: tenant and subject alone made two rows of one person interchangeable. A v1 header
 * is <em>refused</em>, not read - there is no downgrade path and no dual-format reader, because
 * either would let an attacker holding {@code UPDATE} strip the row binding by writing a v1
 * blob.
 *
 * <p>Fixed offsets, no optional sections. The explicit ciphertext length is what makes truncation
 * and trailing bytes structural errors rather than something only GCM authentication would notice.
 * An unknown magic, an unknown version, a truncated blob or trailing bytes is {@link
 * InvalidCiphertextException} ({@link ErrorCodes#FORMAT}), never a best-effort parse and never a
 * plaintext fallback: "decrypt, else return the column as it is" is a downgrade oracle, and it is
 * exactly how a half-finished migration ends up storing personal data in the clear forever (control
 * 17).
 *
 * <p>Tenant and subject travel inside the blob because a Hibernate {@code AttributeConverter} is
 * handed nothing but the column value on the read path. They are re-bound into the AAD on every
 * decrypt, so a blob moved to another row, subject or tenant fails to authenticate.
 */
public record EncryptedValue(
    byte formatVersion,
    byte algId,
    int keyVersion,
    TenantId tenant,
    SubjectId subject,
    RowId rowId,
    byte[] nonce,
    byte[] ciphertext) {

  public static final byte[] MAGIC = {'S', 'H', '1'};

  /** The only format this module writes or reads. */
  public static final byte FORMAT_VERSION = 0x02;

  /** Row-blind, and therefore refused rather than read (Cipher item 12). */
  public static final byte FORMAT_VERSION_V1_UNBOUND = 0x01;
  public static final byte ALG_AES_256_GCM = 0x01;
  public static final int NONCE_BYTES = 12;
  public static final int TAG_BYTES = 16;

  private static final int HEADER_FIXED = 3 + 1 + 1 + 4;

  public EncryptedValue {
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(rowId, "rowId");
    nonce = Objects.requireNonNull(nonce, "nonce").clone();
    ciphertext = Objects.requireNonNull(ciphertext, "ciphertext").clone();
    if (formatVersion != FORMAT_VERSION) {
      throw new InvalidCiphertextException(unsupportedVersion(formatVersion));
    }
    if (algId != ALG_AES_256_GCM) {
      throw new InvalidCiphertextException("unsupported algorithm id 0x" + hex(algId));
    }
    if (keyVersion < 1) {
      throw new InvalidCiphertextException("key version must be >= 1, was " + keyVersion);
    }
    if (nonce.length != NONCE_BYTES) {
      throw new InvalidCiphertextException("nonce must be " + NONCE_BYTES + " bytes");
    }
    if (ciphertext.length < TAG_BYTES) {
      throw new InvalidCiphertextException(
          "ciphertext must carry at least a " + TAG_BYTES + "-byte tag");
    }
  }

  @Override
  public byte[] nonce() {
    return nonce.clone();
  }

  @Override
  public byte[] ciphertext() {
    return ciphertext.clone();
  }

  public byte[] encode() {
    byte[] t = tenant.value().getBytes(StandardCharsets.UTF_8);
    byte[] s = subject.value().getBytes(StandardCharsets.UTF_8);
    ByteBuffer buf =
        ByteBuffer.allocate(
            HEADER_FIXED
                + 1
                + t.length
                + 1
                + s.length
                + 1
                + rowId.bytes().length
                + NONCE_BYTES
                + 4
                + ciphertext.length);
    buf.put(MAGIC).put(formatVersion).put(algId).putInt(keyVersion);
    buf.put((byte) t.length).put(t);
    buf.put((byte) s.length).put(s);
    byte[] r = rowId.bytes();
    buf.put((byte) r.length).put(r);
    buf.put(nonce).putInt(ciphertext.length).put(ciphertext);
    return buf.array();
  }

  /** Parses stored bytes, or fails. There is no lenient mode and no plaintext fallback. */
  public static EncryptedValue decode(byte[] stored) {
    Objects.requireNonNull(stored, "stored");
    if (stored.length < 3 || !Arrays.equals(Arrays.copyOf(stored, 3), MAGIC)) {
      throw new InvalidCiphertextException(
          "stored value does not start with the SH1 magic; core refuses to read a column that is"
              + " not in the encrypted format (see SHRED-FORMAT-001 in docs/index.md)");
    }
    if (stored.length < HEADER_FIXED + 3 + NONCE_BYTES + 4 + TAG_BYTES) {
      throw new InvalidCiphertextException(
          "stored value is " + stored.length + " bytes, too short to be an encrypted value");
    }
    ByteBuffer buf = ByteBuffer.wrap(stored);
    buf.position(3);
    byte version = buf.get();
    if (version != FORMAT_VERSION) {
      throw new InvalidCiphertextException(unsupportedVersion(version));
    }
    byte alg = buf.get();
    int keyVersion = buf.getInt();
    String tenant = readString(buf, "tenant id");
    String subject = readString(buf, "subject id");
    RowId rowId = new RowId(readBytes(buf, "row id"));
    if (buf.remaining() < NONCE_BYTES + 4) {
      throw new InvalidCiphertextException("stored value is truncated after the header");
    }
    byte[] nonce = new byte[NONCE_BYTES];
    buf.get(nonce);
    int ciphertextLength = buf.getInt();
    if (ciphertextLength < TAG_BYTES || ciphertextLength > buf.remaining()) {
      throw new InvalidCiphertextException(
          "stored value declares a "
              + ciphertextLength
              + "-byte ciphertext but carries "
              + buf.remaining()
              + "; the value is truncated or the length field is corrupt");
    }
    byte[] ciphertext = new byte[ciphertextLength];
    buf.get(ciphertext);
    if (buf.hasRemaining()) {
      throw new InvalidCiphertextException(
          "stored value has " + buf.remaining() + " trailing bytes after the ciphertext");
    }
    var value =
        new EncryptedValue(
            version,
            alg,
            keyVersion,
            TenantId.of(tenant),
            SubjectId.of(subject),
            rowId,
            nonce,
            ciphertext);
    // Re-encode and compare: the parse must be exactly reversible, so a field that re-serialises
    // differently from how it was read (a non-canonical length prefix, say) is refused too.
    if (!Arrays.equals(value.encode(), stored)) {
      throw new InvalidCiphertextException("stored value has trailing or non-canonical bytes");
    }
    return value;
  }

  /**
   * Cipher item 12: a v1 blob is refused with the same code an unknown magic gets. Naming the
   * version in the message, and nothing else about the value, is what lets an operator tell a
   * pre-v2 row apart from corruption without a second tool.
   */
  private static String unsupportedVersion(byte version) {
    if (version == FORMAT_VERSION_V1_UNBOUND) {
      return "stored value is in format v1, which binds no row identity and is refused rather than"
          + " read: a v1 blob can be moved between two rows of the same subject and still"
          + " authenticate. Re-encrypt the column through the application before upgrading.";
    }
    return "unsupported format version 0x" + hex(version);
  }

  private static byte[] readBytes(ByteBuffer buf, String what) {
    if (!buf.hasRemaining()) {
      throw new InvalidCiphertextException("stored value is truncated before the " + what);
    }
    int len = buf.get() & 0xff;
    if (len == 0) {
      throw new InvalidCiphertextException(what + " must not be empty");
    }
    if (buf.remaining() < len) {
      throw new InvalidCiphertextException("stored value is truncated inside the " + what);
    }
    byte[] raw = new byte[len];
    buf.get(raw);
    return raw;
  }

  private static String readString(ByteBuffer buf, String what) {
    byte[] raw = readBytes(buf, what);
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(raw))
          .toString();
    } catch (CharacterCodingException e) {
      throw new InvalidCiphertextException(what + " is not valid UTF-8");
    }
  }

  private static String hex(byte b) {
    return String.format("%02x", b);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof EncryptedValue v && Arrays.equals(encode(), v.encode());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encode());
  }

  /** Never prints ciphertext or identifiers beyond the key version. */
  @Override
  public String toString() {
    return "EncryptedValue[v" + formatVersion + " alg" + algId + " key v" + keyVersion + "]";
  }
}
