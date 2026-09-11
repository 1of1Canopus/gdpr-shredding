package com.housedevinci.shredding.domain;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * The row a stored value belongs to (design §3, C-34).
 *
 * <p>The primary key is the only row identity an attacker holding {@code UPDATE} on the table
 * cannot forge: any extra binding column travels with the ciphertext they copy. So the identifier
 * goes into the stored header and into the AAD, and a ciphertext moved between two rows of the same
 * subject - which every earlier version of this module decrypted and displayed - fails to
 * authenticate.
 *
 * <p><strong>The bytes come from the identifier's column value, never {@code toString()}</strong>
 * (finding item 7). {@code Long 1} and {@code String "1"} have the same {@code toString()} and are
 * different rows of different tables; a one-byte type tag in front of a canonical encoding keeps
 * them apart, and an identifier type this module has not been taught is refused at startup rather
 * than encoded by a guess.
 *
 * <table>
 *   <caption>Encoding</caption>
 *   <tr><th>tag</th><th>identifier</th><th>bytes</th></tr>
 *   <tr><td>0x01</td><td>{@code Long}/{@code Integer}/{@code Short}/{@code Byte}</td><td>int64 big-endian</td></tr>
 *   <tr><td>0x02</td><td>{@code UUID}</td><td>16 bytes, msb then lsb</td></tr>
 *   <tr><td>0x03</td><td>{@code String}</td><td>UTF-8</td></tr>
 *   <tr><td>0x04</td><td>{@code byte[]}</td><td>as stored</td></tr>
 *   <tr><td>0x7f</td><td>unbound intermediate</td><td>16 random bytes</td></tr>
 * </table>
 */
public record RowId(byte[] bytes) {

  /** A tag that belongs to no real identifier: an {@code IDENTITY} insert's intermediate. */
  public static final byte TAG_UNBOUND = 0x7f;

  private static final byte TAG_INTEGRAL = 0x01;
  private static final byte TAG_UUID = 0x02;
  private static final byte TAG_STRING = 0x03;
  private static final byte TAG_BYTES = 0x04;

  /** Bytes, not characters: the value is length-prefixed into a one-byte field in the blob. */
  public static final int MAX_BYTES = 255;

  public RowId {
    Objects.requireNonNull(bytes, "bytes");
    if (bytes.length == 0) {
      // finding item 5: no unbound header exists. A zero-length row id in a v2 header that still
      // verified would reopen C-34 for anyone holding UPDATE.
      throw new ShreddingException(ErrorCodes.INVALID, "a row id must not be empty");
    }
    if (bytes.length > MAX_BYTES) {
      throw new ShreddingException(
          ErrorCodes.INVALID, "a row id is " + bytes.length + " bytes, max " + MAX_BYTES);
    }
    boolean allZero = true;
    for (byte b : bytes) {
      if (b != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      throw new ShreddingException(ErrorCodes.INVALID, "a row id must not be all zero bytes");
    }
    bytes = bytes.clone();
  }

  @Override
  public byte[] bytes() {
    return bytes.clone();
  }

  /** The canonical encoding of an entity's identifier value. */
  public static RowId ofIdentifier(Object identifier) {
    if (identifier == null) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "a @Shredded row was bound with no identifier at all. Every shredded value is bound to"
              + " the row it belongs to; with no identifier there is nothing to bind it to.");
    }
    if (identifier instanceof Long
        || identifier instanceof Integer
        || identifier instanceof Short
        || identifier instanceof Byte) {
      return new RowId(
          ByteBuffer.allocate(9)
              .put(TAG_INTEGRAL)
              .putLong(((Number) identifier).longValue())
              .array());
    }
    if (identifier instanceof UUID uuid) {
      return new RowId(
          ByteBuffer.allocate(17)
              .put(TAG_UUID)
              .putLong(uuid.getMostSignificantBits())
              .putLong(uuid.getLeastSignificantBits())
              .array());
    }
    if (identifier instanceof String s) {
      byte[] raw = s.getBytes(StandardCharsets.UTF_8);
      return new RowId(ByteBuffer.allocate(1 + raw.length).put(TAG_STRING).put(raw).array());
    }
    if (identifier instanceof byte[] raw) {
      return new RowId(ByteBuffer.allocate(1 + raw.length).put(TAG_BYTES).put(raw).array());
    }
    throw new ShreddingException(
        ErrorCodes.CONFIG,
        "a @Shredded entity has an identifier of type "
            + identifier.getClass().getName()
            + ", which this module cannot bind a stored value to. Every shredded value is bound to"
            + " its row's identifier, and an identifier whose canonical byte form is unknown would"
            + " have to be guessed. Supported: a numeric id, a UUID, a String or a byte[].");
  }

  /**
   * Design §3.1: what an {@code IDENTITY} insert binds before the generated key exists. Random, so
   * it is unguessable, and tagged so it matches no real identifier's encoding - an intermediate
   * captured by change data capture, a trigger or a physical replica is bound to no row and
   * verifies nowhere.
   */
  public static RowId unboundIntermediate(RandomSource random) {
    byte[] value = new byte[16];
    random.nextBytes(value);
    // A 128-bit random value that is all zero is not worth a retry loop, but it must not trip the
    // all-zero refusal above either.
    value[0] |= 0x01;
    return new RowId(ByteBuffer.allocate(17).put(TAG_UNBOUND).put(value).array());
  }

  public boolean isUnboundIntermediate() {
    return bytes[0] == TAG_UNBOUND;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof RowId other && Arrays.equals(bytes, other.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  /** Never the identifier itself, which is often personal data in its own right. */
  @Override
  public String toString() {
    return "RowId[tag 0x" + String.format("%02x", bytes[0]) + ", " + bytes.length + " bytes]";
  }
}
