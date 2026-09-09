package com.housedevinci.shredding.jpa;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.time.LocalDate;

/**
 * What {@code convertToEntityAttribute} returns instead of plaintext (design §1.1).
 *
 * <p>The converter is blind - no session, no entity, no row - so it cannot verify the value it just
 * decrypted against the row it came from. Rather than hand the plaintext out and hope a verifier
 * runs, it files the plaintext in the read region and returns one of these markers; {@code
 * ShreddingEventListener.onPostLoad}, the one hook that knows the row, verifies and then installs
 * the real value over the marker.
 *
 * <p><strong>Never {@code null}</strong> (Cipher item 2). A {@code null} placeholder for a type
 * with no sentinel - {@code LocalDate}, {@code BigDecimal}, a JSON column - is silent destruction:
 * an entity whose install never ran would hold {@code null} in the field <em>and</em> in the
 * persistence context's loaded state, and the next ordinary (non-{@code @DynamicUpdate}) UPDATE
 * would write {@code NULL} over a live ciphertext with nothing to notice it. A non-null marker
 * turns that same write into {@code SHRED-PLACEHOLDER-001}.
 *
 * <p><strong>Compared by reference identity, never by {@code equals}</strong> (Cipher items 2, 3).
 * The string marker carries 128 bits drawn once per JVM run, so an attacker holding {@code UPDATE}
 * cannot store a value that reads back as a placeholder - and even a lucky guess would be an
 * equal-but-distinct instance, which {@link #isPlaceholder} does not accept. The rendering is ASCII
 * only, with no control character and no {@code %}, {@code &#123;} or {@code &#125;}, so it is safe
 * to drop into a log format string or an exception message.
 */
public final class Placeholders {

  private static final String TOKEN = randomToken();

  /** {@code String} and JSON columns. */
  public static final String STRING = "[SHRED-PLACEHOLDER-" + TOKEN + "]";

  /** {@code byte[]} columns. */
  public static final byte[] BYTES = randomBytes();

  /**
   * {@code LocalDate} columns. A date no application writes, and in any case this exact instance -
   * an equal {@code LocalDate.MIN} obtained elsewhere is not this object.
   */
  public static final LocalDate LOCAL_DATE = LocalDate.of(-999_999_999, 1, 1);

  /** {@code BigDecimal} columns. Same rule: this instance, not this value. */
  public static final BigDecimal BIG_DECIMAL = new BigDecimal("-0.00000000000000000000000000001");

  private Placeholders() {}

  /**
   * Reference identity against every marker. Used by the converter before it encrypts anything and
   * by the {@code Pre*} listeners on the state array, before the blind indexes are written.
   */
  public static boolean isPlaceholder(Object value) {
    return value == STRING || value == BYTES || value == LOCAL_DATE || value == BIG_DECIMAL;
  }

  /** The marker's rendering, for a message that has to name it without printing a real value. */
  public static String describe() {
    return STRING;
  }

  private static String randomToken() {
    byte[] raw = new byte[16];
    new SecureRandom().nextBytes(raw);
    var sb = new StringBuilder(32);
    for (byte b : raw) {
      sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
    }
    return sb.toString();
  }

  private static byte[] randomBytes() {
    byte[] raw = new byte[16];
    new SecureRandom().nextBytes(raw);
    return raw;
  }
}
