package com.housedevinci.shredding.jpa;

import java.math.BigDecimal;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Arrays;

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
 * <p><strong>Matched by value as well as by reference identity</strong> (Cipher items 2, 3; S-3,
 * Cipher sixth pass). An attacker holding {@code UPDATE} still cannot store a value that reads back
 * as a placeholder - that would need a ciphertext of the marker under the subject's own data key,
 * which no amount of {@code UPDATE} gives them, and is exactly the residual {@code
 * a_forged_placeholder_in_the_column_is_refused} covers. What value equality closes is a different
 * hole: a refused load leaves the entity holding the marker <em>instance</em> and detaches it, and
 * the ordinary things an application then does to a detached entity - a DTO round trip through
 * Jackson, {@code new String(...)}, {@code trim()}, a defensive {@code clone()} of a {@code
 * byte[]}, a normalising setter - all produce a value-equal, reference-distinct copy. Recognising
 * only the instance let that copy sail through both write-back checks and overwrite the live
 * ciphertext with the marker's own rendering. The rendering is ASCII only, with no control
 * character and no {@code %}, {@code &#123;} or {@code &#125;}, so it is safe to drop into a log
 * format string or an exception message.
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
   * Reference identity <em>or</em> value equality against every marker (S-3). Used by the converter
   * before it encrypts anything and by the {@code Pre*} listeners on the state array, before the
   * blind indexes are written.
   */
  public static boolean isPlaceholder(Object value) {
    if (value == STRING || value == BYTES || value == LOCAL_DATE || value == BIG_DECIMAL) {
      return true;
    }
    if (value instanceof String s) {
      return STRING.equals(s);
    }
    if (value instanceof byte[] b) {
      return Arrays.equals(BYTES, b);
    }
    if (value instanceof LocalDate d) {
      return LOCAL_DATE.equals(d);
    }
    if (value instanceof BigDecimal n) {
      return BIG_DECIMAL.equals(n);
    }
    return false;
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
