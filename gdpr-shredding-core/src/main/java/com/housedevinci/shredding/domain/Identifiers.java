package com.housedevinci.shredding.domain;

/**
 * Boundary validation for the two identifiers that end up inside an AAD, a primary key and a SQL
 * bind parameter (controls 14, 15).
 *
 * <p>The charset is deliberately narrow: an identifier is a key, not free text. Anything outside it
 * is refused at the boundary rather than normalised, because two identifiers that normalise to the
 * same key would share a data key and therefore share an erasure.
 */
public final class Identifiers {

  /** Bytes, not characters: the value is length-prefixed into a one-byte field in the blob. */
  public static final int MAX_BYTES = 255;

  private Identifiers() {}

  static String validate(String kind, String value) {
    if (value == null || value.isBlank()) {
      throw new ShreddingException(ErrorCodes.INVALID, kind + " must not be null or blank");
    }
    if (!value.equals(value.strip())) {
      throw new ShreddingException(
          ErrorCodes.INVALID, kind + " must not start or end with whitespace");
    }
    int bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    if (bytes > MAX_BYTES) {
      throw new ShreddingException(
          ErrorCodes.INVALID, kind + " is " + bytes + " bytes, max " + MAX_BYTES);
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      boolean ok =
          (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || c == '-'
              || c == '_'
              || c == '.'
              || c == ':'
              || c == '@'
              || c == '+';
      if (!ok) {
        // The offending character is reported by code point, not echoed, so a log line never
        // becomes a copy of an identifier that may itself be personal data.
        throw new ShreddingException(
            ErrorCodes.INVALID,
            kind
                + " contains a character not allowed at index "
                + i
                + " (U+"
                + Integer.toHexString(c)
                + ")");
      }
    }
    return value;
  }
}
