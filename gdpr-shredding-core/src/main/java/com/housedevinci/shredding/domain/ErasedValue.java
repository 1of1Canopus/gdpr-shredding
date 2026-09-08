package com.housedevinci.shredding.domain;

/**
 * What a read returns once the subject's key is gone (control 13).
 *
 * <p>The marker is a fixed, non-empty, non-guessable-looking string so that a value which reaches a
 * screen, a log or an export is obviously an erasure and not an empty field. {@link #toString()} on
 * anything carrying it is this same fixed marker: never the plaintext, never the ciphertext.
 *
 * <p>Writing the marker back is refused ({@link ErrorCodes#ERASED}), and because it round-trips to
 * the identical Java value that was loaded, Hibernate's dirty checking sees no change and never
 * tries (control 11). Both, not either.
 */
public final class ErasedValue {

  /** The sentinel a {@code String} field reads as. */
  public static final String MARKER = "[erased]";

  /** The sentinel a {@code byte[]} field reads as. Empty, and identity-compared. */
  public static final byte[] BYTES_MARKER = new byte[0];

  private ErasedValue() {}

  public static boolean isMarker(Object value) {
    if (value instanceof String s) {
      return MARKER.equals(s);
    }
    return value == BYTES_MARKER;
  }
}
