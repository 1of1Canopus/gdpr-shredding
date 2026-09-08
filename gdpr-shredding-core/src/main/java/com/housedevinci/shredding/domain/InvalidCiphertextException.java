package com.housedevinci.shredding.domain;

/**
 * The stored bytes are not a well-formed {@link EncryptedValue}: unknown magic, unknown version,
 * truncated, or with trailing bytes.
 *
 * <p>Core never falls back to reading such a column as plaintext (control 17): that fallback is a
 * downgrade oracle, and it turns a migration mistake into a silent, permanent plaintext store.
 */
public final class InvalidCiphertextException extends ShreddingException {
  private static final long serialVersionUID = 1L;

  public InvalidCiphertextException(String message) {
    super(ErrorCodes.FORMAT, message);
  }
}
