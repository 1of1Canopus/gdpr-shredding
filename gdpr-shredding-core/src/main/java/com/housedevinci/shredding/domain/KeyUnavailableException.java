package com.housedevinci.shredding.domain;

/**
 * The key store could not be reached, or the key could not be unwrapped for a reason that may go
 * away. Retryable: the caller answers 503 and the health indicator goes DOWN.
 *
 * <p>Never conflated with {@link KeyDestroyedException} (control 16): a KMS outage read as an
 * erasure is an outage that silently deletes data.
 */
public final class KeyUnavailableException extends ShreddingException {
  private static final long serialVersionUID = 1L;

  public KeyUnavailableException(String message) {
    super(ErrorCodes.KEY_UNAVAILABLE, message);
  }

  public KeyUnavailableException(String message, Throwable cause) {
    super(ErrorCodes.KEY_UNAVAILABLE, message, cause);
  }
}
