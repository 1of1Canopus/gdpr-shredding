package com.housedevinci.shredding.domain;

import java.util.Objects;

/**
 * Every failure this module raises, carrying a stable {@link #code()}.
 *
 * <p>The message never contains key material, a plaintext value, or a master key: an exception is a
 * log line and a log line is a copy that outlives the erasure.
 */
public class ShreddingException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final String code;

  public ShreddingException(String code, String message) {
    super(message);
    this.code = Objects.requireNonNull(code, "code");
  }

  public ShreddingException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = Objects.requireNonNull(code, "code");
  }

  public final String code() {
    return code;
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + "[" + code + "] " + getMessage();
  }
}
