package com.housedevinci.shredding.domain;

/** The subject's data key is gone. Terminal: the read yields {@link ErasedValue} (control 16). */
public final class KeyDestroyedException extends ShreddingException {
  private static final long serialVersionUID = 1L;

  public KeyDestroyedException(String message) {
    super(ErrorCodes.KEY_DESTROYED, message);
  }
}
