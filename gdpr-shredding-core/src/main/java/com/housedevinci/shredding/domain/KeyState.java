package com.housedevinci.shredding.domain;

/**
 * Lifecycle of one data key. Checked on read as well as on write (control 7): a node that already
 * holds the unwrapped key must still refuse it once the row says the key is going away.
 */
public enum KeyState {
  /** Usable for encryption and decryption. */
  ACTIVE,
  /**
   * An erasure has claimed this key and is committing. Writes are refused with {@link
   * ErrorCodes#ERASED}; reads are refused too, because a read that succeeds during the erasure
   * window produces a plaintext copy the erasure record then claims does not exist.
   */
  DESTROYING,
  /** The key row is gone. Only ever observed through a cache entry that has not expired yet. */
  DESTROYED;

  public boolean usable() {
    return this == ACTIVE;
  }
}
