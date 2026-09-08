package com.housedevinci.shredding.domain;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * The single source of randomness for nonces and data keys, so a test can substitute a narrow or
 * broken generator and the module can notice (control 3: Cipher replaced the useless "100k
 * encryptions, no nonce collision" property test with exactly this).
 *
 * <p>Production always uses {@link #secure()}, which is {@link SecureRandom}.
 */
@FunctionalInterface
public interface RandomSource {

  void nextBytes(byte[] into);

  static RandomSource secure() {
    SecureRandom random = new SecureRandom();
    return random::nextBytes;
  }

  /** A fresh 96-bit nonce (control 3: random, never a persisted counter). */
  default byte[] nonce() {
    byte[] nonce = new byte[EncryptedValue.NONCE_BYTES];
    nextBytes(nonce);
    return nonce;
  }

  /** A fresh 256-bit data key (control 1: random, never derived from the master key). */
  default byte[] dataKey() {
    byte[] key = new byte[Aes256Gcm.KEY_BYTES];
    nextBytes(key);
    return key;
  }

  static RandomSource of(java.util.Random random) {
    Objects.requireNonNull(random, "random");
    return random::nextBytes;
  }
}
