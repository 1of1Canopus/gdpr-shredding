package com.housedevinci.shredding.domain;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM, from the JDK's SunJCE provider (AES-NI accelerated). No provider is installed and no
 * crypto library is added (control 18).
 *
 * <p>The nonce is 96 random bits from a {@link RandomSource}; a persisted counter cannot be made
 * safe across a converter that has no transaction coordination, and a rolled-back counter is a
 * catastrophic GCM reuse. The tag is 128 bits and is not configurable.
 */
public final class Aes256Gcm {

  public static final int KEY_BYTES = 32;
  public static final int TAG_BITS = 128;

  private Aes256Gcm() {}

  /**
   * @return nonce and ciphertext||tag
   */
  public static Sealed encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
    requireKey(key);
    Objects.requireNonNull(aad, "aad");
    if (aad.length == 0) {
      throw new ShreddingException(ErrorCodes.INVALID, "AAD must never be empty");
    }
    if (nonce.length != EncryptedValue.NONCE_BYTES) {
      throw new ShreddingException(
          ErrorCodes.INVALID, "nonce must be " + EncryptedValue.NONCE_BYTES + " bytes");
    }
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec(key), new GCMParameterSpec(TAG_BITS, nonce));
      cipher.updateAAD(aad);
      return new Sealed(nonce.clone(), cipher.doFinal(plaintext));
    } catch (GeneralSecurityException e) {
      throw new ShreddingException(ErrorCodes.DECRYPT, "AES-256-GCM encryption failed", e);
    }
  }

  public static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
    requireKey(key);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, keySpec(key), new GCMParameterSpec(TAG_BITS, nonce));
      cipher.updateAAD(aad);
      return cipher.doFinal(ciphertext);
    } catch (AEADBadTagException e) {
      // No detail: which of key, nonce, AAD or bytes was wrong is exactly what an oracle wants.
      throw new ShreddingException(
          ErrorCodes.DECRYPT, "authenticated decryption failed for a shredded value", e);
    } catch (GeneralSecurityException e) {
      throw new ShreddingException(
          ErrorCodes.DECRYPT, "authenticated decryption failed for a shredded value", e);
    }
  }

  private static SecretKeySpec keySpec(byte[] key) {
    return new SecretKeySpec(key, "AES");
  }

  private static void requireKey(byte[] key) {
    if (Objects.requireNonNull(key, "key").length != KEY_BYTES) {
      throw new ShreddingException(
          ErrorCodes.INVALID, "AES-256 key must be " + KEY_BYTES + " bytes, was " + key.length);
    }
  }

  /** Zeroises a key or plaintext buffer. Not a guarantee (the JVM may have copied it). */
  public static void wipe(byte[] secret) {
    if (secret != null) {
      Arrays.fill(secret, (byte) 0);
    }
  }

  public record Sealed(byte[] nonce, byte[] ciphertext) {
    public Sealed {
      nonce = nonce.clone();
      ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] nonce() {
      return nonce.clone();
    }

    @Override
    public byte[] ciphertext() {
      return ciphertext.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Sealed s
          && Arrays.equals(nonce, s.nonce)
          && Arrays.equals(ciphertext, s.ciphertext);
    }

    @Override
    public int hashCode() {
      return 31 * Arrays.hashCode(nonce) + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
      return "Sealed[" + ciphertext.length + " bytes]";
    }
  }
}
