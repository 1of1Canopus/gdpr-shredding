package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256, RFC 5869. Thirty lines, verified against the RFC's own test vectors in {@code
 * HkdfTest}.
 *
 * <p>It is here, hand-written, rather than pulled from BouncyCastle: the domain package may not
 * import a crypto library (control 18), and BouncyCastle is a large, regularly-CVE'd dependency
 * with FIPS and export variants and a provider install that fights the host application. Everything
 * this module needs is in the JDK.
 *
 * <p>Used only for domain separation, never to derive a data key from the master key: a derived
 * data key is re-derivable forever, which makes erasure a no-op (control 1).
 */
public final class Hkdf {

  private static final String ALG = "HmacSHA256";
  private static final int HASH_LEN = 32;

  private Hkdf() {}

  /** RFC 5869 §2.2. A null or empty salt is the all-zero string of {@code HashLen} bytes. */
  public static byte[] extract(byte[] salt, byte[] ikm) {
    byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
    return mac(effectiveSalt, ikm);
  }

  /** RFC 5869 §2.3. {@code length} is at most 255 * HashLen. */
  public static byte[] expand(byte[] prk, byte[] info, int length) {
    if (length < 1 || length > 255 * HASH_LEN) {
      throw new ShreddingException(
          ErrorCodes.INVALID,
          "HKDF output length must be 1.." + (255 * HASH_LEN) + ", was " + length);
    }
    byte[] safeInfo = info == null ? new byte[0] : info;
    byte[] out = new byte[length];
    byte[] t = new byte[0];
    int pos = 0;
    for (int counter = 1; pos < length; counter++) {
      byte[] input = new byte[t.length + safeInfo.length + 1];
      System.arraycopy(t, 0, input, 0, t.length);
      System.arraycopy(safeInfo, 0, input, t.length, safeInfo.length);
      input[input.length - 1] = (byte) counter;
      t = mac(prk, input);
      int n = Math.min(t.length, length - pos);
      System.arraycopy(t, 0, out, pos, n);
      pos += n;
      Arrays.fill(input, (byte) 0);
    }
    Arrays.fill(t, (byte) 0);
    return out;
  }

  /** Extract-then-expand in one call. */
  public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
    byte[] prk = extract(salt, ikm);
    try {
      return expand(prk, info.getBytes(StandardCharsets.UTF_8), length);
    } finally {
      Arrays.fill(prk, (byte) 0);
    }
  }

  static byte[] mac(byte[] key, byte[] data) {
    try {
      Mac mac = Mac.getInstance(ALG);
      mac.init(new SecretKeySpec(key, ALG));
      return mac.doFinal(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(ALG + " not available", e);
    }
  }
}
