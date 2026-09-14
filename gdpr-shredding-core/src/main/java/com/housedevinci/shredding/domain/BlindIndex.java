package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Equality lookup over an encrypted column (control 10).
 *
 * <p>It is a <em>prefilter</em>, never an answer: the value is truncated to {@code bits} (default
 * 64) and the query path always re-verifies by decrypting the candidate rows. A full-width index
 * over a low-entropy field such as an email address is an offline dictionary; a truncated one still
 * leaks equality and frequency, which is documented in {@code SECURITY-NOTES.md} rather than
 * engineered away.
 *
 * <p>Its key is its own secret, never the data key and never the erasure-chain material, with a
 * per-tenant subkey derived by HKDF info {@code sh/blind-index/v1|<tenantId>} so the same value
 * under two tenants produces two unrelated indexes.
 *
 * <p><b>Erasure nulls the subject's blind-index columns.</b> Not a property, not configurable: an
 * index that survives an erasure keeps the erased subject searchable and linkable forever, which
 * defeats the entire product.
 */
public final class BlindIndex {

  public static final String INFO_PREFIX = "sh/blind-index/v1|";
  public static final int MIN_BITS = 32;
  public static final int MAX_BITS = 256;
  public static final int DEFAULT_BITS = 64;

  private final byte[] secret;
  private final int bits;

  public BlindIndex(byte[] secret, int bits) {
    Objects.requireNonNull(secret, "secret");
    if (secret.length < 32) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, "shredding.blind-index.hmac-secret must be at least 32 bytes");
    }
    if (bits < MIN_BITS || bits > MAX_BITS || bits % 8 != 0) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.blind-index.bits must be a multiple of 8 between "
              + MIN_BITS
              + " and "
              + MAX_BITS
              + ", was "
              + bits);
    }
    this.secret = secret.clone();
    this.bits = bits;
  }

  public int bits() {
    return bits;
  }

  /**
   * @param normalised the output of {@link Normalisation}, never a raw user value
   */
  public byte[] compute(TenantId tenant, String entity, String field, String normalised) {
    byte[] subkey = Hkdf.derive(secret, null, INFO_PREFIX + tenant.value(), 32);
    try {
      var sb = new StringBuilder("sh-bi1");
      append(sb, Normalisation.VERSION);
      append(sb, entity);
      append(sb, field);
      append(sb, normalised);
      byte[] full = Hkdf.mac(subkey, sb.toString().getBytes(StandardCharsets.UTF_8));
      return Arrays.copyOf(full, bits / 8);
    } finally {
      Aes256Gcm.wipe(subkey);
    }
  }

  private static void append(StringBuilder sb, String value) {
    sb.append('|').append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }
}
