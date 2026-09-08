package com.housedevinci.shredding.domain;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * The key that wraps every data key (control 5).
 *
 * <p>Required, from the environment, base64, at least 32 bytes, with no default and no generated
 * fallback. Well-known sample values are refused at startup: a copied README value is not a key.
 *
 * <p>Held as {@code byte[]} and never as {@code String}, so it can be zeroised and does not sit in
 * the string pool waiting for a heap dump. It never appears in an exception message, a metric tag
 * or a {@code toString}, and the starter removes it from the actuator's {@code /env} and {@code
 * /configprops} explicitly rather than trusting property-name sanitisation to guess.
 *
 * <p>Wrapping is AES-256-GCM with AAD {@code tenant|subject|keyVersion}, so a wrapped-key row
 * cannot be swapped between subjects, tenants or versions.
 */
public final class MasterKey {

  public static final int MIN_BYTES = 32;

  /** Values that appear in documentation and samples; never a real key. */
  private static final List<String> REFUSED =
      List.of(
          "changeme",
          "change-me",
          "0000000000000000000000000000000000000000000",
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "c2FtcGxl",
          "example",
          "insecure",
          "replace-me",
          "test-master-key");

  private final byte[] material;

  private MasterKey(byte[] material) {
    this.material = material;
  }

  /**
   * Parses and validates the configured value, then wipes the caller's copy is up to the caller.
   */
  public static MasterKey fromBase64(String property, String base64) {
    if (base64 == null || base64.isBlank()) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          property
              + " is required: a base64 master key of at least "
              + MIN_BYTES
              + " bytes,"
              + " supplied through the environment. There is no default and none is generated.");
    }
    String trimmed = base64.strip();
    for (String refused : REFUSED) {
      if (trimmed
          .toLowerCase(java.util.Locale.ROOT)
          .contains(refused.toLowerCase(java.util.Locale.ROOT))) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            property
                + " looks like a sample or placeholder value and is refused. Generate one with"
                + " `head -c 32 /dev/urandom | base64` and pass it through the environment.");
      }
    }
    byte[] raw;
    try {
      raw = Base64.getDecoder().decode(trimmed);
    } catch (IllegalArgumentException e) {
      // The value is never echoed: an error message is a log line and a log line is a copy.
      throw new ShreddingException(ErrorCodes.CONFIG, property + " is not valid base64", e);
    }
    if (raw.length < MIN_BYTES) {
      Arrays.fill(raw, (byte) 0);
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          property + " decodes to fewer than " + MIN_BYTES + " bytes; use at least 256 bits.");
    }
    // AES-256 needs exactly 32 bytes; a longer secret is folded, not truncated, so every byte the
    // operator supplied contributes.
    byte[] material =
        raw.length == MIN_BYTES ? raw.clone() : Hkdf.derive(raw, null, "sh/master/v1", MIN_BYTES);
    Arrays.fill(raw, (byte) 0);
    return new MasterKey(material);
  }

  /** For tests and for a provider that already holds raw bytes. */
  public static MasterKey fromBytes(byte[] material) {
    Objects.requireNonNull(material, "material");
    if (material.length < MIN_BYTES) {
      throw new ShreddingException(
          ErrorCodes.CONFIG, "master key must be at least " + MIN_BYTES + " bytes");
    }
    return new MasterKey(
        material.length == MIN_BYTES
            ? material.clone()
            : Hkdf.derive(material, null, "sh/master/v1", MIN_BYTES));
  }

  public byte[] wrap(
      TenantId tenant, SubjectId subject, int keyVersion, byte[] dataKey, RandomSource random) {
    byte[] aad = Aad.forWrap(tenant, subject, keyVersion);
    var sealed = Aes256Gcm.encrypt(material, random.nonce(), dataKey, aad);
    byte[] out = new byte[EncryptedValue.NONCE_BYTES + sealed.ciphertext().length];
    System.arraycopy(sealed.nonce(), 0, out, 0, EncryptedValue.NONCE_BYTES);
    System.arraycopy(
        sealed.ciphertext(), 0, out, EncryptedValue.NONCE_BYTES, sealed.ciphertext().length);
    return out;
  }

  public byte[] unwrap(TenantId tenant, SubjectId subject, int keyVersion, byte[] wrapped) {
    if (wrapped == null
        || wrapped.length <= EncryptedValue.NONCE_BYTES + EncryptedValue.TAG_BYTES) {
      throw new InvalidCiphertextException("wrapped data key is truncated");
    }
    byte[] nonce = Arrays.copyOf(wrapped, EncryptedValue.NONCE_BYTES);
    byte[] ciphertext = Arrays.copyOfRange(wrapped, EncryptedValue.NONCE_BYTES, wrapped.length);
    return Aes256Gcm.decrypt(material, nonce, ciphertext, Aad.forWrap(tenant, subject, keyVersion));
  }

  /** Zeroises the held material. Called on shutdown. */
  public void destroy() {
    Arrays.fill(material, (byte) 0);
  }

  /** Never the key, never a prefix of it, never its length. */
  @Override
  public String toString() {
    return "MasterKey[redacted]";
  }
}
