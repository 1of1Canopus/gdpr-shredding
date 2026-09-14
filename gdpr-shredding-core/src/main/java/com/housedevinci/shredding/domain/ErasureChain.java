package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hash chain over {@link ErasureRecord}s. Module B's audit chain, copied and adapted (control 8);
 * extracting a shared library is a later decision.
 *
 * <p>{@code hash = H(canonical(record, keyId) || prevHash)} where {@code H} is SHA-256 ({@link
 * #unkeyed()}, version {@code sh1}, key id {@link #UNKEYED_KEY_ID}) or HMAC-SHA-256 with a secret
 * ({@link #keyed(byte[], String)}, version {@code sh2h}). The canonical form is length-prefixed, so
 * no rewrite can move a boundary between two fields without changing the hash, and the key id is
 * inside the hashed material from row 1, so key rotation is data rather than a format break.
 *
 * <p>This key is <b>not</b> a data key and is <b>never destroyed by an erasure</b>: destroying it
 * would break the very record that proves the erasure happened.
 */
public final class ErasureChain {

  public static final String GENESIS = "0".repeat(64);
  public static final String CANONICAL_VERSION = "sh1";
  public static final String KEYED_VERSION = "sh2h";
  public static final String UNKEYED_KEY_ID = "none";
  public static final int MIN_KEY_BYTES = 32;

  private static final ErasureChain UNKEYED = new ErasureChain(null, UNKEYED_KEY_ID);

  private final byte[] key;
  private final String keyId;

  private ErasureChain(byte[] key, String keyId) {
    this.key = key;
    this.keyId = Objects.requireNonNull(keyId, "keyId");
  }

  public static ErasureChain unkeyed() {
    return UNKEYED;
  }

  public static ErasureChain keyed(byte[] secret, String keyId) {
    Objects.requireNonNull(secret, "secret");
    Objects.requireNonNull(keyId, "keyId");
    if (secret.length < MIN_KEY_BYTES) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.erasure-log.hmac-secret must be at least " + MIN_KEY_BYTES + " bytes");
    }
    if (keyId.isBlank() || UNKEYED_KEY_ID.equals(keyId)) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.erasure-log.hmac-key-id must not be blank or '"
              + UNKEYED_KEY_ID
              + "' (reserved for unkeyed trails)");
    }
    return new ErasureChain(secret.clone(), keyId);
  }

  public boolean isKeyed() {
    return key != null;
  }

  public String keyId() {
    return keyId;
  }

  public String version() {
    return isKeyed() ? KEYED_VERSION : CANONICAL_VERSION;
  }

  static String canonical(ErasureRecord r, String version, String keyId) {
    var sb = new StringBuilder(version);
    field(sb, keyId);
    field(sb, r.timestamp().toString());
    field(sb, r.tenant().value());
    field(sb, r.subjectPseudonym());
    field(sb, r.requestedBy());
    field(sb, r.reason());
    field(sb, Integer.toString(r.keysDestroyed()));
    field(sb, Integer.toString(r.entityCount()));
    field(sb, Integer.toString(r.fieldCount()));
    field(sb, Integer.toString(r.blindIndexColumnsCleared()));
    field(sb, r.outcome().name());
    field(sb, hookMaterial(r));
    field(sb, r.backupRetentionUntil().toString());
    return sb.toString();
  }

  /** The hook outcomes, themselves length-prefixed, so a hook name cannot swallow a boundary. */
  public static String hookMaterial(ErasureRecord r) {
    var sb = new StringBuilder();
    for (HookOutcome h : r.hookOutcomes()) {
      field(sb, h.hook());
      field(sb, Boolean.toString(h.succeeded()));
      field(sb, h.detail());
    }
    return sb.toString();
  }

  private static void field(StringBuilder sb, String value) {
    sb.append('|');
    if (value == null) {
      sb.append('-');
      return;
    }
    sb.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }

  public String hashOf(ErasureRecord r, String prevHash) {
    String material = canonical(r, version(), keyId) + "|" + prevHash.length() + ":" + prevHash;
    if (key == null) {
      return Hashes.sha256Hex(material);
    }
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return HexFormat.of().formatHex(mac.doFinal(material.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 not available", e);
    }
  }

  public ErasureRecord link(ErasureRecord r, String prevHash) {
    return r.withChain(prevHash, version(), keyId, hashOf(r, prevHash));
  }

  public boolean verify(ErasureRecord r, String expectedPrev) {
    return expectedPrev.equals(r.prevHash()) && hashOf(r, expectedPrev).equals(r.hash());
  }
}
