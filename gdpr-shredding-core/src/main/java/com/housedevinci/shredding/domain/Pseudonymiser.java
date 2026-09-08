package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;

/**
 * The subject identifier as it appears in the erasure record (control 9).
 *
 * <p>HMAC with a pepper, not SHA-256: a plain hash of an email address or a UUID is enumerable in
 * seconds, and the erasure log is the one table that must survive the erasure it records.
 *
 * <p>The pepper is derived by HKDF from the erasure-log HMAC secret with info {@code
 * sh/subject-pseudonym/v1} - the same secret with a provably separated domain, so there is one
 * fewer secret to lose. It is <em>not</em> a data key and is never destroyed by an erasure:
 * destroying it would break the very record that proves the erasure happened.
 */
public final class Pseudonymiser {

  public static final String INFO = "sh/subject-pseudonym/v1";

  private final byte[] pepper;

  public Pseudonymiser(byte[] erasureLogSecret) {
    if (erasureLogSecret == null || erasureLogSecret.length < 32) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "the subject pseudonym pepper needs shredding.erasure-log.hmac-secret, at least 32 bytes");
    }
    this.pepper = Hkdf.derive(erasureLogSecret, null, INFO, 32);
  }

  public String pseudonym(TenantId tenant, SubjectId subject) {
    var sb = new StringBuilder("sh-pseudo1");
    append(sb, tenant.value());
    append(sb, subject.value());
    return Hmacs.hmacSha256Hex(pepper, sb.toString());
  }

  private static void append(StringBuilder sb, String value) {
    sb.append('|').append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }
}
