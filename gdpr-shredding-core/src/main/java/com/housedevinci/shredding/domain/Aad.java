package com.housedevinci.shredding.domain;

import java.nio.charset.StandardCharsets;

/**
 * The additional authenticated data every value and every wrapped key is bound to (control 2).
 *
 * <p>Canonical and <em>length-prefixed</em>, module B's {@code ag1|<len>:<value>} form:
 *
 * <pre>
 * sh1|&lt;len&gt;:format|&lt;len&gt;:alg|&lt;len&gt;:tenant|&lt;len&gt;:subject|&lt;len&gt;:entity|&lt;len&gt;:field|&lt;len&gt;:keyVersion
 * </pre>
 *
 * Plain concatenation would let {@code entity="Custom"} with {@code field="erEmail"} produce the
 * same authenticated material as {@code entity="Customer"} with {@code field="Email"}, and a
 * separator alone would only move the problem into values that contain the separator. With a byte
 * length in front of every field no rewrite can move a boundary without changing the bytes.
 *
 * <p>The AAD is mandatory. It is never configurable and never empty: it is the only thing that
 * stops a ciphertext being moved between rows, fields, subjects or tenants.
 */
public final class Aad {

  /** Format tag; also the first component of the erasure-log and blind-index domain strings. */
  public static final String VERSION = "sh1";

  /** Version of the AAD layout itself, so a future layout is a different authenticated string. */
  static final String LAYOUT = "1";

  private Aad() {}

  /** Binds a stored value to its tenant, subject, entity, field, key version and algorithm. */
  public static byte[] forValue(
      TenantId tenant, SubjectId subject, String entity, String field, int keyVersion, byte algId) {
    var sb = new StringBuilder(VERSION);
    append(sb, LAYOUT);
    append(sb, Byte.toString(algId));
    append(sb, tenant.value());
    append(sb, subject.value());
    append(sb, entity);
    append(sb, field);
    append(sb, Integer.toString(keyVersion));
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Binds a wrapped data key to {@code tenant|subject|keyVersion} (control 5), so a wrapped-key row
   * cannot be swapped between subjects, between tenants, or between versions of the same subject.
   */
  public static byte[] forWrap(TenantId tenant, SubjectId subject, int keyVersion) {
    var sb = new StringBuilder(VERSION);
    append(sb, LAYOUT);
    append(sb, "wrap");
    append(sb, tenant.value());
    append(sb, subject.value());
    append(sb, Integer.toString(keyVersion));
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  private static void append(StringBuilder sb, String value) {
    sb.append('|').append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }
}
