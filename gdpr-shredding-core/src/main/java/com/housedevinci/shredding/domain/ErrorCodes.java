package com.housedevinci.shredding.domain;

/** Stable error codes. Documented in {@code docs/index.md}; never renumbered. */
public final class ErrorCodes {
  private ErrorCodes() {}

  /** Stored bytes are not in the {@link EncryptedValue} format (control 4, control 17). */
  public static final String FORMAT = "SHRED-FORMAT-001";

  /** GCM authentication failed: wrong key, wrong AAD, or tampered bytes. */
  public static final String DECRYPT = "SHRED-DECRYPT-001";

  /** The key store is unreachable. Retryable. Never an erasure (control 16). */
  public static final String KEY_UNAVAILABLE = "SHRED-KEY-UNAVAILABLE";

  /** The key is gone for good. Terminal (control 16). */
  public static final String KEY_DESTROYED = "SHRED-KEY-DESTROYED";

  /** A write was attempted for a subject whose key is DESTROYING or DESTROYED (control 11). */
  public static final String ERASED = "SHRED-ERASED-001";

  /** A converter ran with no write context: bulk JPQL, a criteria parameter, a detached use. */
  public static final String NO_CONTEXT = "SHRED-CONTEXT-001";

  /** The data subject of a persisted row changed (control 14). */
  public static final String SUBJECT_IMMUTABLE = "SHRED-SUBJECT-IMMUTABLE";

  /** The per-key encryption count reached the hard limit; rotate (control 3). */
  public static final String KEY_EXHAUSTED = "SHRED-KEY-EXHAUSTED";

  /** A tenant was required and none was in context. Fails closed (control 15). */
  public static final String TENANT_MISSING = "SHRED-TENANT-MISSING";

  /** Misconfiguration found at startup. Names the property. */
  public static final String CONFIG = "SHRED-CONFIG-001";

  /** The erasure log has rows but no anchor row (control 8). */
  public static final String ERASURE_ANCHOR_MISSING = "SHRED-ERASURE-002";

  /** This instance's keyed/unkeyed mode disagrees with the trail's anchor (control 8). */
  public static final String ERASURE_KEY_MISMATCH = "SHRED-ERASURE-003";

  /** A value or identifier failed boundary validation. */
  public static final String INVALID = "SHRED-INVALID-001";
}
