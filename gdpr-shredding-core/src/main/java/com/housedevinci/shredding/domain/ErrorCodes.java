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

  /**
   * A stored value's header names a different tenant or subject than the row it was read from
   * (CIPHER-01). Distinct from {@link #SUBJECT_IMMUTABLE}: that one is "someone changed this row's
   * subject", this one is "this row holds someone else's ciphertext" - a DPO reading the log needs
   * to tell the two apart.
   */
  public static final String SUBJECT_MISMATCH = "SHRED-SUBJECT-MISMATCH";

  /**
   * C-34: a stored value's header names the right subject and tenant but a different row. Two rows
   * of one subject used to hold interchangeable ciphertexts, so an attacker holding {@code UPDATE}
   * copied one row's column into another and the second row displayed the first's value as its own.
   * Distinct from {@link #SUBJECT_MISMATCH} on purpose: a DPO reading the log needs to tell "this
   * row holds another person's data" from "this row holds another of this person's rows".
   */
  public static final String ROW_MISMATCH = "SHRED-ROW-MISMATCH";

  /**
   * Design §1.1, finding item 2: an attempt to persist the marker a {@code @Shredded} read returns
   * before {@code onPostLoad} installs the verified value. Writing it would destroy a live
   * ciphertext, which is what a {@code null} placeholder did silently for the types that have no
   * sentinel.
   */
  public static final String PLACEHOLDER = "SHRED-PLACEHOLDER-001";

  /** A tenant was required and none was in context. Fails closed (control 15). */
  public static final String TENANT_MISSING = "SHRED-TENANT-MISSING";

  /** Misconfiguration found at startup. Names the property. */
  public static final String CONFIG = "SHRED-CONFIG-001";

  /**
   * S-1, design addendum of 2026-09-10: a written {@code @Shredded} row reached the end of its
   * transaction without what actually stored in it being compared against the scope it was written
   * under - because the row could not be read back, or because the write had no transaction to
   * settle in at all. The write path's other refusals mean "this row is wrong"; this one means
   * "nobody checked whether this row is wrong", and a check that could not run is a refusal, never
   * a pass. The transaction is aborted before commit.
   */
  public static final String UNVERIFIED_WRITE = "SHRED-UNVERIFIED-WRITE";

  /** The erasure log has rows but no anchor row (control 8). */
  public static final String ERASURE_ANCHOR_MISSING = "SHRED-ERASURE-002";

  /** This instance's keyed/unkeyed mode disagrees with the trail's anchor (control 8). */
  public static final String ERASURE_KEY_MISMATCH = "SHRED-ERASURE-003";

  /**
   * S-13, design addendum 3 change 5: an erasure cleared a subject's blind-index columns and then
   * found at least one of them still populated for the same (tenant, subject) inside its own
   * transaction. The row count the {@code UPDATE} claimed is not evidence - a trigger, a rule, a
   * view or a column rewritten since the startup scan can all leave an HMAC of the erased plaintext
   * behind - so the erasure is refused and rolled back rather than recorded as complete.
   */
  public static final String ERASURE_INDEX_RESIDUAL = "SHRED-ERASURE-004";

  /** A value or identifier failed boundary validation. */
  public static final String INVALID = "SHRED-INVALID-001";

  /**
   * CIPHER-11: a {@code @Shredded} converter ran with no read scope at all - not through a managed
   * entity load (which a Spring Data repository call or {@code ShreddingEventListener} brackets)
   * and not through an explicit {@code ShreddingContext.withRead(...)}. A projection, a native
   * query or a detached use has no ambient owner to check the header against, so it is refused
   * rather than decrypted and handed back unverified.
   */
  public static final String READ_UNSCOPED = "SHRED-READ-UNSCOPED";

  /**
   * CIPHER-12: a row carries at least one shredded value and its subject expression could not be
   * evaluated. Unlike {@link #SUBJECT_MISMATCH} (a header naming a different subject than the row),
   * this is a row whose true subject cannot be established at all - and an unknown owner is never a
   * reason to display an already-decrypted value.
   */
  public static final String SUBJECT_UNRESOLVED = "SHRED-SUBJECT-UNRESOLVED";

  /**
   * C-17/C-18/C-20/C-22: a decrypt was reached with the read bracket open but no verifier (neither
   * {@code onPostLoad} nor an explicit {@code ShreddingContext.withRead(...)} scope) ever drained
   * it before the bracket closed. Thrown from {@code popReadBracket()}, after the value was
   * computed but before it is handed back to the caller - the bracket owes a debt, and this is what
   * it means for the debt to go unpaid. Never carries the decrypted value.
   */
  public static final String READ_UNVERIFIED = "SHRED-READ-UNVERIFIED";

  /**
   * C-20: a Spring Data repository call was bracketed, but the module could not establish that
   * every {@code EntityManagerFactory} bean in the application is the one instance {@code
   * ShreddingIntegrator} is wired to. A bracket that cannot tell which Hibernate session it is
   * vouching for cannot vouch for anything, so bracketing every repository is refused outright at
   * startup rather than silently trusting a factory with no listener.
   */
  public static final String EMF_UNINSTRUMENTED = "SHRED-EMF-UNINSTRUMENTED";
}
