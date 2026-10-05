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
   * C-12-1, startup schema verification. None of the module's four tables exist in the resolved
   * schema. The module never creates them with the application's own credentials: a role that can
   * run DDL owns the erasure tables and the guard functions, and an owner can disable or replace
   * its own guards, so control 8 would not hold against the application in any configuration.
   */
  public static final String SCHEMA_ABSENT = "SHRED-SCHEMA-001";

  /**
   * The objects exist but are missing or wrong in shape: a table, a column, the sequence or a
   * constraint.
   */
  public static final String SCHEMA_INCOMPLETE = "SHRED-SCHEMA-002";

  /**
   * A guard is not load-bearing: a trigger missing, extra, disabled, not {@code ENABLE ALWAYS} or
   * pointing at the wrong function; a guard function body that differs from the bundled script; or
   * a rule, a row-level-security flag or a policy on one of the four tables. Control 8 (append-only
   * erasure log) and control 11 (erasure tombstone) do not hold.
   */
  public static final String SCHEMA_UNGUARDED = "SHRED-SCHEMA-003";

  /**
   * The runtime database role is privileged over the module's objects; see the message for the
   * legs.
   */
  public static final String RUNTIME_ROLE_PRIVILEGED = "SHRED-SCHEMA-004";

  /**
   * Verification could not complete: a catalogue read was refused, the connection was lost, or the
   * bundled schema resource was unreadable. Never a pass and never a warning - unverifiable is not
   * clean.
   */
  public static final String SCHEMA_UNVERIFIABLE = "SHRED-SCHEMA-005";

  /** {@code shredding.jdbc.initialize-schema=true} and the DDL failed. */
  public static final String SCHEMA_CREATION_FAILED = "SHRED-SCHEMA-006";

  /**
   * A privilege the adapters need is missing. Never downgraded by {@code
   * shredding.jdbc.allow-privileged-runtime-role}: an application that cannot write the erasure log
   * is broken, not differently configured, and boot is a better place to learn that than the first
   * erasure request.
   */
  public static final String RUNTIME_ROLE_UNDERPRIVILEGED = "SHRED-SCHEMA-007";

  /**
   * C-13-14, name-resolution design section 4.4: the module could not isolate the name resolution
   * of its independent read-back. One statement of an erasure is rendered by Hibernate from the
   * entity mapping, so there is no name in it for this module to qualify; it runs instead with the
   * session's {@code search_path} replaced by {@code pg_catalog, pg_temp} for that one statement
   * and restored immediately, and this code is what the module raises when it cannot establish that
   * the replacement was in force, or that the session was handed back carrying the exact bytes it
   * arrived with.
   *
   * <p><b>Never a startup condition, and never "re-apply the script".</b> Unlike every other code
   * in the {@code SHRED-SCHEMA} family, this one says nothing about the installed schema. It means
   * the connection was in auto-commit when the erasure reached that statement, or something moved
   * {@code search_path} inside the erasure's transaction. The whole transaction is rolled back, so
   * no key is destroyed, no blind index is left half-cleared and no record is appended; callers
   * should treat it as an outage of that operation, like {@link #KEY_UNAVAILABLE}, rather than as a
   * misconfiguration of the database.
   */
  public static final String SCHEMA_NAME_ISOLATION = "SHRED-SCHEMA-008";

  /**
   * Mapping admission (name-resolution design, addendum section A.7): a {@code @Shredded} entity's
   * table, or a column of it the module compares or assigns, has a shape the erasure cannot be
   * trusted on - a view, a foreign table, row level security this role is subject to, a temporary
   * relation, a missing privilege, an equality operator outside {@code pg_catalog}, a
   * non-deterministic collation, a NOT NULL or generated blind-index column. Every one of these
   * makes the erasure and both of its read-backs agree on an answer that is false, or fail.
   *
   * <p><b>Raised from two positions.</b> At startup, for a table that exists and is inadmissible:
   * the context refuses to start. Before an erasure's first statement, inside its transaction and
   * under its lock, for a table that is inadmissible or absent at that moment: that one erasure is
   * refused and nothing is destroyed, cleared or recorded. A table absent at startup is a WARN, not
   * this code, because a table created after the context refreshes is an honest deployment. The
   * remedy is always the mapping or the table, never a retry. A catalogue that cannot be read is
   * {@link #SCHEMA_UNVERIFIABLE}, not this code.
   */
  public static final String MAPPING_INADMISSIBLE = "SHRED-SCHEMA-009";

  /**
   * RC-7, RC-10: an erasure waited on a lock and gave up: another session held a conflicting lock
   * longer than the connection's {@code lock_timeout} (SQLState 55P03), or the database chose this
   * transaction as a deadlock victim (40P01). Raised at every wait of the erasure transaction: the
   * subject's advisory lock, the key rows, the table locks mapping admission takes, the blind-index
   * {@code UPDATE} (an application transaction open on the subject's row) and the erasure-log
   * append. Nothing was destroyed, cleared or recorded: the transaction rolled back whole. It says
   * nothing about the key store, and nothing about the mapping. Retry once the other session has
   * finished.
   */
  public static final String ERASURE_LOCK_WAIT = "SHRED-ERASURE-LOCK-WAIT";

  /**
   * C-20: a Spring Data repository call was bracketed, but the module could not establish that
   * every {@code EntityManagerFactory} bean in the application is the one instance {@code
   * ShreddingIntegrator} is wired to. A bracket that cannot tell which Hibernate session it is
   * vouching for cannot vouch for anything, so bracketing every repository is refused outright at
   * startup rather than silently trusting a factory with no listener.
   */
  public static final String EMF_UNINSTRUMENTED = "SHRED-EMF-UNINSTRUMENTED";
}
