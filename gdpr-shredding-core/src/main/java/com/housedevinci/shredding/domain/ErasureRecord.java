package com.housedevinci.shredding.domain;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * One row of the append-only, hash-chained erasure log: the proof that a key was destroyed.
 *
 * <p>The subject appears only as a pseudonym ({@link Pseudonymiser}, control 9). The log survives
 * the erasure it records, so it must not itself become a copy of the personal data.
 *
 * <p><b>Both instants are truncated to {@link #STORAGE_PRECISION}.</b> They are part of the hashed
 * material, and hashed material may only hold values the store gives back unchanged: PostgreSQL's
 * {@code timestamptz} holds microseconds and <em>rounds</em> anything finer, so a nanosecond
 * timestamp comes back as a different instant and the trail reads {@code BROKEN} although nobody
 * touched it. Truncating here, in the value object, means the record in memory and the record in
 * the database are the same record whatever precision the caller's {@code Clock} has. Truncation
 * rather than rounding, so an erasure is never timestamped later than it happened.
 *
 * @param sequence position in the trail, assigned by the store
 * @param timestamp when the erasure committed
 * @param tenant the tenant whose subject was erased
 * @param subjectPseudonym keyed pseudonym, never a bare hash of the subject id
 * @param requestedBy who asked; an operator identity, not the data subject's own details
 * @param reason free text from the request, bounded
 * @param keysDestroyed how many data-key rows were deleted
 * @param entityCount how many entity types held shredded fields for this subject
 * @param fieldCount how many shredded fields those entity types declare
 * @param blindIndexColumnsCleared how many blind-index columns were nulled (control 10)
 * @param outcome COMPLETE or PARTIAL (control 19)
 * @param hookOutcomes per-hook results, in registration order
 * @param backupRetentionUntil the date the erasure is complete in backups too, printed in the proof
 * @param chainVersion the chain function this row was written with
 * @param keyId the chain key id this row was signed with, inside the hashed material
 * @param prevHash hash of the previous row, or {@link ErasureChain#GENESIS}
 * @param hash this row's hash
 */
public record ErasureRecord(
    long sequence,
    Instant timestamp,
    TenantId tenant,
    String subjectPseudonym,
    String requestedBy,
    String reason,
    int keysDestroyed,
    int entityCount,
    int fieldCount,
    int blindIndexColumnsCleared,
    ErasureOutcome outcome,
    List<HookOutcome> hookOutcomes,
    Instant backupRetentionUntil,
    String chainVersion,
    String keyId,
    String prevHash,
    String hash) {

  /**
   * The finest resolution the erasure log can store and reproduce. PostgreSQL {@code timestamptz}
   * is microsecond-precision; so is every other store this record is likely to reach.
   */
  public static final ChronoUnit STORAGE_PRECISION = ChronoUnit.MICROS;

  public ErasureRecord {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(tenant, "tenant");
    Objects.requireNonNull(subjectPseudonym, "subjectPseudonym");
    Objects.requireNonNull(outcome, "outcome");
    Objects.requireNonNull(backupRetentionUntil, "backupRetentionUntil");
    requestedBy = requestedBy == null ? "" : requestedBy;
    reason = reason == null ? "" : reason;
    hookOutcomes = List.copyOf(hookOutcomes == null ? List.of() : hookOutcomes);
    timestamp = timestamp.truncatedTo(STORAGE_PRECISION);
    backupRetentionUntil = backupRetentionUntil.truncatedTo(STORAGE_PRECISION);
  }

  /** A fresh, unlinked record: the store fills in sequence, version, key id, prevHash and hash. */
  public static ErasureRecord of(
      Instant timestamp,
      TenantId tenant,
      String subjectPseudonym,
      String requestedBy,
      String reason,
      int keysDestroyed,
      int entityCount,
      int fieldCount,
      int blindIndexColumnsCleared,
      ErasureOutcome outcome,
      List<HookOutcome> hookOutcomes,
      Instant backupRetentionUntil) {
    return new ErasureRecord(
        0,
        timestamp,
        tenant,
        subjectPseudonym,
        requestedBy,
        reason,
        keysDestroyed,
        entityCount,
        fieldCount,
        blindIndexColumnsCleared,
        outcome,
        hookOutcomes,
        backupRetentionUntil,
        "",
        "",
        "",
        "");
  }

  public ErasureRecord withChain(String prevHash, String chainVersion, String keyId, String hash) {
    return new ErasureRecord(
        sequence,
        timestamp,
        tenant,
        subjectPseudonym,
        requestedBy,
        reason,
        keysDestroyed,
        entityCount,
        fieldCount,
        blindIndexColumnsCleared,
        outcome,
        hookOutcomes,
        backupRetentionUntil,
        chainVersion,
        keyId,
        prevHash,
        hash);
  }

  public ErasureRecord withSequence(long sequence) {
    return new ErasureRecord(
        sequence,
        timestamp,
        tenant,
        subjectPseudonym,
        requestedBy,
        reason,
        keysDestroyed,
        entityCount,
        fieldCount,
        blindIndexColumnsCleared,
        outcome,
        hookOutcomes,
        backupRetentionUntil,
        chainVersion,
        keyId,
        prevHash,
        hash);
  }
}
