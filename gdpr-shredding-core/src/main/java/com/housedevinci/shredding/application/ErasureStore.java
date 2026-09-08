package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.util.Optional;

/**
 * The transactional half of an erasure (control 6).
 *
 * <p>{@link #erase} takes {@code SELECT ... FOR UPDATE} on the subject's key rows, deletes them,
 * nulls the subject's blind-index columns and appends the chained erasure record, <b>all in one
 * transaction</b>. Not "overwrite then delete": under MVCC an overwrite only writes a second heap
 * tuple holding the same key, and the assurance it implies is false.
 *
 * <p>A destroyed key with no record (an unprovable erasure) and a record with a live key (a false
 * proof) must both be impossible, which is why these are one call and not two.
 */
public interface ErasureStore {

  /** Builds the record once the transaction knows what it actually destroyed. */
  @FunctionalInterface
  interface RecordFactory {
    ErasureRecord create(int keysDestroyed, int blindIndexColumnsCleared);
  }

  /**
   * @param alreadyErased true when there was no key row left; the call is then a no-op and writes
   *     no second record, so a repeated erasure request is idempotent
   */
  record Outcome(
      boolean alreadyErased,
      int keysDestroyed,
      int blindIndexColumnsCleared,
      ErasureRecord record) {}

  Outcome erase(TenantId tenant, SubjectId subject, RecordFactory factory);

  /**
   * Appends one more chained record. Used for the follow-up record that carries the hook outcomes,
   * which cannot be known inside the destruction transaction because hooks run after it commits.
   */
  ErasureRecord append(ErasureRecord record);

  /**
   * The most recent chained record for this (tenant, subject), by its pseudonym. Used on a repeat
   * erasure request (CIPHER-02): a subject with no key row left is idempotent only when its last
   * erasure actually completed. If it left an outstanding {@code PARTIAL} - a failed post-erasure
   * hook, most often - a second call must re-run the hooks and report what they actually did, not
   * repeat an unconditional {@code COMPLETE} that the trail does not support.
   */
  Optional<ErasureRecord> latestForSubject(TenantId tenant, String subjectPseudonym);
}
