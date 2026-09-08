package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.HookOutcome;
import java.time.Instant;
import java.util.List;

/**
 * What one {@link ErasureService#erase} call did.
 *
 * @param outcome COMPLETE only when every hook succeeded (control 19)
 * @param alreadyErased true when the subject had no key left; no second record was written
 * @param keysDestroyed key rows deleted
 * @param blindIndexColumnsCleared blind-index columns nulled (control 10)
 * @param hookOutcomes one entry per registered hook
 * @param records the chained records this call appended, oldest first
 * @param completeInBackupsAt the date the erasure is also complete in backups, PITR archives and
 *     WAL; the proof of erasure states it, because until then a restore brings the key back.
 *     Truncated to {@link ErasureRecord#STORAGE_PRECISION}, so it is the identical instant the
 *     record carries: the value an API hands a caller and the value in the proof must not be two
 *     different times
 */
public record ErasureResult(
    ErasureOutcome outcome,
    boolean alreadyErased,
    int keysDestroyed,
    int blindIndexColumnsCleared,
    List<HookOutcome> hookOutcomes,
    List<ErasureRecord> records,
    Instant completeInBackupsAt) {

  public ErasureResult {
    hookOutcomes = List.copyOf(hookOutcomes);
    records = List.copyOf(records);
    completeInBackupsAt = completeInBackupsAt.truncatedTo(ErasureRecord.STORAGE_PRECISION);
  }

  public boolean complete() {
    return outcome == ErasureOutcome.COMPLETE;
  }
}
