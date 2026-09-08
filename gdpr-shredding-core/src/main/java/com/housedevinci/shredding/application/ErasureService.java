package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.Pseudonymiser;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Erasure by key destruction.
 *
 * <p>The destruction and its proof are one transaction (control 6). Hooks run after that
 * transaction commits, because they touch systems the database cannot roll back; their outcomes go
 * into a second chained record, since the trail is append-only and the first record cannot be
 * updated. Until a {@code COMPLETE} record exists for a subject the erasure is {@link
 * ErasureOutcome#PARTIAL} and a proof of erasure must not say otherwise (control 19).
 *
 * <p>Repeating an erasure is a no-op: the second call finds no key row, writes no second record,
 * and reports {@code alreadyErased}.
 */
public final class ErasureService {

  private static final Logger log = LoggerFactory.getLogger(ErasureService.class);

  private final ErasureStore store;
  private final DataKeyCache cache;
  private final Pseudonymiser pseudonymiser;
  private final List<PostErasureHook> hooks;
  private final Duration backupRetention;
  private final Clock clock;
  private final int entityCount;
  private final int fieldCount;

  public ErasureService(
      ErasureStore store,
      DataKeyCache cache,
      Pseudonymiser pseudonymiser,
      List<PostErasureHook> hooks,
      Duration backupRetention,
      Clock clock,
      int entityCount,
      int fieldCount) {
    this.store = Objects.requireNonNull(store, "store");
    this.cache = Objects.requireNonNull(cache, "cache");
    this.pseudonymiser = Objects.requireNonNull(pseudonymiser, "pseudonymiser");
    this.hooks = List.copyOf(hooks);
    this.backupRetention = Objects.requireNonNull(backupRetention, "backupRetention");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.entityCount = entityCount;
    this.fieldCount = fieldCount;
  }

  public ErasureResult erase(ErasureRequest request) {
    Objects.requireNonNull(request, "request");
    Instant now = clock.instant();
    Instant backupsClearAt = now.plus(backupRetention);
    String pseudonym = pseudonymiser.pseudonym(request.tenant(), request.subject());

    // One transaction: FOR UPDATE on the key rows, DELETE them, null the blind-index columns,
    // append the chained record. A destroyed key with no record and a record with a live key are
    // both impossible because neither half can commit without the other.
    ErasureStore.Outcome outcome =
        store.erase(
            request.tenant(),
            request.subject(),
            (keysDestroyed, columnsCleared) ->
                ErasureRecord.of(
                    now,
                    request.tenant(),
                    pseudonym,
                    request.requestedBy(),
                    request.reason(),
                    keysDestroyed,
                    entityCount,
                    fieldCount,
                    columnsCleared,
                    hooks.isEmpty() ? ErasureOutcome.COMPLETE : ErasureOutcome.PARTIAL,
                    List.of(),
                    backupsClearAt));

    // Local eviction is immediate; peers keep an unwrapped key for up to the cache TTL. That
    // window is real, is documented in SECURITY-NOTES.md, and appears in the proof of erasure.
    cache.evictSubject(request.tenant(), request.subject());

    if (outcome.alreadyErased()) {
      // CIPHER-02: idempotent only reports COMPLETE when the trail actually says COMPLETE. A
      // subject can have no key row left and still have an outstanding PARTIAL - a hook that
      // failed on the first call - and a DPO producing a proof of erasure is exactly the caller
      // who makes this second call. Never claim COMPLETE the trail does not support.
      var latest = store.latestForSubject(request.tenant(), pseudonym);
      if (latest.isPresent() && latest.get().outcome() == ErasureOutcome.COMPLETE) {
        return new ErasureResult(
            ErasureOutcome.COMPLETE, true, 0, 0, List.of(), List.of(), backupsClearAt);
      }
      // Outstanding PARTIAL, or the trail could not say: re-run every hook now and report what
      // they actually did. No key material is destroyed a second time (keysDestroyed stays 0),
      // but alreadyErased stays true because the subject's key was already gone.
      var rerun = runHooksAndAppend(request, pseudonym, 0, 0, backupsClearAt);
      return new ErasureResult(
          rerun.outcome(), true, 0, 0, rerun.hookOutcomes(), rerun.records(), backupsClearAt);
    }

    var records = new ArrayList<ErasureRecord>();
    records.add(outcome.record());

    if (hooks.isEmpty()) {
      return new ErasureResult(
          ErasureOutcome.COMPLETE,
          false,
          outcome.keysDestroyed(),
          outcome.blindIndexColumnsCleared(),
          List.of(),
          records,
          backupsClearAt);
    }

    var hooked =
        runHooksAndAppend(
            request,
            pseudonym,
            outcome.keysDestroyed(),
            outcome.blindIndexColumnsCleared(),
            backupsClearAt);
    records.addAll(hooked.records());

    return new ErasureResult(
        hooked.outcome(),
        false,
        outcome.keysDestroyed(),
        outcome.blindIndexColumnsCleared(),
        hooked.hookOutcomes(),
        records,
        backupsClearAt);
  }

  /** What running every hook once, and appending the record that reports it, produced. */
  private record HookRun(
      ErasureOutcome outcome, List<HookOutcome> hookOutcomes, List<ErasureRecord> records) {}

  private HookRun runHooksAndAppend(
      ErasureRequest request,
      String pseudonym,
      int keysDestroyed,
      int blindIndexColumnsCleared,
      Instant backupsClearAt) {
    var hookOutcomes = new ArrayList<HookOutcome>(hooks.size());
    boolean allSucceeded = true;
    for (PostErasureHook hook : hooks) {
      try {
        hook.afterErasure(request.tenant(), request.subject());
        hookOutcomes.add(HookOutcome.ok(hook.name()));
      } catch (RuntimeException e) {
        allSucceeded = false;
        // The class name, never the message: a hook's message can carry the value it was
        // anonymising, and this row outlives the erasure.
        hookOutcomes.add(HookOutcome.failed(hook.name(), e.getClass().getName()));
        log.warn(
            "shredding: post-erasure hook {} failed; the erasure is PARTIAL until it is retried",
            hook.name(),
            e);
      }
    }

    ErasureOutcome finalOutcome = allSucceeded ? ErasureOutcome.COMPLETE : ErasureOutcome.PARTIAL;
    ErasureRecord appended =
        store.append(
            ErasureRecord.of(
                clock.instant(),
                request.tenant(),
                pseudonym,
                request.requestedBy(),
                request.reason(),
                keysDestroyed,
                entityCount,
                fieldCount,
                blindIndexColumnsCleared,
                finalOutcome,
                hookOutcomes,
                backupsClearAt));
    return new HookRun(finalOutcome, hookOutcomes, List.of(appended));
  }
}
