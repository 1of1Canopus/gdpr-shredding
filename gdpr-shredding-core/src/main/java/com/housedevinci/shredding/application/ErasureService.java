package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
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
 *
 * <p><b>Every hook is named in every record that waits for it</b> (audit-table coverage design,
 * section 3c). The erasure's own record lists each registered hook as pending; a hook bound to an
 * acknowledged copy says which objects it clears. A retry answers the hooks the subject's latest
 * record left pending or failed, by name: a name no hook carries now stays outstanding, carried as
 * not registered, and keeps the erasure {@code PARTIAL}. Configuration cannot close what the trail
 * left open; only a hook run under that name can.
 */
public final class ErasureService {

  private static final Logger log = LoggerFactory.getLogger(ErasureService.class);

  private final ErasureStore store;
  private final DataKeyCache cache;
  private final Pseudonymiser pseudonymiser;
  private final List<PostErasureHook> hooks;
  private final Map<String, PostErasureHook> hooksByName;
  private final Map<String, List<AcknowledgedCopy>> boundByHook;
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
    // Arguments first, the store last: a refusal of a bad argument never depends on the store.
    this.backupRetention = Objects.requireNonNull(backupRetention, "backupRetention");
    requireValidBackupRetention(backupRetention);
    this.clock = Objects.requireNonNull(clock, "clock");
    this.hooks = List.copyOf(hooks);
    // Before the store is read: the service never exists with an ambiguous hook list.
    this.hooksByName = requireValidHooks(this.hooks);
    List<AcknowledgedCopy> copies = List.copyOf(store.acknowledgedCopies());
    requireBound(this.hooks, copies);
    var bound = new LinkedHashMap<String, List<AcknowledgedCopy>>();
    for (AcknowledgedCopy copy : copies) {
      bound.computeIfAbsent(copy.clearedBy(), k -> new ArrayList<>()).add(copy);
    }
    bound.replaceAll((k, v) -> List.copyOf(v));
    this.boundByHook = Map.copyOf(bound);
    this.entityCount = entityCount;
    this.fieldCount = fieldCount;
  }

  /**
   * Rev 5 item 2: every hook has a name that can be recorded, and no two hooks share one. With
   * name-keyed answering (section 3c.6) two hooks of one name would let one answer for the other.
   * Exact string equality. Used by this constructor and by the starter at startup.
   *
   * @return the hooks by name, in registration order
   * @throws ShreddingException {@code SHRED-CONFIG-001}
   */
  public static Map<String, PostErasureHook> requireValidHooks(List<PostErasureHook> hooks) {
    var byName = new LinkedHashMap<String, PostErasureHook>();
    for (PostErasureHook hook : hooks) {
      Objects.requireNonNull(hook, "hook");
      String name = hook.name();
      if (name == null || name.isBlank()) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding: the post-erasure hook "
                + hook.getClass().getName()
                + " has a null or blank name. A hook's name identifies its step in the erasure"
                + " trail, and a name that cannot be recorded cannot be answered; give it a short,"
                + " stable name.");
      }
      if (byName.putIfAbsent(name, hook) != null) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding: two post-erasure hooks are named "
                + LogText.escape(name)
                + ". Hook names identify the step in the erasure trail and must be unique; rename"
                + " one.");
      }
    }
    return byName;
  }

  /**
   * Section 3c.2: every acknowledged copy names, in {@code cleared-by}, a registered hook. Used by
   * this constructor and by the starter at startup.
   *
   * @throws ShreddingException {@code SHRED-CONFIG-001}
   */
  public static void requireBound(List<PostErasureHook> hooks, List<AcknowledgedCopy> copies) {
    var names = new HashSet<String>();
    hooks.forEach(h -> names.add(h.name()));
    for (int i = 0; i < copies.size(); i++) {
      AcknowledgedCopy copy = copies.get(i);
      if (!names.contains(copy.clearedBy())) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding: "
                + AcknowledgedCopy.entry(i)
                + " has cleared-by="
                + LogText.escape(copy.clearedBy())
                + ", and no PostErasureHook has that name. An acknowledged copy needs the hook"
                + " that clears it, or every erasure would be recorded COMPLETE over it.");
      }
    }
  }

  /**
   * RC-9: the longest backup retention accepted, 100 years. Far past any retention a backup policy
   * has, and far inside both {@code Instant}'s range and PostgreSQL's {@code timestamptz} (year
   * 294276), so {@code erasedAt + retention} can always be dated and stored.
   */
  public static final Duration MAX_BACKUP_RETENTION = Duration.ofDays(36_500);

  /**
   * RC-5 and RC-9: the one check of {@code shredding.erasure.backup-retention}, used by this
   * constructor and by the starter's property validation. The proof of erasure states the day the
   * erasure is complete in backups as the erasure's own time plus this duration: a negative value
   * would date it before the erasure happened, and a value past the ceiling cannot be dated or
   * stored, which would refuse every erasure.
   */
  public static void requireValidBackupRetention(Duration backupRetention) {
    Objects.requireNonNull(backupRetention, "backupRetention");
    if (backupRetention.isNegative() || backupRetention.compareTo(MAX_BACKUP_RETENTION) > 0) {
      throw new ShreddingException(
          ErrorCodes.CONFIG,
          "shredding.erasure.backup-retention is "
              + backupRetention
              + ", but must be between 0 and "
              + MAX_BACKUP_RETENTION.toDays()
              + " days. The proof of erasure states the day the erasure is complete in backups as"
              + " the erasure's own time plus this duration: a negative value would date it before"
              + " the erasure happened, and a value above the ceiling cannot be dated or stored."
              + " Use 0 if there are no backups.");
    }
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
                    pendingOutcomes(),
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
      // Outstanding PARTIAL: answer every name the latest record left pending or failed (C11),
      // then run every other registered hook, and report what they actually did. No key material
      // is destroyed a second time (keysDestroyed stays 0), but alreadyErased stays true because
      // the subject's key was already gone.
      var rerun = runHooksAndAppend(request, pseudonym, latest, 0, 0, backupsClearAt);
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
            Optional.of(outcome.record()),
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

  /** Runs one hook and reports it, naming the objects it clears or leaves when it is bound. */
  private HookOutcome run(PostErasureHook hook, ErasureRequest request) {
    List<AcknowledgedCopy> bound = boundByHook.get(hook.name());
    try {
      hook.afterErasure(request.tenant(), request.subject());
      return bound == null
          ? HookOutcome.ok(hook.name())
          : new HookOutcome(hook.name(), true, "clears " + AcknowledgedCopy.describe(bound));
    } catch (RuntimeException e) {
      // The class name, never the message: a hook's message can carry the value it was
      // anonymising, and this row outlives the erasure.
      log.warn(
          "shredding: post-erasure hook {} failed; the erasure is PARTIAL until it is retried",
          LogText.escape(hook.name()),
          e);
      return HookOutcome.failed(
          hook.name(),
          e.getClass().getName()
              + (bound == null ? "" : "; leaves " + AcknowledgedCopy.describe(bound)));
    }
  }

  /** What running every hook once, and appending the record that reports it, produced. */
  private record HookRun(
      ErasureOutcome outcome, List<HookOutcome> hookOutcomes, List<ErasureRecord> records) {}

  /** The erasure's own record: every registered hook, pending, with what a bound one clears. */
  private List<HookOutcome> pendingOutcomes() {
    var out = new ArrayList<HookOutcome>(hooks.size());
    for (PostErasureHook hook : hooks) {
      List<AcknowledgedCopy> bound = boundByHook.get(hook.name());
      out.add(
          HookOutcome.failed(
              hook.name(),
              bound == null
                  ? OutstandingHooks.PENDING
                  : OutstandingHooks.PENDING_CLEARS + AcknowledgedCopy.describe(bound)));
    }
    return out;
  }

  /**
   * Answers {@code latest}: each name it left outstanding first, run if a hook carries that name
   * now and carried as not registered otherwise, then every registered hook it did not name. The
   * appended record is {@code COMPLETE} only if every outcome in it succeeded.
   */
  private HookRun runHooksAndAppend(
      ErasureRequest request,
      String pseudonym,
      Optional<ErasureRecord> latest,
      int keysDestroyed,
      int blindIndexColumnsCleared,
      Instant backupsClearAt) {
    Map<String, HookOutcome> outstanding = OutstandingHooks.of(latest);
    var hookOutcomes = new ArrayList<HookOutcome>(outstanding.size() + hooks.size());
    var carried = new ArrayList<String>();
    for (Map.Entry<String, HookOutcome> e : outstanding.entrySet()) {
      PostErasureHook hook = hooksByName.get(e.getKey());
      if (hook != null) {
        hookOutcomes.add(run(hook, request));
      } else {
        long since = OutstandingHooks.since(e.getValue(), latest.orElseThrow());
        hookOutcomes.add(HookOutcome.failed(e.getKey(), OutstandingHooks.CARRIED_PREFIX + since));
        carried.add(LogText.escape(e.getKey()) + " (outstanding since record " + since + ")");
      }
    }
    for (PostErasureHook hook : hooks) {
      if (!outstanding.containsKey(hook.name())) {
        hookOutcomes.add(run(hook, request));
      }
    }
    if (!carried.isEmpty()) {
      log.warn(
          "shredding: the erasure stays PARTIAL: the trail names hook(s) {} as pending or failed,"
              + " and no hook of that name is registered. Register a hook under that name whose"
              + " run clears, or confirms cleared, what it was named for, and retry the erasure.",
          String.join(", ", carried));
    }
    boolean allSucceeded = hookOutcomes.stream().allMatch(HookOutcome::succeeded);

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
