package com.housedevinci.shredding.application;

import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.ShreddingException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * What a subject's erasure trail still waits for, and the rule every appended record must keep
 * (audit-table coverage design, section 3c.6, C11 and rev 5 item 1).
 *
 * <p>From 0.2.0 every {@code PARTIAL} record names every hook it waits for, with {@code succeeded =
 * false}: pending in the erasure's own record, failed or carried in a later one. The outstanding
 * names of a subject are those of its latest record, because every record that follows a {@code
 * PARTIAL} one must answer each of them; the trail is never walked.
 *
 * <p>The rule, held by both stores under their append lock, whatever the record's outcome: a new
 * record answers every name the subject's latest record left pending or failed (succeeded, failed,
 * or carried as not registered), and names no hook twice. A record the service builds always keeps
 * it; the rule refuses only records written past the service, which is how two direct appends would
 * otherwise launder an outstanding name (a {@code PARTIAL} that drops it, then a {@code COMPLETE}).
 */
public final class OutstandingHooks {

  private OutstandingHooks() {}

  /** The detail of an outcome carried for a hook that is not registered now. */
  public static final String CARRIED_PREFIX = "not registered; outstanding since record ";

  /** The detail of a pending outcome of a hook bound to no acknowledged copy. */
  public static final String PENDING = "pending";

  /** The prefix of a pending outcome of a hook bound to acknowledged copies. */
  public static final String PENDING_CLEARS = "pending; clears ";

  /**
   * The names {@code latest} left pending or failed, in its order, each with its outcome. Empty
   * when there is no record, when it succeeded, or for a 0.1.x record that names no hook.
   */
  public static Map<String, HookOutcome> of(Optional<ErasureRecord> latest) {
    var out = new LinkedHashMap<String, HookOutcome>();
    latest.ifPresent(
        r -> {
          for (HookOutcome o : r.hookOutcomes()) {
            if (!o.succeeded()) {
              out.putIfAbsent(o.hook(), o);
            }
          }
        });
    return out;
  }

  /**
   * The sequence of the record that first named an outstanding hook: the one a carried outcome
   * already states, otherwise {@code latest}'s own. Only the prefix this module writes is parsed.
   */
  public static long since(HookOutcome outstanding, ErasureRecord latest) {
    String detail = outstanding.detail();
    if (detail.startsWith(CARRIED_PREFIX)) {
      String digits = detail.substring(CARRIED_PREFIX.length());
      if (digits.matches("[1-9][0-9]{0,18}")) {
        try {
          return Long.parseLong(digits);
        } catch (NumberFormatException e) {
          return latest.sequence();
        }
      }
    }
    return latest.sequence();
  }

  /**
   * Refuses {@code next} unless it answers every name {@code latest} left outstanding and names no
   * hook twice. Called by a store under the lock that orders its appends, so {@code latest} is the
   * subject's latest record at the moment {@code next} is written.
   *
   * @throws ShreddingException {@code SHRED-CONFIG-001}; nothing is written
   */
  public static void requireAnswered(Optional<ErasureRecord> latest, ErasureRecord next) {
    var seen = new HashSet<String>();
    for (HookOutcome o : next.hookOutcomes()) {
      if (!seen.add(o.hook())) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding: refused to append an erasure record for this subject: it reports hook "
                + LogText.escape(o.hook())
                + " more than once.");
      }
    }
    for (String name : of(latest).keySet()) {
      if (!seen.contains(name)) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "shredding: refused to append an erasure record for this subject: record "
                + latest.orElseThrow().sequence()
                + " left hook "
                + LogText.escape(name)
                + " pending or failed and the new record does not report it.");
      }
    }
  }
}
