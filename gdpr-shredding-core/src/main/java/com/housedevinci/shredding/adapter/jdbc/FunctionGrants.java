package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.IntFunction;

/**
 * C-PR45-3: no role in reach, and PUBLIC no more than the server's own default, holds EXECUTE on a
 * function the server or a shipped extension withholds, on an alias of one, on native {@code
 * SECURITY DEFINER} code, on native code made by hand, or on a shipped extension member that is no
 * longer as shipped. The record those rules read is itself checked against the pinned files of
 * {@link PinnedCatalogue}. Design revision 5 adds R6: no object that calls a function with its
 * owner's rights, or with no EXECUTE check, and that reach or PUBLIC may use, calls such a function
 * for a role outside reach; and R7: every core native function is as initdb ships it.
 *
 * <p>Runs on the verification's connection, inside its pinned window, after the parameter leg. A
 * finding is a {@code SHRED-SCHEMA-004} line. A server major with no pinned files, a baseline oid
 * whose signature differs (R0), and an installed extension version the manifest does not list (R5v)
 * and a core native function that differs from its pinned line (R7) are {@code SHRED-SCHEMA-005}:
 * the record cannot be judged, and unverifiable is not clean, whatever {@code
 * allow-privileged-runtime-role} says.
 */
final class FunctionGrants {

  private FunctionGrants() {}

  /** One row of statement 1. */
  record RecordRow(String rule, long oid, String detail, String label, boolean updateSource) {}

  /** One row of statement 2: one (function, grantee) pair, by its lowest leg and case. */
  record ExecuteRow(
      long fn,
      long grantee,
      int leg,
      int sub,
      String ref,
      String label,
      String sameAs,
      boolean granteeOwns,
      String owner,
      String extension,
      String version,
      String symbol) {}

  /** One R6 finding: a caller object that calls a judged function for reach or PUBLIC. */
  record CallerRow(
      String kind,
      long oid,
      String label,
      String slot,
      String ownerName,
      String function,
      int leg,
      int sub,
      String ref,
      String sameAs,
      String extension,
      String version) {}

  /**
   * The slots of each caller-object branch of statement 3, in the statement's order: the slot of a
   * row is its 1-based position here.
   */
  static final Map<String, List<String>> SLOTS =
      Map.of(
          "agg",
          List.of(
              "transfn",
              "finalfn",
              "combinefn",
              "serialfn",
              "deserialfn",
              "mtransfn",
              "minvtransfn",
              "mfinalfn"),
          "opr",
          List.of("oprcode", "oprrest", "oprjoin"),
          "lang",
          List.of("handler", "inline", "validator"));

  /**
   * True when the server calls the slot's function with the object owner's EXECUTE checked, or with
   * none: the slots R6 judges. Measured on both pins (revision 5, round 5 review): an operator's
   * {@code oprcode} is checked as the caller ({@code permission denied for function}); aggregate
   * support functions are checked as the owner; language handlers, inline handlers and validators,
   * and operator estimators, are called with no check at all.
   */
  static boolean ownerOrNobody(String kind, int slot) {
    return !(kind.equals("opr") && slot == 1);
  }

  static void check(
      Connection c, SchemaVerification.Reach reach, List<String> accepted, List<String> excess)
      throws SQLException {
    check(c, reach, accepted, excess, PinnedCatalogue::forMajor);
  }

  /** As {@link #check}, with the pinned files chosen by {@code lookup}: the seam for R0 tests. */
  static void check(
      Connection c,
      SchemaVerification.Reach reach,
      List<String> accepted,
      List<String> excess,
      IntFunction<Optional<PinnedCatalogue>> lookup)
      throws SQLException {
    int major = FunctionGrantsSql.major(c);
    Optional<PinnedCatalogue> pinned = lookup.apply(major);
    if (pinned.isEmpty()) {
      PinnedCatalogue none = PinnedCatalogue.none(major);
      List<String> seen =
          judgeRecords(records(c, none), none).stream()
              .filter(r -> r.rule().equals("R2") || r.rule().equals("R4"))
              .map(r -> FunctionGrantMessages.record(r, major, ""))
              .toList();
      throw unverifiable(
          List.of(
              "no pinned initdb baseline and extension manifest for PostgreSQL "
                  + major
                  + "; this release verifies "
                  + PinnedCatalogue.shippedMajors()
                  + ". A module release with files for "
                  + major
                  + " fixes it"),
          seen);
    }
    PinnedCatalogue catalogue = pinned.orElseThrow();
    catalogue.refuseInstallableNames(accepted);
    var unjudged = new ArrayList<String>();
    for (RecordRow row : judgeRecords(records(c, catalogue), catalogue)) {
      String baseAcl = catalogue.baselineAcl(row.oid()).orElse("");
      switch (row.rule()) {
        case "R0" -> unjudged.add(FunctionGrantMessages.signature(row, major));
        case "R5v" -> unjudged.add(FunctionGrantMessages.version(row, catalogue));
        default -> excess.add(FunctionGrantMessages.record(row, major, baseAcl));
      }
    }
    if (!unjudged.isEmpty()) {
      throw unverifiable(unjudged, List.of());
    }
    List<FunctionGrantsSql.ExecuteFact> facts =
        FunctionGrantsSql.executes(c, reach.oids(), baselineOids(catalogue));
    List<String> rewritten = judgeCore(facts, catalogue);
    if (superuserLogin(reach)) {
      // "login role X is a superuser" says it all (F28): the bootstrap superuser is the owner in
      // the default ACL of every withheld function, so the leg would list each one.
      if (!rewritten.isEmpty()) {
        throw unverifiable(rewritten, List.of());
      }
      return;
    }
    var reachOids = new HashSet<Long>();
    for (long oid : reach.oids()) {
      reachOids.add(oid);
    }
    List<FunctionGrantsSql.CallerFact> callers = FunctionGrantsSql.callers(c, reach.oids());
    var lines = new ArrayList<String>();
    for (ExecuteRow row : judgeExecutes(facts, catalogue, accepted, reachOids, supports(callers))) {
      long g = row.grantee();
      lines.add(
          FunctionGrantMessages.held(
              row, reach.named(g), g == 0 ? "PUBLIC" : reach.name(g), catalogue));
    }
    for (CallerRow row : judgeCallers(callers, facts, catalogue, accepted, reachOids)) {
      lines.add(FunctionGrantMessages.caller(row, catalogue));
    }
    if (!rewritten.isEmpty()) {
      // R7 first: a rewritten core function means the record the other legs read is not the
      // one this module verified. What they saw is still listed, as "also seen".
      throw unverifiable(rewritten, lines);
    }
    excess.addAll(lines);
  }

  static List<FunctionGrantsSql.RecordFact> records(Connection c, PinnedCatalogue catalogue)
      throws SQLException {
    var okExtensions = new ArrayList<>(catalogue.installableExtensions());
    var okPairs =
        catalogue.versions().stream()
            .filter(PinnedCatalogue.Version::installable)
            .map(v -> v.extension() + "\t" + v.version())
            .toList();
    return FunctionGrantsSql.records(c, baselineOids(catalogue), okExtensions, okPairs);
  }

  static long[] baselineOids(PinnedCatalogue catalogue) {
    return catalogue.baseline().stream().mapToLong(PinnedCatalogue.Withheld::oid).toArray();
  }

  // ------------------------------------------------------------ statement 1: R0 R1 R2 R4 R5v

  /** R0, R1, R2, R4 and R5v over the facts of statement 1, in oid order. */
  static List<RecordRow> judgeRecords(
      List<FunctionGrantsSql.RecordFact> facts, PinnedCatalogue catalogue) {
    var functions = new HashMap<Long, FunctionGrantsSql.RecordFact>();
    facts.stream().filter(f -> f.kind().equals("fn")).forEach(f -> functions.put(f.oid(), f));
    var baseline = new HashMap<Long, PinnedCatalogue.Withheld>();
    catalogue.baseline().forEach(w -> baseline.put(w.oid(), w));
    var out = new ArrayList<RecordRow>();
    for (PinnedCatalogue.Withheld w : catalogue.baseline()) {
      var live = functions.get(w.oid());
      if (live == null || !live.signature().equals(w.signature())) {
        out.add(
            new RecordRow(
                "R0", w.oid(), w.signature(), live == null ? "" : live.signature(), false));
        continue;
      }
      if (!live.privtype().equals("i")) {
        out.add(new RecordRow("R1-missing", w.oid(), "", w.signature(), false));
      } else if (!normalAcl(live.acl()).equals(w.acl())) {
        out.add(new RecordRow("R1-changed", w.oid(), normalAcl(live.acl()), w.signature(), false));
      }
    }
    for (var f :
        functions.values().stream().sorted(Comparator.comparingLong(f -> f.oid())).toList()) {
      String acl = normalAcl(f.acl());
      if (f.privtype().equals("i") && !baseline.containsKey(f.oid())) {
        out.add(new RecordRow("R1-unknown", f.oid(), acl, f.signature(), false));
      }
      if (f.privtype().equals("i") && (f.namesPublic() || f.namesLate())) {
        out.add(new RecordRow("R2", f.oid(), acl, f.signature(), false));
      }
      if (f.privtype().equals("e") && f.nativeCode() && f.namesPublic()) {
        out.add(new RecordRow("R4", f.oid(), acl, f.signature(), false));
      }
    }
    Set<String> shipped = catalogue.installableExtensions();
    for (var e : facts) {
      if (!e.kind().equals("ext") || !shipped.contains(e.extension())) {
        continue;
      }
      List<String> listed = catalogue.installableVersions(e.extension());
      if (listed.contains(e.version())) {
        continue;
      }
      boolean updateSource =
          !e.targets().isEmpty()
              && Arrays.stream(e.targets().split("\t")).anyMatch(listed::contains);
      out.add(
          new RecordRow(
              "R5v", e.oid(), e.extension() + "\t" + e.version(), e.extension(), updateSource));
    }
    return out;
  }

  /** A shipped ACL in normal form: entries sorted by byte order, as the generator writes them. */
  static String normalAcl(String acl) {
    if (acl.isEmpty()) {
      return "";
    }
    return Arrays.stream(acl.split(","))
        .sorted(PinnedCatalogue.C_ORDER)
        .reduce((a, b) -> a + "," + b)
        .orElse("");
  }

  // ------------------------------------------------------- statement 2: legs 1 to 3, R3, R5

  /** What every verdict reads: the baseline oids, the symbols of W, the manifest index. */
  private record Context(
      TreeMap<Long, List<FunctionGrantsSql.ExecuteFact>> byOid,
      Set<Long> baselineOids,
      Map<String, String> wSymbols,
      Map<String, String> initdbSymbols,
      ManifestIndex index) {}

  private static Context context(
      List<FunctionGrantsSql.ExecuteFact> facts,
      PinnedCatalogue catalogue,
      Map<Long, String> supports) {
    var baselineOids = new HashSet<Long>();
    catalogue.baseline().forEach(w -> baselineOids.add(w.oid()));
    var byOid = new TreeMap<Long, List<FunctionGrantsSql.ExecuteFact>>();
    facts.forEach(f -> byOid.computeIfAbsent(f.oid(), k -> new ArrayList<>()).add(f));
    // Symbols of the caller-rights functions in W, and of its initdb part, with the lowest oid.
    var wSymbols = new HashMap<String, String>();
    var initdbSymbols = new HashMap<String, String>();
    for (var list : byOid.values()) {
      var f = list.get(0);
      if (f.securityDefiner()) {
        continue;
      }
      if (inW(f, baselineOids)) {
        wSymbols.putIfAbsent(f.symbol(), f.label());
      }
      if (inInitdbW(f, baselineOids)) {
        initdbSymbols.putIfAbsent(f.symbol(), f.label());
      }
    }
    return new Context(
        byOid, baselineOids, wSymbols, initdbSymbols, new ManifestIndex(catalogue, supports));
  }

  /**
   * Legs 1 to 3, R3 (leg 4), R5a (leg 5) and R5b (leg 6) over the facts of statement 2. Each
   * (function, grantee) pair is reported once, by its lowest leg, in (function, grantee) order.
   * {@code supports} holds the live support column of each aggregate ({@link #supports}).
   */
  static List<ExecuteRow> judgeExecutes(
      List<FunctionGrantsSql.ExecuteFact> facts,
      PinnedCatalogue catalogue,
      List<String> accepted,
      Set<Long> reach,
      Map<Long, String> supports) {
    var ctx = context(facts, catalogue, supports);
    var out = new ArrayList<ExecuteRow>();
    for (var list : ctx.byOid().values()) {
      var f = list.get(0);
      var grantees = list.stream().filter(x -> x.grantee().isPresent()).toList();
      if (grantees.isEmpty()) {
        continue;
      }
      Optional<Verdict> v = verdict(f, ctx, accepted);
      if (v.isEmpty()) {
        continue;
      }
      Verdict verdict = v.orElseThrow();
      for (var g : grantees) {
        long grantee = g.grantee().orElseThrow();
        out.add(
            new ExecuteRow(
                f.oid(),
                grantee,
                verdict.leg(),
                verdict.sub(),
                verdict.ref(),
                f.label(),
                verdict.sameAs(),
                grantee == f.owner(),
                f.ownerName(),
                f.extension(),
                f.version(),
                f.symbol()));
      }
    }
    return out;
  }

  /** The lowest leg one function falls under, if any. */
  private record Verdict(int leg, int sub, String ref, String sameAs) {}

  private static Optional<Verdict> verdict(
      FunctionGrantsSql.ExecuteFact f, Context ctx, List<String> accepted) {
    Set<Long> baselineOids = ctx.baselineOids();
    ManifestIndex index = ctx.index();
    if (inW(f, baselineOids)) {
      return Optional.of(new Verdict(1, 0, "", ""));
    }
    if (f.kind().equals("a")) {
      // R6 (revision 5): an aggregate runs no code of its own (symbol aggregate_dummy). R6 judges
      // the functions it calls; R5b still judges a shipped aggregate, support functions included.
      return index.r5b(f, accepted);
    }
    if (!f.nativeCode()) {
      return Optional.empty();
    }
    Map<String, String> wSymbols = ctx.wSymbols();
    Map<String, String> initdbSymbols = ctx.initdbSymbols();
    // Leg 2 (C-PR45-3-16): a core function in language internal can run only server built-ins,
    // so it is compared with the initdb part of W; every other native function with all of W.
    boolean core = f.oid() < FunctionGrantsSql.FIRST_NORMAL_OID && f.extension().isEmpty();
    Map<String, String> aliases =
        core && f.language().equals("internal") ? initdbSymbols : wSymbols;
    if (!f.securityDefiner() && aliases.containsKey(f.symbol())) {
      return Optional.of(new Verdict(2, 0, f.symbol(), aliases.get(f.symbol())));
    }
    if (f.securityDefiner()) {
      return Optional.of(new Verdict(3, 0, "", ""));
    }
    if (f.oid() >= FunctionGrantsSql.FIRST_NORMAL_OID && f.extension().isEmpty()) {
      return Optional.of(new Verdict(4, 0, "", ""));
    }
    return index.r5a(f).or(() -> index.r5b(f, accepted));
  }

  static boolean inW(FunctionGrantsSql.ExecuteFact f, Set<Long> baselineOids) {
    return baselineOids.contains(f.oid()) || (!f.privtype().isEmpty() && !f.shippedPublic());
  }

  static boolean inInitdbW(FunctionGrantsSql.ExecuteFact f, Set<Long> baselineOids) {
    return baselineOids.contains(f.oid()) || (f.privtype().equals("i") && !f.shippedPublic());
  }

  /** The pinned manifest and baseline, indexed for R5a and R5b. */
  private static final class ManifestIndex {
    private final Map<String, PinnedCatalogue.Member> byKey = new HashMap<>();
    private final Map<String, PinnedCatalogue.Member> withheldSymbolByVersion = new HashMap<>();
    private final Map<String, PinnedCatalogue.Member> withheldSymbol = new TreeMap<>();
    private final Map<String, PinnedCatalogue.Withheld> baselineKey = new HashMap<>();
    private final Map<String, PinnedCatalogue.Withheld> baselineSymbol = new HashMap<>();
    private final Set<String> okPairs = new HashSet<>();
    private final Set<String> okExtensions;
    private final Map<Long, String> supports;

    ManifestIndex(PinnedCatalogue catalogue, Map<Long, String> supports) {
      this.supports = supports;
      for (var m : catalogue.manifest()) {
        byKey.put(m.extension() + "\t" + m.version() + "\t" + m.key(), m);
        if (m.withheld() && !m.securityDefiner()) {
          withheldSymbolByVersion.putIfAbsent(
              m.extension() + "\t" + m.version() + "\t" + m.symbol(), m);
          withheldSymbol.putIfAbsent(m.symbol(), m);
        }
      }
      for (var w : catalogue.baseline()) {
        baselineKey.putIfAbsent(w.key(), w);
        if (!w.securityDefiner()) {
          baselineSymbol.putIfAbsent(w.symbol(), w);
        }
      }
      catalogue.versions().stream()
          .filter(PinnedCatalogue.Version::installable)
          .forEach(v -> okPairs.add(v.extension() + "\t" + v.version()));
      okExtensions = catalogue.installableExtensions();
    }

    /** R5a, pinned withheld code, cases 1 to 4 (design section 5, R5). */
    Optional<Verdict> r5a(FunctionGrantsSql.ExecuteFact f) {
      String ev = f.extension() + "\t" + f.version();
      if (!f.extension().isEmpty()) {
        var entry = byKey.get(ev + "\t" + f.key());
        if (entry != null && entry.withheld()) {
          return Optional.of(new Verdict(5, 1, line(entry), ""));
        }
        var same = withheldSymbolByVersion.get(ev + "\t" + f.symbol());
        if (!f.securityDefiner() && same != null) {
          return Optional.of(new Verdict(5, 2, line(same), ""));
        }
      }
      var byBaselineKey = baselineKey.get(f.key());
      if (byBaselineKey != null) {
        return Optional.of(new Verdict(5, 3, byBaselineKey.symbol(), byBaselineKey.signature()));
      }
      var byBaselineSymbol = baselineSymbol.get(f.symbol());
      if (!f.securityDefiner() && byBaselineSymbol != null) {
        return Optional.of(new Verdict(5, 3, f.symbol(), byBaselineSymbol.signature()));
      }
      var any = withheldSymbol.get(f.symbol());
      if (!f.extension().isEmpty()
          && !okExtensions.contains(f.extension())
          && !f.securityDefiner()
          && any != null) {
        return Optional.of(new Verdict(5, 4, line(any), ""));
      }
      return Optional.empty();
    }

    /** R5b, an extension member not as shipped: (i) sub 1, (ii) sub 2. */
    Optional<Verdict> r5b(FunctionGrantsSql.ExecuteFact f, List<String> accepted) {
      if (f.extension().isEmpty()) {
        return Optional.empty();
      }
      String ev = f.extension() + "\t" + f.version();
      if (okPairs.contains(ev)) {
        var entry = byKey.get(ev + "\t" + f.key());
        boolean asShipped =
            entry != null
                && entry.symbol().equals(f.symbol())
                && entry.securityDefiner() == f.securityDefiner()
                && entry.supports().equals(supports.getOrDefault(f.oid(), ""));
        return asShipped ? Optional.empty() : Optional.of(new Verdict(6, 1, "", ""));
      }
      if (okExtensions.contains(f.extension())) {
        return Optional.empty(); // R5v reports it in statement 1, as 005
      }
      return accepted.contains(f.extension())
          ? Optional.empty()
          : Optional.of(new Verdict(6, 2, "", ""));
    }

    private static String line(PinnedCatalogue.Member m) {
      return String.join("\t", m.extension(), m.version(), m.key(), m.symbol());
    }
  }

  // ------------------------------------------------------- statement 3: R6, caller objects

  /**
   * The live support column of each aggregate in statement 3, in the manifest's form: {@code
   * slot=key} items in slot order, joined by ';'.
   */
  static Map<Long, String> supports(List<FunctionGrantsSql.CallerFact> callers) {
    var bySlot = new TreeMap<Long, TreeMap<Integer, String>>();
    for (var c : callers) {
      if (c.kind().equals("agg")) {
        bySlot
            .computeIfAbsent(c.oid(), k -> new TreeMap<>())
            .put(c.slot(), slotName(c) + "=" + c.fnKey());
      }
    }
    var out = new HashMap<Long, String>();
    bySlot.forEach((oid, slots) -> out.put(oid, String.join(";", slots.values())));
    return out;
  }

  /**
   * R6: a caller object that reach or PUBLIC may use, owned by a role outside reach, whose slot
   * runs with the owner's EXECUTE checked or with none, and whose slot function falls under leg 1
   * to 6. An object owned by a role in reach is skipped: its owner checks run as reach, and the
   * other legs judge what reach holds. One row per (object, slot), in (kind, object, slot) order.
   */
  static List<CallerRow> judgeCallers(
      List<FunctionGrantsSql.CallerFact> callers,
      List<FunctionGrantsSql.ExecuteFact> facts,
      PinnedCatalogue catalogue,
      List<String> accepted,
      Set<Long> reach) {
    var ctx = context(facts, catalogue, supports(callers));
    var out = new ArrayList<CallerRow>();
    for (var c : callers) {
      if (!ownerOrNobody(c.kind(), c.slot()) || !c.usable() || reach.contains(c.owner())) {
        continue;
      }
      var list = ctx.byOid().get(c.fn());
      if (list == null) {
        continue; // not native, no shipped record, not in the baseline: code reach could write
      }
      var f = list.get(0);
      Optional<Verdict> v = verdict(f, ctx, accepted);
      if (v.isEmpty()) {
        continue;
      }
      Verdict verdict = v.orElseThrow();
      out.add(
          new CallerRow(
              c.kind(),
              c.oid(),
              c.label(),
              slotName(c),
              c.ownerName(),
              f.label(),
              verdict.leg(),
              verdict.sub(),
              verdict.ref(),
              verdict.sameAs(),
              f.extension(),
              f.version()));
    }
    return out;
  }

  private static String slotName(FunctionGrantsSql.CallerFact c) {
    List<String> names = SLOTS.getOrDefault(c.kind(), List.of());
    return c.slot() >= 1 && c.slot() <= names.size() ? names.get(c.slot() - 1) : "slot " + c.slot();
  }

  // ------------------------------------------------------------- R7, core native functions

  /**
   * R7 (C-PR45-3-17): each function the core record lists (by signature, below oid 16384, in an
   * extension or not, so {@code ALTER EXTENSION ... ADD} does not hide it) matches its line in
   * language, symbol, library and rights mode; and each native function below oid 16384 in no
   * extension has a line. {@code CREATE OR REPLACE} keeps the oid, so only this record tells "as
   * shipped" from "rewritten in place". Each mismatch is one {@code 005} line, in signature order.
   */
  static List<String> judgeCore(
      List<FunctionGrantsSql.ExecuteFact> facts, PinnedCatalogue catalogue) {
    var live = new TreeMap<String, FunctionGrantsSql.ExecuteFact>(PinnedCatalogue.C_ORDER);
    for (var f : facts) {
      if (f.oid() < FunctionGrantsSql.FIRST_NORMAL_OID) {
        live.putIfAbsent(f.label(), f);
      }
    }
    var lines = new TreeMap<String, String>(PinnedCatalogue.C_ORDER);
    var recorded = new HashSet<String>();
    int major = catalogue.major();
    for (var line : catalogue.core()) {
      recorded.add(line.signature());
      var f = live.get(line.signature());
      if (f == null) {
        lines.put(line.signature(), FunctionGrantMessages.coreMissing(line, major));
      } else if (!f.nativeCode()
          || !f.language().equals(line.language())
          || !f.symbol().equals(line.symbol())
          || !library(f).equals(line.library())
          || f.securityDefiner() != line.securityDefiner()) {
        lines.put(
            line.signature(), FunctionGrantMessages.coreRewritten(f, library(f), line, major));
      }
    }
    for (var f : live.values()) {
      if (f.nativeCode() && f.extension().isEmpty() && !recorded.contains(f.label())) {
        lines.put(f.label(), FunctionGrantMessages.coreUnknown(f, library(f), major));
      }
    }
    return List.copyOf(lines.values());
  }

  /** The library column of a fact, as the core record writes it. */
  static String library(FunctionGrantsSql.ExecuteFact f) {
    return f.library().isEmpty() ? "-" : f.library();
  }

  private static boolean superuserLogin(SchemaVerification.Reach reach) {
    return reach.roles().stream().anyMatch(r -> r.oid() == reach.loginOid() && r.superuser());
  }

  private static ShreddingException unverifiable(List<String> why, List<String> alsoSeen) {
    var lines = new ArrayList<String>(why);
    alsoSeen.forEach(s -> lines.add("also seen: " + s));
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: the function grants of this server cannot be judged (C-PR45-3):"
            + lines.stream().map(l -> "\n  - " + l).reduce("", String::concat)
            + "\nThe check compares the server's record of withheld functions with files pinned"
            + " in this jar. Unverifiable is not clean, so this is a refusal, and"
            + " shredding.jdbc.allow-privileged-runtime-role does not relax it.");
  }
}
