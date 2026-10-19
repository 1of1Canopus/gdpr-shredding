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
 * {@link PinnedCatalogue}.
 *
 * <p>Runs on the verification's connection, inside its pinned window, after the parameter leg. A
 * finding is a {@code SHRED-SCHEMA-004} line. A server major with no pinned files, a baseline oid
 * whose signature differs (R0), and an installed extension version the manifest does not list (R5v)
 * are {@code SHRED-SCHEMA-005}: the record cannot be judged, and unverifiable is not clean,
 * whatever {@code allow-privileged-runtime-role} says.
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
    if (superuserLogin(reach)) {
      // "login role X is a superuser" says it all (F28): the bootstrap superuser is the owner in
      // the default ACL of every withheld function, so the leg would list each one.
      return;
    }
    var reachOids = new HashSet<Long>();
    for (long oid : reach.oids()) {
      reachOids.add(oid);
    }
    List<FunctionGrantsSql.ExecuteFact> facts =
        FunctionGrantsSql.executes(c, reach.oids(), baselineOids(catalogue));
    for (ExecuteRow row : judgeExecutes(facts, catalogue, accepted, reachOids)) {
      long g = row.grantee();
      excess.add(
          FunctionGrantMessages.held(
              row, reach.named(g), g == 0 ? "PUBLIC" : reach.name(g), catalogue));
    }
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

  /**
   * Legs 1 to 3, R3 (leg 4), R5a (leg 5) and R5b (leg 6) over the facts of statement 2. Each
   * (function, grantee) pair is reported once, by its lowest leg, in (function, grantee) order.
   */
  static List<ExecuteRow> judgeExecutes(
      List<FunctionGrantsSql.ExecuteFact> facts,
      PinnedCatalogue catalogue,
      List<String> accepted,
      Set<Long> reach) {
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
    var index = new ManifestIndex(catalogue);

    var out = new ArrayList<ExecuteRow>();
    for (var list : byOid.values()) {
      var f = list.get(0);
      var grantees = list.stream().filter(x -> x.grantee().isPresent()).toList();
      if (grantees.isEmpty()) {
        continue;
      }
      if (f.kind().equals("a") && reach.contains(f.owner())) {
        // pending ruling (C-PR45-3-15, design revision 5): an aggregate owned by a role in reach
        // runs its support functions with reach's rights, so legs 1 to 3 judge what it can call.
        // An aggregate owned outside reach is not exempt and stays judged below.
        continue;
      }
      Optional<Verdict> v = verdict(f, baselineOids, wSymbols, initdbSymbols, index, accepted);
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
      FunctionGrantsSql.ExecuteFact f,
      Set<Long> baselineOids,
      Map<String, String> wSymbols,
      Map<String, String> initdbSymbols,
      ManifestIndex index,
      List<String> accepted) {
    if (inW(f, baselineOids)) {
      return Optional.of(new Verdict(1, 0, "", ""));
    }
    if (!f.nativeCode()) {
      return Optional.empty();
    }
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

    ManifestIndex(PinnedCatalogue catalogue) {
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
                && entry.securityDefiner() == f.securityDefiner();
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
