package com.housedevinci.shredding.adapter.jdbc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.postgresql.util.PSQLException;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Writes the four pinned files of one PostgreSQL major from a pristine container of the pinned
 * image (C-PR45-3, revision 4 with C-PR45-3-13): the initdb baseline, the per-version extension
 * manifest (with each aggregate's support functions), the list of available versions, and the
 * record of every core native function (revision 5, R7). Never typed by hand: {@code
 * tools/generate-pinned-catalogue.sh} runs {@link #main}, and the byte-for-byte tests run {@link
 * #generate} and compare.
 *
 * <p>Each version is installed in a fresh database under the server's default {@code search_path}
 * (a non-relocatable script needs it), and its members are read inside the pinned window. It
 * refuses, and writes nothing, when a version fails for any reason other than a library the image
 * does not carry, when an extension is half installable, when a chain install differs from the
 * direct one, when an entry repeats, or when any pristine install or a clean core gives an R5 row.
 */
final class PinnedCatalogueGenerator {

  /** A refusal of the generator: no file is written. */
  static final class Refused extends IllegalStateException {
    Refused(String message) {
      super(message);
    }
  }

  /** The four files, as bytes would be written, plus what the self-check saw. */
  record Output(
      String baseline,
      String manifest,
      String versions,
      String core,
      int databasesJudged,
      List<String> otherLegRows) {}

  /** One initdb function with a shipped record, as read from the image. */
  record BaselineRow(
      long oid,
      String signature,
      String key,
      String symbol,
      boolean definer,
      String acl,
      boolean publicExecutes) {}

  private static final Comparator<String> C_ORDER = PinnedCatalogue.C_ORDER;

  /**
   * The login oid statement 3 takes (C-PR47-4). The generator passes no reach, so no CASE branch
   * calls pg_has_role; oid 10 is the bootstrap superuser, which every cluster has.
   */
  private static final long BOOTSTRAP_SUPERUSER = 10L;

  private PinnedCatalogueGenerator() {}

  /** {@code major outDir}: starts the pinned image of {@code major}, writes its four files. */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      throw new IllegalArgumentException("usage: <major 16|17> <output directory>");
    }
    int major = Integer.parseInt(args[0]);
    Path out = Path.of(args[1]);
    try (var pg = TwoRoleCluster.pristine(TwoRoleCluster.image(major))) {
      pg.start();
      Output o = generate(pg);
      Files.writeString(out.resolve(PinnedCatalogue.baselineResource(major)), o.baseline());
      Files.writeString(out.resolve(PinnedCatalogue.manifestResource(major)), o.manifest());
      Files.writeString(out.resolve(PinnedCatalogue.versionsResource(major)), o.versions());
      Files.writeString(out.resolve(PinnedCatalogue.coreResource(major)), o.core());
      System.out.printf(
          "PostgreSQL %d: baseline %d, manifest %d, versions %d, core %d lines;"
              + " %d databases judged%n",
          major,
          o.baseline().lines().count(),
          o.manifest().lines().count(),
          o.versions().lines().count(),
          o.core().lines().count(),
          o.databasesJudged());
    }
  }

  static Output generate(PostgreSQLContainer<?> pg) throws SQLException {
    return generate(pg, false);
  }

  /**
   * @param installPinned mutation 26 only: install inside the pinned window, the C-PR45-3-13
   *     mistake. Production of the files always passes {@code false}.
   */
  static Output generate(PostgreSQLContainer<?> pg, boolean installPinned) throws SQLException {
    var dbs = new ArrayList<String>();
    try (Connection admin = connect(pg, pg.getDatabaseName())) {
      admin.setAutoCommit(true);
      int major = FunctionGrantsSql.major(admin);
      String baseline = baselineText(baselineRows(admin));
      var versions = new ArrayList<PinnedCatalogue.Version>();
      var members = new TreeMap<String, List<String>>(C_ORDER);
      var internalWithheld = new TreeMap<String, String>(C_ORDER);
      int n = 0;
      for (String[] ev : available(admin)) {
        String db = "gen_" + (n++);
        create(admin, db);
        dbs.add(db);
        Optional<String> error = install(pg, db, ev[0], ev[1], installPinned);
        versions.add(version(ev[0], ev[1], error));
        if (error.isEmpty()) {
          members.put(ev[0] + "\t" + ev[1], members(pg, db, ev[0], internalWithheld));
        }
      }
      String versionsText = versionsText(versions);
      String manifest = manifestText(members);
      // Chain installs: the oldest installable version updated to each other one.
      for (var chain : chains(admin, versions).entrySet()) {
        String[] from = chain.getKey().split("\t");
        for (String to : chain.getValue()) {
          // One database per target: each starts at the oldest version.
          String each = "gen_" + (n++);
          create(admin, each);
          dbs.add(each);
          if (install(pg, each, from[0], from[1], installPinned).isPresent()
              || !update(pg, each, from[0], to)) {
            throw new Refused(
                "chain install of " + from[0] + " " + from[1] + " to " + to + " failed");
          }
          List<String> chained = members(pg, each, from[0], internalWithheld);
          List<String> direct = members.getOrDefault(from[0] + "\t" + to, List.of());
          if (!chained.equals(direct)) {
            throw new Refused(
                "extension "
                    + from[0]
                    + " "
                    + to
                    + ": the chain install from "
                    + from[1]
                    + " differs from the direct install");
          }
        }
      }
      String core = "gen_core";
      create(admin, core);
      dbs.add(core);
      var cleanCore = facts(pg, core);
      String coreText = coreText(cleanCore);
      var catalogue =
          PinnedCatalogue.of(
              major,
              PinnedCatalogue.parseBaseline("baseline", baseline),
              PinnedCatalogue.parseManifest("manifest", manifest),
              PinnedCatalogue.parseVersions("versions", versionsText),
              PinnedCatalogue.parseCore("core", coreText));
      proveCoreExemption(cleanCore, catalogue, internalWithheld);
      var other = new ArrayList<String>();
      for (String db : dbs) {
        selfCheck(pg, db, catalogue, other);
      }
      for (String db : dbs) {
        try (Statement s = admin.createStatement()) {
          s.execute("DROP DATABASE " + db);
        }
      }
      return new Output(baseline, manifest, versionsText, coreText, dbs.size(), List.copyOf(other));
    }
  }

  // ------------------------------------------------------------------ baseline

  private static List<BaselineRow> baselineRows(Connection c) throws SQLException {
    var rows = new ArrayList<BaselineRow>();
    pin(c);
    for (var f : FunctionGrantsSql.records(c, new long[0], List.of(), List.of())) {
      if (f.kind().equals("fn") && f.privtype().equals("i")) {
        rows.add(
            new BaselineRow(
                f.oid(),
                f.signature(),
                f.key(),
                f.symbol(),
                f.securityDefiner(),
                FunctionGrants.normalAcl(f.acl()),
                f.namesPublic()));
      }
    }
    return rows;
  }

  /** The baseline file. Refuses an oid initdb assigns at run time, and a PUBLIC initdb record. */
  static String baselineText(List<BaselineRow> rows) {
    var out = new StringBuilder();
    rows.stream()
        .sorted(Comparator.comparingLong(BaselineRow::oid))
        .forEach(
            r -> {
              if (r.oid() >= PinnedCatalogue.FIXED_OID_LIMIT) {
                throw new Refused("oid " + r.oid() + " is not fixed by pg_proc.dat");
              }
              if (r.publicExecutes()) {
                throw new Refused("initdb record of " + r.signature() + " gives EXECUTE to PUBLIC");
              }
              out.append(
                      String.join(
                          "\t",
                          Long.toString(r.oid()),
                          field(r.signature()),
                          field(r.key()),
                          field(r.symbol()),
                          r.definer() ? "t" : "f",
                          field(r.acl())))
                  .append('\n');
            });
    if (out.isEmpty()) {
      throw new Refused("the image has no withheld initdb function");
    }
    return out.toString();
  }

  // ------------------------------------------------------------------ versions

  private static List<String[]> available(Connection c) throws SQLException {
    var out = new ArrayList<String[]>();
    try (Statement s = c.createStatement();
        ResultSet rs =
            s.executeQuery(
                "SELECT name::pg_catalog.text, version FROM"
                    + " pg_catalog.pg_available_extension_versions")) {
      while (rs.next()) {
        out.add(new String[] {rs.getString(1), rs.getString(2)});
      }
    }
    out.sort((a, b) -> C_ORDER.compare(a[0] + "\t" + a[1], b[0] + "\t" + b[1]));
    return out;
  }

  /** One versions line. A failure other than a missing library refuses (C-PR45-3-13). */
  static PinnedCatalogue.Version version(String ext, String ver, Optional<String> error) {
    if (error.isEmpty()) {
      return new PinnedCatalogue.Version(ext, ver, true, "");
    }
    String e = error.orElseThrow();
    if (!e.startsWith(PinnedCatalogue.LOAD_FAILURE)) {
      throw new Refused("extension " + ext + " " + ver + " failed to install: " + e);
    }
    return new PinnedCatalogue.Version(ext, ver, false, field(e));
  }

  static String versionsText(List<PinnedCatalogue.Version> versions) {
    var ok = new java.util.HashSet<String>();
    var fails = new java.util.HashSet<String>();
    var out = new StringBuilder();
    for (var v : versions) {
      (v.installable() ? ok : fails).add(v.extension());
      out.append(v.extension())
          .append('\t')
          .append(v.version())
          .append('\t')
          .append(v.installable() ? "ok" : "fails")
          .append('\t')
          .append(v.error())
          .append('\n');
    }
    ok.stream()
        .filter(fails::contains)
        .findFirst()
        .ifPresent(
            e -> {
              throw new Refused("extension " + e + " has both installable and failing versions");
            });
    return out.toString();
  }

  // ------------------------------------------------------------------ installs

  private static Optional<String> install(
      PostgreSQLContainer<?> pg, String db, String ext, String ver, boolean pinned)
      throws SQLException {
    try (Connection c = connect(pg, db);
        Statement s = c.createStatement()) {
      if (pinned) {
        pin(c);
      }
      try (ResultSet rs =
          s.executeQuery(
              "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = " + literal(ext))) {
        if (rs.next()) {
          // plpgsql: the template already holds it. Its members are the shipped ones.
          if (!rs.getString(1).equals(ver)) {
            throw new Refused("extension " + ext + " is pre-installed at " + rs.getString(1));
          }
          return Optional.empty();
        }
      }
      try {
        s.execute("CREATE EXTENSION " + ident(ext) + " VERSION " + literal(ver) + " CASCADE");
        return Optional.empty();
      } catch (PSQLException e) {
        // The first ERROR line, never a NOTICE that came before it.
        String message =
            e.getServerErrorMessage() == null
                ? String.valueOf(e.getMessage())
                : e.getServerErrorMessage().getMessage();
        return Optional.of(message);
      }
    }
  }

  private static boolean update(PostgreSQLContainer<?> pg, String db, String ext, String to)
      throws SQLException {
    try (Connection c = connect(pg, db);
        Statement s = c.createStatement()) {
      s.execute("ALTER EXTENSION " + ident(ext) + " UPDATE TO " + literal(to));
      return true;
    }
  }

  /**
   * The native members of {@code ext} in {@code db}, read inside the pinned window by the gate's
   * own statement 2, so the file and the gate read one text. Withheld means PUBLIC may not execute
   * it. A withheld member in language internal goes to {@code internalWithheld}, for the proof of
   * {@link #proveCoreExemption}.
   */
  private static List<String> members(
      PostgreSQLContainer<?> pg, String db, String ext, Map<String, String> internalWithheld)
      throws SQLException {
    var byOid = new TreeMap<Long, List<FunctionGrantsSql.ExecuteFact>>();
    Map<Long, String> supports;
    try (Connection c = connect(pg, db)) {
      pin(c);
      supports =
          FunctionGrants.supports(FunctionGrantsSql.callers(c, new long[0], BOOTSTRAP_SUPERUSER));
      for (var f : FunctionGrantsSql.executes(c, new long[0], new long[0])) {
        if (f.nativeCode() && f.extension().equals(ext)) {
          byOid.computeIfAbsent(f.oid(), k -> new ArrayList<>()).add(f);
        }
      }
    }
    var out = new ArrayList<String>();
    for (var list : byOid.values()) {
      var f = list.get(0);
      boolean withheld = list.stream().noneMatch(x -> x.grantee().isPresent());
      if (withheld && f.language().equals("internal")) {
        internalWithheld.putIfAbsent(f.symbol(), ext + " " + f.version() + " " + f.key());
      }
      out.add(
          String.join(
              "\t",
              field(f.key()),
              field(f.symbol()),
              f.securityDefiner() ? "t" : "f",
              withheld ? "t" : "f",
              aggregateSupports(f, supports)));
    }
    out.sort(C_ORDER);
    return out;
  }

  /** The seventh manifest column: an aggregate's support functions, empty for any other. */
  private static String aggregateSupports(
      FunctionGrantsSql.ExecuteFact f, Map<Long, String> supports) {
    if (!f.kind().equals("a")) {
      return "";
    }
    String s = supports.getOrDefault(f.oid(), "");
    if (s.isEmpty()) {
      throw new Refused("aggregate " + f.label() + " has no support function in statement 3");
    }
    return field(s);
  }

  /**
   * The R7 record (C-PR45-3-17): every native function below the first normal oid in no extension,
   * by signature, from a clean database. Refuses a repeated signature.
   */
  static String coreText(List<FunctionGrantsSql.ExecuteFact> cleanCore) {
    var lines = new TreeMap<String, String>(C_ORDER);
    var seen = new java.util.HashSet<Long>();
    for (var f : cleanCore) {
      if (f.oid() >= FunctionGrantsSql.FIRST_NORMAL_OID
          || !f.extension().isEmpty()
          || !f.nativeCode()
          || !seen.add(f.oid())) {
        continue;
      }
      String line =
          String.join(
              "\t",
              field(f.label()),
              field(f.language()),
              field(f.symbol()),
              field(FunctionGrants.library(f)),
              f.securityDefiner() ? "t" : "f");
      if (lines.put(f.label(), line) != null) {
        throw new Refused("core signature " + f.label() + " appears twice");
      }
    }
    if (lines.isEmpty()) {
      throw new Refused("the image has no core native function");
    }
    var out = new StringBuilder();
    lines.values().forEach(l -> out.append(l).append('\n'));
    return out.toString();
  }

  /**
   * C-PR45-3-16: leg 2 compares a core function in language internal with the initdb part of W
   * only. That gives nothing away only if every withheld internal extension symbol outside the
   * baseline is already run by a core function PUBLIC may execute on a clean image. Refuses
   * otherwise, so a future image that breaks it writes no file.
   */
  static void proveCoreExemption(
      List<FunctionGrantsSql.ExecuteFact> cleanCore,
      PinnedCatalogue catalogue,
      Map<String, String> internalWithheld) {
    var baselineSymbols = new java.util.HashSet<String>();
    catalogue.baseline().forEach(w -> baselineSymbols.add(w.symbol()));
    var publicCore = new java.util.HashSet<String>();
    for (var f : cleanCore) {
      if (f.oid() < FunctionGrantsSql.FIRST_NORMAL_OID
          && f.extension().isEmpty()
          && f.language().equals("internal")
          && f.grantee().isPresent()
          && f.grantee().getAsLong() == 0) {
        publicCore.add(f.symbol());
      }
    }
    for (var e : internalWithheld.entrySet()) {
      if (!baselineSymbols.contains(e.getKey()) && !publicCore.contains(e.getKey())) {
        throw new Refused(
            "the withheld internal member "
                + e.getValue()
                + " (symbol "
                + e.getKey()
                + ") is not run by any core function PUBLIC may execute: the leg 2 core"
                + " exemption would give it away");
      }
    }
  }

  static String manifestText(Map<String, List<String>> members) {
    var lines = new ArrayList<String>();
    members.forEach((ev, list) -> list.forEach(m -> lines.add(ev + "\t" + m)));
    lines.sort(C_ORDER);
    var seen = new java.util.HashSet<String>();
    var out = new StringBuilder();
    for (String line : lines) {
      String[] f = line.split("\t");
      if (!seen.add(f[0] + "\t" + f[1] + "\t" + f[2])) {
        throw new Refused("extension " + f[0] + " " + f[1] + " lists " + f[2] + " twice");
      }
      out.append(line).append('\n');
    }
    return out.toString();
  }

  /**
   * For each extension with more than one installable version: its oldest installable version (the
   * one that reaches the most others) and every other installable version it reaches.
   */
  private static Map<String, List<String>> chains(
      Connection c, List<PinnedCatalogue.Version> versions) throws SQLException {
    var byExt = new LinkedHashMap<String, List<String>>();
    versions.stream()
        .filter(PinnedCatalogue.Version::installable)
        .forEach(
            v -> byExt.computeIfAbsent(v.extension(), k -> new ArrayList<>()).add(v.version()));
    var out = new LinkedHashMap<String, List<String>>();
    for (var e : byExt.entrySet()) {
      if (e.getValue().size() < 2) {
        continue;
      }
      var reach = new TreeMap<String, List<String>>(C_ORDER);
      try (PreparedStatement ps =
          c.prepareStatement(
              "SELECT source, target FROM pg_catalog.pg_extension_update_paths(?)"
                  + " WHERE path IS NOT NULL")) {
        ps.setString(1, e.getKey());
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            if (e.getValue().contains(rs.getString(1)) && e.getValue().contains(rs.getString(2))) {
              reach.computeIfAbsent(rs.getString(1), k -> new ArrayList<>()).add(rs.getString(2));
            }
          }
        }
      }
      reach.entrySet().stream()
          .max(Comparator.comparingInt((Map.Entry<String, List<String>> r) -> r.getValue().size()))
          .ifPresent(
              r -> {
                var targets = new ArrayList<>(r.getValue());
                targets.sort(C_ORDER);
                out.put(e.getKey() + "\t" + r.getKey(), targets);
              });
    }
    return out;
  }

  // ------------------------------------------------------------------ self-check

  /** Runs the gate's own statements and rules with PUBLIC alone: any R5 row refuses. */
  private static void selfCheck(
      PostgreSQLContainer<?> pg, String db, PinnedCatalogue catalogue, List<String> other)
      throws SQLException {
    try (Connection c = connect(pg, db)) {
      pin(c);
      for (var r : FunctionGrants.judgeRecords(FunctionGrants.records(c, catalogue), catalogue)) {
        if (r.rule().equals("R5v")) {
          throw new Refused(db + ": R5v " + r.detail());
        }
        other.add(db + ": " + r.rule() + " " + r.label());
      }
      var facts =
          FunctionGrantsSql.executes(c, new long[0], FunctionGrants.baselineOids(catalogue));
      for (String line : FunctionGrants.judgeCore(facts, catalogue)) {
        throw new Refused(db + ": R7 " + line);
      }
      var callers = FunctionGrantsSql.callers(c, new long[0], BOOTSTRAP_SUPERUSER);
      for (var r :
          FunctionGrants.judgeCallers(callers, facts, catalogue, List.of(), java.util.Set.of())) {
        throw new Refused(db + ": R6 " + r.label() + " " + r.slot() + " " + r.function());
      }
      for (var r :
          FunctionGrants.judgeExecutes(
              facts, catalogue, List.of(), java.util.Set.of(), FunctionGrants.supports(callers))) {
        if (r.leg() >= 5) {
          throw new Refused(
              db + ": R5 row, leg " + r.leg() + " case " + r.sub() + " on " + r.label());
        }
        other.add(db + ": leg " + r.leg() + " " + r.label());
      }
    }
  }

  private static List<FunctionGrantsSql.ExecuteFact> facts(PostgreSQLContainer<?> pg, String db)
      throws SQLException {
    try (Connection c = connect(pg, db)) {
      pin(c);
      return FunctionGrantsSql.executes(c, new long[0], new long[0]);
    }
  }

  // ------------------------------------------------------------------ plumbing

  private static void create(Connection admin, String db) throws SQLException {
    try (Statement s = admin.createStatement()) {
      s.execute("CREATE DATABASE " + db + " STRATEGY = FILE_COPY");
    }
  }

  private static Connection connect(PostgreSQLContainer<?> pg, String db) throws SQLException {
    return DriverManager.getConnection(
        "jdbc:postgresql://"
            + pg.getHost()
            + ":"
            + pg.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + db,
        pg.getUsername(),
        pg.getPassword());
  }

  private static void pin(Connection c) throws SQLException {
    try (Statement s = c.createStatement()) {
      s.execute("SET search_path = " + JdbcSupport.PINNED_PATH);
      s.execute("SET jit = off");
    }
  }

  private static String field(String value) {
    if (value == null || value.isEmpty() || value.contains("\t") || value.contains("\n")) {
      throw new Refused("a column is empty or holds a tab or a line break: " + value);
    }
    return value;
  }

  private static String ident(String name) {
    return "\"" + name.replace("\"", "\"\"") + "\"";
  }

  private static String literal(String text) {
    return "'" + text.replace("'", "''") + "'";
  }
}
