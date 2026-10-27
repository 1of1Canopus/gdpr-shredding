package com.housedevinci.shredding.adapter.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Rules O2 and O3 of the owner-context design page, Rev 2 (C-RC021-2c, -2f, -2g). Code that the
 * server runs as a role outside reach because reach wrote a row or ran a statement (owner context)
 * must not resolve a name into, or write to, an object reach controls; and reach must not run
 * maintenance on a table it does not own.
 *
 * <ul>
 *   <li><b>O2.</b> When the database holds at least one owner-context entry point, reach and PUBLIC
 *       hold no CREATE on any schema, no role in reach owns a schema, and no role in reach owns any
 *       other object of the database. An entry point is (i) a {@code SECURITY DEFINER} function or
 *       procedure owned outside reach, any language, any ACL, or (ii) a foreign key, any action,
 *       whose referencing or referenced table is owned outside reach. The entry list is closed
 *       against the server's identity-switch call sites ({@link #CALL_SITES}): a major whose list
 *       is missing, or has a site that maps to none of the known outcomes, makes O2 apply with no
 *       condition. Relaxed by {@code allow-privileged-runtime-role}, with its WARN.
 *   <li><b>O3.</b> Reach and PUBLIC hold no {@code MAINTAIN} (PostgreSQL 17) and no {@code TRIGGER}
 *       (C-PR53-1) on a relation owned outside reach, and reach owns no partitioned table or index
 *       with a partition owned outside reach (C-PR53-3). Not relaxed by any mode.
 * </ul>
 *
 * <p>The facts come from the statement file {@value #STATEMENT}, beside the pinned files, in the
 * house dialect; Java decides. Runs on the verification's connection, inside its pinned window.
 */
final class OwnerContext {

  private OwnerContext() {}

  static final String STATEMENT = "owner-context.sql";

  /** The binds of the statement: each takes the reach oids. */
  static final int BINDS = 6;

  /** The call-site map of a major: one line per source file, {@code file<TAB>outcome}. */
  static String callSitesResource(int major) {
    return "owner-context-call-sites-" + major + ".tsv";
  }

  /**
   * The outcomes a call site may map to (Closure table of the design page): {@code i} and {@code
   * ii} are the O2 entry points, {@code O3} maintenance, {@code caller} a switch to the caller
   * itself, {@code refused} a path the gate already refuses, {@code not-reach} a switch that is not
   * reach's statement, {@code definition} the file that defines the switch function.
   */
  static final Set<String> CALL_SITES =
      Set.of("i", "ii", "O3", "caller", "refused", "not-reach", "definition");

  /** One row of the statement: see the file's header. */
  record Fact(String kind, long oid, String label, long owner, String ownerName, long other) {}

  static void check(
      Connection c, SchemaVerification.Reach reach, List<String> excess, List<String> strict)
      throws SQLException {
    int major = FunctionGrantsSql.major(c);
    var reachOids = new HashSet<Long>();
    for (long oid : reach.oids()) {
      reachOids.add(oid);
    }
    Verdict v = judge(facts(c, reach.oids()), reachOids, callSitesMapped(major), major);
    v.o2().forEach(line -> excess.add(line.with(reach)));
    v.o3().forEach(line -> strict.add(line.with(reach)));
  }

  /** A finding before the holder is named: {@code who} is a role oid, or 0 for PUBLIC. */
  record Line(long who, String rest) {
    String with(SchemaVerification.Reach reach) {
      return reach.named(who) + " " + rest;
    }
  }

  /** The two rules' findings, in statement order. */
  record Verdict(List<String> entryPoints, List<Line> o2, List<Line> o3) {}

  /** O2 and O3 over the facts. {@code mapped} is {@link #callSitesMapped} for the server major. */
  static Verdict judge(List<Fact> facts, Set<Long> reach, boolean mapped, int major) {
    var entries = new ArrayList<String>();
    for (Fact f : facts) {
      if (f.kind().equals("def") && !reach.contains(f.owner())) {
        entries.add(
            "function "
                + text(f.label())
                + " is SECURITY DEFINER, owned by "
                + text(f.ownerName())
                + " outside reach");
      } else if (f.kind().equals("fk")
          && (!reach.contains(f.owner()) || !reach.contains(f.other()))) {
        entries.add(text(f.label()) + " has a table owned outside reach");
      }
    }
    var o3 = new ArrayList<Line>();
    for (Fact f : facts) {
      if (f.kind().equals("mnt") && !reach.contains(f.owner())) {
        o3.add(
            new Line(
                f.other(),
                "holds MAINTAIN on relation "
                    + text(f.label())
                    + ", owned by "
                    + text(f.ownerName())
                    + " outside reach: VACUUM, ANALYZE, CLUSTER, REINDEX and REFRESH MATERIALIZED"
                    + " VIEW run its index expressions as the owner. Revoke it;"
                    + " allow-privileged-runtime-role does not relax this (O3, C-RC021-2f)"));
      }
    }
    for (Fact f : facts) {
      if (f.kind().equals("trg") && !reach.contains(f.owner())) {
        o3.add(
            new Line(
                f.other(),
                "holds TRIGGER on relation "
                    + text(f.label())
                    + ", owned by "
                    + text(f.ownerName())
                    + " outside reach: a trigger it adds fires for every writer, and its WHEN runs"
                    + " as the owner when a foreign-key action or the owner's own session writes."
                    + " Revoke it; allow-privileged-runtime-role does not relax this (O3,"
                    + " C-PR53-1)"));
      } else if (f.kind().equals("ptn") && !reach.contains(f.other())) {
        String[] pair = f.label().split("\t", 2);
        o3.add(
            new Line(
                f.owner(),
                "owns partitioned relation "
                    + text(pair[0])
                    + ", whose partition "
                    + text(pair.length == 2 ? pair[1] : "")
                    + " is owned by "
                    + text(f.ownerName())
                    + " outside reach: REINDEX on the parent rebuilds the partition's"
                    + " indexes, and runs their expressions, as that owner. Give the parent to the"
                    + " partition's owner; allow-privileged-runtime-role does not relax this (O3,"
                    + " C-PR53-3)"));
      } else if (f.kind().equals("nso") && !reach.contains(f.other())) {
        String[] pair = f.label().split("\\t", 2);
        o3.add(
            new Line(
                f.owner(),
                "owns schema "
                    + text(pair[0])
                    + ", which holds relation "
                    + text(pair.length == 2 ? pair[1] : "")
                    + ", owned by "
                    + text(f.ownerName())
                    + " outside reach: REINDEX SCHEMA by the schema's owner rebuilds that"
                    + " relation's indexes, and runs their expressions, as its owner. Give the"
                    + " schema to the relation's owner, or move the relation out;"
                    + " allow-privileged-runtime-role does not relax this (O3, C-PR53-6)"));
      }
    }
    if (entries.isEmpty() && mapped) {
      return new Verdict(List.of(), List.of(), o3);
    }
    String why = because(entries, mapped, major);
    var o2 = new ArrayList<Line>();
    for (Fact f : facts) {
      switch (f.kind()) {
        case "nsp" -> {
          if (reach.contains(f.owner())) {
            o2.add(new Line(f.owner(), "owns schema " + text(f.label()) + why));
          }
        }
        case "crt" ->
            o2.add(new Line(f.other(), "holds CREATE on schema " + text(f.label()) + why));
        case "own" -> {
          if (reach.contains(f.owner())) {
            o2.add(new Line(f.owner(), "owns " + text(f.label()) + why));
          }
        }
        default -> {
          // def, fk: entry points above; mnt: O3 above
        }
      }
    }
    return new Verdict(List.copyOf(entries), o2, o3);
  }

  private static String because(List<String> entries, boolean mapped, int major) {
    String which =
        mapped
            ? entries.get(0) + (entries.size() > 1 ? ", and " + (entries.size() - 1) + " more" : "")
            : "the server's identity-switch sites for PostgreSQL "
                + major
                + " are not all mapped by this release, so every one counts";
    return ", and this database runs code as a role outside reach because of what reach writes"
        + " or calls ("
        + which
        + "). That code resolves names into, and writes to, what reach owns or may create. Give"
        + " the object to a role outside reach, or revoke CREATE; or keep reach as the owner of"
        + " every such table and function (O2, C-RC021-2c, C-RC021-2g)";
  }

  /**
   * True when this release ships a call-site map for {@code major} and every site in it maps to a
   * known outcome. A missing or unreadable map is false: O2 then applies with no condition.
   */
  static boolean callSitesMapped(int major) {
    return callSites(major)
        .map(m -> !m.isEmpty() && CALL_SITES.containsAll(m.values()))
        .orElse(false);
  }

  /** The call-site map of {@code major}, file to outcome, in file order; empty when not shipped. */
  static Optional<Map<String, String>> callSites(int major) {
    try (InputStream in = OwnerContext.class.getResourceAsStream(callSitesResource(major))) {
      if (in == null) {
        return Optional.empty();
      }
      var out = new LinkedHashMap<String, String>();
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        if (line.isBlank() || line.startsWith("#")) {
          continue;
        }
        String[] cells = line.split("\t", -1);
        out.put(cells[0], cells.length == 2 ? cells[1] : "");
      }
      return Optional.of(out);
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  /** The text of the statement, read from the jar ({@code 005} when missing). */
  static String ownerContextStatement() {
    return FunctionGrantsSql.resource(STATEMENT);
  }

  static List<Fact> facts(Connection c, long[] reachOids) throws SQLException {
    var out = new ArrayList<Fact>();
    try (PreparedStatement ps = c.prepareStatement(ownerContextStatement())) {
      for (int i = 1; i <= BINDS; i++) {
        ps.setArray(i, c.createArrayOf("oid", boxed(reachOids)));
      }
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.add(
              new Fact(
                  rs.getString(1),
                  rs.getLong(2),
                  nonNull(rs.getString(3)),
                  rs.getLong(4),
                  nonNull(rs.getString(5)),
                  rs.getLong(6)));
        }
      }
    }
    return out;
  }

  private static String nonNull(String s) {
    return s == null ? "" : s;
  }

  private static String text(String s) {
    return com.housedevinci.shredding.application.LogText.escape(s);
  }

  private static Long[] boxed(long[] values) {
    var out = new Long[values.length];
    for (int i = 0; i < values.length; i++) {
      out[i] = values[i];
    }
    return out;
  }
}
