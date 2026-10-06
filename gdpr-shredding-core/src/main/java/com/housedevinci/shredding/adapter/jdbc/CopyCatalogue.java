package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Acknowledged;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.application.AcknowledgedCopy;
import com.housedevinci.shredding.application.LogText;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The catalogue leg of audit-table coverage (design section 3, rows 10, 11, 15-25, 27b, 45): every
 * object the system catalogue shows through which a copy of a blind-index column exists, or comes
 * to exist, outside the admitted table and its descendants. Any one of them refuses with {@code
 * SHRED-SCHEMA-010}, unless it is a trigger, a publication that publishes {@code UPDATE} or a
 * non-{@code pgoutput} logical slot that an entry of the acknowledgement list names exactly
 * (section 3c): that one is admitted and returned, so the erasure's record names it as pending on
 * its clearing hook. Rules, materialized views, foreign keys and stale tables are never
 * acknowledgeable: the module can see they keep the value.
 *
 * <p><b>Paths, each with its own test in {@code CopyCataloguePostgresTest}:</b>
 *
 * <ol>
 *   <li>triggers on the table or any descendant: every non-internal trigger that is not disabled,
 *       whatever its event, timing, level or column list, constraint triggers and {@code ENABLE
 *       REPLICA} / {@code ENABLE ALWAYS} included. This module cannot see where a trigger writes,
 *       and an {@code INSERT} trigger copied the index long before any erasure. A trigger cloned to
 *       partitions is reported once, on its parent ({@code tgparentid});
 *   <li>rules ({@code pg_rewrite} other than a view's {@code _RETURN}): a rule rewrites the
 *       erasure's own {@code UPDATE};
 *   <li>materialized views reading a blind-index column, the whole row, or a view that does, walked
 *       through {@code pg_depend} one level per statement and bounded;
 *   <li>foreign keys with a blind-index column on either side;
 *   <li>publications carrying a blind-index column, read with {@code pg_get_publication_tables} so
 *       {@code FOR ALL TABLES}, {@code FOR TABLES IN SCHEMA} and partition roots resolve the way
 *       the server resolves them; a column list that leaves the column out is not a copy;
 *   <li>logical replication slots of this database whose plugin is not {@code pgoutput}: such a
 *       slot decodes every table without a publication;
 *   <li>stale audit and history tables, by name ({@code <table>_aud}, {@code <table>_AUD}, {@code
 *       <table>_history} in the table's schema, and every table the mapping names in {@link
 *       CopySignatures#named()}) and by shape (a column named as a blind-index column together with
 *       both columns of one {@link CopySignatures#signatures()} pair). Shape, never contents.
 * </ol>
 *
 * <p>A generated column over the index is not a path: the erasure's {@code UPDATE} recomputes it.
 * Rows of partitions and inheritance children are not a path: the erasure's {@code UPDATE} on the
 * parent reaches them.
 *
 * <p><b>Positions.</b> Called by {@link MappingAdmission#verdict} at startup, inside every erasure
 * after its table locks and before its first statement, and again after the erasure's {@code
 * UPDATE} on the same connection (C5): {@code CREATE MATERIALIZED VIEW} and {@code CREATE
 * PUBLICATION ... FOR ALL TABLES} are not blocked by the erasure's locks, and the second run moves
 * their window from the whole erasure to the time between that run and commit.
 *
 * <p>Every statement is fully qualified, binds every value, composes no identifier, and the
 * identifiers that reach a message are quoted by the server ({@code quote_ident}). The number of
 * statements never depends on the number of rows.
 */
final class CopyCatalogue {

  private CopyCatalogue() {}

  /** A view graph larger than this is unverifiable rather than walked forever. */
  static final int MAX_VIEW_NODES = 1_000;

  /** Each blind-index column on each family member, with its attribute number there. */
  static final String INDEX_COLUMNS_SQL =
      "SELECT c.oid AS relid, c.relispartition, c.relkind,"
          + " pg_catalog.quote_ident(n.nspname) AS nsp, pg_catalog.quote_ident(c.relname) AS rel,"
          + " w.ordinality AS wanted, a.attnum, a.attname AS raw,"
          + " pg_catalog.quote_ident(a.attname) AS col"
          + " FROM pg_catalog.unnest(?) WITH ORDINALITY AS f"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " CROSS JOIN pg_catalog.unnest(?) WITH ORDINALITY AS w"
          + " JOIN pg_catalog.pg_attribute a ON (a.attrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (a.attname OPERATOR(pg_catalog.=)"
          + " (SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(w.w)) WITH ORDINALITY AS p"
          + " WHERE (p.ordinality OPERATOR(pg_catalog.=) 1)))"
          + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND (NOT a.attisdropped)"
          + " ORDER BY f.ordinality, w.ordinality";

  /** Every enabled, non-internal trigger on a family member. */
  static final String TRIGGERS_SQL =
      "SELECT t.oid, t.tgrelid, pg_catalog.quote_ident(t.tgname) AS name, t.tgparentid, t.tgtype,"
          + " t.tgenabled,"
          + " (t.tgconstraint OPERATOR(pg_catalog.<>) CAST(0 AS pg_catalog.oid)) AS is_constraint,"
          + " pg_catalog.concat_ws('.', pg_catalog.quote_ident(pn.nspname),"
          + " pg_catalog.quote_ident(p.proname)) AS function,"
          + " (SELECT pg_catalog.string_agg(pg_catalog.quote_ident(a.attname), ', '"
          + " ORDER BY a.attnum) FROM pg_catalog.pg_attribute a"
          + " WHERE (a.attrelid OPERATOR(pg_catalog.=) t.tgrelid)"
          + " AND (CAST(a.attnum AS pg_catalog.text) OPERATOR(pg_catalog.=) ANY"
          + " (pg_catalog.string_to_array(CAST(t.tgattr AS pg_catalog.text), ' ')))) AS columns,"
          + " CAST(t.tgname AS pg_catalog.text) AS raw_name,"
          + " CAST(rn.nspname AS pg_catalog.text) AS raw_nsp,"
          + " CAST(rc.relname AS pg_catalog.text) AS raw_rel"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_trigger t"
          + " ON (t.tgrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_class rc ON (rc.oid OPERATOR(pg_catalog.=) t.tgrelid)"
          + " JOIN pg_catalog.pg_namespace rn ON (rn.oid OPERATOR(pg_catalog.=) rc.relnamespace)"
          + " JOIN pg_catalog.pg_proc p ON (p.oid OPERATOR(pg_catalog.=) t.tgfoid)"
          + " JOIN pg_catalog.pg_namespace pn ON (pn.oid OPERATOR(pg_catalog.=) p.pronamespace)"
          + " WHERE (NOT t.tgisinternal) AND (t.tgenabled OPERATOR(pg_catalog.<>) 'D')"
          + " ORDER BY t.tgrelid, t.tgname";

  /** Every enabled rule on a family member other than a view's own {@code _RETURN}. */
  static final String RULES_SQL =
      "SELECT r.ev_class, pg_catalog.quote_ident(r.rulename) AS name, r.ev_type, r.is_instead"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_rewrite r"
          + " ON (r.ev_class OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " WHERE (r.rulename OPERATOR(pg_catalog.<>) '_RETURN')"
          + " AND (r.ev_enabled OPERATOR(pg_catalog.<>) 'D')"
          + " ORDER BY r.ev_class, r.rulename";

  /**
   * One level of the view walk: every view or materialized view whose rule depends on one of the
   * given relations, with the column it depends on ({@code 0}: the relation as a whole, which every
   * view records) and whether its stored tree holds a whole-row reference.
   */
  static final String VIEWS_SQL =
      "SELECT d.refobjid, d.refobjsubid, v.oid AS view, v.relkind,"
          + " pg_catalog.quote_ident(vn.nspname) AS nsp, pg_catalog.quote_ident(v.relname) AS rel,"
          + " (pg_catalog.strpos(CAST(r.ev_action AS pg_catalog.text), ':varattno 0 ')"
          + " OPERATOR(pg_catalog.>) 0) AS whole_row"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_depend d"
          + " ON (d.refclassid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (d.refobjid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " AND (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_rewrite' AS pg_catalog.regclass))"
          + " JOIN pg_catalog.pg_rewrite r ON (r.oid OPERATOR(pg_catalog.=) d.objid)"
          + " JOIN pg_catalog.pg_class v ON (v.oid OPERATOR(pg_catalog.=) r.ev_class)"
          + " JOIN pg_catalog.pg_namespace vn ON (vn.oid OPERATOR(pg_catalog.=) v.relnamespace)"
          + " WHERE (r.ev_class OPERATOR(pg_catalog.<>) d.refobjid)"
          + " ORDER BY vn.nspname, v.relname, d.refobjid, d.refobjsubid";

  /** Every foreign key, not a partition clone, with a family member on either side. */
  static final String FOREIGN_KEYS_SQL =
      "SELECT DISTINCT k.oid, pg_catalog.quote_ident(k.conname) AS name, k.conrelid, k.confrelid,"
          + " CAST(k.conkey AS pg_catalog.text) AS conkey,"
          + " CAST(k.confkey AS pg_catalog.text) AS confkey,"
          + " pg_catalog.concat_ws('.', pg_catalog.quote_ident(rn.nspname),"
          + " pg_catalog.quote_ident(rc.relname)) AS referencing,"
          + " pg_catalog.concat_ws('.', pg_catalog.quote_ident(fn.nspname),"
          + " pg_catalog.quote_ident(fc.relname)) AS referenced"
          + " FROM pg_catalog.pg_constraint k"
          + " JOIN pg_catalog.unnest(?) AS f"
          + " ON ((k.conrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " OR (k.confrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid)))"
          + " JOIN pg_catalog.pg_class rc ON (rc.oid OPERATOR(pg_catalog.=) k.conrelid)"
          + " JOIN pg_catalog.pg_namespace rn ON (rn.oid OPERATOR(pg_catalog.=) rc.relnamespace)"
          + " JOIN pg_catalog.pg_class fc ON (fc.oid OPERATOR(pg_catalog.=) k.confrelid)"
          + " JOIN pg_catalog.pg_namespace fn ON (fn.oid OPERATOR(pg_catalog.=) fc.relnamespace)"
          + " WHERE (k.contype OPERATOR(pg_catalog.=) 'f')"
          + " AND (k.conparentid OPERATOR(pg_catalog.=) CAST(0 AS pg_catalog.oid))"
          + " ORDER BY k.oid";

  /** Every publication that carries a family member, as the server resolves it. */
  static final String PUBLICATIONS_SQL =
      "SELECT pg_catalog.quote_ident(p.pubname) AS name, p.pubupdate, t.relid,"
          + " CAST(p.pubname AS pg_catalog.text) AS raw_name,"
          + " CAST(t.attrs AS pg_catalog.text) AS attrs"
          + " FROM pg_catalog.pg_publication p,"
          + " pg_catalog.pg_get_publication_tables(CAST(p.pubname AS pg_catalog.text)) AS t,"
          + " pg_catalog.unnest(?) AS f"
          + " WHERE (t.relid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " ORDER BY p.pubname, t.relid";

  /** Every logical slot of this database that decodes without a publication. */
  static final String SLOTS_SQL =
      "SELECT pg_catalog.quote_ident(s.slot_name) AS name,"
          + " CAST(s.slot_name AS pg_catalog.text) AS raw_name,"
          + " pg_catalog.quote_ident(s.plugin) AS plugin"
          + " FROM pg_catalog.pg_replication_slots s"
          + " WHERE (s.slot_type OPERATOR(pg_catalog.=) 'logical')"
          + " AND (s.database OPERATOR(pg_catalog.=) pg_catalog.current_database())"
          + " AND (s.plugin OPERATOR(pg_catalog.<>) 'pgoutput')"
          + " ORDER BY s.slot_name";

  /**
   * Every relation outside the family and the system schemas that holds a column named as a
   * blind-index column, with all its column names, whether the mapping names it ({@code named}: the
   * 1-based position in the bound list) and whether it is named as a default audit or history table
   * of the root ({@code default_name}).
   */
  static final String STALE_SQL =
      "SELECT c.oid, pg_catalog.quote_ident(n.nspname) AS nsp,"
          + " pg_catalog.quote_ident(c.relname) AS rel, a.attname AS raw,"
          + " pg_catalog.quote_ident(a.attname) AS col,"
          + " (SELECT pg_catalog.array_agg(CAST(x.attname AS pg_catalog.text) ORDER BY x.attnum)"
          + " FROM pg_catalog.pg_attribute x WHERE (x.attrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (x.attnum OPERATOR(pg_catalog.>) 0) AND (NOT x.attisdropped)) AS cols,"
          + " (SELECT pg_catalog.array_agg(pg_catalog.quote_ident(x.attname) ORDER BY x.attnum)"
          + " FROM pg_catalog.pg_attribute x WHERE (x.attrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (x.attnum OPERATOR(pg_catalog.>) 0) AND (NOT x.attisdropped)) AS quoted,"
          + " (SELECT pg_catalog.min(w.ordinality)"
          + " FROM pg_catalog.unnest(?) WITH ORDINALITY AS w"
          + " WHERE (pg_catalog.cardinality(pg_catalog.parse_ident(w.w)) OPERATOR(pg_catalog.=) 2)"
          + " AND ((SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(w.w))"
          + " WITH ORDINALITY AS p WHERE (p.ordinality OPERATOR(pg_catalog.=) 1))"
          + " OPERATOR(pg_catalog.=) CAST(n.nspname AS pg_catalog.text))"
          + " AND ((SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(w.w))"
          + " WITH ORDINALITY AS p WHERE (p.ordinality OPERATOR(pg_catalog.=) 2))"
          + " OPERATOR(pg_catalog.=) CAST(c.relname AS pg_catalog.text))) AS named,"
          + " (CASE WHEN (c.relnamespace OPERATOR(pg_catalog.<>) r.relnamespace) THEN NULL"
          + " WHEN (CAST(c.relname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " pg_catalog.concat(r.relname, '_aud')) THEN 'Hibernate Envers'"
          + " WHEN (CAST(c.relname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " pg_catalog.concat(r.relname, '_AUD')) THEN 'Hibernate'"
          + " WHEN (CAST(c.relname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " pg_catalog.concat(r.relname, '_history')) THEN 'Hibernate' END) AS default_name,"
          + " (CAST(c.relname AS pg_catalog.text) OPERATOR(pg_catalog.=)"
          + " pg_catalog.concat(r.relname, '_history')) AS default_history"
          + " FROM pg_catalog.pg_attribute a"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) a.attrelid)"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " JOIN pg_catalog.pg_class r ON (r.oid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))"
          + " WHERE (a.attname OPERATOR(pg_catalog.=) ANY(?))"
          + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND (NOT a.attisdropped)"
          + " AND ((c.relkind OPERATOR(pg_catalog.=) 'r') OR (c.relkind OPERATOR(pg_catalog.=) 'p')"
          + " OR (c.relkind OPERATOR(pg_catalog.=) 'f') OR (c.relkind OPERATOR(pg_catalog.=) 'm'))"
          + " AND (NOT c.relispartition)"
          + " AND (n.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " AND (n.nspname OPERATOR(pg_catalog.<>) 'information_schema')"
          + " AND (NOT pg_catalog.starts_with(CAST(n.nspname AS pg_catalog.text), 'pg_toast'))"
          + " AND (NOT pg_catalog.starts_with(CAST(n.nspname AS pg_catalog.text), 'pg_temp_'))"
          + " AND ((SELECT pg_catalog.count(*) FROM pg_catalog.unnest(?) AS f"
          + " WHERE (CAST(f.f AS pg_catalog.oid) OPERATOR(pg_catalog.=) c.oid))"
          + " OPERATOR(pg_catalog.=) 0)"
          + " ORDER BY n.nspname, c.relname, a.attnum";

  /** Every statement this leg runs on every call, in order; each is a refusal when it fails. */
  static final List<String> STATEMENTS =
      List.of(
          INDEX_COLUMNS_SQL,
          TRIGGERS_SQL,
          RULES_SQL,
          VIEWS_SQL,
          FOREIGN_KEYS_SQL,
          PUBLICATIONS_SQL,
          SLOTS_SQL,
          STALE_SQL);

  // ------------------------------------------------------------------------------------- facts

  /** One family member that carries the blind-index columns. */
  private record Member(
      long oid,
      String name,
      boolean partition,
      String relkind,
      Map<Integer, IndexColumn> byAttnum) {}

  /** One blind-index column on one family member. */
  private record IndexColumn(Column column, String raw, String quoted) {}

  // ------------------------------------------------------------------------------------ check

  /**
   * Reads every copy path of {@code target}'s blind-index columns over its whole family and returns
   * the {@code SHRED-SCHEMA-010} message, one sentence group per finding, when any exists.
   *
   * @param family the table's oid first, then every descendant the admission walk found
   */
  /**
   * What one call found.
   *
   * @param refused the {@code SHRED-SCHEMA-010} message, when any finding is not acknowledged
   * @param acknowledged the findings an entry of the acknowledgement list admitted
   */
  record Result(Optional<String> refused, List<Acknowledged> acknowledged) {
    Result {
      acknowledged = List.copyOf(acknowledged);
    }
  }

  static Result check(
      Connection c,
      Target target,
      List<Long> family,
      CopySignatures signatures,
      List<AcknowledgedCopy> entries)
      throws SQLException {
    var blind = new ArrayList<Column>();
    for (Column col : target.columns()) {
      if (MappingAdmission.BLIND_INDEX.equals(col.role())) {
        blind.add(col);
      }
    }
    if (blind.isEmpty()) {
      return new Result(Optional.empty(), List.of());
    }
    Map<Long, Member> members = members(c, family, blind);
    Member root = members.get(family.get(0));
    if (root == null || root.byAttnum().size() != blind.size()) {
      throw new SQLException("the index-column leg did not find every blind-index column", "XX000");
    }
    var findings = new ArrayList<String>();
    var admitted = new ArrayList<Acknowledged>();
    triggers(c, family, members, root, entries, findings, admitted);
    rules(c, family, members, root, findings);
    views(c, family, members, findings);
    foreignKeys(c, family, members, findings);
    publications(c, family, members, entries, findings, admitted);
    slots(c, root, entries, findings, admitted);
    stale(c, target, family, root, signatures, findings);
    return new Result(
        findings.isEmpty() ? Optional.empty() : Optional.of(String.join(" ", findings)), admitted);
  }

  /** The position of the entry that names exactly this object, if one does. */
  private static Optional<Integer> entryFor(
      List<AcknowledgedCopy> entries,
      AcknowledgedCopy.Kind kind,
      Optional<String> schema,
      Optional<String> table,
      String name) {
    for (int i = 0; i < entries.size(); i++) {
      AcknowledgedCopy e = entries.get(i);
      if (e.kind() == kind
          && e.schema().equals(schema)
          && e.table().equals(table)
          && e.name().equals(name)) {
        return Optional.of(i);
      }
    }
    return Optional.empty();
  }

  /** The startup WARN of an admitted acknowledgement, one line, identifiers escaped. */
  private static Acknowledged acknowledged(
      int entry, AcknowledgedCopy copy, String carrier, String sees, String noun) {
    return new Acknowledged(
        entry,
        copy,
        "shredding: "
            + copy.printable()
            + " "
            + LogText.escape(carrier)
            + " is admitted by "
            + AcknowledgedCopy.entry(entry)
            + " and cleared by hook "
            + LogText.escape(copy.clearedBy())
            + ". This module does not see what "
            + sees
            + " or what the hook clears; each erasure is recorded PARTIAL until that hook reports"
            + " success, and its record names this "
            + noun
            + ".");
  }

  /** The remedy sentence that offers the acknowledgement, with the entry's exact values. */
  private static String acknowledge(String what, String values) {
    return " Or, if "
        + what
        + ", acknowledge it with the hook that clears it: "
        + AcknowledgedCopy.PROPERTY
        + "[n] with "
        + values
        + ", cleared-by=<hook name>.";
  }

  private static Map<Long, Member> members(Connection c, List<Long> family, List<Column> blind)
      throws SQLException {
    var texts = new String[blind.size()];
    for (int i = 0; i < texts.length; i++) {
      texts[i] = blind.get(i).ref().sql();
    }
    var out = new LinkedHashMap<Long, Member>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    Array wanted = c.createArrayOf("text", texts);
    try (PreparedStatement ps = c.prepareStatement(INDEX_COLUMNS_SQL)) {
      ps.setArray(1, oids);
      ps.setArray(2, wanted);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          long oid = rs.getLong("relid");
          Member m =
              out.computeIfAbsent(
                  oid,
                  k -> {
                    try {
                      return new Member(
                          k,
                          JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel"),
                          rs.getBoolean("relispartition"),
                          rs.getString("relkind"),
                          new LinkedHashMap<>());
                    } catch (SQLException e) {
                      throw new IllegalStateException(e);
                    }
                  });
          m.byAttnum()
              .put(
                  rs.getInt("attnum"),
                  new IndexColumn(
                      blind.get(rs.getInt("wanted") - 1),
                      rs.getString("raw"),
                      JdbcSupport.printed(rs, "col")));
        }
      } catch (IllegalStateException e) {
        if (e.getCause() instanceof SQLException sql) {
          throw sql;
        }
        throw e;
      }
    } finally {
      oids.free();
      wanted.free();
    }
    return out;
  }

  // -------------------------------------------------------------------------------- triggers

  private record Trigger(
      long oid,
      long relid,
      String name,
      long parent,
      int type,
      String enabled,
      boolean constraint,
      String function,
      Optional<String> columns,
      String rawSchema,
      String rawTable,
      String rawName) {}

  private static void triggers(
      Connection c,
      List<Long> family,
      Map<Long, Member> members,
      Member root,
      List<AcknowledgedCopy> entries,
      List<String> out,
      List<Acknowledged> admitted)
      throws SQLException {
    var all = new ArrayList<Trigger>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(TRIGGERS_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          all.add(
              new Trigger(
                  rs.getLong("oid"),
                  rs.getLong("tgrelid"),
                  JdbcSupport.printed(rs, "name"),
                  rs.getLong("tgparentid"),
                  rs.getInt("tgtype"),
                  rs.getString("tgenabled"),
                  rs.getBoolean("is_constraint"),
                  JdbcSupport.printed(rs, "function"),
                  Optional.ofNullable(JdbcSupport.printed(rs, "columns")),
                  rs.getString("raw_nsp"),
                  rs.getString("raw_rel"),
                  rs.getString("raw_name")));
        }
      }
    } finally {
      oids.free();
    }
    var byOid = new LinkedHashMap<Long, Trigger>();
    all.forEach(t -> byOid.put(t.oid(), t));
    var clones = new LinkedHashMap<Long, Integer>();
    var reported = new ArrayList<Trigger>();
    for (Trigger t : all) {
      Optional<Trigger> top = reportedAncestor(t, byOid);
      if (top.isPresent()) {
        clones.merge(top.get().oid(), 1, Integer::sum);
      } else {
        reported.add(t);
      }
    }
    for (Trigger t : reported) {
      Member on = members.get(t.relid());
      String where =
          on == null || on.oid() == root.oid()
              ? ""
              : (on.partition() ? " on partition " : " on inheritance child ") + on.name();
      int cloned = clones.getOrDefault(t.oid(), 0);
      String table = on == null ? root.name() : on.name();
      Optional<Integer> entry =
          entryFor(
              entries,
              AcknowledgedCopy.Kind.TRIGGER,
              Optional.of(t.rawSchema()),
              Optional.of(t.rawTable()),
              t.rawName());
      if (entry.isPresent()) {
        admitted.add(
            acknowledged(
                entry.get(),
                entries.get(entry.get()),
                "on a table with " + indexColumns(root),
                "the trigger writes",
                "trigger"));
        continue;
      }
      out.add(
          "shredding: "
              + root.name()
              + " holds the "
              + indexColumns(root)
              + " and has trigger "
              + t.name()
              + where
              + " ("
              + describe(t)
              + ")"
              + (cloned > 0
                  ? ", cloned to " + cloned + (cloned == 1 ? " partition" : " partitions")
                  : "")
              + ". This module cannot see where a trigger writes; one that copies the row keeps"
              + " the erased subject's index after every erasure, and the erasure's own UPDATE"
              + " fires it. Drop or disable the trigger: ALTER TABLE "
              + JdbcSupport.sqlIdentifier(table)
              + " DISABLE TRIGGER "
              + JdbcSupport.sqlIdentifier(t.name())
              + "."
              + acknowledge(
                  "it never stores the index or a hook clears what it stores",
                  "kind=trigger, schema="
                      + LogText.escape(t.rawSchema())
                      + ", table="
                      + LogText.escape(t.rawTable())
                      + ", name="
                      + LogText.escape(t.rawName())));
    }
  }

  /** The nearest ancestor of a cloned trigger that this leg reports itself, if any. */
  private static Optional<Trigger> reportedAncestor(Trigger t, Map<Long, Trigger> byOid) {
    Optional<Trigger> found = Optional.empty();
    var seen = new HashSet<Long>();
    Trigger at = t;
    while (at.parent() != 0 && seen.add(at.oid())) {
      Trigger parent = byOid.get(at.parent());
      if (parent == null) {
        break;
      }
      found = Optional.of(parent);
      at = parent;
    }
    return found;
  }

  private static String describe(Trigger t) {
    int type = t.type();
    String timing = (type & 2) != 0 ? "BEFORE" : (type & 64) != 0 ? "INSTEAD OF" : "AFTER";
    var events = new ArrayList<String>();
    if ((type & 4) != 0) {
      events.add("INSERT");
    }
    if ((type & 16) != 0) {
      events.add("UPDATE" + t.columns().map(cols -> " OF " + cols).orElse(""));
    }
    if ((type & 8) != 0) {
      events.add("DELETE");
    }
    if ((type & 32) != 0) {
      events.add("TRUNCATE");
    }
    var parts = new ArrayList<String>();
    parts.add(timing + " " + String.join(" OR ", events));
    parts.add((type & 1) != 0 ? "FOR EACH ROW" : "FOR EACH STATEMENT");
    if (t.constraint()) {
      parts.add("constraint trigger");
    }
    if ("R".equals(t.enabled())) {
      parts.add("ENABLE REPLICA");
    } else if ("A".equals(t.enabled())) {
      parts.add("ENABLE ALWAYS");
    }
    parts.add("function " + t.function());
    return String.join(", ", parts);
  }

  // ----------------------------------------------------------------------------------- rules

  private static void rules(
      Connection c, List<Long> family, Map<Long, Member> members, Member root, List<String> out)
      throws SQLException {
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(RULES_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          Member on = members.get(rs.getLong("ev_class"));
          String table = on == null ? root.name() : on.name();
          String where =
              on == null || on.oid() == root.oid()
                  ? ""
                  : (on.partition() ? " on partition " : " on inheritance child ") + on.name();
          String event =
              switch (rs.getString("ev_type")) {
                case "1" -> "SELECT";
                case "2" -> "UPDATE";
                case "3" -> "INSERT";
                case "4" -> "DELETE";
                default -> "an event";
              };
          String name = JdbcSupport.printed(rs, "name");
          out.add(
              "shredding: "
                  + root.name()
                  + " holds the "
                  + indexColumns(root)
                  + " and has rule "
                  + name
                  + where
                  + " (ON "
                  + event
                  + (rs.getBoolean("is_instead") ? " DO INSTEAD" : " DO ALSO")
                  + "). A rule rewrites the statements on the table, the erasure's own UPDATE"
                  + " included, and this module cannot see where it writes. Drop it: DROP RULE "
                  + JdbcSupport.sqlIdentifier(name)
                  + " ON "
                  + JdbcSupport.sqlIdentifier(table)
                  + ".");
        }
      }
    } finally {
      oids.free();
    }
  }

  // --------------------------------------------------------------------- materialized views

  /** How a carrying relation reaches the index: the column on the table, and the last view. */
  private record Reach(IndexColumn column, String table, boolean wholeRow, Optional<String> via) {}

  private static void views(
      Connection c, List<Long> family, Map<Long, Member> members, List<String> out)
      throws SQLException {
    var carrying = new LinkedHashMap<Long, Reach>();
    var visited = new HashSet<Long>(family);
    var level = new ArrayList<Long>(family);
    var reported = new LinkedHashSet<Long>();
    int nodes = 0;
    try (PreparedStatement ps = c.prepareStatement(VIEWS_SQL)) {
      while (!level.isEmpty()) {
        var next = new ArrayList<Long>();
        Array oids = c.createArrayOf("int8", level.toArray(new Long[0]));
        try {
          ps.setArray(1, oids);
          try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
              long ref = rs.getLong("refobjid");
              int sub = rs.getInt("refobjsubid");
              long view = rs.getLong("view");
              String viewName =
                  JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel");
              boolean wholeRow = rs.getBoolean("whole_row");
              Optional<Reach> reach = reach(ref, sub, wholeRow, members, carrying);
              if (reach.isEmpty()) {
                continue;
              }
              String relkind = rs.getString("relkind");
              if ("m".equals(relkind)) {
                if (reported.add(view)) {
                  out.add(matviewFinding(viewName, reach.get()));
                }
              } else if ("v".equals(relkind) && !carrying.containsKey(view)) {
                Reach r = reach.get();
                carrying.put(
                    view, new Reach(r.column(), r.table(), r.wholeRow(), Optional.of(viewName)));
              }
              if (visited.add(view)) {
                if (++nodes > MAX_VIEW_NODES) {
                  throw new SQLException(
                      "more than " + MAX_VIEW_NODES + " views depend on the table", "54000");
                }
                next.add(view);
              }
            }
          }
        } finally {
          oids.free();
        }
        level = next;
      }
    }
  }

  private static Optional<Reach> reach(
      long ref, int sub, boolean wholeRow, Map<Long, Member> members, Map<Long, Reach> carrying) {
    Member m = members.get(ref);
    if (m != null) {
      IndexColumn col = m.byAttnum().get(sub);
      if (col != null) {
        return Optional.of(new Reach(col, m.name(), false, Optional.empty()));
      }
      if (sub == 0 && wholeRow) {
        IndexColumn first = m.byAttnum().values().iterator().next();
        return Optional.of(new Reach(first, m.name(), true, Optional.empty()));
      }
      return Optional.empty();
    }
    return Optional.ofNullable(carrying.get(ref));
  }

  private static String matviewFinding(String view, Reach r) {
    String reads =
        r.wholeRow()
            ? "reads the whole row of "
                + r.table()
                + ", blind-index column "
                + r.column().quoted()
                + label(r.column())
                + " included"
            : "reads the blind-index column "
                + r.table()
                + "."
                + r.column().quoted()
                + label(r.column());
    return "shredding: materialized view "
        + view
        + " "
        + reads
        + r.via().map(v -> " through view " + v).orElse("")
        + ". It holds every index value as of its last refresh, and no erasure reaches it. Leave"
        + " the column out of the view, or drop it: DROP MATERIALIZED VIEW "
        + JdbcSupport.sqlIdentifier(view)
        + ".";
  }

  // ---------------------------------------------------------------------------- foreign keys

  private static void foreignKeys(
      Connection c, List<Long> family, Map<Long, Member> members, List<String> out)
      throws SQLException {
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(FOREIGN_KEYS_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String name = JdbcSupport.printed(rs, "name");
          String referencing = JdbcSupport.printed(rs, "referencing");
          String referenced = JdbcSupport.printed(rs, "referenced");
          Member from = members.get(rs.getLong("conrelid"));
          Member to = members.get(rs.getLong("confrelid"));
          Optional<IndexColumn> own =
              from == null ? Optional.empty() : hit(from, rs.getString("conkey"));
          Optional<IndexColumn> theirs =
              to == null ? Optional.empty() : hit(to, rs.getString("confkey"));
          if (theirs.isPresent()) {
            IndexColumn col = theirs.get();
            out.add(
                "shredding: foreign key "
                    + name
                    + " on "
                    + referencing
                    + " references the blind-index column "
                    + to.name()
                    + "."
                    + col.quoted()
                    + label(col)
                    + ", so "
                    + referencing
                    + " holds index values and no erasure reaches it. Reference the table by its"
                    + " identifier instead, then drop the constraint and the column: ALTER TABLE "
                    + JdbcSupport.sqlIdentifier(referencing)
                    + " DROP CONSTRAINT "
                    + JdbcSupport.sqlIdentifier(name)
                    + ".");
          } else if (own.isPresent()) {
            IndexColumn col = own.get();
            out.add(
                "shredding: foreign key "
                    + name
                    + " on "
                    + from.name()
                    + " makes the blind-index column "
                    + col.quoted()
                    + label(col)
                    + " reference "
                    + referenced
                    + ", so "
                    + referenced
                    + " holds the same index values and no erasure reaches it. Drop the"
                    + " constraint: ALTER TABLE "
                    + JdbcSupport.sqlIdentifier(from.name())
                    + " DROP CONSTRAINT "
                    + JdbcSupport.sqlIdentifier(name)
                    + ".");
          }
        }
      }
    } finally {
      oids.free();
    }
  }

  /** The first blind-index column of {@code m} among the attribute numbers in {@code array}. */
  private static Optional<IndexColumn> hit(Member m, String array) {
    if (array == null) {
      return Optional.empty();
    }
    for (int attnum : attnums(array)) {
      IndexColumn col = m.byAttnum().get(attnum);
      if (col != null) {
        return Optional.of(col);
      }
    }
    return Optional.empty();
  }

  /**
   * The first blind-index attribute number a publication's column list carries. A NULL list is
   * every column, never none (S-7): PostgreSQL 15 returns NULL for a publication without a column
   * list; 16 and 17 return the full list (measured), so no fixture on the supported versions
   * reaches the NULL branch and {@code CopyCatalogueTest} holds it.
   */
  static Optional<Integer> carried(List<Integer> indexAttnums, String attrs) {
    if (attrs == null) {
      return indexAttnums.stream().findFirst();
    }
    for (int attnum : attnums(attrs)) {
      if (indexAttnums.contains(attnum)) {
        return Optional.of(attnum);
      }
    }
    return Optional.empty();
  }

  /** Attribute numbers from an array's or an {@code int2vector}'s text form. */
  static List<Integer> attnums(String text) {
    var out = new ArrayList<Integer>();
    for (String part :
        text.replace("{", " ").replace("}", " ").replace(",", " ").trim().split(" +")) {
      if (!part.isEmpty()) {
        out.add(Integer.parseInt(part));
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------- publications

  private static void publications(
      Connection c,
      List<Long> family,
      Map<Long, Member> members,
      List<AcknowledgedCopy> entries,
      List<String> out,
      List<Acknowledged> admitted)
      throws SQLException {
    var reported = new LinkedHashSet<String>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(PUBLICATIONS_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String name = JdbcSupport.printed(rs, "name");
          Member m = members.get(rs.getLong("relid"));
          if (m == null || reported.contains(name)) {
            continue;
          }
          Optional<IndexColumn> col =
              carried(List.copyOf(m.byAttnum().keySet()), rs.getString("attrs"))
                  .map(m.byAttnum()::get);
          if (col.isEmpty()) {
            continue;
          }
          reported.add(name);
          String column = m.name() + "." + col.get().quoted() + label(col.get());
          String raw = rs.getString("raw_name");
          if (rs.getBoolean("pubupdate")) {
            Optional<Integer> entry =
                entryFor(
                    entries,
                    AcknowledgedCopy.Kind.PUBLICATION,
                    Optional.empty(),
                    Optional.empty(),
                    raw);
            if (entry.isPresent()) {
              admitted.add(
                  acknowledged(
                      entry.get(),
                      entries.get(entry.get()),
                      "publishing the blind-index column " + column,
                      "a subscriber keeps",
                      "publication"));
              continue;
            }
          }
          String remedy =
              " Publish the table with a column list that leaves out "
                  + col.get().quoted()
                  + ", or remove it from the publication.";
          out.add(
              rs.getBoolean("pubupdate")
                  ? "shredding: publication "
                      + name
                      + " publishes the blind-index column "
                      + column
                      + ". A subscriber receives the erasure's UPDATE, but what it keeps is out of"
                      + " this module's sight."
                      + remedy
                      + acknowledge(
                          "a hook clears what its subscribers keep",
                          "kind=publication, name=" + LogText.escape(raw))
                  : "shredding: publication "
                      + name
                      + " publishes the blind-index column "
                      + column
                      + " and does not publish UPDATE: a subscriber keeps every index value it"
                      + " received after every erasure."
                      + remedy);
        }
      }
    } finally {
      oids.free();
    }
  }

  // ----------------------------------------------------------------------------------- slots

  private static void slots(
      Connection c,
      Member root,
      List<AcknowledgedCopy> entries,
      List<String> out,
      List<Acknowledged> admitted)
      throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(SLOTS_SQL);
        ResultSet rs = ps.executeQuery()) {
      while (rs.next()) {
        String raw = rs.getString("raw_name");
        Optional<Integer> entry =
            entryFor(
                entries,
                AcknowledgedCopy.Kind.REPLICATION_SLOT,
                Optional.empty(),
                Optional.empty(),
                raw);
        if (entry.isPresent()) {
          admitted.add(
              acknowledged(
                  entry.get(),
                  entries.get(entry.get()),
                  "(plugin "
                      + JdbcSupport.printed(rs, "plugin")
                      + ") decoding a table with "
                      + indexColumns(root),
                  "its consumer keeps",
                  "slot"));
          continue;
        }
        out.add(
            "shredding: logical replication slot "
                + JdbcSupport.printed(rs, "name")
                + " (plugin "
                + JdbcSupport.printed(rs, "plugin")
                + ") decodes every table of this database, including "
                + root.name()
                + " with "
                + indexColumns(root)
                + ". Every index value written since the slot was created has already been sent"
                + " to its consumer, and this module cannot see or clear what the consumer keeps."
                + " Drop the slot, or publish through pgoutput with a column list that excludes the"
                + " index."
                + acknowledge(
                    "a hook clears what its consumer keeps",
                    "kind=replication-slot, name=" + LogText.escape(raw)));
      }
    }
  }

  // ---------------------------------------------------------------------- stale audit tables

  private static void stale(
      Connection c,
      Target target,
      List<Long> family,
      Member root,
      CopySignatures signatures,
      List<String> out)
      throws SQLException {
    var named = new ArrayList<CopySignatures.NamedCopy>();
    for (CopySignatures.NamedCopy n : signatures.named()) {
      if (n.source().equals(target.table())) {
        named.add(n);
      }
    }
    var namedTexts = new String[named.size()];
    for (int i = 0; i < namedTexts.length; i++) {
      namedTexts[i] = named.get(i).copy().sql();
    }
    var byRaw = new LinkedHashMap<String, IndexColumn>();
    root.byAttnum().values().forEach(col -> byRaw.put(col.raw(), col));
    var reported = new HashSet<Long>();
    Array namedArray = c.createArrayOf("text", namedTexts);
    Array raws = c.createArrayOf("text", byRaw.keySet().toArray(new String[0]));
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(STALE_SQL)) {
      ps.setArray(1, namedArray);
      ps.setLong(2, root.oid());
      ps.setArray(3, raws);
      ps.setArray(4, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          long oid = rs.getLong("oid");
          if (reported.contains(oid)) {
            continue;
          }
          String relation = JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel");
          String quotedCol = JdbcSupport.printed(rs, "col");
          String clear =
              "UPDATE "
                  + JdbcSupport.sqlIdentifier(relation)
                  + " SET "
                  + JdbcSupport.sqlIdentifier(quotedCol)
                  + " = NULL; ALTER TABLE "
                  + JdbcSupport.sqlIdentifier(relation)
                  + " DROP COLUMN "
                  + JdbcSupport.sqlIdentifier(quotedCol)
                  + ".";
          int namedAt = rs.getInt("named");
          boolean isNamed = !rs.wasNull();
          String defaultWriter = rs.getString("default_name");
          boolean history = rs.getBoolean("default_history");
          if (isNamed) {
            CopySignatures.NamedCopy n = named.get(namedAt - 1);
            reported.add(oid);
            out.add(
                "shredding: "
                    + relation
                    + " has a column "
                    + quotedCol
                    + " and is the "
                    + n.kind()
                    + " table "
                    + n.writer()
                    + " writes for "
                    + root.name()
                    + ". No erasure reaches it. Clear and drop the column: "
                    + clear
                    + " If it is not "
                    + article(n.kind())
                    + " table, rename the column.");
            continue;
          }
          if (defaultWriter != null) {
            String kind = history ? "history" : "audit";
            reported.add(oid);
            out.add(
                "shredding: "
                    + relation
                    + " has a column "
                    + quotedCol
                    + " and is named as "
                    + defaultWriter
                    + " names the "
                    + kind
                    + " table of "
                    + root.name()
                    + ". No erasure reaches it. Clear and drop the column: "
                    + clear
                    + " If it is not "
                    + article(kind)
                    + " table, rename the column.");
            continue;
          }
          List<String> cols = strings(rs.getArray("cols"));
          List<String> quoted =
              strings(rs.getArray("quoted")).stream()
                  .map(com.housedevinci.shredding.application.LogText::escape)
                  .toList();
          for (CopySignatures.RevisionSignature s : signatures.signatures()) {
            int first = cols.indexOf(s.first());
            int second = cols.indexOf(s.second());
            if (first < 0 || second < 0) {
              continue;
            }
            reported.add(oid);
            out.add(
                "shredding: "
                    + relation
                    + " has a column "
                    + quotedCol
                    + ", the blind-index column of "
                    + root.name()
                    + ", together with the columns "
                    + quoted.get(first)
                    + " and "
                    + quoted.get(second)
                    + " that "
                    + s.writer()
                    + " writes in "
                    + article(s.kind())
                    + " table. No erasure reaches it. If it is "
                    + article(s.kind())
                    + " table from an earlier configuration, clear and drop the column: "
                    + clear
                    + " If it is not, rename the column.");
            break;
          }
        }
      }
    } finally {
      namedArray.free();
      raws.free();
      oids.free();
    }
  }

  private static List<String> strings(Array array) throws SQLException {
    if (array == null) {
      return List.of();
    }
    try {
      var out = new ArrayList<String>();
      for (Object o : (Object[]) array.getArray()) {
        out.add(String.valueOf(o));
      }
      return out;
    } finally {
      array.free();
    }
  }

  private static String article(String kind) {
    return "audit".equals(kind) ? "an audit" : "a " + kind;
  }

  // -------------------------------------------------------------------------------- messages

  private static String indexColumns(Member root) {
    var names = new ArrayList<String>();
    for (IndexColumn col : root.byAttnum().values()) {
      names.add(col.quoted() + label(col));
    }
    return (names.size() == 1 ? "blind-index column " : "blind-index columns ")
        + String.join(", ", names);
  }

  private static String label(IndexColumn col) {
    return col.column().attribute().map(a -> " (" + a + ")").orElse("");
  }
}
