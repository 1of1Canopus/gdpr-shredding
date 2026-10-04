package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Mapping admission (name-resolution design, addendum §A.1-§A.13): before the first erasure, a
 * {@code @Shredded} mapping whose table is not a plain permanent relation this module can address,
 * or whose compared columns have an equality this module does not share with the application, is
 * refused.
 *
 * <p><b>Why a catalogue read and not a predicate at erasure time (§A.1).</b> The erasure's three
 * legs - the blind-index {@code UPDATE}, its same-text read-back and the framework-rendered
 * read-back - are built independently but compare on the same relation the same way. A hiding view,
 * a row-level-security policy, a foreign table over a remote hiding view, a {@code citext} or an
 * application-defined equality, or a non-deterministic collation makes all three agree on a
 * falsehood, and the erasure is recorded {@code COMPLETE} over residue. The system catalogue is the
 * only source the erasure does not share.
 *
 * <p><b>The statements.</b> Every one is built by this module, fully qualified under section 3.1,
 * and takes the mapping's rendered text as a bind parameter; none composes an identifier. The table
 * text and each column text go through {@code pg_catalog.parse_ident} in its strict, one-argument
 * form, which is PostgreSQL's own identifier folding and refuses text it cannot parse. The
 * two-argument form ({@code strictmode => false}) silently parses {@code app.t; DROP TABLE app.t}
 * and is never used.
 *
 * <p><b>Shape, and the one deviation from the design's two statements.</b> The design gives the
 * check as two statements with recursive common table expressions and array subscripts. The name
 * gate refuses both - a CTE name in a {@code FROM} list is an unqualified relation to a lexer, and
 * {@code [} is an unclassified character - so the same facts are read by four simpler statements
 * and the two recursions run in Java: the relation (one row, always), its inheritance children one
 * level at a time (only when it has any), the compared and assigned columns (one row per column),
 * and the facts of each distinct column type (once per type, then once per domain level). A plain
 * table with {@code varchar} tenant and subject and a {@code bigint} id costs four statements, and
 * the count never depends on the number of rows.
 *
 * <p><b>Two positions, one verdict.</b> {@link #verdict} is called at startup by the starter's
 * admission bean and again by {@link JdbcErasureStore} inside every erasure's transaction, after a
 * {@code LOCK TABLE} and before the blind-index {@code UPDATE}; it is never cached (§A.5).
 */
public final class MappingAdmission {

  private MappingAdmission() {}

  /** Whether a column is compared by an erasure or write statement, or only assigned. */
  public enum Use {
    /**
     * Compared with {@code OPERATOR(pg_catalog.=)}: clauses C-a to C-e and C-h apply, and C-i for a
     * tenant or subject column.
     */
    COMPARED,
    /** Only assigned ({@code SET <col> = NULL}): clauses C-a, C-f and C-g apply. */
    ASSIGNED
  }

  /**
   * One column the check reads.
   *
   * @param ref the column exactly as the mapping renders it
   * @param use compared or assigned
   * @param role what the column is: one of {@link #TENANT}, {@link #SUBJECT}, {@link #IDENTIFIER}
   *     or {@link #BLIND_INDEX}. A closed set, because clause C-i is decided by it: the tenant and
   *     subject columns are the two this module compares against a bound {@code String}
   */
  public record Column(ColumnRef ref, Use use, String role) {
    public Column {
      Objects.requireNonNull(ref, "ref");
      Objects.requireNonNull(use, "use");
      Objects.requireNonNull(role, "role");
      if (!List.of(TENANT, SUBJECT, IDENTIFIER, BLIND_INDEX).contains(role)) {
        throw new ShreddingException(
            ErrorCodes.CONFIG,
            "a mapping admission column role must be one of \""
                + TENANT
                + "\", \""
                + SUBJECT
                + "\", \""
                + IDENTIFIER
                + "\" or \""
                + BLIND_INDEX
                + "\", was \""
                + role
                + "\"");
      }
    }

    /** Clause C-i applies: a tenant or subject column, compared against a bound string. */
    boolean comparedAsText() {
      return use == Use.COMPARED && (TENANT.equals(role) || SUBJECT.equals(role));
    }
  }

  /** The tenant column of a blind index. */
  public static final String TENANT = "tenant column";

  /** The subject column of a blind index. */
  public static final String SUBJECT = "subject column";

  /** The entity's identifier column. */
  public static final String IDENTIFIER = "identifier column";

  /** A blind-index column. */
  public static final String BLIND_INDEX = "blind-index column";

  /**
   * Clause C-i: the built-in types a tenant or subject column may resolve to, by oid - {@code
   * pg_catalog.text} (25), {@code pg_catalog.varchar} (1043), {@code pg_catalog.bpchar} (1042).
   * Fixed oids assigned at initdb, never a spelling. Equality between two of these is {@code
   * pg_catalog}'s, and the runtime role can create neither a cast nor an operator between two
   * built-in types, so nothing outside the table lock can change what the erasure's comparison
   * resolves to.
   */
  static final java.util.Set<Long> TEXT_TYPE_OIDS = java.util.Set.of(25L, 1043L, 1042L);

  /**
   * One mapped table and the columns of it the module's statements compare or assign.
   *
   * @param entity the entity name for messages; empty at erasure time, where the store holds
   *     blind-index columns rather than entities and the message names the table instead
   */
  public record Target(Optional<String> entity, TableRef table, List<Column> columns) {
    public Target {
      Objects.requireNonNull(entity, "entity");
      Objects.requireNonNull(table, "table");
      columns = List.copyOf(columns);
    }

    /**
     * The targets an erasure checks: one per distinct table, in the order the blind-index columns
     * name them, each carrying the tenant and subject columns its {@code UPDATE} compares and the
     * index columns it assigns. The order is the lock order, so two erasures take their locks in
     * the same sequence.
     */
    public static List<Target> forErasure(List<BlindIndexColumn> columns) {
      var byTable = new LinkedHashMap<TableRef, List<Column>>();
      for (BlindIndexColumn c : columns) {
        var list = byTable.computeIfAbsent(c.table(), t -> new ArrayList<>());
        addOnce(list, new Column(c.tenantColumn(), Use.COMPARED, TENANT));
        addOnce(list, new Column(c.subjectColumn(), Use.COMPARED, SUBJECT));
        addOnce(list, new Column(c.column(), Use.ASSIGNED, BLIND_INDEX));
      }
      var out = new ArrayList<Target>();
      byTable.forEach((table, cols) -> out.add(new Target(Optional.empty(), table, cols)));
      return out;
    }

    private static void addOnce(List<Column> list, Column column) {
      for (Column existing : list) {
        if (existing.ref().equals(column.ref()) && existing.use() == column.use()) {
          return;
        }
      }
      list.add(column);
    }
  }

  /** The outcome of one check. */
  public sealed interface Verdict permits Admitted, Absent, Refused {}

  /**
   * Admitted. {@code warnings} are postures the erasure is sound under and the operator must still
   * hear about: an unlogged table or descendant, and an admission that depends on the runtime role
   * holding {@code BYPASSRLS}.
   */
  public record Admitted(List<String> warnings) implements Verdict {
    public Admitted {
      warnings = List.copyOf(warnings);
    }
  }

  /** R-b: the relation does not exist. A WARN at startup, a refusal at erasure (§A.5). */
  public record Absent(String message) implements Verdict {}

  /**
   * Present and inadmissible.
   *
   * @param rule the clause that decided it (R-a ... C-h), for tests and for the reader
   */
  public record Refused(String rule, String message) implements Verdict {}

  // ------------------------------------------------------------------------------- statements

  /**
   * The relation leg. Always exactly one row: {@code parts} is how many elements {@code
   * parse_ident} found (R-a), and every relation column is NULL when no such relation exists (R-b).
   * {@code bypassrls} is read for the role running the check (S-4), never assumed.
   */
  static final String RELATION_SQL =
      "SELECT x.parts, c.oid, c.relkind, c.relpersistence, c.relrowsecurity,"
          + " c.relforcerowsecurity,"
          + " pg_catalog.pg_has_role(c.relowner, 'USAGE') AS owns,"
          + " pg_catalog.has_table_privilege(c.oid, 'SELECT') AS may_read,"
          + " pg_catalog.has_table_privilege(c.oid, 'UPDATE') AS may_write,"
          + " (SELECT r.rolbypassrls FROM pg_catalog.pg_roles r"
          + " WHERE (r.rolname OPERATOR(pg_catalog.=) CURRENT_USER)) AS bypassrls,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_inherits i"
          + " WHERE (i.inhparent OPERATOR(pg_catalog.=) c.oid)) AS children"
          + " FROM (SELECT pg_catalog.cardinality(pg_catalog.parse_ident(?)) AS parts,"
          + " (SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(?)) WITH ORDINALITY AS p"
          + " WHERE (p.ordinality OPERATOR(pg_catalog.=) 1)) AS sch,"
          + " (SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(?)) WITH ORDINALITY AS p"
          + " WHERE (p.ordinality OPERATOR(pg_catalog.=) 2)) AS rel) x"
          + " LEFT JOIN pg_catalog.pg_namespace n ON (n.nspname OPERATOR(pg_catalog.=) x.sch)"
          + " LEFT JOIN pg_catalog.pg_class c"
          + " ON (c.relnamespace OPERATOR(pg_catalog.=) n.oid)"
          + " AND (c.relname OPERATOR(pg_catalog.=) x.rel)";

  /** One level of the descendant walk: the direct children of one relation. */
  static final String CHILDREN_SQL =
      "SELECT i.inhrelid, c.relkind, c.relpersistence,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_inherits j"
          + " WHERE (j.inhparent OPERATOR(pg_catalog.=) i.inhrelid)) AS children"
          + " FROM pg_catalog.pg_inherits i"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) i.inhrelid)"
          + " WHERE (i.inhparent OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))"
          + " ORDER BY i.inhrelid";

  /**
   * The column leg: one row per requested column, in request order. An absent column is a row of
   * NULLs, never no row (S-5), so C-a keys on {@code attnum IS NULL}. A non-collatable type has no
   * {@code pg_collation} row, so {@code collisdeterministic} is NULL for it (S-5).
   */
  static final String COLUMNS_SQL =
      "SELECT w.w, a.attnum, a.attnotnull, a.attgenerated, a.atttypid, cl.collisdeterministic,"
          + " (SELECT pg_catalog.cardinality(pg_catalog.parse_ident(w.w))) AS parts"
          + " FROM pg_catalog.unnest(?) WITH ORDINALITY AS w"
          + " LEFT JOIN pg_catalog.pg_attribute a"
          + " ON (a.attrelid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))"
          + " AND (a.attname OPERATOR(pg_catalog.=)"
          + " (SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(w.w)) WITH ORDINALITY AS p"
          + " WHERE (p.ordinality OPERATOR(pg_catalog.=) 1)))"
          + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND (NOT a.attisdropped)"
          + " LEFT JOIN pg_catalog.pg_collation cl"
          + " ON (cl.oid OPERATOR(pg_catalog.=) a.attcollation)"
          + " ORDER BY w.ordinality";

  /**
   * The facts of one type. {@code own_eq_schema} is the schema of the equality operator of the
   * type's default btree (strategy 3) or hash (strategy 1) operator class, read through {@code
   * anyenum} for an enum. {@code binary_implicit_to} lists, for every implicit binary cast, the
   * target's own schema and the schema of the target's own default equality (S-6), as {@code
   * schema:eqschema}, with {@code -} for none. {@code declared_shadow_eq_schema} is clause C-h's
   * fact (S-1): a non-{@code pg_catalog} two-sided {@code =} on this very type, for a type that is
   * not itself in {@code pg_catalog}.
   */
  static final String TYPE_SQL =
      "SELECT t.typtype, t.typcategory, t.typbasetype, tn.nspname,"
          + " pg_catalog.format_type(t.oid, NULL) AS spelled,"
          + " (SELECT en.nspname FROM pg_catalog.pg_opclass oc"
          + " JOIN pg_catalog.pg_am am ON (am.oid OPERATOR(pg_catalog.=) oc.opcmethod)"
          + " JOIN pg_catalog.pg_amop ao"
          + " ON (ao.amopfamily OPERATOR(pg_catalog.=) oc.opcfamily)"
          + " AND (ao.amoplefttype OPERATOR(pg_catalog.=) oc.opcintype)"
          + " AND (ao.amoprighttype OPERATOR(pg_catalog.=) oc.opcintype)"
          + " AND (((am.amname OPERATOR(pg_catalog.=) 'btree')"
          + " AND (ao.amopstrategy OPERATOR(pg_catalog.=) 3))"
          + " OR ((am.amname OPERATOR(pg_catalog.=) 'hash')"
          + " AND (ao.amopstrategy OPERATOR(pg_catalog.=) 1)))"
          + " JOIN pg_catalog.pg_operator op ON (op.oid OPERATOR(pg_catalog.=) ao.amopopr)"
          + " JOIN pg_catalog.pg_namespace en ON (en.oid OPERATOR(pg_catalog.=) op.oprnamespace)"
          + " WHERE (oc.opcintype OPERATOR(pg_catalog.=)"
          + " (CASE WHEN (t.typtype OPERATOR(pg_catalog.=) 'e')"
          + " THEN CAST('pg_catalog.anyenum' AS pg_catalog.regtype) ELSE t.oid END))"
          + " AND oc.opcdefault"
          + " ORDER BY am.amname LIMIT 1) AS own_eq_schema,"
          + " (SELECT pg_catalog.string_agg(DISTINCT (tn2.nspname OPERATOR(pg_catalog.||) ':')"
          + " OPERATOR(pg_catalog.||) (CASE WHEN teq.nspname IS NULL THEN '-'"
          + " ELSE CAST(teq.nspname AS pg_catalog.text) END), ',')"
          + " FROM pg_catalog.pg_cast ct"
          + " JOIN pg_catalog.pg_type tt ON (tt.oid OPERATOR(pg_catalog.=) ct.casttarget)"
          + " JOIN pg_catalog.pg_namespace tn2 ON (tn2.oid OPERATOR(pg_catalog.=) tt.typnamespace)"
          + " LEFT JOIN pg_catalog.pg_opclass toc"
          + " ON (toc.opcintype OPERATOR(pg_catalog.=) tt.oid) AND toc.opcdefault"
          + " LEFT JOIN pg_catalog.pg_am tam ON (tam.oid OPERATOR(pg_catalog.=) toc.opcmethod)"
          + " LEFT JOIN pg_catalog.pg_amop tao"
          + " ON (tao.amopfamily OPERATOR(pg_catalog.=) toc.opcfamily)"
          + " AND (tao.amoplefttype OPERATOR(pg_catalog.=) toc.opcintype)"
          + " AND (tao.amoprighttype OPERATOR(pg_catalog.=) toc.opcintype)"
          + " AND (((tam.amname OPERATOR(pg_catalog.=) 'btree')"
          + " AND (tao.amopstrategy OPERATOR(pg_catalog.=) 3))"
          + " OR ((tam.amname OPERATOR(pg_catalog.=) 'hash')"
          + " AND (tao.amopstrategy OPERATOR(pg_catalog.=) 1)))"
          + " LEFT JOIN pg_catalog.pg_operator top ON (top.oid OPERATOR(pg_catalog.=) tao.amopopr)"
          + " LEFT JOIN pg_catalog.pg_namespace teq"
          + " ON (teq.oid OPERATOR(pg_catalog.=) top.oprnamespace)"
          + " WHERE (ct.castsource OPERATOR(pg_catalog.=) t.oid)"
          + " AND (ct.castmethod OPERATOR(pg_catalog.=) 'b')"
          + " AND (ct.castcontext OPERATOR(pg_catalog.=) 'i')) AS binary_implicit_to,"
          + " (SELECT en.nspname FROM pg_catalog.pg_operator op"
          + " JOIN pg_catalog.pg_namespace en ON (en.oid OPERATOR(pg_catalog.=) op.oprnamespace)"
          + " WHERE (op.oprleft OPERATOR(pg_catalog.=) t.oid)"
          + " AND (op.oprright OPERATOR(pg_catalog.=) t.oid)"
          + " AND (op.oprname OPERATOR(pg_catalog.=) '=')"
          + " AND (tn.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " AND (en.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " ORDER BY en.nspname LIMIT 1) AS declared_shadow_eq_schema"
          + " FROM pg_catalog.pg_type t"
          + " JOIN pg_catalog.pg_namespace tn ON (tn.oid OPERATOR(pg_catalog.=) t.typnamespace)"
          + " WHERE (t.oid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))";

  /** A domain chain longer than this is unverifiable rather than chased forever. */
  static final int MAX_DOMAIN_DEPTH = 16;

  /** A descendant set larger than this is unverifiable rather than walked forever. */
  static final int MAX_DESCENDANTS = 10_000;

  // ------------------------------------------------------------------------------------ facts

  /**
   * The relation leg's one row. Every field but {@code parts} is empty when the relation is absent.
   */
  record RelationFacts(
      int parts,
      Optional<Long> oid,
      String relkind,
      String persistence,
      boolean rowSecurity,
      boolean forceRowSecurity,
      boolean owns,
      boolean mayRead,
      boolean mayWrite,
      boolean bypassRls,
      long children) {}

  /** One member of the descendant set. */
  record Descendant(long oid, String relkind, String persistence, long children) {}

  /** One type, as the type leg read it. */
  record TypeFacts(
      long oid,
      String typtype,
      String category,
      long baseType,
      String schema,
      String spelled,
      Optional<String> ownEqSchema,
      List<String> binaryImplicitTo,
      Optional<String> declaredShadowEqSchema) {}

  /**
   * One column, with its declared type and the base type a domain chain resolves to.
   *
   * @param present false for C-a's row of NULLs
   * @param deterministic NULL for a non-collatable type (S-5), carried as {@code Optional.empty()}
   */
  record ColumnFacts(
      Column column,
      boolean present,
      boolean notNull,
      String generated,
      Optional<Boolean> deterministic,
      Optional<TypeFacts> declared,
      Optional<TypeFacts> base) {}

  // --------------------------------------------------------------------------------- the check

  /**
   * Reads the catalogue for one target and decides. Every name is {@code pg_catalog}'s and every
   * value is bound, so the session's {@code search_path} decides nothing here (A24, the N46 test).
   *
   * @throws ShreddingException {@code SHRED-SCHEMA-005} when the catalogue cannot be read: a {@code
   *     SQLException} on any statement, a text {@code parse_ident} refuses, or a fact the
   *     statements did not return. Unverifiable is not clean.
   */
  public static Verdict verdict(Connection c, Target target) {
    Objects.requireNonNull(c, "c");
    Objects.requireNonNull(target, "target");
    try {
      RelationFacts relation = relation(c, target.table());
      if (relation.parts() != 2 || relation.oid().isEmpty()) {
        return judge(target, relation, List.of(), List.of());
      }
      long oid = relation.oid().get();
      List<Descendant> descendants =
          relation.children() > 0 ? descendants(c, oid) : List.<Descendant>of();
      List<ColumnFacts> columns = columns(c, oid, target.columns());
      return judge(target, relation, descendants, columns);
    } catch (SQLException e) {
      throw unverifiable(target, "SQLState " + e.getSQLState(), e);
    }
  }

  private static RelationFacts relation(Connection c, TableRef table) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(RELATION_SQL)) {
      String text = table.sql();
      ps.setString(1, text);
      ps.setString(2, text);
      ps.setString(3, text);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("the relation leg returned no row", "XX000");
        }
        int parts = rs.getInt("parts");
        long oid = rs.getLong("oid");
        boolean absent = rs.wasNull();
        RelationFacts facts =
            absent
                ? new RelationFacts(
                    parts,
                    Optional.empty(),
                    "",
                    "",
                    false,
                    false,
                    false,
                    false,
                    false,
                    rs.getBoolean("bypassrls"),
                    0)
                : new RelationFacts(
                    parts,
                    Optional.of(oid),
                    rs.getString("relkind"),
                    rs.getString("relpersistence"),
                    rs.getBoolean("relrowsecurity"),
                    rs.getBoolean("relforcerowsecurity"),
                    rs.getBoolean("owns"),
                    rs.getBoolean("may_read"),
                    rs.getBoolean("may_write"),
                    rs.getBoolean("bypassrls"),
                    rs.getLong("children"));
        if (rs.next()) {
          throw new SQLException("the relation leg returned a second row", "XX000");
        }
        return facts;
      }
    }
  }

  /**
   * The whole descendant set, breadth first, one statement per relation that has children, each
   * relation once. The inheritance set is a DAG, not a tree: legacy inheritance allows several
   * parents, so a relation under a diamond has one {@code pg_inherits} row per parent and would
   * otherwise be visited once per path (security review C-19-4). PostgreSQL refuses a cycle, and
   * the visited set would end one regardless. The bound counts distinct relations, so a catalogue
   * this module did not expect is unverifiable rather than a long loop.
   */
  private static List<Descendant> descendants(Connection c, long root) throws SQLException {
    var out = new ArrayList<Descendant>();
    var visited = new java.util.HashSet<Long>();
    visited.add(root);
    var queue = new ArrayDeque<Long>();
    queue.add(root);
    try (PreparedStatement ps = c.prepareStatement(CHILDREN_SQL)) {
      while (!queue.isEmpty()) {
        ps.setLong(1, queue.poll());
        try (ResultSet rs = ps.executeQuery()) {
          while (rs.next()) {
            var d =
                new Descendant(
                    rs.getLong("inhrelid"),
                    rs.getString("relkind"),
                    rs.getString("relpersistence"),
                    rs.getLong("children"));
            if (!visited.add(d.oid())) {
              continue;
            }
            out.add(d);
            if (d.children() > 0) {
              queue.add(d.oid());
            }
            if (out.size() > MAX_DESCENDANTS) {
              throw new SQLException("more than " + MAX_DESCENDANTS + " descendants", "54000");
            }
          }
        }
      }
    }
    return out;
  }

  private static List<ColumnFacts> columns(Connection c, long oid, List<Column> wanted)
      throws SQLException {
    var texts = new String[wanted.size()];
    for (int i = 0; i < texts.length; i++) {
      texts[i] = wanted.get(i).ref().sql();
    }
    var raw = new ArrayList<Object[]>();
    Array array = c.createArrayOf("text", texts);
    try (PreparedStatement ps = c.prepareStatement(COLUMNS_SQL)) {
      ps.setArray(1, array);
      ps.setLong(2, oid);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          if (rs.getInt("parts") != 1) {
            throw new SQLException(
                "parse_ident found " + rs.getInt("parts") + " parts in a column", "XX000");
          }
          int attnum = rs.getInt("attnum");
          boolean present = !rs.wasNull();
          boolean notNull = rs.getBoolean("attnotnull");
          String generated = Optional.ofNullable(rs.getString("attgenerated")).orElse("");
          long type = rs.getLong("atttypid");
          boolean det = rs.getBoolean("collisdeterministic");
          Optional<Boolean> deterministic = rs.wasNull() ? Optional.empty() : Optional.of(det);
          raw.add(new Object[] {present && attnum > 0, notNull, generated, type, deterministic});
        }
      }
    } finally {
      array.free();
    }
    if (raw.size() != wanted.size()) {
      throw new SQLException(
          "the column leg returned " + raw.size() + " rows for " + wanted.size() + " columns",
          "XX000");
    }
    var types = new LinkedHashMap<Long, TypeFacts>();
    var out = new ArrayList<ColumnFacts>();
    try (PreparedStatement ps = c.prepareStatement(TYPE_SQL)) {
      for (int i = 0; i < wanted.size(); i++) {
        Object[] r = raw.get(i);
        boolean present = (Boolean) r[0];
        @SuppressWarnings("unchecked")
        Optional<Boolean> deterministic = (Optional<Boolean>) r[4];
        if (!present) {
          out.add(
              new ColumnFacts(
                  wanted.get(i),
                  false,
                  false,
                  "",
                  deterministic,
                  Optional.empty(),
                  Optional.empty()));
          continue;
        }
        long declaredOid = (Long) r[3];
        TypeFacts declared = type(ps, types, declaredOid);
        TypeFacts base = declared;
        int depth = 0;
        while ("d".equals(base.typtype())) {
          if (++depth > MAX_DOMAIN_DEPTH) {
            throw new SQLException("a domain chain deeper than " + MAX_DOMAIN_DEPTH, "54000");
          }
          base = type(ps, types, base.baseType());
        }
        out.add(
            new ColumnFacts(
                wanted.get(i),
                true,
                (Boolean) r[1],
                (String) r[2],
                deterministic,
                Optional.of(declared),
                Optional.of(base)));
      }
    }
    return out;
  }

  private static TypeFacts type(PreparedStatement ps, Map<Long, TypeFacts> seen, long oid)
      throws SQLException {
    TypeFacts known = seen.get(oid);
    if (known != null) {
      return known;
    }
    ps.setLong(1, oid);
    try (ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        throw new SQLException("no pg_type row for oid " + oid, "XX000");
      }
      String implicit = rs.getString("binary_implicit_to");
      var facts =
          new TypeFacts(
              oid,
              rs.getString("typtype"),
              rs.getString("typcategory"),
              rs.getLong("typbasetype"),
              rs.getString("nspname"),
              rs.getString("spelled"),
              Optional.ofNullable(rs.getString("own_eq_schema")),
              implicit == null || implicit.isEmpty() ? List.of() : List.of(implicit.split(",", -1)),
              Optional.ofNullable(rs.getString("declared_shadow_eq_schema")));
      seen.put(oid, facts);
      return facts;
    }
  }

  // --------------------------------------------------------------------------------- the rules

  private static final String CATALOG = "pg_catalog";

  /**
   * The rules of §A.3, in Java, over the facts the statements returned. Package-private so every
   * clause, every NULL branch and every ordering can be tested without a database.
   */
  static Verdict judge(
      Target target,
      RelationFacts relation,
      List<Descendant> descendants,
      List<ColumnFacts> columns) {
    TableRef table = target.table();
    String who = who(target);
    String head = target.entity().isPresent() ? who + " maps table " + table : who;
    // R-a: section 3.2 at the catalogue.
    if (relation.parts() != 2) {
      return new Refused(
          "R-a",
          who
              + (target.entity().isPresent() ? " maps table \"" : " \"")
              + table
              + "\", which "
              + (relation.parts() == 1 ? "names no schema" : "has " + relation.parts() + " parts")
              + ". Set"
              + " spring.jpa.properties.hibernate.default_schema=<schema>, or map"
              + " @Table(schema = \"<schema>\") on the entity.");
    }
    // R-b: absent. The caller decides WARN or refusal.
    if (relation.oid().isEmpty()) {
      return new Absent(
          head
              + ", which does not exist. Create the table, or check that the migration that"
              + " creates it ran.");
    }
    var warnings = new ArrayList<String>();
    // R-c: only an ordinary or a partitioned table.
    String kind = relation.relkind();
    if (!"r".equals(kind) && !"p".equals(kind)) {
      return new Refused("R-c", head + relkindMessage(kind));
    }
    // R-d / R-e (S-3): one rule over the whole descendant set.
    for (Descendant d : descendants) {
      boolean leaf = d.children() == 0;
      if (!"r".equals(d.relkind()) && !"p".equals(d.relkind())) {
        return new Refused(
            "R-d",
            head
                + ", which is partitioned (or inherited) and has a descendant that is "
                + kindName(d.relkind())
                + " (relkind '"
                + d.relkind()
                + "'). Every partition or inheritance child of a shredded entity's table must be"
                + " an ordinary permanent table: the erasure's UPDATE routes to it, and none of"
                + " its read-backs can tell whether that relation hid a row.");
      }
      if (leaf && !"r".equals(d.relkind())) {
        return new Refused(
            "R-d",
            head
                + ", which has a partitioned descendant with no partitions of its own (relkind"
                + " 'p' as a leaf). Every leaf of a shredded entity's table must be an ordinary"
                + " table.");
      }
      if ("t".equals(d.persistence())) {
        return new Refused(
            "R-d", head + ", which has a temporary descendant. Nothing durable is erased there.");
      }
      if ("u".equals(d.persistence())) {
        warnings.add(
            head
                + ": a partition or inheritance child is UNLOGGED. The erasure is sound; after a"
                + " crash PostgreSQL empties an unlogged table, residue included, which is the"
                + " application's durability decision, not this module's.");
      }
    }
    // R-f.
    if ("t".equals(relation.persistence())) {
      return new Refused(
          "R-f",
          head
              + ", which is a temporary relation. Nothing durable is erased in it; map the entity"
              + " to a permanent table.");
    }
    if ("u".equals(relation.persistence())) {
      warnings.add(
          head
              + ": the table is UNLOGGED. The erasure is sound; after a crash PostgreSQL empties"
              + " an unlogged table, residue included, which is the application's durability"
              + " decision, not this module's.");
    }
    // R-g (S-4: bypassrls is the relation leg's own column).
    if (relation.rowSecurity()) {
      boolean subject = !relation.owns() || relation.forceRowSecurity();
      if (subject && !relation.bypassRls()) {
        return new Refused(
            "R-g",
            head
                + ", which has row level security enabled"
                + (relation.forceRowSecurity() ? " and forced" : "")
                + ", and this role is subject to it, so a policy can hide the rows an erasure"
                + " must clear from the erasure and from both of its read-backs at once. Exempt"
                + " the module's role from the policy (BYPASSRLS, or a policy that admits it), or"
                + " do not apply row level security to a shredded entity's table.");
      }
      if (subject) {
        warnings.add(
            head
                + ": row level security is enabled and is admitted only because this role holds"
                + " BYPASSRLS [advisory posture]. A role without it would be refused here.");
      }
    }
    // R-h.
    if (!relation.mayRead() || !relation.mayWrite()) {
      return new Refused(
          "R-h",
          head
              + ", and this role holds "
              + (relation.mayRead() ? "SELECT but not UPDATE" : "neither SELECT nor UPDATE")
              + " on it. The erasure would fail at its first statement. Grant SELECT and UPDATE"
              + " on the table to the runtime role (SECURITY-NOTES.md, \"Database roles\").");
    }
    for (ColumnFacts col : columns) {
      Optional<Refused> refused = judgeColumn(who, table, col);
      if (refused.isPresent()) {
        return refused.get();
      }
    }
    return new Admitted(warnings);
  }

  private static Optional<Refused> judgeColumn(String who, TableRef table, ColumnFacts col) {
    Column column = col.column();
    String where = column.role() + " " + table + "." + column.ref().sql();
    // C-a (S-5): a row of NULLs. Read only once the relation leg admitted the relation.
    if (!col.present()) {
      return Optional.of(
          new Refused(
              "C-a",
              who
                  + " names the "
                  + column.role()
                  + " "
                  + column.ref().sql()
                  + ", which "
                  + table
                  + " does not have. Correct the mapping."));
    }
    if (column.use() == Use.ASSIGNED) {
      // C-f, C-g: the blind-index column is assigned NULL by the erasure.
      if (col.notNull()) {
        return Optional.of(
            new Refused(
                "C-f",
                who
                    + ": the "
                    + where
                    + " is NOT NULL; an erasure nulls it. Drop the constraint."));
      }
      if (!col.generated().isEmpty()) {
        return Optional.of(
            new Refused(
                "C-g",
                who
                    + ": the "
                    + where
                    + " is a generated column, which cannot be erased independently of its"
                    + " source. Index a plain column."));
      }
      return Optional.empty();
    }
    TypeFacts declared = col.declared().orElseThrow();
    TypeFacts base = col.base().orElseThrow();
    String remedy =
        column.comparedAsText()
            ? " Map the tenant and subject columns as text, varchar or char(n)."
            : " Map the identifier column as a numeric, uuid, text or varchar column.";
    // C-b: the base type's own default-opclass equality is not pg_catalog's.
    if (base.ownEqSchema().isPresent() && !CATALOG.equals(base.ownEqSchema().get())) {
      return Optional.of(
          new Refused(
              "C-b",
              who
                  + ": the "
                  + where
                  + " is of type "
                  + qualifiedType(base)
                  + ", whose equality operator is "
                  + base.ownEqSchema().get()
                  + ".=, not pg_catalog's. This module compares it with OPERATOR(pg_catalog.=),"
                  + " which answers differently from the application's own lookup, and the"
                  + " independent read-back runs with search_path replaced, where the type's"
                  + " own operator is not reachable at all. A cast to text is not offered: it"
                  + " would make the erasure case-sensitive where the application is not."
                  + remedy));
    }
    // C-c (S-6): no own equality; admitted only through an implicit binary cast to a pg_catalog
    // type whose own equality is pg_catalog's. Ordered after C-b.
    if (base.ownEqSchema().isEmpty() && !reachesCatalogEquality(base.binaryImplicitTo())) {
      return Optional.of(
          new Refused(
              "C-c",
              who
                  + ": the "
                  + where
                  + " is of type "
                  + qualifiedType(base)
                  + ", which has no equality operator this module can reach in pg_catalog."
                  + remedy));
    }
    // C-d: a non-array base type or an enum (a domain has already been chased to its base).
    boolean scalarBase = "b".equals(base.typtype()) && !"A".equals(base.category());
    if (!scalarBase && !"e".equals(base.typtype())) {
      return Optional.of(
          new Refused(
              "C-d",
              who
                  + ": the "
                  + where
                  + " is of type "
                  + qualifiedType(base)
                  + " (typtype '"
                  + base.typtype()
                  + "'"
                  + ("A".equals(base.category()) ? ", an array" : "")
                  + "), which this module has not been shown to compare soundly."
                  + remedy));
    }
    // C-e (S-5): NULL is a non-collatable type and is admitted by its own branch.
    if (col.deterministic().isPresent() && !col.deterministic().get()) {
      return Optional.of(
          new Refused(
              "C-e",
              who
                  + ": the "
                  + where
                  + " uses a collation that is not deterministic, so an erasure for one value"
                  + " also matches values the collation treats as equal (an erasure for s1 also"
                  + " clears S1, measured: 2 rows where 1 was asked for). Use a deterministic"
                  + " collation on the compared columns."));
    }
    // C-h (S-1): an application-defined two-sided '=' on the declared type.
    if (declared.declaredShadowEqSchema().isPresent()) {
      return Optional.of(
          new Refused(
              "C-h",
              who
                  + ": the "
                  + where
                  + " is of declared type "
                  + qualifiedType(declared)
                  + ", which carries its own equality operator "
                  + declared.declaredShadowEqSchema().get()
                  + ".=("
                  + declared.spelled()
                  + ", "
                  + declared.spelled()
                  + ") outside pg_catalog. This module compares it with"
                  + " OPERATOR(pg_catalog.=), which is not that operator (measured: 0 rows where"
                  + " the application's own lookup matches 1), and the independent read-back runs"
                  + " with search_path replaced, where the application's operator is not"
                  + " reachable at all."
                  + remedy));
    }
    // C-i (security review C-19-1, -2, -3, -5): a tenant or subject column is compared against a
    // bound String. Only text, varchar and char(n) compare that string as written. Any other base
    // type either parses it (uuid, numeric: one spelling of a subject clears another's index),
    // truncates it (name, "char": a long subject id is never matched), lets a cast the runtime role
    // owns decide the comparison (an enum: the erasure clears nothing and records COMPLETE), or has
    // no operator for it at all (every erasure fails). Decided by the base type's oid, after the
    // domain chase; no pg_cast read, because pg_cast is not pinned by the table lock.
    if (column.comparedAsText() && !TEXT_TYPE_OIDS.contains(base.oid())) {
      return Optional.of(
          new Refused(
              "C-i",
              who
                  + ": the "
                  + where
                  + " is of type "
                  + qualifiedType(declared)
                  + (declared.oid() == base.oid()
                      ? ""
                      : " (a domain over " + qualifiedType(base) + ")")
                  + ". This module compares tenant and subject columns against the request's"
                  + " string, and only text, varchar and char(n) compare that string as written:"
                  + " another type parses it (a uuid or a number, so one spelling of a subject"
                  + " clears another subject's index), truncates it (name, \"char\"), lets a cast"
                  + " the application's role owns decide the comparison (an enum), or has no"
                  + " comparison with a string at all."
                  + remedy
                  + " A UUID or numeric subject id is stored in a text column."));
    }
    return Optional.empty();
  }

  /**
   * C-c's reading of {@code binary_implicit_to}: a {@code pg_catalog} target whose own equality is.
   */
  static boolean reachesCatalogEquality(List<String> binaryImplicitTo) {
    for (String entry : binaryImplicitTo) {
      int colon = entry.indexOf(':');
      if (colon < 0) {
        continue;
      }
      if (CATALOG.equals(entry.substring(0, colon)) && CATALOG.equals(entry.substring(colon + 1))) {
        return true;
      }
    }
    return false;
  }

  private static String qualifiedType(TypeFacts type) {
    return CATALOG.equals(type.schema()) ? type.spelled() : type.schema() + "." + type.spelled();
  }

  private static String who(Target target) {
    return target
        .entity()
        .map(e -> "@Shredded entity " + e)
        .orElseGet(() -> "shredding: the blind-indexed table " + target.table());
  }

  private static String kindName(String relkind) {
    return switch (relkind) {
      case "v" -> "a view";
      case "f" -> "a foreign table";
      case "m" -> "a materialized view";
      case "p" -> "a partitioned table";
      case "r" -> "a table";
      default -> "not a table";
    };
  }

  private static String relkindMessage(String relkind) {
    return switch (relkind) {
      case "v" ->
          ", which is a view (pg_class.relkind = 'v'), not a table. A view can hide a subject's"
              + " rows from the erasure and from both of its read-backs at once, so all three"
              + " agree the index was cleared while it was not. Map the entity to the table the"
              + " view reads, and keep the view for the application's queries.";
      case "f" ->
          ", which is a foreign table (pg_class.relkind = 'f'). The rows it shows are decided"
              + " by another server, which can hide a subject's rows from the erasure and from"
              + " both of its read-backs. Map the entity to an ordinary table.";
      case "m" ->
          ", which is a materialized view (pg_class.relkind = 'm'): an UPDATE cannot address"
              + " it and its contents are a copy. Map the entity to the table it is built from.";
      default ->
          ", which is not a table (pg_class.relkind = '"
              + relkind
              + "'). Map the entity to an ordinary table.";
    };
  }

  private static ShreddingException unverifiable(Target target, String why, Throwable cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: the mapping of "
            + target.entity().orElse("a blind-indexed entity")
            + " to "
            + target.table()
            + " could not be checked against the catalogue ("
            + why
            + "). Unverifiable is not clean, so this is a refusal.",
        cause);
  }
}
