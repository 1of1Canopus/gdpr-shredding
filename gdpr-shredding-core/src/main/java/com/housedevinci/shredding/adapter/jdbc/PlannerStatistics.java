package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Planner statistics on a blind-index column are a copy of it (audit-table coverage design, section
 * 3b, rows 30, 37, 47 and 48, C13, and the confirmation's item 5). {@code ANALYZE} stores sampled
 * values of a column - most common values, histogram bounds - in {@code pg_statistic}; {@code
 * pg_stats} shows them to any role with {@code SELECT} on the column; and an erasure's {@code
 * UPDATE} does not remove them. An erased subject's index then stays matchable with the
 * application's own index secret, which is exactly what clearing the index exists to end.
 *
 * <p><b>Every path by which statistics can exist for the column</b>, each with its own test in
 * {@code PlannerStatisticsPostgresTest} on PostgreSQL 16 and 17:
 *
 * <ol>
 *   <li>the column's own target: {@code attstattarget} anything but 0, NULL included, because 16
 *       stores the default as {@code -1} and 17 as {@code NULL}, and NULL is not 0 (S-7);
 *   <li>rows already stored, {@code inherited} or not, read through {@code pg_stats} - the same
 *       view the attacker reads - by the runtime role;
 *   <li>an expression index computing over the column (its own statistics are the expression's
 *       values). Read from the stored expression tree, not from {@code pg_depend}, which does not
 *       tell an expression from a predicate and gives every expression index a whole-table entry. A
 *       predicate-only partial index stores no statistics of the column (measured 0 rows on 16.15
 *       and 17.11) and is admitted; a whole-row reference ({@code varattno 0}) counts;
 *   <li>an extended-statistics object covering the column by key or by expression, read through
 *       {@code pg_depend}, which records both (measured) - its data is invisible to a non-owner, so
 *       detection is by definition;
 *   <li>every partition and inheritance child, each with its own target, rows, indexes and objects;
 *   <li>a stored generated column computed from the column: measured on 16.15, 17.11 and 18.6, its
 *       own {@code pg_stats} row holds the derived values ({@code lower(email_idx)} is the index
 *       itself), so it is checked as a carrier on paths 1 to 4. A virtual generated column stores
 *       nothing and cannot be given a target (measured on 18.6), so it is not one.
 * </ol>
 *
 * <p><b>Unverifiable is not clean.</b> {@code pg_stats} hides a relation's rows from a role without
 * {@code SELECT} on the column and from a role row level security applies to; for such a member the
 * check cannot see what it exists to see, and refuses with {@code SHRED-SCHEMA-005}.
 *
 * <p><b>The remedy is printed, never run.</b> {@code SET STATISTICS 0} stops future sampling and
 * {@code ALTER COLUMN ... TYPE <same type> USING <column>} deletes the stored rows without
 * rewriting the table. That statement fails when a view, a rule, a policy or a generated column
 * depends on the column (C13), so the dependents are read too: plain views and policies are
 * re-created by a printed one-transaction script from their catalogue definitions; anything else is
 * named, with the two alternatives that clear statistics without retyping.
 *
 * <p>Every statement is fully qualified, binds every value, and composes no identifier: identifiers
 * that reach a message are quoted by the server ({@code quote_ident}).
 */
final class PlannerStatistics {

  private PlannerStatistics() {}

  /**
   * Each member of the family (the table and its descendants) that has the blind-index column, and
   * on it the column itself and every stored generated column computed from it.
   */
  static final String CARRIERS_SQL =
      "SELECT c.oid AS relid, c.relispartition,"
          + " pg_catalog.quote_ident(n.nspname) AS nsp, pg_catalog.quote_ident(c.relname) AS rel,"
          + " b.attnum AS base_attnum, a.attnum, pg_catalog.quote_ident(a.attname) AS col,"
          + " a.attgenerated, a.attstattarget,"
          + " pg_catalog.format_type(a.atttypid, a.atttypmod) AS spelled,"
          + " pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT') AS may_read,"
          + " (c.relrowsecurity AND pg_catalog.row_security_active(c.oid)) AS rls_active,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_stats s"
          + " WHERE (s.schemaname OPERATOR(pg_catalog.=) n.nspname)"
          + " AND (s.tablename OPERATOR(pg_catalog.=) c.relname)"
          + " AND (s.attname OPERATOR(pg_catalog.=) a.attname)) AS stats_rows"
          + " FROM pg_catalog.unnest(?) WITH ORDINALITY AS f"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " JOIN pg_catalog.pg_attribute b ON (b.attrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (b.attname OPERATOR(pg_catalog.=)"
          + " (SELECT p.p FROM pg_catalog.unnest(pg_catalog.parse_ident(?)) WITH ORDINALITY AS p"
          + " WHERE (p.ordinality OPERATOR(pg_catalog.=) 1)))"
          + " AND (b.attnum OPERATOR(pg_catalog.>) 0) AND (NOT b.attisdropped)"
          + " JOIN pg_catalog.pg_attribute a ON (a.attrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND (NOT a.attisdropped)"
          + " AND ((a.attnum OPERATOR(pg_catalog.=) b.attnum)"
          + " OR ((a.attgenerated OPERATOR(pg_catalog.=) 's')"
          + " AND ((SELECT pg_catalog.count(*) FROM pg_catalog.pg_attrdef ad"
          + " JOIN pg_catalog.pg_depend d ON (d.objid OPERATOR(pg_catalog.=) ad.oid)"
          + " WHERE (ad.adrelid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (ad.adnum OPERATOR(pg_catalog.=) a.attnum)"
          + " AND (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_attrdef' AS pg_catalog.regclass))"
          + " AND (d.refclassid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (d.refobjid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (d.refobjsubid OPERATOR(pg_catalog.=) b.attnum)) OPERATOR(pg_catalog.>) 0)))"
          + " ORDER BY f.ordinality, a.attnum";

  /** Every index on a family member that has expressions, with its stored expression tree. */
  static final String INDEXES_SQL =
      "SELECT i.indrelid, pg_catalog.quote_ident(inn.nspname) AS nsp,"
          + " pg_catalog.quote_ident(ic.relname) AS rel,"
          + " pg_catalog.quote_ident(rn.nspname) AS root_nsp,"
          + " pg_catalog.quote_ident(rc.relname) AS root_rel,"
          + " CAST(i.indexprs AS pg_catalog.text) AS exprs,"
          + " CAST(i.indpred AS pg_catalog.text) AS pred"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_index i"
          + " ON (i.indrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_class ic ON (ic.oid OPERATOR(pg_catalog.=) i.indexrelid)"
          + " JOIN pg_catalog.pg_namespace inn ON (inn.oid OPERATOR(pg_catalog.=) ic.relnamespace)"
          + " JOIN pg_catalog.pg_class rc ON (rc.oid OPERATOR(pg_catalog.=)"
          + " (CASE WHEN ic.relispartition"
          + " THEN CAST(pg_catalog.pg_partition_root(CAST(ic.oid AS pg_catalog.regclass))"
          + " AS pg_catalog.oid) ELSE ic.oid END))"
          + " JOIN pg_catalog.pg_namespace rn ON (rn.oid OPERATOR(pg_catalog.=) rc.relnamespace)"
          + " WHERE (i.indexprs IS NOT NULL)"
          + " ORDER BY inn.nspname, ic.relname";

  /** Every extended-statistics object on a family member, with the columns it depends on. */
  static final String EXTENDED_SQL =
      "SELECT s.stxrelid, pg_catalog.quote_ident(sn.nspname) AS nsp,"
          + " pg_catalog.quote_ident(s.stxname) AS name,"
          + " (SELECT pg_catalog.string_agg(CAST(d.refobjsubid AS pg_catalog.text), ' ')"
          + " FROM pg_catalog.pg_depend d"
          + " WHERE (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_statistic_ext' AS pg_catalog.regclass))"
          + " AND (d.objid OPERATOR(pg_catalog.=) s.oid)"
          + " AND (d.refclassid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (d.refobjid OPERATOR(pg_catalog.=) s.stxrelid)"
          + " AND (d.refobjsubid OPERATOR(pg_catalog.>) 0)) AS deps,"
          + " CAST(s.stxkeys AS pg_catalog.text) AS keys,"
          + " CAST(s.stxexprs AS pg_catalog.text) AS exprs"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_statistic_ext s"
          + " ON (s.stxrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_namespace sn ON (sn.oid OPERATOR(pg_catalog.=) s.stxnamespace)"
          + " ORDER BY sn.nspname, s.stxname";

  /** Every stored generated column on a family member, with its stored expression tree. */
  static final String GENERATED_SQL =
      "SELECT pg_catalog.concat_ws('.', pg_catalog.quote_ident(n.nspname),"
          + " pg_catalog.quote_ident(c.relname), pg_catalog.quote_ident(a.attname)) AS col,"
          + " CAST(ad.adbin AS pg_catalog.text) AS exprs"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_attrdef ad"
          + " ON (ad.adrelid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_attribute a ON (a.attrelid OPERATOR(pg_catalog.=) ad.adrelid)"
          + " AND (a.attnum OPERATOR(pg_catalog.=) ad.adnum)"
          + " AND (a.attgenerated OPERATOR(pg_catalog.=) 's')"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) ad.adrelid)"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " ORDER BY 1";

  /**
   * The functions among the given oids that are not in {@code pg_catalog}, or are not immutable
   * (C-24-8: {@code query_to_xml} is {@code pg_catalog}'s and runs any SQL), by qualified name.
   */
  static final String FOREIGN_FUNCTIONS_SQL =
      "SELECT pg_catalog.concat_ws('.', pg_catalog.quote_ident(n.nspname),"
          + " pg_catalog.quote_ident(p.proname)) AS name"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_proc p ON (p.oid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) p.pronamespace)"
          + " WHERE (n.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " OR (p.provolatile OPERATOR(pg_catalog.<>) 'i')"
          + " ORDER BY 1";

  /**
   * The operators among the given oids that are not {@code pg_catalog}'s, or whose function is not,
   * by qualified name.
   */
  static final String FOREIGN_OPERATORS_SQL =
      "SELECT pg_catalog.concat_ws('.', pg_catalog.quote_ident(n.nspname), o.oprname) AS name"
          + " FROM pg_catalog.unnest(?) AS f"
          + " JOIN pg_catalog.pg_operator o"
          + " ON (o.oid OPERATOR(pg_catalog.=) CAST(f.f AS pg_catalog.oid))"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) o.oprnamespace)"
          + " JOIN pg_catalog.pg_proc p ON (p.oid OPERATOR(pg_catalog.=) o.oprcode)"
          + " JOIN pg_catalog.pg_namespace pn ON (pn.oid OPERATOR(pg_catalog.=) p.pronamespace)"
          + " WHERE (n.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " OR (pn.nspname OPERATOR(pg_catalog.<>) 'pg_catalog')"
          + " OR (p.provolatile OPERATOR(pg_catalog.<>) 'i')"
          + " ORDER BY 1";

  /** Reads and restores the session's search_path around the remedy's catalogue reads. */
  static final String READ_PATH_SQL = "SELECT pg_catalog.current_setting('search_path')";

  static final String SET_PATH_SQL = "SELECT pg_catalog.set_config('search_path', ?, true)";

  /**
   * What depends on one column of one family member, as the owner's {@code ALTER COLUMN ... TYPE}
   * would meet it. Indexes, constraints, column defaults and extended statistics are rebuilt by
   * that statement and are not listed; a view's rule is read back to its view.
   */
  static final String DEPENDENTS_SQL =
      "SELECT CAST(CAST(d.classid AS pg_catalog.regclass) AS pg_catalog.text) AS catalog,"
          + " d.objid,"
          + " pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid) AS described,"
          + " (SELECT ga.attgenerated FROM pg_catalog.pg_attrdef ad"
          + " JOIN pg_catalog.pg_attribute ga ON (ga.attrelid OPERATOR(pg_catalog.=) ad.adrelid)"
          + " AND (ga.attnum OPERATOR(pg_catalog.=) ad.adnum)"
          + " WHERE (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_attrdef' AS pg_catalog.regclass))"
          + " AND (ad.oid OPERATOR(pg_catalog.=) d.objid)) AS generated,"
          + " (SELECT pg_catalog.concat_ws('.', pg_catalog.quote_ident(gn.nspname),"
          + " pg_catalog.quote_ident(gc.relname), pg_catalog.quote_ident(ga.attname))"
          + " FROM pg_catalog.pg_attrdef ad"
          + " JOIN pg_catalog.pg_attribute ga ON (ga.attrelid OPERATOR(pg_catalog.=) ad.adrelid)"
          + " AND (ga.attnum OPERATOR(pg_catalog.=) ad.adnum)"
          + " JOIN pg_catalog.pg_class gc ON (gc.oid OPERATOR(pg_catalog.=) ad.adrelid)"
          + " JOIN pg_catalog.pg_namespace gn ON (gn.oid OPERATOR(pg_catalog.=) gc.relnamespace)"
          + " WHERE (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_attrdef' AS pg_catalog.regclass))"
          + " AND (ad.oid OPERATOR(pg_catalog.=) d.objid)) AS generated_column,"
          + " (SELECT r.ev_class FROM pg_catalog.pg_rewrite r"
          + " WHERE (d.classid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_rewrite' AS pg_catalog.regclass))"
          + " AND (r.oid OPERATOR(pg_catalog.=) d.objid)"
          + " AND (r.rulename OPERATOR(pg_catalog.=) '_RETURN')) AS view_oid"
          + " FROM pg_catalog.pg_depend d"
          + " WHERE (d.refclassid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (d.refobjid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))"
          + " AND (d.refobjsubid OPERATOR(pg_catalog.=) ?)"
          + " AND (d.deptype OPERATOR(pg_catalog.<>) 'i')"
          + " ORDER BY 3";

  /**
   * One view a column depends on: its definition and everything a faithful re-creation needs, and
   * the counts that decide whether a re-creation can be faithful at all.
   */
  static final String VIEW_SQL =
      "SELECT pg_catalog.quote_ident(n.nspname) AS nsp, pg_catalog.quote_ident(c.relname) AS rel,"
          + " c.relkind, pg_catalog.pg_get_viewdef(c.oid, true) AS def,"
          + " pg_catalog.array_to_string(c.reloptions, ', ') AS opts,"
          + " pg_catalog.quote_ident(o.rolname) AS owner,"
          + " pg_catalog.quote_literal(pg_catalog.obj_description(c.oid, 'pg_class')) AS remark,"
          + " (c.relacl IS NULL) AS default_acl,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_depend d"
          + " WHERE (d.refclassid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (d.refobjid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (d.deptype OPERATOR(pg_catalog.<>) 'i')) AS dependents,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger t"
          + " WHERE (t.tgrelid OPERATOR(pg_catalog.=) c.oid)) AS triggers,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_rewrite r"
          + " WHERE (r.ev_class OPERATOR(pg_catalog.=) c.oid)"
          + " AND (r.rulename OPERATOR(pg_catalog.<>) '_RETURN')) AS rules,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a"
          + " WHERE (a.attrelid OPERATOR(pg_catalog.=) c.oid) AND (a.attacl IS NOT NULL))"
          + " AS column_acls,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_description de"
          + " WHERE (de.objoid OPERATOR(pg_catalog.=) c.oid)"
          + " AND (de.classoid OPERATOR(pg_catalog.=)"
          + " CAST('pg_catalog.pg_class' AS pg_catalog.regclass))"
          + " AND (de.objsubid OPERATOR(pg_catalog.>) 0)) AS column_remarks,"
          + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_default_acl da"
          + " WHERE (da.defaclobjtype OPERATOR(pg_catalog.=) 'r')"
          + " AND ((da.defaclnamespace OPERATOR(pg_catalog.=) CAST(0 AS pg_catalog.oid))"
          + " OR (da.defaclnamespace OPERATOR(pg_catalog.=) c.relnamespace))) AS default_privileges"
          + " FROM pg_catalog.pg_class c"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " JOIN pg_catalog.pg_roles o ON (o.oid OPERATOR(pg_catalog.=) c.relowner)"
          + " WHERE (c.oid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))";

  /** The explicit grants on one view, each as {@code GRANT} would spell it. */
  static final String GRANTS_SQL =
      "SELECT (CASE WHEN (g.grantee OPERATOR(pg_catalog.=) CAST(0 AS pg_catalog.oid))"
          + " THEN 'PUBLIC' ELSE pg_catalog.quote_ident(r.rolname) END) AS grantee,"
          + " g.privilege_type, g.is_grantable"
          + " FROM pg_catalog.pg_class c"
          + " CROSS JOIN pg_catalog.aclexplode(c.relacl) AS g"
          + " LEFT JOIN pg_catalog.pg_roles r ON (r.oid OPERATOR(pg_catalog.=) g.grantee)"
          + " WHERE (c.oid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))"
          + " ORDER BY 1, 2";

  /** One policy a column depends on, as {@code CREATE POLICY} would spell it. */
  static final String POLICY_SQL =
      "SELECT pg_catalog.quote_ident(p.polname) AS name, pg_catalog.quote_ident(n.nspname) AS nsp,"
          + " pg_catalog.quote_ident(c.relname) AS rel, p.polpermissive, p.polcmd,"
          + " (SELECT pg_catalog.string_agg((CASE WHEN (x.x OPERATOR(pg_catalog.=)"
          + " CAST(0 AS pg_catalog.oid)) THEN 'PUBLIC' ELSE pg_catalog.quote_ident(o.rolname) END),"
          + " ', ' ORDER BY x.ordinality)"
          + " FROM pg_catalog.unnest(p.polroles) WITH ORDINALITY AS x"
          + " LEFT JOIN pg_catalog.pg_roles o ON (o.oid OPERATOR(pg_catalog.=) x.x)) AS roles,"
          + " pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS qual,"
          + " pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS checked,"
          + " pg_catalog.quote_literal(pg_catalog.obj_description(p.oid, 'pg_policy')) AS remark"
          + " FROM pg_catalog.pg_policy p"
          + " JOIN pg_catalog.pg_class c ON (c.oid OPERATOR(pg_catalog.=) p.polrelid)"
          + " JOIN pg_catalog.pg_namespace n ON (n.oid OPERATOR(pg_catalog.=) c.relnamespace)"
          + " WHERE (p.oid OPERATOR(pg_catalog.=) CAST(? AS pg_catalog.oid))";

  // -------------------------------------------------------------------------------- facts

  /** One column statistics can be stored under: the blind-index column or a generated one. */
  record Carrier(
      long relid,
      boolean root,
      boolean partition,
      String relation,
      int baseAttnum,
      int attnum,
      String column,
      boolean generated,
      Optional<Integer> target,
      String spelled,
      boolean mayRead,
      boolean rlsActive,
      long statsRows) {

    String qualified() {
      return relation + "." + column;
    }
  }

  /** One expression index on a family member. */
  record ExpressionIndex(long relid, String name, String root, String exprs, String pred) {}

  /** One extended-statistics object on a family member, with the attnums it covers. */
  record ExtendedStatistics(long relid, String name, Set<Integer> attnums, String exprs) {}

  /** What a stored expression tree calls: function oids and operator oids. */
  record Calls(Set<Long> functions, Set<Long> operators) {}

  /** A stored expression tree's {@code Var} node: the attnum of the column it reads. */
  private static final Pattern VAR = Pattern.compile("\\{VAR :varno (\\d+) :varattno (-?\\d+) ");

  private static final Pattern VAR_TOKEN = Pattern.compile("\\{VAR ");

  /**
   * The attnums a stored expression tree reads, {@code 0} for a whole-row reference. Every {@code
   * {VAR } node must parse: a tree whose {@code Var} nodes this pattern no longer recognises (a
   * format change in a later PostgreSQL) is unverifiable, never an expression that reads nothing.
   */
  static Set<Integer> referencedAttnums(String tree) {
    var out = new LinkedHashSet<Integer>();
    Matcher m = VAR.matcher(tree);
    int parsed = 0;
    while (m.find()) {
      out.add(Integer.parseInt(m.group(2)));
      parsed++;
    }
    int tokens = 0;
    Matcher t = VAR_TOKEN.matcher(tree);
    while (t.find()) {
      tokens++;
    }
    if (tokens != parsed) {
      throw new IllegalArgumentException(
          tokens + " Var nodes in a stored expression, " + parsed + " of them readable");
    }
    return out;
  }

  private static final Pattern FUNC = Pattern.compile("\\{FUNCEXPR :funcid (\\d+) ");

  private static final Pattern FUNC_TOKEN = Pattern.compile("\\{FUNCEXPR ");

  private static final Pattern OP =
      Pattern.compile(
          "\\{(?:OPEXPR|DISTINCTEXPR|NULLIFEXPR|SCALARARRAYOPEXPR) :opno (\\d+) :opfuncid (\\d+) ");

  private static final Pattern OP_TOKEN =
      Pattern.compile("\\{(?:OPEXPR|DISTINCTEXPR|NULLIFEXPR|SCALARARRAYOPEXPR) ");

  /**
   * The functions and operators a stored expression tree calls (C-24-4): a function body is opaque
   * to the {@code Var} scan, so what it calls is the other half of the reading. Same rule as {@link
   * #referencedAttnums}: every call node must parse, or the tree is unverifiable.
   */
  static Calls calls(String tree) {
    var functions = new LinkedHashSet<Long>();
    var operators = new LinkedHashSet<Long>();
    if (tree == null) {
      return new Calls(functions, operators);
    }
    int parsed = 0;
    Matcher f = FUNC.matcher(tree);
    while (f.find()) {
      functions.add(Long.parseLong(f.group(1)));
      parsed++;
    }
    Matcher o = OP.matcher(tree);
    while (o.find()) {
      operators.add(Long.parseLong(o.group(1)));
      long code = Long.parseLong(o.group(2));
      if (code != 0) {
        functions.add(code);
      }
      parsed++;
    }
    int tokens = count(FUNC_TOKEN, tree) + count(OP_TOKEN, tree);
    if (tokens != parsed) {
      throw new IllegalArgumentException(
          tokens + " call nodes in a stored expression, " + parsed + " of them readable");
    }
    return new Calls(functions, operators);
  }

  private static int count(Pattern p, String tree) {
    int n = 0;
    Matcher m = p.matcher(tree);
    while (m.find()) {
      n++;
    }
    return n;
  }

  /** A space-separated list of attnums, as {@code int2vector} and {@code string_agg} print. */
  static Set<Integer> attnums(String list) {
    var out = new LinkedHashSet<Integer>();
    if (list == null) {
      return out;
    }
    for (String part : list.trim().split(" +")) {
      if (!part.isEmpty()) {
        out.add(Integer.parseInt(part));
      }
    }
    return out;
  }

  // ---------------------------------------------------------------------------- the check

  /**
   * Reads the statistics facts of every blind-index column of {@code target} over its whole family,
   * and returns the {@code SHRED-SCHEMA-010} message when any exists.
   *
   * @param family the table's oid first, then every descendant the admission walk found
   * @throws ShreddingException {@code SHRED-SCHEMA-005} when a family member's statistics are
   *     hidden from the runtime role, or a stored expression cannot be read
   */
  static Optional<String> check(Connection c, Target target, long root, List<Long> family)
      throws SQLException {
    return withPinnedPath(c, () -> checkPinned(c, target, root, family));
  }

  private static Optional<String> checkPinned(
      Connection c, Target target, long root, List<Long> family) throws SQLException {
    var blind = new ArrayList<Column>();
    for (Column col : target.columns()) {
      if (MappingAdmission.BLIND_INDEX.equals(col.role())) {
        blind.add(col);
      }
    }
    if (blind.isEmpty()) {
      return Optional.empty();
    }
    var carriers = new LinkedHashMap<Column, List<Carrier>>();
    for (Column col : blind) {
      carriers.put(col, carriers(c, root, family, col));
    }
    List<ExpressionIndex> indexes = indexes(c, family);
    List<ExtendedStatistics> extended = extended(c, family);
    refuseOpaqueExpressions(c, family, indexes, extended);

    var findings = new ArrayList<Finding>();
    for (Column col : blind) {
      List<Carrier> own = carriers.get(col);
      for (Carrier carrier : own) {
        refuseIfHidden(carrier);
      }
      Finding finding = facts(col, own, indexes, extended);
      if (!finding.facts().isEmpty()) {
        findings.add(finding);
      }
    }
    if (findings.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(message(c, findings));
  }

  /** What was found for one blind-index column. */
  private record Finding(
      Column column,
      Carrier base,
      List<Carrier> carriers,
      List<String> facts,
      boolean needsColumnStatements) {}

  private static List<Carrier> carriers(Connection c, long root, List<Long> family, Column col)
      throws SQLException {
    var out = new ArrayList<Carrier>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(CARRIERS_SQL)) {
      ps.setArray(1, oids);
      ps.setString(2, col.ref().sql());
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          int target = rs.getInt("attstattarget");
          Optional<Integer> stored = rs.wasNull() ? Optional.empty() : Optional.of(target);
          long relid = rs.getLong("relid");
          out.add(
              new Carrier(
                  relid,
                  relid == root,
                  rs.getBoolean("relispartition"),
                  JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel"),
                  rs.getInt("base_attnum"),
                  rs.getInt("attnum"),
                  JdbcSupport.printed(rs, "col"),
                  "s".equals(rs.getString("attgenerated")),
                  stored,
                  JdbcSupport.printed(rs, "spelled"),
                  rs.getBoolean("may_read"),
                  rs.getBoolean("rls_active"),
                  rs.getLong("stats_rows")));
        }
      }
    } finally {
      oids.free();
    }
    if (out.stream().noneMatch(k -> k.root() && !k.generated())) {
      throw new SQLException(
          "the carrier leg found no row for the blind-index column " + col.ref().sql(), "XX000");
    }
    return out;
  }

  private static List<ExpressionIndex> indexes(Connection c, List<Long> family)
      throws SQLException {
    var out = new ArrayList<ExpressionIndex>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(INDEXES_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.add(
              new ExpressionIndex(
                  rs.getLong("indrelid"),
                  JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel"),
                  JdbcSupport.printed(rs, "root_nsp") + "." + JdbcSupport.printed(rs, "root_rel"),
                  rs.getString("exprs"),
                  rs.getString("pred")));
        }
      }
    } finally {
      oids.free();
    }
    return out;
  }

  private static List<ExtendedStatistics> extended(Connection c, List<Long> family)
      throws SQLException {
    var out = new ArrayList<ExtendedStatistics>();
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(EXTENDED_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          var covered = new LinkedHashSet<Integer>(attnums(rs.getString("deps")));
          covered.addAll(attnums(rs.getString("keys")));
          out.add(
              new ExtendedStatistics(
                  rs.getLong("stxrelid"),
                  JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "name"),
                  covered,
                  rs.getString("exprs")));
        }
      }
    } finally {
      oids.free();
    }
    return out;
  }

  /**
   * C-24-4: an expression index, an expression in extended statistics, or a stored generated column
   * on a family member that calls a function or operator outside {@code pg_catalog} stores
   * statistics of whatever that function reads, which no catalogue read can see. Unverifiable is
   * not clean: {@code SHRED-SCHEMA-005}, naming the object and what it calls.
   */
  private static void refuseOpaqueExpressions(
      Connection c,
      List<Long> family,
      List<ExpressionIndex> indexes,
      List<ExtendedStatistics> extended)
      throws SQLException {
    var trees = new LinkedHashMap<String, String>();
    for (ExpressionIndex index : indexes) {
      trees.put("expression index " + index.name(), index.exprs());
      if (index.pred() != null) {
        trees.put("the predicate of expression index " + index.name(), index.pred());
      }
    }
    for (ExtendedStatistics stats : extended) {
      if (stats.exprs() != null) {
        trees.put("extended statistics " + stats.name(), stats.exprs());
      }
    }
    Array oids = c.createArrayOf("int8", family.toArray(new Long[0]));
    try (PreparedStatement ps = c.prepareStatement(GENERATED_SQL)) {
      ps.setArray(1, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          trees.put(
              "stored generated column " + JdbcSupport.printed(rs, "col"), rs.getString("exprs"));
        }
      }
    } finally {
      oids.free();
    }
    for (var tree : trees.entrySet()) {
      Calls calls;
      try {
        calls = calls(tree.getValue());
      } catch (IllegalArgumentException e) {
        throw opaque(
            tree.getKey(), "an expression this module could not read (" + e.getMessage() + ")", e);
      }
      List<String> foreign = new ArrayList<>(foreign(c, false, calls.functions()));
      for (String op : foreign(c, true, calls.operators())) {
        foreign.add("operator " + op);
      }
      if (!foreign.isEmpty()) {
        throw opaque(
            tree.getKey(),
            String.join(", ", foreign)
                + (foreign.size() == 1 ? ", which is" : ", which are")
                + " outside pg_catalog or not immutable",
            null);
      }
    }
  }

  private static List<String> foreign(Connection c, boolean operators, Set<Long> oids)
      throws SQLException {
    var out = new ArrayList<String>();
    if (oids.isEmpty()) {
      return out;
    }
    Array array = c.createArrayOf("int8", oids.toArray(new Long[0]));
    try (PreparedStatement ps =
        c.prepareStatement(operators ? FOREIGN_OPERATORS_SQL : FOREIGN_FUNCTIONS_SQL)) {
      ps.setArray(1, array);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.add(JdbcSupport.printed(rs, "name"));
        }
      }
    } finally {
      array.free();
    }
    return out;
  }

  private static ShreddingException opaque(String object, String calls, Throwable cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: "
            + object
            + " on a blind-indexed table calls "
            + calls
            + ". Its statistics hold whatever that function reads, which this module cannot see,"
            + " so it cannot tell whether they hold a blind-index column. Unverifiable is not"
            + " clean, so this is a refusal. Drop it, or replace the function by an immutable"
            + " pg_catalog expression.",
        cause);
  }

  private static void refuseIfHidden(Carrier carrier) {
    String member = carrier.partition() ? "the partition" : "the table";
    if (!carrier.mayRead()) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the runtime role has no SELECT on "
              + carrier.qualified()
              + ", so it cannot see whether statistics are stored for it. Grant SELECT on "
              + member
              + ", or run the check as a role that has it.");
    }
    if (carrier.rlsActive()) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: row level security on "
              + carrier.relation()
              + " applies to the runtime role, and pg_stats hides the statistics of a relation"
              + " row level security applies to, so the role cannot see whether statistics are"
              + " stored for "
              + carrier.qualified()
              + ". Exempt the role from it (BYPASSRLS), or run the check as a role that is"
              + " exempt.");
    }
  }

  private static Finding facts(
      Column col,
      List<Carrier> carriers,
      List<ExpressionIndex> indexes,
      List<ExtendedStatistics> extended) {
    var facts = new ArrayList<String>();
    boolean statements = false;
    Carrier base = null;
    for (Carrier k : carriers) {
      if (k.root() && !k.generated()) {
        base = k;
      }
      String where = k.root() ? "" : " on " + member(k) + " " + k.relation();
      String subject = k.generated() ? "stored generated column " + k.qualified() : null;
      if (k.target().isEmpty() || k.target().get() != 0) {
        String target =
            k.target()
                .map(v -> v == -1 ? "-1 (the default)" : String.valueOf(v))
                .orElse("the default (NULL)");
        String fact =
            subject == null
                ? "its statistics target" + where + " is " + target
                : subject + " is computed from it, and its statistics target is " + target;
        facts.add(fact + ", so the next ANALYZE samples it");
        statements = true;
      }
      if (k.statsRows() > 0) {
        facts.add(
            subject == null
                ? "pg_stats holds sampled values for it" + where
                : subject + " is computed from it, and pg_stats holds sampled values for it");
        statements = true;
      }
    }
    var dropped = new LinkedHashSet<String>();
    for (ExpressionIndex index : indexes) {
      Set<Integer> read;
      Set<Integer> selects;
      try {
        read = referencedAttnums(index.exprs());
        selects = index.pred() == null ? Set.of() : referencedAttnums(index.pred());
      } catch (IllegalArgumentException e) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "shredding: the expression of index "
                + index.name()
                + " could not be read ("
                + e.getMessage()
                + "), so this module cannot tell whether it computes over the blind-index column."
                + " Unverifiable is not clean, so this is a refusal.",
            e);
      }
      for (Carrier k : carriers) {
        if (k.relid() == index.relid()
            && !(read.contains(k.attnum()) || read.contains(0))
            && (selects.contains(k.attnum()) || selects.contains(0))
            && dropped.add(index.name())) {
          // C-24-6: ANALYZE samples an expression index only from the rows its predicate selects,
          // so a predicate on the blind index keeps, under the index, which values it held.
          facts.add(
              "expression index "
                  + index.name()
                  + " samples only the rows its predicate selects by it (drop it: DROP INDEX "
                  + index.root()
                  + ")");
        }
        if (k.relid() == index.relid()
            && (read.contains(k.attnum()) || read.contains(0))
            && dropped.add(index.name())) {
          String through =
              k.generated() && !read.contains(0) && !read.contains(k.baseAttnum())
                  ? " through stored generated column " + k.qualified()
                  : "";
          facts.add(
              "expression index "
                  + index.name()
                  + " computes over it"
                  + through
                  + " (drop it: DROP INDEX "
                  + index.root()
                  + ")");
        }
      }
    }
    for (ExtendedStatistics stats : extended) {
      for (Carrier k : carriers) {
        if (k.relid() == stats.relid()
            && stats.attnums().contains(k.attnum())
            && dropped.add(stats.name())) {
          facts.add(
              "extended statistics "
                  + stats.name()
                  + " cover it (drop them: DROP STATISTICS "
                  + stats.name()
                  + ")");
        }
      }
    }
    return new Finding(col, base, carriers, facts, statements);
  }

  private static String member(Carrier k) {
    return k.partition() ? "partition" : "inheritance child";
  }

  // ------------------------------------------------------------------------------ message

  /** One piece of work on the connection. */
  @FunctionalInterface
  interface PathWork<T> {
    T run() throws SQLException;
  }

  /**
   * C-24-2: runs {@code work} with {@code search_path} pinned to {@code pg_catalog, pg_temp}, so
   * every name the server deparses ({@code pg_get_viewdef}, {@code pg_get_expr}, {@code
   * format_type}, {@code pg_describe_object}) comes back qualified unless it is {@code
   * pg_catalog}'s. A definition deparsed on the application's own path prints names relative to
   * that path, and the operator who runs the printed remedy in another session re-binds them: the
   * view over another table, the policy calling another function. The pin is transaction-local and
   * read back; on an auto-commit connection a transaction is opened and rolled back, inside one the
   * arrived path is restored and read back (the erasure that called this is refused anyway).
   */
  static <T> T withPinnedPath(Connection c, PathWork<T> work) throws SQLException {
    boolean auto = c.getAutoCommit();
    String arrived = readPath(c);
    if (auto) {
      c.setAutoCommit(false);
    }
    Throwable primary = null;
    try {
      setPath(c, JdbcSupport.PINNED_PATH);
      return work.run();
    } catch (RuntimeException | SQLException | Error e) {
      primary = e;
      throw e;
    } finally {
      if (auto) {
        c.rollback();
        c.setAutoCommit(true);
      } else {
        // C-24-5: restored on every exit, a refusal included: a caller of the public verdict that
        // catches it keeps working in its own transaction. A restore that fails because the work
        // aborted the transaction (25P02) is attached to the primary, never in its place.
        try {
          setPath(c, arrived);
        } catch (SQLException restore) {
          if (primary == null) {
            throw restore;
          }
          primary.addSuppressed(restore);
        }
      }
    }
  }

  private static String readPath(Connection c) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(READ_PATH_SQL);
        ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        throw new SQLException("current_setting returned no row", "XX000");
      }
      return rs.getString(1);
    }
  }

  private static void setPath(Connection c, String path) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(SET_PATH_SQL)) {
      ps.setString(1, path);
      ps.execute();
    }
    String now = readPath(c);
    if (!path.equals(now)) {
      throw new SQLException(
          "search_path read back as \"" + now + "\" after setting \"" + path + "\"", "XX000");
    }
  }

  private static final String WHY =
      " Statistics store sampled values of the column (most common values, histogram bounds); any"
          + " role with SELECT on the table reads them from pg_stats, and an erasure does not"
          + " remove them.";

  private static final String STEP = " See docs/upgrading-0.2.0.md, step 3a.";

  private static String message(Connection c, List<Finding> findings) throws SQLException {
    var out = new StringBuilder("shredding: PostgreSQL keeps, or will keep, planner statistics on");
    for (int i = 0; i < findings.size(); i++) {
      Finding f = findings.get(i);
      out.append(i == 0 ? " the blind-index column " : ", and on the blind-index column ")
          .append(f.base().qualified())
          .append(f.column().attribute().map(a -> " (" + a + ")").orElse(""))
          .append(": ")
          .append(String.join("; ", f.facts()));
    }
    out.append('.').append(WHY);
    var retyped = findings.stream().filter(Finding::needsColumnStatements).toList();
    if (retyped.isEmpty()) {
      return out.append(" Drop the objects named above as the table owner.")
          .append(STEP)
          .toString();
    }
    var views = new TreeMap<String, Long>();
    var policies = new TreeMap<String, PolicyRef>();
    var named = new TreeMap<String, Boolean>();
    var generated = new LinkedHashSet<String>();
    for (Finding f : retyped) {
      for (Carrier k : f.carriers()) {
        if (!k.generated()) {
          dependents(c, k, views, policies, named, generated);
        }
      }
    }
    for (var view : List.copyOf(views.entrySet())) {
      Optional<String> why = viewNotRecreatable(c, view.getValue());
      if (why.isPresent()) {
        views.remove(view.getKey());
        named.put("view " + view.getKey() + why.get(), true);
      }
    }
    if (!named.isEmpty()) {
      // The named branch still prints what it can run: SET STATISTICS 0 on the column and on
      // every stored generated column computed from it, which needs no retyping. Only clearing
      // the rows already stored needs a statement this module does not generate.
      var zero = new StringBuilder();
      var cleared = new ArrayList<String>();
      for (Finding f : retyped) {
        for (Carrier k : f.carriers()) {
          if (k.root() || k.generated()) {
            zero.append(" ALTER TABLE ")
                .append(k.relation())
                .append(" ALTER COLUMN ")
                .append(k.column())
                .append(" SET STATISTICS 0;");
            cleared.add(k.qualified());
          }
        }
      }
      return out.append(
              " Objects that depend on the column and are not re-created by a generated"
                  + " statement: ")
          .append(String.join("; ", named.keySet()))
          .append(". Clear the statistics without retyping. As the table owner run: SET")
          .append(" search_path = pg_catalog, pg_temp;")
          .append(zero)
          .append(" The rows already stored for ")
          .append(String.join(", ", cleared))
          .append(
              " then need a statement this module does not generate: on PostgreSQL 18 or later,"
                  + " as the table owner, pg_catalog.pg_clear_attribute_stats for each column; on"
                  + " 16 or 17, a superuser deletes their pg_statistic rows.")
          .append(STEP)
          .toString();
    }
    var alter = new StringBuilder();
    for (Finding f : retyped) {
      Carrier b = f.base();
      alter
          .append(" ALTER TABLE ")
          .append(b.relation())
          .append(" ALTER COLUMN ")
          .append(b.column())
          .append(" SET STATISTICS 0;");
    }
    for (Finding f : retyped) {
      Carrier b = f.base();
      alter
          .append(" ALTER TABLE ")
          .append(b.relation())
          .append(" ALTER COLUMN ")
          .append(b.column())
          .append(" TYPE ")
          .append(b.spelled())
          .append(" USING ")
          .append(b.column())
          .append(';');
    }
    if (views.isEmpty() && policies.isEmpty()) {
      out.append(
              " As the table owner run: SET search_path = pg_catalog, pg_temp; SET lock_timeout ="
                  + " '5s';")
          .append(alter);
      out.append(
          retyped.size() == 1
              ? " The TYPE statement deletes the statistics already stored; it does not rewrite"
                  + " the table but takes an ACCESS EXCLUSIVE lock briefly."
              : " Each TYPE statement deletes the statistics already stored for its column; it"
                  + " does not rewrite the table but takes an ACCESS EXCLUSIVE lock briefly.");
      return out.append(STEP).toString();
    }
    var listed = new ArrayList<String>();
    views.keySet().forEach(v -> listed.add("view " + v));
    policies.values().forEach(p -> listed.add("policy " + p.name() + " on " + p.relation()));
    out.append(" Objects that depend on the column and must be dropped and re-created with it: ")
        .append(String.join("; ", listed))
        .append(
            ". As the table owner run: BEGIN; SET LOCAL search_path = pg_catalog, pg_temp; SET LOCAL"
                + " lock_timeout = '5s';");
    var recreate = new StringBuilder();
    for (var view : views.entrySet()) {
      out.append(" DROP VIEW ").append(view.getKey()).append(';');
      recreate.append(recreateView(c, view.getValue()));
    }
    for (var policy : policies.entrySet()) {
      out.append(" DROP POLICY ")
          .append(policy.getValue().name())
          .append(" ON ")
          .append(policy.getValue().relation())
          .append(';');
      recreate.append(recreatePolicy(c, policy.getValue().oid()));
    }
    out.append(alter).append(recreate).append(" COMMIT;");
    out.append(
        " One transaction, so the table is never readable without its policies; the TYPE"
            + " statement deletes the statistics already stored, does not rewrite the table, and"
            + " holds an ACCESS EXCLUSIVE lock until COMMIT.");
    return out.append(STEP).toString();
  }

  private static void dependents(
      Connection c,
      Carrier base,
      Map<String, Long> views,
      Map<String, PolicyRef> policies,
      Map<String, Boolean> named,
      Set<String> generated)
      throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(DEPENDENTS_SQL)) {
      ps.setLong(1, base.relid());
      ps.setInt(2, base.attnum());
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String catalog = rs.getString("catalog");
          String described = rs.getString("described");
          switch (catalog) {
            case "pg_class", "pg_constraint", "pg_statistic_ext" -> {
              // Rebuilt by ALTER COLUMN ... TYPE: an index (an expression index is a fact of its
              // own), a sequence the column owns, a CHECK or foreign key, a statistics object.
            }
            case "pg_attrdef" -> {
              String kind = rs.getString("generated");
              if (kind != null && !kind.isEmpty()) {
                String column = JdbcSupport.printed(rs, "generated_column");
                named.put(
                    ("s".equals(kind) ? "stored generated column " : "virtual generated column ")
                        + column,
                    true);
                if ("s".equals(kind)) {
                  generated.add(column);
                }
              }
            }
            case "pg_rewrite" -> {
              long view = rs.getLong("view_oid");
              if (rs.wasNull()) {
                named.put(described, true);
              } else {
                String name = viewName(c, view);
                if (name.startsWith("v:")) {
                  views.put(name.substring(2), view);
                } else {
                  named.put(name.substring(2), true);
                }
              }
            }
            case "pg_policy" -> {
              PolicyRef policy = policy(c, rs.getLong("objid"));
              policies.put(policy.relation() + " " + policy.name(), policy);
            }
            default -> named.put(described, true);
          }
        }
      }
    }
  }

  /** {@code v:<qualified>} for a view, {@code x:materialized view <qualified>} otherwise. */
  private static String viewName(Connection c, long oid) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(VIEW_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("no pg_class row for view oid " + oid, "XX000");
        }
        String name = JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel");
        return "v".equals(rs.getString("relkind")) ? "v:" + name : "x:materialized view " + name;
      }
    }
  }

  private static Optional<String> viewNotRecreatable(Connection c, long oid) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(VIEW_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("no pg_class row for view oid " + oid, "XX000");
        }
        if (rs.getLong("dependents") > 0) {
          return Optional.of(" (other views depend on it)");
        }
        if (rs.getLong("triggers") > 0 || rs.getLong("rules") > 0) {
          return Optional.of(" (it has triggers or rules of its own)");
        }
        if (rs.getLong("column_acls") > 0 || rs.getLong("column_remarks") > 0) {
          return Optional.of(" (it has column privileges or column comments)");
        }
        // C-24-3: CREATE VIEW applies the creating role's default privileges, so a re-created
        // view could carry grants the original never had. Any default for relations, global or
        // for the view's schema and whoever it belongs to, names the view instead.
        if (rs.getLong("default_privileges") > 0) {
          return Optional.of(" (default privileges would change its grants)");
        }
        return Optional.empty();
      }
    }
  }

  private static String recreateView(Connection c, long oid) throws SQLException {
    var out = new StringBuilder();
    String name;
    try (PreparedStatement ps = c.prepareStatement(VIEW_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("no pg_class row for view oid " + oid, "XX000");
        }
        name = JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel");
        String def = rs.getString("def").strip();
        if (def.endsWith(";")) {
          def = def.substring(0, def.length() - 1);
        }
        String opts = rs.getString("opts");
        out.append(" CREATE VIEW ")
            .append(name)
            .append(opts == null || opts.isEmpty() ? "" : " WITH (" + opts + ")")
            .append(" AS ")
            .append(def.replaceAll("\\s+", " "))
            .append(';');
        out.append(" ALTER VIEW ")
            .append(name)
            .append(" OWNER TO ")
            .append(JdbcSupport.printed(rs, "owner"))
            .append(';');
        if (!rs.getBoolean("default_acl")) {
          out.append(" REVOKE ALL ON ")
              .append(name)
              .append(" FROM ")
              .append(JdbcSupport.printed(rs, "owner"))
              .append(';');
        }
        String remark = rs.getString("remark");
        if (remark != null) {
          out.append(" COMMENT ON VIEW ").append(name).append(" IS ").append(remark).append(';');
        }
      }
    }
    try (PreparedStatement ps = c.prepareStatement(GRANTS_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          out.append(" GRANT ")
              .append(rs.getString("privilege_type"))
              .append(" ON ")
              .append(name)
              .append(" TO ")
              .append(JdbcSupport.printed(rs, "grantee"))
              .append(rs.getBoolean("is_grantable") ? " WITH GRANT OPTION" : "")
              .append(';');
        }
      }
    }
    return out.toString();
  }

  /** A policy a column depends on, with its server-quoted name and relation. */
  private record PolicyRef(long oid, String name, String relation) {}

  private static PolicyRef policy(Connection c, long oid) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(POLICY_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("no pg_policy row for oid " + oid, "XX000");
        }
        return new PolicyRef(
            oid,
            JdbcSupport.printed(rs, "name"),
            JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel"));
      }
    }
  }

  private static String recreatePolicy(Connection c, long oid) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(POLICY_SQL)) {
      ps.setLong(1, oid);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          throw new SQLException("no pg_policy row for oid " + oid, "XX000");
        }
        String relation = JdbcSupport.printed(rs, "nsp") + "." + JdbcSupport.printed(rs, "rel");
        String cmd =
            switch (rs.getString("polcmd")) {
              case "r" -> "SELECT";
              case "a" -> "INSERT";
              case "w" -> "UPDATE";
              case "d" -> "DELETE";
              default -> "ALL";
            };
        var out =
            new StringBuilder(" CREATE POLICY ")
                .append(JdbcSupport.printed(rs, "name"))
                .append(" ON ")
                .append(relation)
                .append(rs.getBoolean("polpermissive") ? " AS PERMISSIVE" : " AS RESTRICTIVE")
                .append(" FOR ")
                .append(cmd)
                .append(" TO ")
                .append(JdbcSupport.printed(rs, "roles"));
        String qual = rs.getString("qual");
        if (qual != null) {
          out.append(" USING (").append(qual).append(')');
        }
        String checked = rs.getString("checked");
        if (checked != null) {
          out.append(" WITH CHECK (").append(checked).append(')');
        }
        out.append(';');
        String remark = rs.getString("remark");
        if (remark != null) {
          out.append(" COMMENT ON POLICY ")
              .append(JdbcSupport.printed(rs, "name"))
              .append(" ON ")
              .append(relation)
              .append(" IS ")
              .append(remark)
              .append(';');
        }
        return out.toString();
      }
    }
  }
}
