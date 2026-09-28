package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.adapter.jdbc.SchemaExpectations.Column;
import com.housedevinci.shredding.adapter.jdbc.SchemaExpectations.Constraint;
import com.housedevinci.shredding.adapter.jdbc.SchemaExpectations.TablePrivileges;
import com.housedevinci.shredding.adapter.jdbc.SchemaExpectations.Trigger;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads the PostgreSQL catalogue and decides whether the schema in {@code current_schema()} still
 * carries the guards this module's controls rest on, and whether the role that is about to write to
 * it is privileged enough to remove them.
 *
 * <p>Design §4 of {@code no-ddl-at-runtime-design.md}, version 2.1. One connection, catalogue reads
 * only, no DDL and no writes of any kind. Every leg runs before anything is thrown, so a partial
 * schema is reported in one message rather than one object per restart.
 *
 * <p>Two rules run through all of it. <b>Unverifiable is not clean</b>: any {@link SQLException}
 * from verification itself is {@code SHRED-SCHEMA-005}, never a pass and never a warning - {@code
 * REVOKE SELECT ON pg_trigger FROM PUBLIC} is a real and reachable way to make this check blind.
 * <b>Nothing is created, ever</b>: a gap is a refusal with the remedy in the message, because the
 * role that can close the gap is by definition a role that can disable the guards.
 */
final class SchemaVerification {

  private SchemaVerification() {}

  /**
   * @param allowPrivilegedRuntimeRole when true, the {@code 004} legs become the verdict's {@link
   *     Verdict#privilegeLegs()} for the caller to warn about, instead of a refusal. {@code 007} is
   *     never downgraded.
   */
  /**
   * Verifies in <b>one read-only transaction of its own</b> (C-13-4). Without this the eleven
   * catalogue reads take eleven snapshots, so "schema verified" is a claim about no single instant
   * of the database, and nothing on the server side refuses a write from a connection whose whole
   * contract is "catalogue reads only" - the rule would be enforced by review alone. The connection
   * is rolled back and all three settings restored whatever happens.
   */
  static SchemaVerdict verify(Connection connection, boolean allowPrivilegedRuntimeRole) {
    boolean previousAutoCommit;
    boolean previousReadOnly;
    int previousIsolation;
    try {
      previousAutoCommit = connection.getAutoCommit();
      previousReadOnly = connection.isReadOnly();
      previousIsolation = connection.getTransactionIsolation();
      // Both before setAutoCommit(false): PostgreSQL refuses either inside an open transaction.
      connection.setReadOnly(true);
      connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
      connection.setAutoCommit(false);
    } catch (SQLException e) {
      throw unverifiable(e);
    }
    try {
      return run(connection, allowPrivilegedRuntimeRole);
    } catch (SQLException e) {
      throw unverifiable(e);
    } finally {
      restore(connection, previousAutoCommit, previousReadOnly, previousIsolation);
    }
  }

  /**
   * Verifies inside a transaction the caller already opened, changing no connection setting. The
   * creation path is the only caller: it has just run the bundled script in this very transaction,
   * under the script's advisory lock, so it is neither read-only nor a fresh snapshot and must not
   * be made either.
   */
  static SchemaVerdict verifyInCallersTransaction(
      Connection connection, boolean allowPrivilegedRuntimeRole) {
    try {
      return run(connection, allowPrivilegedRuntimeRole);
    } catch (SQLException e) {
      throw unverifiable(e);
    }
  }

  private static void restore(Connection c, boolean autoCommit, boolean readOnly, int isolation) {
    try {
      c.rollback();
      c.setAutoCommit(autoCommit);
      c.setReadOnly(readOnly);
      c.setTransactionIsolation(isolation);
    } catch (SQLException ignored) {
      // The connection is about to be closed or returned to a pool that discards a broken one. A
      // failure to put settings back is never a reason to turn a clean verification into a refusal,
      // or a refusal into something else.
    }
  }

  private static SchemaVerdict run(Connection c, boolean allowPrivileged) throws SQLException {
    Session session = session(c);
    VerifiedSchema schema = session.schema();

    Map<String, Relation> relations = relations(c);
    List<String> missing =
        SchemaExpectations.TABLES.stream().filter(t -> !relations.containsKey(t)).toList();
    if (missing.size() == SchemaExpectations.TABLES.size()) {
      throw absent(session);
    }

    var shape = new ArrayList<String>();
    var guards = new ArrayList<String>();
    missing.forEach(t -> shape.add("table " + t + " does not exist"));

    checkRelationShape(relations, shape, guards);
    checkColumns(c, relations, shape);
    checkSequence(c, relations, shape);
    checkConstraints(c, relations, shape);

    Map<String, Function> functions = functions(c);
    checkGuardFunctions(functions, guards);
    checkTriggers(c, relations, functions, guards);
    checkRulesAndPolicies(c, relations, guards);
    checkInheritance(c, relations, guards);

    List<String> indexWarnings = new ArrayList<>();
    Map<String, Relation> indexes = indexes(c);
    SchemaExpectations.INDEXES.stream()
        .filter(i -> !indexes.containsKey(i))
        .forEach(
            i ->
                indexWarnings.add(
                    i + " (a subject lookup on the erasure log or the key table is a full scan)"));

    var excess = new ArrayList<String>();
    var underprivileged = new ArrayList<String>();
    checkRole(c, session, relations, indexes, functions, excess, underprivileged);

    // §4.7: every leg has run, and one refusal lists everything that is wrong, so an operator
    // fixes the database in one round rather than restarting N times to discover the next object.
    // The code is the most serious category present, in this order: a guard that is not
    // load-bearing, then a shape that is wrong, then a privilege the adapters need, then a
    // privilege the role should not have.
    var problems = new ArrayList<String>();
    problems.addAll(guards);
    problems.addAll(shape);
    problems.addAll(underprivileged);
    if (!allowPrivileged) {
      problems.addAll(excess);
    }
    if (!problems.isEmpty()) {
      var remedies = new ArrayList<String>();
      if (!guards.isEmpty()) {
        remedies.add(unguardedRemedy());
      }
      if (!shape.isEmpty()) {
        remedies.add(incompleteRemedy());
      }
      if (!underprivileged.isEmpty()) {
        remedies.add(underprivilegedRemedy());
      }
      if (!allowPrivileged && !excess.isEmpty()) {
        remedies.add(privilegedRemedy());
      }
      throw refusal(code(guards, shape, underprivileged), problems, session, remedies);
    }
    return new SchemaVerdict(schema, session.role(), session.database(), excess, indexWarnings);
  }

  private static String code(
      List<String> guards, List<String> shape, List<String> underprivileged) {
    if (!guards.isEmpty()) {
      return ErrorCodes.SCHEMA_UNGUARDED;
    }
    if (!shape.isEmpty()) {
      return ErrorCodes.SCHEMA_INCOMPLETE;
    }
    if (!underprivileged.isEmpty()) {
      return ErrorCodes.RUNTIME_ROLE_UNDERPRIVILEGED;
    }
    return ErrorCodes.RUNTIME_ROLE_PRIVILEGED;
  }

  // ---------------------------------------------------------------- session

  private record Session(VerifiedSchema schema, String role, String database) {}

  private static Session session(Connection c) throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement("SELECT current_schema(), current_user, current_database()");
        ResultSet rs = ps.executeQuery()) {
      if (!rs.next() || rs.getString(1) == null) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "current_schema() is null on this connection: every schema on the search_path is"
                + " missing or not visible to this role, so there is no schema to verify and no"
                + " schema this module's statements would resolve against. Set a schema in the JDBC"
                + " URL (currentSchema=...) or grant USAGE on the one that holds the shredding"
                + " tables.");
      }
      return new Session(new VerifiedSchema(rs.getString(1)), rs.getString(2), rs.getString(3));
    }
  }

  // ---------------------------------------------------------------- objects

  /**
   * A {@code pg_class} row of interest. {@code ownedByRole} is {@code pg_has_role(.., 'MEMBER')}.
   */
  private record Relation(
      long oid,
      String name,
      String kind,
      String persistence,
      boolean hasRules,
      boolean rowSecurity,
      boolean forceRowSecurity,
      boolean ownedByRole) {}

  private static Map<String, Relation> relations(Connection c) throws SQLException {
    return relations(
        c,
        "SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relhasrules, c.relrowsecurity,"
            + " c.relforcerowsecurity, pg_has_role(current_user, c.relowner, 'MEMBER')"
            + " FROM pg_class c"
            + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY(?)",
        SchemaExpectations.TABLES);
  }

  private static Map<String, Relation> indexes(Connection c) throws SQLException {
    return relations(
        c,
        "SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relhasrules, c.relrowsecurity,"
            + " c.relforcerowsecurity, pg_has_role(current_user, c.relowner, 'MEMBER')"
            + " FROM pg_class c"
            + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind = 'i'"
            + " AND c.relname = ANY(?)",
        SchemaExpectations.INDEXES);
  }

  private static Map<String, Relation> relations(Connection c, String sql, List<String> names)
      throws SQLException {
    var found = new LinkedHashMap<String, Relation>();
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setArray(1, c.createArrayOf("text", names.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          found.put(
              rs.getString(2),
              new Relation(
                  rs.getLong(1),
                  rs.getString(2),
                  rs.getString(3),
                  rs.getString(4),
                  rs.getBoolean(5),
                  rs.getBoolean(6),
                  rs.getBoolean(7),
                  rs.getBoolean(8)));
        }
      }
    }
    return found;
  }

  private static void checkRelationShape(
      Map<String, Relation> relations, List<String> shape, List<String> guards) {
    for (Relation r : relations.values()) {
      if (!"r".equals(r.kind())) {
        shape.add(
            r.name()
                + " is not an ordinary table (pg_class.relkind='"
                + r.kind()
                + "'). A view, a foreign table or a partitioned parent with this name carries none"
                + " of the append-only triggers this module's controls rest on.");
      }
      if (!"p".equals(r.persistence())) {
        shape.add(
            r.name()
                + " is not a permanent table (pg_class.relpersistence='"
                + r.persistence()
                + "'). An UNLOGGED or TEMPORARY erasure log loses the proof of erasure on a crash.");
      }
    }
  }

  private static void checkColumns(
      Connection c, Map<String, Relation> relations, List<String> shape) throws SQLException {
    var actual = new LinkedHashMap<String, List<Column>>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, a.attname, a.attnotnull, format_type(a.atttypid, a.atttypmod)"
                + " FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid"
                + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY(?)"
                + " AND a.attnum > 0 AND NOT a.attisdropped"
                + " ORDER BY c.relname, a.attnum")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          actual
              .computeIfAbsent(rs.getString(1), k -> new ArrayList<>())
              .add(new Column(rs.getString(2), rs.getBoolean(3), rs.getString(4)));
        }
      }
    }
    SchemaExpectations.COLUMNS.forEach(
        (table, expected) -> {
          if (!relations.containsKey(table)) {
            return;
          }
          List<Column> found = actual.getOrDefault(table, List.of());
          for (int i = 0; i < expected.size(); i++) {
            Column want = expected.get(i);
            Column have = i < found.size() ? found.get(i) : null;
            if (have == null) {
              shape.add(
                  table + "." + want.name() + " is missing (expected at ordinal " + (i + 1) + ")");
            } else if (!want.equals(have)) {
              shape.add(
                  table
                      + " column "
                      + (i + 1)
                      + " is "
                      + describe(have)
                      + ", expected "
                      + describe(want));
            }
          }
          for (int i = expected.size(); i < found.size(); i++) {
            shape.add(
                table
                    + " has an unexpected column "
                    + found.get(i).name()
                    + " at ordinal "
                    + (i + 1)
                    + "; this module compares the whole column set, because a table hand-written"
                    + " from the README is exactly what this leg exists to catch.");
          }
        });
  }

  private static String describe(Column column) {
    return column.name() + " " + column.type() + (column.notNull() ? " NOT NULL" : " NULL");
  }

  private static void checkSequence(
      Connection c, Map<String, Relation> relations, List<String> shape) throws SQLException {
    if (!relations.containsKey(SchemaExpectations.ERASURE)) {
      return;
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT s.relkind, (SELECT count(*) FROM pg_depend d"
                + "   WHERE d.classid = 'pg_class'::regclass AND d.objid = s.oid"
                + "     AND d.refclassid = 'pg_class'::regclass AND d.refobjid = t.oid"
                + "     AND d.refobjsubid = a.attnum AND d.deptype = 'a')"
                + " FROM pg_class s, pg_class t, pg_attribute a"
                + " WHERE s.relnamespace = current_schema()::regnamespace AND s.relname = ?"
                + "   AND t.oid = ? AND a.attrelid = t.oid AND a.attname = 'seq'")) {
      ps.setString(1, SchemaExpectations.SEQUENCE);
      ps.setLong(2, relations.get(SchemaExpectations.ERASURE).oid());
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          shape.add(
              SchemaExpectations.SEQUENCE
                  + " does not exist, or shredding_erasure has no seq column. The erasure log's"
                  + " seq is a bigserial; without its sequence every append fails on nextval.");
          return;
        }
        if (!"S".equals(rs.getString(1))) {
          shape.add(
              SchemaExpectations.SEQUENCE
                  + " is not a sequence (relkind='"
                  + rs.getString(1)
                  + "')");
        }
        if (rs.getLong(2) != 1) {
          shape.add(
              SchemaExpectations.SEQUENCE
                  + " is not the sequence owned by shredding_erasure.seq (no pg_depend 'a' edge)."
                  + " A hand-made table with no bigserial default takes its first append to"
                  + " discover that.");
        }
      }
    }
  }

  private static void checkConstraints(
      Connection c, Map<String, Relation> relations, List<String> shape) throws SQLException {
    var actual = new LinkedHashMap<String, Constraint>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, con.conname, con.contype, pg_get_constraintdef(con.oid)"
                + " FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid"
                + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY(?)")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          actual.put(
              rs.getString(2),
              new Constraint(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
        }
      }
    }
    for (Constraint want : SchemaExpectations.CONSTRAINTS) {
      if (!relations.containsKey(want.table())) {
        continue;
      }
      Constraint have = actual.remove(want.name());
      if (have == null) {
        shape.add(
            "constraint "
                + want.name()
                + " on "
                + want.table()
                + " is missing ("
                + want.definition()
                + ")");
      } else if (!want.equals(have)) {
        shape.add(
            "constraint "
                + want.name()
                + " on "
                + have.table()
                + " is "
                + have.definition()
                + ", expected "
                + want.definition()
                + " on "
                + want.table()
                + ". Compared on the definition, never the name: a UNIQUE moved to another column"
                + " keeps its name.");
      }
    }
    actual
        .values()
        .forEach(
            extra ->
                shape.add(
                    "unexpected constraint "
                        + extra.name()
                        + " on "
                        + extra.table()
                        + " ("
                        + extra.definition()
                        + "). This module's tables carry exactly six constraints; anything else was"
                        + " added after the schema step and this module cannot tell a benign one"
                        + " from a foreign key that makes an append fail."));
  }

  // ---------------------------------------------------------------- guards

  private record Function(
      long oid,
      String name,
      String body,
      String kind,
      int args,
      boolean securityDefiner,
      boolean noConfig,
      String language,
      String returns,
      boolean ownedByRole) {}

  private static Map<String, Function> functions(Connection c) throws SQLException {
    var found = new LinkedHashMap<String, Function>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT p.oid, p.proname, p.prosrc, p.prokind, p.pronargs, p.prosecdef,"
                + " p.proconfig IS NULL, l.lanname, pg_get_function_result(p.oid),"
                + " pg_has_role(current_user, p.proowner, 'MEMBER')"
                + " FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang"
                + " WHERE p.pronamespace = current_schema()::regnamespace AND p.proname = ANY(?)")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.GUARD_FUNCTIONS.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          found.put(
              rs.getString(2),
              new Function(
                  rs.getLong(1),
                  rs.getString(2),
                  rs.getString(3),
                  rs.getString(4),
                  rs.getInt(5),
                  rs.getBoolean(6),
                  rs.getBoolean(7),
                  rs.getString(8),
                  rs.getString(9),
                  rs.getBoolean(10)));
        }
      }
    }
    return found;
  }

  private static void checkGuardFunctions(Map<String, Function> functions, List<String> guards) {
    Map<String, String> expected = GuardBodies.fromBundledScript();
    for (String name : SchemaExpectations.GUARD_FUNCTIONS) {
      Function have = functions.get(name);
      if (have == null) {
        guards.add(
            "guard function "
                + name
                + " does not exist in this schema. Without it the append-only triggers have"
                + " nothing to call and the erasure log is an ordinary table.");
        continue;
      }
      if (!"f".equals(have.kind())
          || have.args() != 0
          || have.securityDefiner()
          || !have.noConfig()
          || !"plpgsql".equals(have.language())
          || !"trigger".equals(have.returns())) {
        guards.add(
            "guard function "
                + name
                + " is not the shape the schema step creates (prokind="
                + have.kind()
                + ", pronargs="
                + have.args()
                + ", prosecdef="
                + have.securityDefiner()
                + ", proconfig "
                + (have.noConfig() ? "unset" : "set")
                + ", language "
                + have.language()
                + ", returns "
                + have.returns()
                + ")");
        continue;
      }
      String actual = GuardBodies.normalise(have.body());
      if (actual.indexOf('\r') >= 0) {
        guards.add(carriageReturn(name));
        continue;
      }
      String want = expected.get(name);
      if (!MessageDigest.isEqual(
          actual.getBytes(StandardCharsets.UTF_8), want.getBytes(StandardCharsets.UTF_8))) {
        guards.add(
            "guard function "
                + name
                + " does not have the body the bundled schema script defines: "
                + actual.length()
                + " characters, md5 "
                + md5Prefix(actual)
                + ", expected "
                + want.length()
                + " characters, md5 "
                + md5Prefix(want)
                + ". CREATE OR REPLACE FUNCTION keeps the oid, so the trigger still points at the"
                + " same function and every identity check passes while the guard allows"
                + " everything. Re-apply schema-postgresql.sql as the owner role.");
      }
    }
  }

  private static String carriageReturn(String name) {
    return "guard function "
        + name
        + " contains a carriage return that is not part of a CRLF line ending. PostgreSQL ends a"
        + " -- comment at a lone CR, so the code the server runs is not the code the body reads"
        + " as, and a body normalised by dropping every CR compares equal to the bundled one while"
        + " behaving differently. Re-apply schema-postgresql.sql as the owner role.";
  }

  private static String md5Prefix(String value) {
    try {
      byte[] digest =
          MessageDigest.getInstance("MD5").digest(value.getBytes(StandardCharsets.UTF_8));
      var hex = new StringBuilder();
      for (int i = 0; i < 6; i++) {
        hex.append(String.format("%02x", digest[i]));
      }
      return hex.toString();
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("MD5 is required of every JRE", impossible);
    }
  }

  private static void checkTriggers(
      Connection c,
      Map<String, Relation> relations,
      Map<String, Function> functions,
      List<String> guards)
      throws SQLException {
    // tgqual and tgattr are read for C-13-1. Every other column here is byte-identical before and
    // after the two rewrites they catch, so without them a guard recreated WHEN (false), or
    // narrowed to UPDATE OF one column, is present, enabled, pointing at the right function and of
    // the right type - and never fires once. Both are constants on a script-created schema,
    // measured: tgqual null and tgattr empty for all seven.
    record Found(
        String name,
        String table,
        String function,
        int type,
        String enabled,
        boolean inSchema,
        boolean hasWhenClause,
        String columnList) {}
    var actual = new LinkedHashMap<String, Found>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT t.tgname, c.relname, p.proname, t.tgtype, t.tgenabled,"
                + " p.pronamespace = current_schema()::regnamespace,"
                + " t.tgqual IS NOT NULL, t.tgattr::text"
                + " FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
                + " JOIN pg_proc p ON p.oid = t.tgfoid"
                + " WHERE c.relnamespace = current_schema()::regnamespace"
                + "   AND c.relname = ANY(?) AND NOT t.tgisinternal")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String attributes = rs.getString(8);
          actual.put(
              rs.getString(1),
              new Found(
                  rs.getString(1),
                  rs.getString(2),
                  rs.getString(3),
                  rs.getInt(4),
                  rs.getString(5),
                  rs.getBoolean(6),
                  rs.getBoolean(7),
                  attributes == null ? "" : attributes.trim()));
        }
      }
    }
    for (Trigger want : SchemaExpectations.TRIGGERS) {
      if (!relations.containsKey(want.table())) {
        continue;
      }
      Found have = actual.remove(want.name());
      if (have == null) {
        guards.add("trigger " + want.name() + " on " + want.table() + " is missing");
        continue;
      }
      if (!want.table().equals(have.table()) || want.type() != have.type()) {
        guards.add(
            "trigger "
                + want.name()
                + " is on "
                + have.table()
                + " with tgtype "
                + have.type()
                + ", expected "
                + want.table()
                + " with tgtype "
                + want.type());
      }
      if (!want.function().equals(have.function()) || !have.inSchema()) {
        guards.add(
            "trigger "
                + want.name()
                + " calls "
                + have.function()
                + (have.inSchema() ? "" : " in another schema")
                + ", expected "
                + want.function()
                + " in this schema. The function is followed through tgfoid, so a trigger repointed"
                + " at a same-named no-op elsewhere is caught.");
      }
      if (have.hasWhenClause()) {
        guards.add(
            "trigger "
                + want.name()
                + " on "
                + want.table()
                + " carries a WHEN clause (pg_trigger.tgqual is set). The guards this module ships"
                + " have none, and a WHEN predicate decides whether the trigger body runs at all:"
                + " WHEN (false) leaves the name, the relation, the function, the tgtype and"
                + " ENABLE ALWAYS exactly as this check expects, and fires never. It is visible in"
                + " psql with \\d+ "
                + want.table()
                + ". Re-apply schema-postgresql.sql as the owner role.");
      }
      if (!have.columnList().isEmpty()) {
        guards.add(
            "trigger "
                + want.name()
                + " on "
                + want.table()
                + " is narrowed to a column list (pg_trigger.tgattr = "
                + have.columnList()
                + "), so it fires for an UPDATE of those columns and for no others. The guards this"
                + " module ships are narrowed to nothing. Neither tgtype nor tgenabled changes when"
                + " a trigger is narrowed this way, which is why this is its own check. Re-apply"
                + " schema-postgresql.sql as the owner role.");
      }
      if (!"A".equals(have.enabled())) {
        guards.add(
            "trigger "
                + want.name()
                + " on "
                + want.table()
                + " is tgenabled='"
                + have.enabled()
                + "', expected 'A' (ENABLE ALWAYS). "
                + explainEnabled(have.enabled())
                + " Remedy: re-apply schema-postgresql.sql as the owner role - from 0.2.0 it issues"
                + " ALTER TABLE ... ENABLE ALWAYS TRIGGER for all seven guards, unconditionally.");
      }
      if (!functions.containsKey(want.function())) {
        guards.add("guard function " + want.function() + " is not in this schema");
      }
    }
    actual
        .values()
        .forEach(
            extra ->
                guards.add(
                    "unexpected trigger "
                        + extra.name()
                        + " on "
                        + extra.table()
                        + " calling "
                        + extra.function()
                        + " (tgtype "
                        + extra.type()
                        + "). The trigger set is exhaustive, not existential: a BEFORE INSERT"
                        + " trigger that returns NULL makes every append vanish with no error"
                        + " while all seven guards are still present and enabled."));
  }

  private static String explainEnabled(String enabled) {
    return switch (enabled) {
      case "D" ->
          "'D' means someone ran ALTER TABLE ... DISABLE TRIGGER: the guard is off right now.";
      case "R" ->
          "'R' (ENABLE REPLICA) means the guard fires only for a replication apply worker, which is"
              + " to say never for this application.";
      case "O" ->
          "'O' (the default of CREATE TRIGGER) means the guard does not fire for a replication apply"
              + " worker, for a superuser session in session_replication_role=replica, or under"
              + " pg_restore --disable-triggers.";
      default -> "";
    };
  }

  /**
   * C-13-2. An inheritance child of one of the four tables carries none of the parent's triggers,
   * and its rows are returned by every read of the <em>parent</em> name - this module's own {@code
   * read()} and the chain verifier included - and deletable through the parent name with no guard
   * anywhere near the statement. Same shape as the rules and the policies: a statement re-targeted
   * before any guard sees it.
   *
   * <p>{@code pg_inherits}, deliberately not {@code pg_class.relhassubclass}: that flag is a hint,
   * PostgreSQL does not clear it when the last child is dropped, and a refusal an operator cannot
   * clear by fixing the database is a refusal that teaches people to set the weaker property.
   *
   * <p>Both directions. A child of ours is the attack; a table of ours that is itself a child is
   * the mirror case, costs one more row in the same query, and nothing legitimate produces it.
   */
  private static void checkInheritance(
      Connection c, Map<String, Relation> relations, List<String> guards) throws SQLException {
    if (relations.isEmpty()) {
      return;
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT parent.relname, child.relname,"
                + " parent.relnamespace = current_schema()::regnamespace"
                + " FROM pg_inherits i"
                + " JOIN pg_class parent ON parent.oid = i.inhparent"
                + " JOIN pg_class child ON child.oid = i.inhrelid"
                + " WHERE (parent.relnamespace = current_schema()::regnamespace"
                + "        AND parent.relname = ANY(?))"
                + "    OR (child.relnamespace = current_schema()::regnamespace"
                + "        AND child.relname = ANY(?))")) {
      var names = c.createArrayOf("text", SchemaExpectations.TABLES.toArray());
      ps.setArray(1, names);
      ps.setArray(2, names);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String parent = rs.getString(1);
          String child = rs.getString(2);
          if (relations.containsKey(parent)) {
            guards.add(
                parent
                    + " has an inheritance child, "
                    + child
                    + ". A child carries none of the parent's triggers, its rows are returned by"
                    + " every read of "
                    + parent
                    + " - this module's own reads and the chain verifier included - and a DELETE"
                    + " against "
                    + parent
                    + " removes them with no guard firing. Drop the child, as the owner.");
          } else {
            guards.add(
                child
                    + " inherits from "
                    + parent
                    + ". This module's tables inherit from nothing; a parent decides what a read of"
                    + " this relation returns. Drop the inheritance, as the owner.");
          }
        }
      }
    }
  }

  private static void checkRulesAndPolicies(
      Connection c, Map<String, Relation> relations, List<String> guards) throws SQLException {
    for (Relation r : relations.values()) {
      if (r.hasRules()) {
        guards.add(
            r.name()
                + " carries a rewrite rule (pg_class.relhasrules). A DO INSTEAD rule rewrites the"
                + " statement before any trigger sees it, so an append can be sent elsewhere or"
                + " dropped while every trigger is present and enabled.");
      }
      if (r.rowSecurity() || r.forceRowSecurity()) {
        guards.add(
            r.name()
                + " has row-level security enabled (relrowsecurity="
                + r.rowSecurity()
                + ", relforcerowsecurity="
                + r.forceRowSecurity()
                + "). A policy that hides the erasure tombstone makes the mint-time erased check"
                + " and isErased answer \"not erased\", which defeats control 11 silently.");
      }
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, count(pol.oid) FROM pg_class c"
                + " LEFT JOIN pg_policy pol ON pol.polrelid = c.oid"
                + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY(?)"
                + " GROUP BY c.relname")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          if (rs.getLong(2) > 0) {
            guards.add(
                rs.getString(1)
                    + " has "
                    + rs.getLong(2)
                    + " row-level-security policy(ies). A policy created while RLS is disabled"
                    + " leaves relrowsecurity false and sits armed: one ALTER TABLE ... ENABLE ROW"
                    + " LEVEL SECURITY by the owner turns it on, so the two booleans alone do not"
                    + " cover it.");
          }
        }
      }
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, count(r.oid) FROM pg_class c"
                + " LEFT JOIN pg_rewrite r ON r.ev_class = c.oid"
                + " WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY(?)"
                + " GROUP BY c.relname")) {
      ps.setArray(1, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          if (rs.getLong(2) > 0 && !relations.get(rs.getString(1)).hasRules()) {
            guards.add(rs.getString(1) + " has " + rs.getLong(2) + " pg_rewrite entry(ies)");
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------- the role

  private static void checkRole(
      Connection c,
      Session session,
      Map<String, Relation> relations,
      Map<String, Relation> indexes,
      Map<String, Function> functions,
      List<String> excess,
      List<String> missing)
      throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT current_setting('is_superuser'),"
                    + " has_schema_privilege(current_user, current_schema(), 'CREATE'),"
                    + " has_schema_privilege(current_user, current_schema(), 'USAGE'),"
                    + " has_database_privilege(current_user, current_database(), 'TEMP'),"
                    + " has_database_privilege(current_user, current_database(), 'CREATE'),"
                    + " pg_has_role(current_user, (SELECT datdba FROM pg_database"
                    + "   WHERE datname = current_database()), 'MEMBER')");
        ResultSet rs = ps.executeQuery()) {
      rs.next();
      if ("on".equalsIgnoreCase(rs.getString(1))) {
        excess.add("is a superuser");
      }
      if (rs.getBoolean(2)) {
        excess.add("holds CREATE on schema " + session.schema());
      }
      if (!rs.getBoolean(3)) {
        missing.add("USAGE on schema " + session.schema());
      }
      if (rs.getBoolean(4)) {
        excess.add("holds TEMPORARY on database " + session.database());
      }
      if (rs.getBoolean(5)) {
        excess.add("holds CREATE on database " + session.database());
      }
      if (rs.getBoolean(6)) {
        excess.add("is, or is a member of, the owner of database " + session.database());
      }
    }
    relations.values().stream()
        .filter(Relation::ownedByRole)
        .forEach(r -> excess.add("owns table " + r.name()));
    indexes.values().stream()
        .filter(Relation::ownedByRole)
        .forEach(r -> excess.add("owns index " + r.name()));
    functions.values().stream()
        .filter(Function::ownedByRole)
        .forEach(f -> excess.add("owns guard function " + f.name()));
    checkSequenceOwnerAndPrivileges(c, excess, missing);
    checkTablePrivileges(c, relations, excess, missing);
  }

  private static void checkSequenceOwnerAndPrivileges(
      Connection c, List<String> excess, List<String> missing) throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT pg_has_role(current_user, s.relowner, 'MEMBER'),"
                + " has_sequence_privilege(current_user, s.oid, 'USAGE'),"
                + " has_sequence_privilege(current_user, s.oid, 'SELECT'),"
                + " has_sequence_privilege(current_user, s.oid, 'UPDATE')"
                + " FROM pg_class s"
                + " WHERE s.relnamespace = current_schema()::regnamespace AND s.relname = ?")) {
      ps.setString(1, SchemaExpectations.SEQUENCE);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          return;
        }
        if (rs.getBoolean(1)) {
          excess.add("owns sequence " + SchemaExpectations.SEQUENCE);
        }
        if (!rs.getBoolean(2)) {
          missing.add("USAGE on sequence " + SchemaExpectations.SEQUENCE);
        }
        if (rs.getBoolean(3)) {
          excess.add("holds SELECT on sequence " + SchemaExpectations.SEQUENCE);
        }
        if (rs.getBoolean(4)) {
          excess.add(
              "holds UPDATE on sequence "
                  + SchemaExpectations.SEQUENCE
                  + " (setval can rewind the erasure log's seq)");
        }
      }
    }
  }

  private static void checkTablePrivileges(
      Connection c, Map<String, Relation> relations, List<String> excess, List<String> missing)
      throws SQLException {
    for (TablePrivileges want : SchemaExpectations.PRIVILEGES) {
      Relation relation = relations.get(want.table());
      if (relation == null) {
        continue;
      }
      for (String privilege : want.required()) {
        if (!hasTablePrivilege(c, relation.oid(), privilege)) {
          missing.add(privilege + " on " + want.table());
        }
      }
      for (String privilege : want.refused()) {
        if (hasTablePrivilege(c, relation.oid(), privilege)) {
          excess.add("holds " + privilege + " on " + want.table());
        }
      }
      checkColumnUpdate(c, relation, want, excess, missing);
    }
  }

  /**
   * {@code has_table_privilege} is table level only: a column grant does not make it true. The two
   * functions together separate the one legitimate column grant per table from an over-grant, which
   * version 1's uniform "no DELETE or TRUNCATE" could not do.
   */
  private static void checkColumnUpdate(
      Connection c,
      Relation relation,
      TablePrivileges want,
      List<String> excess,
      List<String> missing)
      throws SQLException {
    if (want.required().contains("UPDATE")) {
      return;
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT a.attname, has_column_privilege(current_user, a.attrelid, a.attnum, 'UPDATE')"
                + " FROM pg_attribute a"
                + " WHERE a.attrelid = ? AND a.attnum > 0 AND NOT a.attisdropped")) {
      ps.setLong(1, relation.oid());
      try (ResultSet rs = ps.executeQuery()) {
        boolean sawRequired = false;
        while (rs.next()) {
          String column = rs.getString(1);
          boolean held = rs.getBoolean(2);
          boolean allowed = column.equals(want.updatableColumn());
          if (held && !allowed) {
            excess.add("holds UPDATE on " + want.table() + "." + column);
          }
          if (allowed) {
            sawRequired = held;
          }
        }
        if (want.updatableColumn() != null && !sawRequired) {
          missing.add("UPDATE (" + want.updatableColumn() + ") on " + want.table());
        }
      }
    }
  }

  private static boolean hasTablePrivilege(Connection c, long oid, String privilege)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement("SELECT has_table_privilege(current_user, ?::oid, ?)")) {
      ps.setLong(1, oid);
      ps.setString(2, privilege);
      try (ResultSet rs = ps.executeQuery()) {
        rs.next();
        return rs.getBoolean(1);
      }
    }
  }

  // ---------------------------------------------------------------- refusals

  private static ShreddingException refusal(
      String code, List<String> problems, Session session, List<String> remedies) {
    Set<String> unique = new LinkedHashSet<>(problems);
    return new ShreddingException(
        code,
        "shredding: the schema in "
            + session.schema()
            + " of database "
            + session.database()
            + ", as role "
            + session.role()
            + ", is not one this module will write to. "
            + unique.size()
            + " problem(s), all of them listed so they can be fixed in one round:"
            + unique.stream().map(p -> "\n  - " + p).reduce("", String::concat)
            + "\n"
            + String.join("\n", remedies));
  }

  private static ShreddingException absent(Session session) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_ABSENT,
        "shredding: none of this module's tables exist in schema "
            + session.schema()
            + " of database "
            + session.database()
            + " (as role "
            + session.role()
            + "), and this module does not create them with the application's own credentials."
            + " A role that can run this DDL owns the erasure tables and the guard functions, and"
            + " an owner can ALTER TABLE ... DISABLE TRIGGER or CREATE OR REPLACE a guard into a"
            + " no-op, so the append-only erasure log (control 8) would hold in no configuration"
            + " you could actually run. Apply"
            + " com/housedevinci/shredding/schema-postgresql.sql from the gdpr-shredding-core jar"
            + " once, with a privileged role, then grant this role the statements in"
            + " SECURITY-NOTES.md \"Database roles\". For a local trial only, set"
            + " shredding.jdbc.initialize-schema=true, which runs that script with these"
            + " credentials and warns at every startup. See docs/upgrading-0.2.0.md.");
  }

  private static String incompleteRemedy() {
    return "Re-apply com/housedevinci/shredding/schema-postgresql.sql as the owner role; it is"
        + " idempotent and adds no column. If the tables were hand-written from the README, drop"
        + " them and let the script create them. See docs/upgrading-0.2.0.md.";
  }

  private static String unguardedRemedy() {
    return "Until these are fixed, the erasure log and the erasure tombstone are ordinary tables:"
        + " control 8 and control 11 do not hold. Re-apply"
        + " com/housedevinci/shredding/schema-postgresql.sql as the owner role - from 0.2.0 it"
        + " restores the guard bodies and sets all seven triggers to ENABLE ALWAYS. A rule, a"
        + " policy or an extra trigger has to be dropped by hand, by the owner. See"
        + " docs/upgrading-0.2.0.md.";
  }

  private static String privilegedRemedy() {
    return "A privilege can be held directly, through a group role, through a predefined role such"
        + " as pg_write_all_data, or through PUBLIC, so an empty grep of your grant scripts proves"
        + " nothing: check with has_table_privilege('<role>', '<table>', '<privilege>'). Move"
        + " ownership with ALTER TABLE ... OWNER TO and ALTER FUNCTION ... OWNER TO (the functions"
        + " do not move with the tables), REVOKE what is not in the \"Database roles\" block of"
        + " SECURITY-NOTES.md, and point spring.datasource.username at the runtime role. Step by"
        + " step: docs/upgrading-0.2.0.md. To boot anyway and accept that the append-only controls"
        + " are advisory in this configuration, set"
        + " shredding.jdbc.allow-privileged-runtime-role=true, which warns at every startup.";
  }

  private static String underprivilegedRemedy() {
    return "These are privileges the adapters need; without them the first erasure fails, so boot"
        + " is a better place to learn it. They can be held directly, through a group or predefined"
        + " role, or through PUBLIC. Apply the \"Database roles\" block of SECURITY-NOTES.md in"
        + " full. shredding.jdbc.allow-privileged-runtime-role=true does not suppress this: an"
        + " application that cannot write the erasure log is broken, not differently configured.";
  }

  private static ShreddingException unverifiable(SQLException cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_UNVERIFIABLE,
        "shredding: the schema could not be verified (SQLState "
            + cause.getSQLState()
            + "). Unverifiable is not clean, so this is a refusal rather than a warning. Two"
            + " explanations are common. One: a catalogue read was refused - this module reads"
            + " pg_class, pg_attribute, pg_constraint, pg_proc, pg_trigger, pg_rewrite, pg_policy"
            + " and pg_depend, and an estate that has REVOKEd SELECT on any of them from PUBLIC"
            + " must grant it to this role. Two: a schema migration is in flight - the schema step"
            + " holds an advisory lock for its whole transaction and PostgreSQL DDL is"
            + " transactional, so a verification that runs beside it sees the pre-migration state;"
            + " restart after the migration commits. The driver's own message is not repeated here"
            + " because it can carry a bind value.",
        cause);
  }
}
