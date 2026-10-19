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
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;

/**
 * Reads the PostgreSQL catalogue and decides whether the schema in {@code current_schema()} still
 * carries the guards this module's controls rest on, and whether the role that is about to write to
 * it is privileged enough to remove them.
 *
 * <p>Design §4 of {@code no-ddl-at-runtime-design.md}, version 2.3. One connection, one read-only
 * REPEATABLE READ transaction, catalogue reads only, no DDL and no writes of any kind. Every leg
 * runs before anything is thrown, so a partial schema is reported in one message rather than one
 * object per restart.
 *
 * <p><b>Nothing this class asks is asked through a name the verified role can resolve</b> (design
 * §4.9, findings C-13-9 and C-13-10). A function name resolves along {@code search_path} exactly as
 * a relation name does, any role may {@code ALTER ROLE <itself> SET search_path}, and the ordinary
 * runtime role owns a schema it may create functions in - so a {@code pg_has_role} or a {@code
 * format_type} written bare is a predicate the subject of the check supplies the answer to. Two
 * halves, neither sufficient alone: the transaction pins {@code search_path} to {@code pg_catalog,
 * pg_temp} for its own duration and reads the pin back, and every catalogue function, catalogue
 * relation, operator, type and cast is written with its {@code pg_catalog.} prefix anyway. Because
 * the path is pinned, the module's own schema can no longer be named by {@code current_schema()}:
 * it is captured once, before the pin, and bound into every later query as the namespace oid.
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
   * The one pinned value in this module, shared with every other place a path is replaced (§6).
   * {@code pg_temp} is named because the implicit {@code pg_temp} precedes the path for
   * <em>relation</em> references, so a role holding {@code TEMPORARY} can put a {@code pg_class} of
   * its own in front of the real catalogue; naming it explicitly is the only way to demote it.
   * Every catalogue relation here is qualified as well, so this changes no answer today - it
   * removes the question for the next line.
   */
  /**
   * The same constant the one-statement window of {@link JdbcSupport#inOneStatementWindow} uses:
   * one pinned value in this module, not two (design section 6).
   */
  private static final String PINNED_PATH = JdbcSupport.PINNED_PATH;

  /**
   * Verifies in <b>one read-only transaction of its own</b> (C-13-4). Without this the eleven
   * catalogue reads take eleven snapshots, so "schema verified" is a claim about no single instant
   * of the database, and nothing on the server side refuses a write from a connection whose whole
   * contract is "catalogue reads only" - the rule would be enforced by review alone. The connection
   * is rolled back and auto-commit restored whatever happens.
   *
   * <p>Read-only and the level are set with SQL, as the transaction's first statement, never with
   * {@code Connection.setReadOnly} or {@code setTransactionIsolation} (C-PR-1b, round 2, item 1): a
   * read/write-splitting driver moves to a replica when it sees {@code setReadOnly(true)}, and a
   * {@code SET TRANSACTION} covers this transaction only, so the session's own settings are never
   * touched and there is nothing else to restore.
   *
   * <p>The pin of §4.9 is transaction-local, so the {@code rollback()} in {@link #restore} undoes
   * it and the connection goes back to the pool with the {@code search_path} it arrived with.
   *
   * @param allowPrivilegedRuntimeRole when true, the {@code 004} legs become the verdict's {@link
   *     SchemaVerdict#privilegeLegs()} for the caller to warn about, instead of a refusal. {@code
   *     007} is never downgraded.
   */
  static SchemaVerdict verify(
      Connection connection, DataSource dataSource, boolean allowPrivilegedRuntimeRole) {
    return verify(connection, dataSource, allowPrivilegedRuntimeRole, List.of());
  }

  /**
   * As {@link #verify(Connection, DataSource, boolean)}, with the operator's accepted third-party
   * extensions (C-PR45-3, rule R5b (ii)); already normalised by {@link AcceptedExtensions}.
   */
  static SchemaVerdict verify(
      Connection connection,
      DataSource dataSource,
      boolean allowPrivilegedRuntimeRole,
      List<String> acceptedExtensions) {
    boolean previousAutoCommit;
    try {
      previousAutoCommit = connection.getAutoCommit();
      connection.setAutoCommit(false);
    } catch (SQLException e) {
      throw unverifiable(e);
    }
    try {
      try (Statement st = connection.createStatement()) {
        st.execute(BEGIN_SQL);
      }
      return run(connection, dataSource, allowPrivilegedRuntimeRole, acceptedExtensions);
    } catch (SQLException e) {
      throw unverifiable(e);
    } finally {
      restore(connection, previousAutoCommit);
    }
  }

  /** The verification transaction's first statement: one snapshot, refused any write. */
  static final String BEGIN_SQL = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY";

  /**
   * Verifies inside a transaction the caller already opened, changing no connection setting. The
   * creation path is the only caller: it has just run the bundled script in this very transaction,
   * under the script's advisory lock, so it is neither read-only nor a fresh snapshot and must not
   * be made either.
   *
   * <p>The §4.9 pin is issued here too, and is still transaction-local: the caller commits
   * immediately after this returns, which ends the pin. {@code set_config} with {@code is_local =
   * true} silently does nothing outside a transaction block, which is why the pin is read back - a
   * caller that handed us an auto-commit connection gets {@code SHRED-SCHEMA-005} rather than
   * eleven legs that are qualified in text and unqualified in substance.
   */
  static SchemaVerdict verifyInCallersTransaction(
      Connection connection, DataSource dataSource, boolean allowPrivilegedRuntimeRole) {
    return verifyInCallersTransaction(
        connection, dataSource, allowPrivilegedRuntimeRole, List.of());
  }

  /** As above, with the accepted third-party extensions (C-PR45-3). */
  static SchemaVerdict verifyInCallersTransaction(
      Connection connection,
      DataSource dataSource,
      boolean allowPrivilegedRuntimeRole,
      List<String> acceptedExtensions) {
    try {
      return run(connection, dataSource, allowPrivilegedRuntimeRole, acceptedExtensions);
    } catch (SQLException e) {
      throw unverifiable(e);
    }
  }

  private static void restore(Connection c, boolean autoCommit) {
    try {
      c.rollback();
      c.setAutoCommit(autoCommit);
    } catch (SQLException ignored) {
      // The connection is about to be closed or returned to a pool that discards a broken one. A
      // failure to put settings back is never a reason to turn a clean verification into a refusal,
      // or a refusal into something else.
    }
  }

  /**
   * @param dataSource the object {@code c} was taken from. It is bound into the {@link
   *     VerifiedSchema} (C-PR-1), so a store can only write through the pool that was verified.
   */
  private static SchemaVerdict run(
      Connection c, DataSource dataSource, boolean allowPrivileged, List<String> accepted)
      throws SQLException {
    // §4.9, in this order and before any leg: capture the session facts through qualified names,
    // pin the path so a name somebody forgets to prefix later still resolves in pg_catalog, and
    // read the pin back because set_config echoes its own argument whether or not it took.
    SessionFacts facts = sessionFacts(c);
    pinSearchPath(c);
    long schemaOid = namespaceOid(c, facts);
    // C-PR-1c: the login and its reach first, so a login that cannot be judged (revoked
    // function, a login role dropped while connected) is reported as such before anything else.
    Reach reach = reach(c, facts, loginOid(c, facts));
    DatabaseIdentity.Facts reached = identity(c, facts, schemaOid);
    Session session =
        new Session(
            facts,
            dataSource,
            schemaOid,
            reached.withLogin(reach.loginOid(), reach.login()),
            reach);
    VerifiedSchema schema = session.schema();
    long ns = session.schemaOid();

    long login = session.reach().loginOid();
    Map<String, Relation> relations = relations(c, ns, login);
    List<String> missing =
        SchemaExpectations.TABLES.stream().filter(t -> !relations.containsKey(t)).toList();
    if (missing.size() == SchemaExpectations.TABLES.size()) {
      throw absent(session);
    }

    var shape = new ArrayList<String>();
    var guards = new ArrayList<String>();
    missing.forEach(t -> shape.add("table " + t + " does not exist"));

    checkRelationShape(relations, shape, guards);
    checkColumns(c, ns, relations, shape);
    checkSequence(c, ns, relations, shape);
    checkConstraints(c, ns, relations, shape);

    Map<String, Function> functions = functions(c, ns, login);
    checkGuardFunctions(functions, guards);
    checkTriggers(c, ns, relations, functions, guards);
    checkRulesAndPolicies(c, ns, relations, guards);
    checkInheritance(c, ns, relations, guards);

    List<String> indexWarnings = new ArrayList<>();
    Map<String, Relation> indexes = indexes(c, ns, login);
    SchemaExpectations.INDEXES.stream()
        .filter(i -> !indexes.containsKey(i))
        .forEach(
            i ->
                indexWarnings.add(
                    i + " (a subject lookup on the erasure log or the key table is a full scan)"));

    var excess = new ArrayList<String>();
    var underprivileged = new ArrayList<String>();
    checkRole(c, session, relations, indexes, functions, accepted, excess, underprivileged);
    var legs = List.copyOf(new LinkedHashSet<>(excess));
    excess.clear();
    excess.addAll(legs);

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

  private record SessionFacts(String schema, String role, String database) {}

  private record Session(
      VerifiedSchema schema, long schemaOid, String role, String database, Reach reach) {
    Session(
        SessionFacts facts,
        DataSource dataSource,
        long schemaOid,
        DatabaseIdentity identity,
        Reach reach) {
      this(
          new VerifiedSchema(facts.schema(), dataSource, identity),
          schemaOid,
          facts.role(),
          facts.database(),
          reach);
    }

    /** "shredding_app", or "shredding_app (login role gateway)" when the two differ. */
    String described() {
      return reach.login().equals(role) ? role : role + " (login role " + reach.login() + ")";
    }
  }

  /**
   * C-PR-1b: what this connection reaches, read with the fingerprint every store connection runs
   * later, in this transaction, under the pin. Three refusals, each {@code SHRED-SCHEMA-005}:
   * {@code pg_control_system()} denied to this role, with the grant that fixes it (there is no
   * fallback, round 2, item 6); a server in recovery, which can pass every catalogue leg while
   * every store call would be refused; and a fingerprint that does not return exactly one row.
   */
  private static DatabaseIdentity.Facts identity(Connection c, SessionFacts facts, long schemaOid)
      throws SQLException {
    DatabaseIdentity.Observed observed;
    try {
      observed = DatabaseIdentity.read(c, facts.schema(), false);
    } catch (SQLException e) {
      if ("42501".equals(e.getSQLState())) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "shredding: the runtime role cannot execute pg_catalog.pg_control_system() (SQLState"
                + " 42501), so the cluster this connection reaches cannot be identified, and no"
                + " store connection could later be checked against it (C-PR-1b). Unverifiable is"
                + " not clean, so this is a refusal. As a superuser, run: GRANT EXECUTE ON"
                + " FUNCTION pg_catalog.pg_control_system() TO "
                + roleIdentifier(facts.role())
                + ". PostgreSQL grants it to PUBLIC by default.",
            e);
      }
      throw e;
    }
    if (observed.inRecovery()) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the database this connection reaches is in recovery (a standby or read"
              + " replica). It can lag the primary and serve a data key the primary has already"
              + " destroyed, and it cannot be written to, so the module does not verify it. Point"
              + " the module's DataSource at the primary.");
    }
    if (observed.rows() != 1 || observed.facts().orElseThrow().schemaOid() != schemaOid) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the database this connection reaches could not be identified: the"
              + " fingerprint returned "
              + observed.rows()
              + " rows where exactly one is required, or another schema than the one just"
              + " verified. Unverifiable is not clean.");
    }
    return observed.facts().orElseThrow();
  }

  // ---------------------------------------------------------------- the login role and its reach

  /**
   * A role the login role can become (C-PR-1c): the login role itself, and every role it is a
   * member of, directly or through other roles, with or without INHERIT, SET or ADMIN. {@code
   * 'MEMBER'} is required, not only tolerated: a grant {@code WITH ADMIN TRUE, INHERIT FALSE, SET
   * FALSE} passes {@code 'SET'} and {@code 'USAGE'}, and its holder can grant itself SET (design
   * round 2, item 2).
   *
   * @param serverRole one of {@link SchemaExpectations#SERVER_ROLES}, resolved to oids in SQL
   */
  record ReachRole(
      long oid, String name, boolean superuser, boolean createRole, boolean serverRole) {}

  /**
   * The login role and its reach. {@code current} is the role statements run as; it is always in
   * the reach of a login that is not a superuser.
   */
  record Reach(long loginOid, String login, String current, List<ReachRole> roles) {

    long[] oids() {
      return roles.stream().mapToLong(ReachRole::oid).toArray();
    }

    /**
     * Who a leg fired for, for a message that already names the role: "login role X" or "role R,
     * reachable from login role X,". {@code 0} is PUBLIC.
     */
    String named(long oid) {
      if (oid == 0) {
        return "PUBLIC";
      }
      String name = name(oid);
      return name.equals(login)
          ? "login role " + login
          : "role " + name + ", reachable from login role " + login + ",";
    }

    /**
     * As {@link #named}, but empty for the current role, so a grant to the runtime role itself
     * keeps the text it always had ("holds UPDATE on shredding_erasure").
     */
    String holder(long oid) {
      if (oid != 0 && name(oid).equals(current)) {
        return "";
      }
      return named(oid) + " ";
    }

    String name(long oid) {
      return roles.stream()
          .filter(r -> r.oid() == oid)
          .map(ReachRole::name)
          .findFirst()
          .orElse("oid " + oid);
    }

    /** The prefix of an ownership leg: empty when the login is the current role. */
    String owner() {
      return login.equals(current) ? "" : "login role " + login + " ";
    }
  }

  /**
   * C-PR-1c: the role this connection authenticated as, read from the backend's own activity entry.
   * Zero rows, a NULL, or any {@link SQLException} is {@code SHRED-SCHEMA-005}: a check that cannot
   * see the login cannot judge it, and there is no fallback to {@code session_user}, which a
   * superuser login moves (design section 4, R2.2 item 1).
   */
  private static long loginOid(Connection c, SessionFacts facts) {
    try (PreparedStatement ps = c.prepareStatement(LOGIN_SQL);
        ResultSet rs = ps.executeQuery()) {
      long oid = rs.next() ? rs.getLong(1) : 0L;
      if (oid == 0) {
        throw loginUnreadable(facts, "the backend's activity entry returned no login role", null);
      }
      return oid;
    } catch (SQLException e) {
      throw loginUnreadable(facts, "SQLState " + e.getSQLState(), e);
    }
  }

  /**
   * The login role: the backend's own activity entry, written once when the connection
   * authenticated. {@code SET ROLE}, {@code SET SESSION AUTHORIZATION} and {@code track_activities
   * = off} leave {@code usesysid} as it was (design section 2).
   */
  private static final String LOGIN_SQL =
      "SELECT a.usesysid FROM pg_catalog.pg_stat_get_activity(pg_catalog.pg_backend_pid()) a";

  private static final String REACH_SQL =
      "SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole,"
          + " ((r.oid OPERATOR(pg_catalog.=)"
          + " 'pg_execute_server_program'::pg_catalog.regrole::pg_catalog.oid)"
          + " OR (r.oid OPERATOR(pg_catalog.=)"
          + " 'pg_write_server_files'::pg_catalog.regrole::pg_catalog.oid)"
          + " OR (r.oid OPERATOR(pg_catalog.=)"
          + " 'pg_read_server_files'::pg_catalog.regrole::pg_catalog.oid))"
          + " FROM pg_catalog.pg_roles r"
          + " WHERE pg_catalog.pg_has_role(?::pg_catalog.oid, r.oid, 'MEMBER')"
          + " ORDER BY r.rolname";

  /** One statement, bound to the login oid. The login role is in its own result. */
  private static Reach reach(Connection c, SessionFacts facts, long loginOid) {
    var roles = new ArrayList<ReachRole>();
    try (PreparedStatement ps = c.prepareStatement(REACH_SQL)) {
      ps.setLong(1, loginOid);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          roles.add(
              new ReachRole(
                  rs.getLong(1),
                  rs.getString(2),
                  rs.getBoolean(3),
                  rs.getBoolean(4),
                  rs.getBoolean(5)));
        }
      }
    } catch (SQLException e) {
      throw loginUnreadable(facts, "SQLState " + e.getSQLState(), e);
    }
    ReachRole login =
        roles.stream()
            .filter(r -> r.oid() == loginOid)
            .findFirst()
            .orElseThrow(
                () -> loginUnreadable(facts, "the login role is not in the role catalogue", null));
    // A superuser login reaches every role (SET SESSION AUTHORIZATION), and "login role X is a
    // superuser" says all there is to say: the other legs would list every role of the cluster.
    var judged = login.superuser() ? List.of(login) : List.copyOf(roles);
    return new Reach(loginOid, login.name(), facts.role(), judged);
  }

  private static ShreddingException loginUnreadable(
      SessionFacts facts, String why, SQLException cause) {
    String message =
        "shredding: the login role of this connection could not be read ("
            + why
            + "). The schema check judges the role the connection logged in as, and every role"
            + " that login can become, read from pg_catalog.pg_stat_get_activity(pg_backend_pid())"
            + " and pg_catalog.pg_roles (C-PR-1c). Unverifiable is not clean, so this is a"
            + " refusal. PostgreSQL grants EXECUTE on that function to PUBLIC by default; if it was"
            + " revoked, run as a superuser: GRANT EXECUTE ON FUNCTION"
            + " pg_catalog.pg_stat_get_activity(integer) TO "
            + roleIdentifier(facts.role())
            + ". If the login role was dropped while this connection was open, reconnect.";
    return cause == null
        ? new ShreddingException(ErrorCodes.SCHEMA_UNVERIFIABLE, message)
        : new ShreddingException(ErrorCodes.SCHEMA_UNVERIFIABLE, message, cause);
  }

  /** The role as an SQL identifier for a printed statement: bare when it is plain lower case. */
  private static String roleIdentifier(String role) {
    String escaped = com.housedevinci.shredding.application.LogText.escape(role);
    return role.matches("[a-z_][a-z0-9_$]*")
        ? escaped
        : "\"" + escaped.replace("\"", "\"\"") + "\"";
  }

  /**
   * Statement 1 of the transaction, and it contains <b>no operator name at all</b> (C-13-13). It
   * necessarily runs before the pin, because after the pin {@code current_schema()} answers {@code
   * pg_catalog} - right for resolving catalogue names, wrong for naming this module's tables - so
   * the schema has to be read first and carried as an oid afterwards. Version 1 read the name and
   * the oid in one statement, which put {@code n.nspname = pg_catalog.current_schema()} on the
   * unpinned side: a role that owns a schema ahead of {@code pg_catalog} defines its own {@code
   * =(name, name)} there and splits the two, so the gate verifies one schema while {@link
   * VerifiedSchema#qualify} sends every write to another. The split is into three statements -
   * facts, pin, oid - so the only comparison is on the pinned side (§6).
   *
   * <p>{@code current_user} is a keyword, not a function, and cannot be shadowed.
   */
  private static SessionFacts sessionFacts(Connection c) throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT pg_catalog.current_schema(), current_user,"
                    + " pg_catalog.current_database()");
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
      return new SessionFacts(rs.getString(1), rs.getString(2), rs.getString(3));
    }
  }

  /**
   * Statement 4, the first leg that runs under the pin: the namespace oid every later leg binds.
   * The schema name is a <b>bind parameter</b> carrying the bytes statement 1 read, and the
   * comparison is qualified as well, so neither half depends on the role's path.
   *
   * <p>The oid comes from an exact {@code nspname} match rather than from {@code
   * '<name>'::regnamespace}: {@code regnamespacein} parses its argument as an SQL identifier, so a
   * schema called {@code my schema} or {@code Public} - which {@link VerifiedSchema} deliberately
   * supports - would turn every leg into {@code SHRED-SCHEMA-005}.
   */
  private static long namespaceOid(Connection c, SessionFacts facts) throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT n.oid FROM pg_catalog.pg_namespace n"
                + " WHERE n.nspname OPERATOR(pg_catalog.=) ?")) {
      ps.setString(1, facts.schema());
      try (ResultSet rs = ps.executeQuery()) {
        long oid = rs.next() ? rs.getLong(1) : 0L;
        if (oid == 0) {
          throw new ShreddingException(
              ErrorCodes.SCHEMA_UNVERIFIABLE,
              "current_schema() answered "
                  + facts.schema()
                  + " but no pg_namespace row carries that name, so the schema this module's"
                  + " statements resolve against cannot be identified and nothing about it can be"
                  + " verified. Unverifiable is not clean.");
        }
        return oid;
      }
    }
  }

  /**
   * Statements 2 and 3 of the transaction. The pin is {@code is_local = true}, so it ends with the
   * transaction and cannot follow a pooled connection out of verification. It is total over
   * function, aggregate and operator names; over relation names it is total only because it names
   * {@code pg_temp} explicitly, and every relation here stays explicitly qualified as well.
   *
   * <p>The read-back is the pin's own backstop and is compared against the literal {@code
   * pg_catalog}, never against the value just sent: {@code set_config} returns its own argument
   * whether or not the setting took, and outside a transaction block a local {@code set_config}
   * takes no effect, raises nothing, and leaves every later leg qualified in text and unqualified
   * in substance.
   *
   * <p>The same statement turns JIT off for the transaction (C-PR45-3-18): the function-grants
   * statements read every row of {@code pg_proc}, and JIT compiling them costs more than it saves.
   * It changes speed only, never a row, and is local like the pin, so it ends at commit or
   * rollback.
   */
  private static void pinSearchPath(Connection c) throws SQLException {
    try (PreparedStatement ps =
            c.prepareStatement(
                "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true),"
                    + " pg_catalog.set_config('jit', 'off', true)");
        ResultSet rs = ps.executeQuery()) {
      rs.next();
    }
    try (PreparedStatement ps =
            c.prepareStatement("SELECT pg_catalog.current_setting('search_path')");
        ResultSet rs = ps.executeQuery()) {
      String pinned = rs.next() ? rs.getString(1) : null;
      if (!PINNED_PATH.equals(pinned)) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "shredding: the verification transaction could not pin its own search_path to"
                + " '"
                + PINNED_PATH
                + "' (it reads back as "
                + pinned
                + "). Every catalogue function this check calls is also written with a pg_catalog."
                + " prefix, but the pin is the backstop for the one call a later edit forgets, and"
                + " a verification running without it is not the verification this module"
                + " documents. The usual cause is a connection that is not inside a transaction"
                + " block: a transaction-local set_config is silently ignored there. Unverifiable"
                + " is not clean, so this is a refusal rather than a warning.");
      }
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

  /**
   * The two relation statements are constants, one per call site, rather than a {@code String}
   * parameter of the shared reader. Design §3.5.1, as the security review ruled it: a gate that
   * resolves a statement built in another method needs a parameter hop, a hop that exists grows to
   * two, and two constants in the source are less untested code inside a control than a resolver
   * is. The shared reader takes the {@link PreparedStatement}, so the statement text is a literal
   * at the call that prepares it.
   */
  private static final String RELATIONS_SQL =
      "SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relhasrules, c.relrowsecurity,"
          + " c.relforcerowsecurity,"
          + " pg_catalog.pg_has_role(?::pg_catalog.oid, c.relowner, 'MEMBER')"
          + " FROM pg_catalog.pg_class c"
          + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
          + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))";

  private static final String INDEXES_SQL =
      "SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relhasrules, c.relrowsecurity,"
          + " c.relforcerowsecurity,"
          + " pg_catalog.pg_has_role(?::pg_catalog.oid, c.relowner, 'MEMBER')"
          + " FROM pg_catalog.pg_class c"
          + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
          + " AND (c.relkind OPERATOR(pg_catalog.=) 'i')"
          + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))";

  /**
   * {@code ownedByRole} asks about the <b>login role</b>, bound as an oid (C-PR-1c). {@code
   * pg_has_role(.., 'MEMBER')} is transitive and the current role is always in the login's reach,
   * so one check on the login covers every role the connection can become.
   */
  private static Map<String, Relation> relations(Connection c, long ns, long login)
      throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(RELATIONS_SQL)) {
      return relations(c, ps, ns, login, SchemaExpectations.TABLES);
    }
  }

  private static Map<String, Relation> indexes(Connection c, long ns, long login)
      throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(INDEXES_SQL)) {
      return relations(c, ps, ns, login, SchemaExpectations.INDEXES);
    }
  }

  private static Map<String, Relation> relations(
      Connection c, PreparedStatement ps, long ns, long login, List<String> names)
      throws SQLException {
    var found = new LinkedHashMap<String, Relation>();
    ps.setLong(1, login);
    ps.setLong(2, ns);
    ps.setArray(3, c.createArrayOf("text", names.toArray()));
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
      Connection c, long ns, Map<String, Relation> relations, List<String> shape)
      throws SQLException {
    var actual = new LinkedHashMap<String, List<Column>>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, a.attname, a.attnotnull,"
                + " pg_catalog.format_type(a.atttypid, a.atttypmod)"
                + " FROM pg_catalog.pg_class c"
                + " JOIN pg_catalog.pg_attribute a"
                + "   ON (a.attrelid OPERATOR(pg_catalog.=) c.oid)"
                + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))"
                + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped"
                + " ORDER BY c.relname, a.attnum")) {
      ps.setLong(1, ns);
      ps.setArray(2, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
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
      Connection c, long ns, Map<String, Relation> relations, List<String> shape)
      throws SQLException {
    if (!relations.containsKey(SchemaExpectations.ERASURE)) {
      return;
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT s.relkind, (SELECT pg_catalog.count(*) FROM pg_catalog.pg_depend d"
                + "   WHERE (d.classid OPERATOR(pg_catalog.=)"
                + "            'pg_catalog.pg_class'::pg_catalog.regclass)"
                + "     AND (d.objid OPERATOR(pg_catalog.=) s.oid)"
                + "     AND (d.refclassid OPERATOR(pg_catalog.=)"
                + "            'pg_catalog.pg_class'::pg_catalog.regclass)"
                + "     AND (d.refobjid OPERATOR(pg_catalog.=) t.oid)"
                + "     AND (d.refobjsubid OPERATOR(pg_catalog.=) a.attnum)"
                + "     AND (d.deptype OPERATOR(pg_catalog.=) 'a')),"
                + " (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attrdef ad"
                + "   JOIN pg_catalog.pg_depend d2"
                + "     ON (d2.classid OPERATOR(pg_catalog.=)"
                + "           'pg_catalog.pg_attrdef'::pg_catalog.regclass)"
                + "     AND (d2.objid OPERATOR(pg_catalog.=) ad.oid)"
                + "     AND (d2.refclassid OPERATOR(pg_catalog.=)"
                + "            'pg_catalog.pg_class'::pg_catalog.regclass)"
                + "     AND (d2.refobjid OPERATOR(pg_catalog.=) s.oid)"
                + "     AND (d2.deptype OPERATOR(pg_catalog.=) 'n')"
                + "   WHERE (ad.adrelid OPERATOR(pg_catalog.=) t.oid)"
                + "     AND (ad.adnum OPERATOR(pg_catalog.=) a.attnum))"
                + " FROM pg_catalog.pg_class s, pg_catalog.pg_class t, pg_catalog.pg_attribute a"
                + " WHERE (s.relnamespace OPERATOR(pg_catalog.=) ?)"
                + "   AND (s.relname OPERATOR(pg_catalog.=) ?)"
                + "   AND (t.oid OPERATOR(pg_catalog.=) ?)"
                + "   AND (a.attrelid OPERATOR(pg_catalog.=) t.oid)"
                + "   AND (a.attname OPERATOR(pg_catalog.=) 'seq')")) {
      ps.setLong(1, ns);
      ps.setString(2, SchemaExpectations.SEQUENCE);
      ps.setLong(3, relations.get(SchemaExpectations.ERASURE).oid());
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
        if (rs.getLong(3) != 1) {
          shape.add(
              "shredding_erasure.seq has no default wired to "
                  + SchemaExpectations.SEQUENCE
                  + " (no pg_attrdef row with a pg_depend 'n' edge to the sequence). A dropped"
                  + " bigserial default, or a default wired to a different sequence, takes the"
                  + " first append to discover that.");
        }
      }
    }
  }

  private static void checkConstraints(
      Connection c, long ns, Map<String, Relation> relations, List<String> shape)
      throws SQLException {
    var actual = new LinkedHashMap<String, Constraint>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, con.conname, con.contype,"
                + " pg_catalog.pg_get_constraintdef(con.oid)"
                + " FROM pg_catalog.pg_constraint con"
                + " JOIN pg_catalog.pg_class c"
                + "   ON (c.oid OPERATOR(pg_catalog.=) con.conrelid)"
                + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))")) {
      ps.setLong(1, ns);
      ps.setArray(2, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
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

  /**
   * @param config the function's {@code pg_proc.proconfig}, empty when the column is SQL NULL. Read
   *     as a {@code java.sql.Array} and compared in Java against {@link
   *     SchemaExpectations#GUARD_PROCONFIG}: a SQL-side comparison of a NULL array evaluates to
   *     NULL rather than to false, which would drop the row and report the guard as absent instead
   *     of unguarded (design §2.6).
   */
  private record Function(
      long oid,
      String name,
      String body,
      String kind,
      int args,
      boolean securityDefiner,
      Optional<List<String>> config,
      String language,
      String returns,
      boolean ownedByRole) {}

  private static Map<String, Function> functions(Connection c, long ns, long login)
      throws SQLException {
    var found = new LinkedHashMap<String, Function>();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT p.oid, p.proname, p.prosrc, p.prokind, p.pronargs, p.prosecdef,"
                + " p.proconfig, l.lanname,"
                + " pg_catalog.pg_get_function_result(p.oid),"
                + " pg_catalog.pg_has_role(?::pg_catalog.oid, p.proowner, 'MEMBER')"
                + " FROM pg_catalog.pg_proc p"
                + " JOIN pg_catalog.pg_language l"
                + "   ON (l.oid OPERATOR(pg_catalog.=) p.prolang)"
                + " WHERE (p.pronamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (p.proname OPERATOR(pg_catalog.=) ANY(?))")) {
      ps.setLong(1, login);
      ps.setLong(2, ns);
      ps.setArray(3, c.createArrayOf("text", SchemaExpectations.GUARD_FUNCTIONS.toArray()));
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
                  config(rs.getArray(7)),
                  rs.getString(8),
                  rs.getString(9),
                  rs.getBoolean(10)));
        }
      }
    }
    return found;
  }

  /**
   * {@code proconfig} as a list, or empty when the column is SQL NULL. Not a {@code getString}: the
   * text rendering of a {@code text[]} quotes and escapes per element, so comparing it to a joined
   * constant would compare two renderings rather than two values.
   */
  private static Optional<List<String>> config(java.sql.Array array) throws SQLException {
    if (array == null) {
      return Optional.empty();
    }
    Object elements = array.getArray();
    if (!(elements instanceof Object[] values)) {
      return Optional.empty();
    }
    var out = new ArrayList<String>(values.length);
    for (Object value : values) {
      out.add(value == null ? "" : value.toString());
    }
    return Optional.of(List.copyOf(out));
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
                + ", language "
                + have.language()
                + ", returns "
                + have.returns()
                + ")");
        continue;
      }
      // Not a `continue`: the body digest is checked too, so a schema built by an older copy of
      // the script is told about both halves of §2.3 in one refusal rather than one per restart.
      if (!SchemaExpectations.GUARD_PROCONFIG.equals(have.config().orElse(null))) {
        guards.add(unpinnedGuard(name, have.config()));
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

  /**
   * The inverted {@code proconfig} leg's refusal (design §2.4, finding C-13-14). Its own message,
   * not a clause of the shape leg's, because the remedy and the consequence are specific: the
   * guard's body resolves its operator names in the writing session, which is the session of the
   * role the guard constrains.
   */
  private static String unpinnedGuard(String name, Optional<List<String>> actual) {
    return "guard function "
        + name
        + " does not carry the search_path clause the schema step gives it: pg_proc.proconfig is "
        + actual.map(Object::toString).orElse("NULL")
        + ", expected exactly "
        + SchemaExpectations.GUARD_PROCONFIG
        + ". A guard function is not SECURITY DEFINER, so without that clause its body resolves"
        + " its operator, function and type names along the search_path of whoever writes to the"
        + " table - and a role that owns a single schema of its own can define an"
        + " =(boolean,boolean) or a <>(bigint,bigint) there and write what the guard was meant to"
        + " refuse. CREATE OR REPLACE FUNCTION with no SET clause clears the column with no error,"
        + " so an older copy of schema-postgresql.sql re-applied over this schema is the usual"
        + " cause. Re-apply the bundled schema-postgresql.sql as the owner role.";
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
      long ns,
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
                + " (p.pronamespace OPERATOR(pg_catalog.=) ?),"
                + " t.tgqual IS NOT NULL, t.tgattr::pg_catalog.text"
                + " FROM pg_catalog.pg_trigger t"
                + " JOIN pg_catalog.pg_class c"
                + "   ON (c.oid OPERATOR(pg_catalog.=) t.tgrelid)"
                + " JOIN pg_catalog.pg_proc p"
                + "   ON (p.oid OPERATOR(pg_catalog.=) t.tgfoid)"
                + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + "   AND (c.relname OPERATOR(pg_catalog.=) ANY(?))"
                + "   AND NOT t.tgisinternal")) {
      ps.setLong(1, ns);
      ps.setLong(2, ns);
      ps.setArray(3, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
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
      Connection c, long ns, Map<String, Relation> relations, List<String> guards)
      throws SQLException {
    if (relations.isEmpty()) {
      return;
    }
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT parent.relname, child.relname,"
                + " (parent.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " FROM pg_catalog.pg_inherits i"
                + " JOIN pg_catalog.pg_class parent"
                + "   ON (parent.oid OPERATOR(pg_catalog.=) i.inhparent)"
                + " JOIN pg_catalog.pg_class child"
                + "   ON (child.oid OPERATOR(pg_catalog.=) i.inhrelid)"
                + " WHERE ((parent.relnamespace OPERATOR(pg_catalog.=) ?)"
                + "        AND (parent.relname OPERATOR(pg_catalog.=) ANY(?)))"
                + "    OR ((child.relnamespace OPERATOR(pg_catalog.=) ?)"
                + "        AND (child.relname OPERATOR(pg_catalog.=) ANY(?)))")) {
      var names = c.createArrayOf("text", SchemaExpectations.TABLES.toArray());
      ps.setLong(1, ns);
      ps.setLong(2, ns);
      ps.setArray(3, names);
      ps.setLong(4, ns);
      ps.setArray(5, names);
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
      Connection c, long ns, Map<String, Relation> relations, List<String> guards)
      throws SQLException {
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
            "SELECT c.relname, pg_catalog.count(pol.oid) FROM pg_catalog.pg_class c"
                + " LEFT JOIN pg_catalog.pg_policy pol"
                + "   ON (pol.polrelid OPERATOR(pg_catalog.=) c.oid)"
                + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))"
                + " GROUP BY c.relname")) {
      ps.setLong(1, ns);
      ps.setArray(2, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
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
            "SELECT c.relname, pg_catalog.count(r.oid) FROM pg_catalog.pg_class c"
                + " LEFT JOIN pg_catalog.pg_rewrite r"
                + "   ON (r.ev_class OPERATOR(pg_catalog.=) c.oid)"
                + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))"
                + " GROUP BY c.relname")) {
      ps.setLong(1, ns);
      ps.setArray(2, c.createArrayOf("text", SchemaExpectations.TABLES.toArray()));
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

  /**
   * The privilege legs. Since C-PR-1c they judge the <b>login role and every role in its reach</b>,
   * not only {@code current_user}: a pool can log in as the owner or a superuser and move in its
   * init SQL ({@code SET ROLE}, {@code SET SESSION AUTHORIZATION}), and any statement on it can
   * move back. Required privileges ("can the work run") stay on {@code current_user}, the role the
   * work runs as. The module never runs {@code SET ROLE}, {@code RESET ROLE} or {@code SET SESSION
   * AUTHORIZATION} itself.
   */
  private static void checkRole(
      Connection c,
      Session session,
      Map<String, Relation> relations,
      Map<String, Relation> indexes,
      Map<String, Function> functions,
      List<String> accepted,
      List<String> excess,
      List<String> missing)
      throws SQLException {
    Reach reach = session.reach();
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT pg_catalog.current_setting('is_superuser'),"
                + " pg_catalog.has_schema_privilege(current_user, ?::pg_catalog.oid, 'USAGE'),"
                + " pg_catalog.pg_has_role(?::pg_catalog.oid,"
                + "   (SELECT d.datdba FROM pg_catalog.pg_database d"
                + "      WHERE (d.datname OPERATOR(pg_catalog.=) ?)), 'MEMBER'),"
                + " pg_catalog.pg_has_role(?::pg_catalog.oid,"
                + "   (SELECT n.nspowner FROM pg_catalog.pg_namespace n"
                + "      WHERE (n.oid OPERATOR(pg_catalog.=) ?::pg_catalog.oid)), 'MEMBER')")) {
      ps.setLong(1, session.schemaOid());
      ps.setLong(2, reach.loginOid());
      ps.setString(3, session.database());
      ps.setLong(4, reach.loginOid());
      ps.setLong(5, session.schemaOid());
      try (ResultSet rs = ps.executeQuery()) {
        rs.next();
        if ("on".equalsIgnoreCase(rs.getString(1))) {
          excess.add("is a superuser");
        }
        if (!rs.getBoolean(2)) {
          missing.add("USAGE on schema " + session.schema());
        }
        if (rs.getBoolean(3)) {
          excess.add(
              reach.owner() + "is, or is a member of, the owner of database " + session.database());
        }
        if (rs.getBoolean(4)) {
          // C-PR45-1: the owner of a schema can DROP every object in it, whoever owns the object,
          // and keeps that right after it revokes CREATE from itself. The grant list cannot show
          // it.
          excess.add(
              (reach.owner().isEmpty()
                      ? "owns "
                      : reach.owner() + "owns, or is a member of the owner of, ")
                  + "schema "
                  + session.schema());
        }
      }
    }
    checkReach(reach, excess);
    String owns =
        reach.owner().isEmpty()
            ? "owns "
            : reach.owner() + "owns, or is a member of the owner of, ";
    relations.values().stream()
        .filter(Relation::ownedByRole)
        .forEach(r -> excess.add(owns + "table " + r.name()));
    indexes.values().stream()
        .filter(Relation::ownedByRole)
        .forEach(r -> excess.add(owns + "index " + r.name()));
    functions.values().stream()
        .filter(Function::ownedByRole)
        .forEach(f -> excess.add(owns + "guard function " + f.name()));
    checkSequenceOwnerAndPrivileges(c, session.schemaOid(), reach, owns, excess, missing);
    checkTablePrivileges(c, relations, excess, missing);
    checkObjectGrants(c, session, reach, excess);
    checkColumnGrants(c, session.schemaOid(), relations, reach, excess);
    checkParameterGrants(c, reach, excess);
    checkFunctionGrants(c, reach, accepted, excess);
  }

  /**
   * C-PR45-3: EXECUTE on withheld functions, their aliases, native SECURITY DEFINER code, native
   * code made by hand, and shipped extension members no longer as shipped, judged by reach and
   * PUBLIC against the pinned files of {@link PinnedCatalogue}. Same connection, same pinned
   * window, same reach array as the parameter leg.
   */
  private static void checkFunctionGrants(
      Connection c, Reach reach, List<String> accepted, List<String> excess) throws SQLException {
    FunctionGrants.check(c, reach, accepted, excess);
  }

  /**
   * The legs on the reach set itself (C-PR-1c, C-PR1c-1, C-PR1c-7). A superuser login reaches every
   * role through {@code SET SESSION AUTHORIZATION}; a superuser or CREATEROLE role in reach is one
   * {@code SET ROLE} away; the server-file and server-program roles run programs as the server's
   * operating-system user; any other predefined role is refused unless it is on the accepted list.
   */
  private static void checkReach(Reach reach, List<String> excess) {
    for (ReachRole role : reach.roles()) {
      String who = reach.named(role.oid());
      if (role.superuser()) {
        excess.add(who + " is a superuser");
      }
      if (role.createRole()) {
        excess.add(who + " has CREATEROLE");
      }
      if (role.serverRole()) {
        excess.add(
            who
                + " is a server-file or server-program role (it reads or writes files, or runs"
                + " programs, as the server's operating-system user)");
      } else if (role.name().startsWith("pg_")
          && !SchemaExpectations.ACCEPTED_PREDEFINED_ROLES.contains(role.name())) {
        excess.add(who + " is a predefined role this module does not accept");
      }
    }
  }

  private static void checkSequenceOwnerAndPrivileges(
      Connection c, long ns, Reach reach, String owns, List<String> excess, List<String> missing)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT pg_catalog.pg_has_role(?::pg_catalog.oid, s.relowner, 'MEMBER'),"
                + " pg_catalog.has_sequence_privilege(current_user, s.oid, 'USAGE')"
                + " FROM pg_catalog.pg_class s"
                + " WHERE (s.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (s.relname OPERATOR(pg_catalog.=) ?)")) {
      ps.setLong(1, reach.loginOid());
      ps.setLong(2, ns);
      ps.setString(3, SchemaExpectations.SEQUENCE);
      try (ResultSet rs = ps.executeQuery()) {
        if (!rs.next()) {
          return;
        }
        if (rs.getBoolean(1)) {
          excess.add(owns + "sequence " + SchemaExpectations.SEQUENCE);
        }
        if (!rs.getBoolean(2)) {
          missing.add("USAGE on sequence " + SchemaExpectations.SEQUENCE);
        }
      }
    }
  }

  /** The required table privileges, on {@code current_user}: can the work run. */
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
      checkColumnUpdate(c, relation, want, excess, missing);
    }
  }

  /**
   * The allow list over explicit grants (C-PR1c-4): every ACL entry of the four tables, the
   * sequence, the schema and the database whose grantee is in reach or is PUBLIC. A default ACL
   * ({@code NULL}) is read as {@code acldefault}, which holds the owner's implicit rights. The
   * owner's own entries of a table, the sequence and the database are left out: a reachable owner
   * is already refused by its ownership leg, and its implicit rights would repeat it forty times.
   * The schema has an ownership leg too (C-PR45-1, in {@code checkRole}): its owner can drop every
   * object in it even with {@code CREATE} revoked, so the owner's {@code CREATE} entry stays here
   * only as a second message for the same finding. Any privilege type outside the object's list
   * refuses, whatever its name, so a type a later release adds is refused without a version switch.
   */
  private static final String OBJECT_GRANTS_SQL =
      "SELECT c.relname, c.relkind, x.grantee, x.privilege_type"
          + " FROM pg_catalog.pg_class c,"
          + " pg_catalog.aclexplode(CASE WHEN c.relacl IS NOT NULL THEN c.relacl"
          + " ELSE pg_catalog.acldefault("
          + "CASE WHEN (c.relkind OPERATOR(pg_catalog.=) 'S') THEN 's'::pg_catalog.\"char\""
          + " ELSE 'r'::pg_catalog.\"char\" END, c.relowner) END) x"
          + " WHERE (c.relnamespace OPERATOR(pg_catalog.=) ?)"
          + " AND (c.relname OPERATOR(pg_catalog.=) ANY(?))"
          + " AND (x.grantee OPERATOR(pg_catalog.<>) c.relowner)"
          + " AND ((x.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
          + " OR (x.grantee OPERATOR(pg_catalog.=) '0'::pg_catalog.oid))"
          + " UNION ALL"
          + " SELECT n.nspname, 'n', x.grantee, x.privilege_type"
          + " FROM pg_catalog.pg_namespace n,"
          + " pg_catalog.aclexplode(CASE WHEN n.nspacl IS NOT NULL THEN n.nspacl"
          + " ELSE pg_catalog.acldefault('n'::pg_catalog.\"char\", n.nspowner) END) x"
          + " WHERE (n.oid OPERATOR(pg_catalog.=) ?)"
          + " AND ((x.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
          + " OR (x.grantee OPERATOR(pg_catalog.=) '0'::pg_catalog.oid))"
          + " UNION ALL"
          + " SELECT d.datname, 'd', x.grantee, x.privilege_type"
          + " FROM pg_catalog.pg_database d,"
          + " pg_catalog.aclexplode(CASE WHEN d.datacl IS NOT NULL THEN d.datacl"
          + " ELSE pg_catalog.acldefault('d'::pg_catalog.\"char\", d.datdba) END) x"
          + " WHERE (d.datname OPERATOR(pg_catalog.=) ?)"
          + " AND (x.grantee OPERATOR(pg_catalog.<>) d.datdba)"
          + " AND ((x.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
          + " OR (x.grantee OPERATOR(pg_catalog.=) '0'::pg_catalog.oid))";

  private static void checkObjectGrants(
      Connection c, Session session, Reach reach, List<String> excess) throws SQLException {
    var names = new ArrayList<String>(SchemaExpectations.TABLES);
    names.add(SchemaExpectations.SEQUENCE);
    try (PreparedStatement ps = c.prepareStatement(OBJECT_GRANTS_SQL)) {
      var oids = c.createArrayOf("oid", boxed(reach.oids()));
      ps.setLong(1, session.schemaOid());
      ps.setArray(2, c.createArrayOf("text", names.toArray()));
      ps.setArray(3, oids);
      ps.setLong(4, session.schemaOid());
      ps.setArray(5, oids);
      ps.setString(6, session.database());
      ps.setArray(7, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String object = rs.getString(1);
          String kind = rs.getString(2);
          long grantee = rs.getLong(3);
          String privilege = rs.getString(4);
          String held = reach.holder(grantee) + "holds " + privilege + " on ";
          switch (kind) {
            case "n" -> {
              if (!SchemaExpectations.SCHEMA_ALLOWED.contains(privilege)) {
                excess.add(held + "schema " + object);
              }
            }
            case "d" -> {
              if (!SchemaExpectations.DATABASE_ALLOWED.contains(privilege)) {
                excess.add(held + "database " + object);
              }
            }
            case "S" -> {
              if (!SchemaExpectations.SEQUENCE_ALLOWED.contains(privilege)) {
                excess.add(
                    held
                        + "sequence "
                        + object
                        + ("UPDATE".equals(privilege)
                            ? " (setval can rewind the erasure log's seq)"
                            : ""));
              }
            }
            default -> {
              if (!allowedOn(object).contains(privilege)) {
                excess.add(held + object);
              }
            }
          }
        }
      }
    }
  }

  private static List<String> allowedOn(String table) {
    return SchemaExpectations.PRIVILEGES.stream()
        .filter(p -> p.table().equals(table))
        .map(TablePrivileges::required)
        .findFirst()
        .orElse(List.of());
  }

  private static Long[] boxed(long[] values) {
    var out = new Long[values.length];
    for (int i = 0; i < values.length; i++) {
      out[i] = values[i];
    }
    return out;
  }

  /**
   * Column grants over reach (C-PR-1c). {@code UPDATE} on a column other than the one the module
   * updates refuses for any role in reach, held by a column grant or by a table-wide one; any other
   * column grant must be a privilege the table allows. The current role's own column legs are in
   * {@link #checkColumnUpdate}.
   */
  private static void checkColumnGrants(
      Connection c, long ns, Map<String, Relation> relations, Reach reach, List<String> excess)
      throws SQLException {
    if (relations.isEmpty()) {
      return;
    }
    Long[] tables = relations.values().stream().map(Relation::oid).toArray(Long[]::new);
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT c.relname, a.attname, reached, 'UPDATE'"
                + " FROM pg_catalog.pg_class c"
                + " JOIN pg_catalog.pg_attribute a ON (a.attrelid OPERATOR(pg_catalog.=) c.oid),"
                + " pg_catalog.unnest(?::pg_catalog._oid) AS reached"
                + " WHERE (c.oid OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
                + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped"
                + " AND pg_catalog.has_column_privilege(reached, c.oid, a.attnum, 'UPDATE')"
                + " AND NOT pg_catalog.pg_has_role(reached, c.relowner, 'MEMBER')"
                + " UNION ALL"
                + " SELECT c.relname, a.attname, x.grantee, x.privilege_type"
                + " FROM pg_catalog.pg_class c"
                + " JOIN pg_catalog.pg_attribute a ON (a.attrelid OPERATOR(pg_catalog.=) c.oid),"
                + " pg_catalog.aclexplode(a.attacl) x"
                + " WHERE ((c.oid OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
                + " OR ((c.relnamespace OPERATOR(pg_catalog.=) ?)"
                + " AND (c.relname OPERATOR(pg_catalog.=) ?)))"
                + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped"
                + " AND (x.privilege_type OPERATOR(pg_catalog.<>) 'UPDATE')"
                + " AND (x.grantee OPERATOR(pg_catalog.<>) c.relowner)"
                + " AND ((x.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
                + " OR (x.grantee OPERATOR(pg_catalog.=) '0'::pg_catalog.oid))")) {
      var oids = c.createArrayOf("oid", boxed(reach.oids()));
      var tableOids = c.createArrayOf("oid", tables);
      ps.setArray(1, oids);
      ps.setArray(2, tableOids);
      ps.setArray(3, tableOids);
      ps.setLong(4, ns);
      ps.setString(5, SchemaExpectations.SEQUENCE);
      ps.setArray(6, oids);
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          String table = rs.getString(1);
          String column = rs.getString(2);
          long grantee = rs.getLong(3);
          String privilege = rs.getString(4);
          // C-PR45-2: only the UPDATE rows are left to checkColumnUpdate for the current role.
          // Any other column privilege (REFERENCES, INSERT, SELECT) is judged for it too.
          if ("UPDATE".equals(privilege)
              && grantee != 0
              && reach.name(grantee).equals(reach.current())) {
            continue;
          }
          boolean allowed;
          if (table.equals(SchemaExpectations.SEQUENCE)) {
            // C-PR45-6: a column grant on the sequence is judged against the sequence allow list,
            // like a whole-sequence grant.
            allowed = SchemaExpectations.SEQUENCE_ALLOWED.contains(privilege);
          } else {
            TablePrivileges want =
                SchemaExpectations.PRIVILEGES.stream()
                    .filter(p -> p.table().equals(table))
                    .findFirst()
                    .orElseThrow();
            allowed =
                "UPDATE".equals(privilege)
                    ? want.required().contains("UPDATE") || column.equals(want.updatableColumn())
                    : want.required().contains(privilege);
          }
          if (!allowed) {
            excess.add(
                reach.holder(grantee) + "holds " + privilege + " on " + table + "." + column);
          }
        }
      }
    }
  }

  /**
   * C-PR1c-2: a parameter grant ({@code GRANT SET} or {@code ALTER SYSTEM ON PARAMETER}, PostgreSQL
   * 15 and later) to any role in reach or to PUBLIC refuses. {@code ALTER SYSTEM} on {@code
   * archive_command} is a shell as the server's operating-system user after the next reload, and no
   * runtime role needs any parameter grant. On PostgreSQL 14 the catalogue does not exist and the
   * read fails as {@code 005}: fail closed.
   */
  private static void checkParameterGrants(Connection c, Reach reach, List<String> excess)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement(
            "SELECT p.parname, x.grantee, x.privilege_type"
                + " FROM pg_catalog.pg_parameter_acl p, pg_catalog.aclexplode(p.paracl) x"
                + " WHERE (x.grantee OPERATOR(pg_catalog.=) ANY (?::pg_catalog._oid))"
                + " OR (x.grantee OPERATOR(pg_catalog.=) '0'::pg_catalog.oid)"
                + " ORDER BY p.parname")) {
      ps.setArray(1, c.createArrayOf("oid", boxed(reach.oids())));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) {
          excess.add(
              reach.named(rs.getLong(2))
                  + " holds "
                  + rs.getString(3)
                  + " on parameter "
                  + rs.getString(1));
        }
      }
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
            "SELECT a.attname,"
                + " pg_catalog.has_column_privilege(current_user, a.attrelid, a.attnum, 'UPDATE')"
                + " FROM pg_catalog.pg_attribute a"
                + " WHERE (a.attrelid OPERATOR(pg_catalog.=) ?)"
                + " AND (a.attnum OPERATOR(pg_catalog.>) 0) AND NOT a.attisdropped")) {
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
        c.prepareStatement(
            "SELECT pg_catalog.has_table_privilege(current_user, ?::pg_catalog.oid, ?)")) {
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
            + session.described()
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
            + session.described()
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
        + " shredding.jdbc.allow-privileged-runtime-role=true (starter), or call"
        + " JdbcSupport.verifySchema(ds, true) / initializeAndVerifySchema(ds, true) (core"
        + " without the starter, which never reads the property). Both warn at every call."
        + " The check judges the role the pool logs in as and every role that login can become"
        + " (C-PR-1c). Log in as the runtime role itself, or as a role whose only membership is"
        + " the runtime role. A SET ROLE in the pool's init SQL does not lower privilege: any"
        + " statement can RESET ROLE. A membership that leads to a privileged role is removed with"
        + " REVOKE <role> FROM <member>.";
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
