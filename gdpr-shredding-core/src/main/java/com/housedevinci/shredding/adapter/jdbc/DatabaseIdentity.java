package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.application.LogText;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * What a connection reaches, as the server states it (finding C-PR-1b): the cluster's system
 * identifier, the database's oid and name, the verified schema's oid, the login role and the
 * current role.
 *
 * <p>Verification reads it once, inside its own transaction, and {@link VerifiedSchema} carries it.
 * Every store connection reads it again with the same query, inside the call's own transaction,
 * before the work ({@link JdbcSupport}). A {@code DataSource} object can be retargeted after
 * verification - a routing pool, a refresh-scoped proxy, {@code setTargetDataSource}, a mutable
 * URL, an application delegate, a failover URL, new credentials - and the object stays the same, so
 * a check on the object cannot see the move. These facts can only come from the server the
 * connection is open on, and the runtime role cannot change any of them.
 *
 * <p><b>Why each fact.</b> The system identifier tells two clusters apart even when one was built
 * by the same script as the other: same database name, same roles, the {@code public} oid fixed at
 * 2200, and on a fresh cluster the same database oid. The database oid and name tell two databases
 * of one cluster apart. The schema oid catches a verified schema other than {@code public} that the
 * target does not hold. The two roles catch a pool whose login changed. {@code pg_is_in_recovery()}
 * must be false: a hot standby or read replica has every other fact of its primary, and a lagging
 * one can serve a data key the primary has already destroyed. A physical standby that has been
 * promoted is the same database, and is accepted.
 *
 * <p><b>What it does not resist.</b> A superuser on the wrong target can forge every fact (create a
 * database with a chosen oid, replace a {@code pg_catalog} function; a system identifier is not a
 * secret). A physical copy of the verified cluster (base backup, snapshot, point-in-time restore)
 * answers every fact the same, by construction. Both are stated in SECURITY-NOTES.
 *
 * <p>No operator in the query is resolved along the role's path: every comparison is {@code
 * OPERATOR(pg_catalog.=)} and every function and relation is {@code pg_catalog.}-qualified. {@code
 * session_user} and {@code current_user} are keywords and cannot be shadowed. Exactly one row is
 * required.
 *
 * <p><b>The login role</b> (C-PR-1c). {@code session_user} is the login role only when the login is
 * not a superuser: a superuser login can move it with {@code SET SESSION AUTHORIZATION} and restore
 * the verified session and current roles in its init SQL, and both role columns then match. The
 * server's own record of the login is the backend's activity entry ({@code
 * pg_stat_get_activity(pg_backend_pid()).usesysid}), which no {@code SET} moves. Reading it copies
 * every live backend's entry, which costs up to about 2 ms with 400 backends and 32 kB query text
 * (design R2.1). A backend's login never changes, so the check reads it once per backend: when it
 * matches, the same statement stores this verification's {@link VerifiedSchema#loginMarker()
 * marker} in a session setting of that backend, {@value #MARKER_SETTING}, and later calls on that
 * backend compare the marker and skip the read (design R2.7, S5). A new backend, a reset one
 * ({@code DISCARD ALL}, {@code RESET ALL}), or one whose marking transaction rolled back has no
 * marker or an empty one, and reads the login again.
 */
record DatabaseIdentity(
    long systemIdentifier,
    long databaseOid,
    String databaseName,
    long schemaOid,
    String sessionUser,
    String currentUser,
    long loginRoleOid,
    String loginRole) {

  /** The session setting that remembers "this backend's login was checked" (C-PR-1c). */
  static final String MARKER_SETTING = "shredding.login_checked";

  /**
   * The fingerprint. One row per call: the database the connection is in. The schema column is the
   * oid that the verified schema's <em>name</em> resolves to on this connection - the name every
   * module statement is qualified with - so a target whose schema of that name is another object,
   * or absent ({@code NULL}, read as 0), differs from the verified oid. The name is a bind
   * parameter.
   */
  static final String IDENTITY_SQL =
      "SELECT pg_catalog.pg_is_in_recovery(), s.system_identifier, d.oid, d.datname,"
          + " (SELECT n.oid FROM pg_catalog.pg_namespace n"
          + " WHERE (n.nspname OPERATOR(pg_catalog.=) ?)),"
          + " session_user, current_user"
          + " FROM pg_catalog.pg_control_system() s, pg_catalog.pg_database d"
          + " WHERE (d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database())";

  /**
   * The per-call fingerprint: {@link #IDENTITY_SQL} plus the login column (C-PR-1c, S5). Bind
   * order: the schema name, the marker, the marker, the verified login oid, the marker.
   *
   * <p>The column answers the marker when the backend already carries it, or when its login is the
   * verified one, in which case it also stores the marker at session level ({@code is_local =
   * false}: a transaction-local marker would end at this call's commit). Anything else is NULL. The
   * activity read sits in the second branch only, so a marked backend never runs it. A wrong value
   * and the empty string that {@code RESET} leaves both fall through to the read. The value is
   * compared again in Java, in constant time.
   */
  static final String FINGERPRINT_SQL =
      IDENTITY_SQL.replace(
          " session_user, current_user FROM",
          " session_user, current_user,"
              + " CASE WHEN (pg_catalog.current_setting('"
              + MARKER_SETTING
              + "', true) OPERATOR(pg_catalog.=) ?) THEN ?"
              + " WHEN ((SELECT a.usesysid FROM pg_catalog.pg_stat_get_activity("
              + "pg_catalog.pg_backend_pid()) a) OPERATOR(pg_catalog.=) ?::pg_catalog.oid)"
              + " THEN pg_catalog.set_config('"
              + MARKER_SETTING
              + "', ?, false) END"
              + " FROM");

  /**
   * The same query for a read in a transaction this module began: it also makes that transaction
   * read-only, with SQL and without a statement of its own (round 2, items 1 and 7). {@code
   * set_config(..., true)} is transaction-local and ends with the commit. Never {@code
   * Connection.setReadOnly}: a read/write-splitting driver moves to a replica on that call.
   */
  static final String FINGERPRINT_READ_ONLY_SQL =
      FINGERPRINT_SQL.replace(
          "SELECT pg_catalog.pg_is_in_recovery(),",
          "SELECT pg_catalog.pg_is_in_recovery(),"
              + " pg_catalog.set_config('transaction_read_only', 'on', true),");

  /** True when the two markers are the same value, compared in constant time. */
  static boolean sameMarker(Optional<String> observed, String verified) {
    return observed.isPresent()
        && MessageDigest.isEqual(
            observed.get().getBytes(StandardCharsets.UTF_8),
            verified.getBytes(StandardCharsets.UTF_8));
  }

  DatabaseIdentity {
    Objects.requireNonNull(databaseName, "databaseName");
    Objects.requireNonNull(sessionUser, "sessionUser");
    Objects.requireNonNull(currentUser, "currentUser");
    Objects.requireNonNull(loginRole, "loginRole");
  }

  /** The facts one fingerprint row carries, without the login role. */
  record Facts(
      long systemIdentifier,
      long databaseOid,
      String databaseName,
      long schemaOid,
      String sessionUser,
      String currentUser) {

    DatabaseIdentity withLogin(long loginRoleOid, String loginRole) {
      return new DatabaseIdentity(
          systemIdentifier,
          databaseOid,
          databaseName,
          schemaOid,
          sessionUser,
          currentUser,
          loginRoleOid,
          loginRole);
    }
  }

  /**
   * What one run of the fingerprint returned. {@code marker} is the login column of the per-call
   * statement: empty when the column was NULL, and always empty for verification's read.
   */
  record Observed(boolean inRecovery, int rows, Optional<Facts> facts, Optional<String> marker) {}

  /**
   * Verification's read: {@link #IDENTITY_SQL} on {@code c}, in whatever transaction {@code c} is
   * in. No login column: verification reads the login with its own statement and changes no session
   * state.
   */
  static Observed read(Connection c, String schemaName, boolean readOnly) throws SQLException {
    String sql = readOnly ? READ_ONLY_PREFIX.apply(IDENTITY_SQL) : IDENTITY_SQL;
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setString(1, schemaName);
      return observe(ps, readOnly ? 1 : 0, false);
    }
  }

  /** The per-call read: {@link #FINGERPRINT_SQL} or its read-only form, with the marker bound. */
  private static Observed check(Connection c, VerifiedSchema schema, boolean readOnly)
      throws SQLException {
    String sql = readOnly ? FINGERPRINT_READ_ONLY_SQL : FINGERPRINT_SQL;
    String marker = schema.loginMarker();
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setString(1, schema.name());
      ps.setString(2, marker);
      ps.setString(3, marker);
      ps.setLong(4, schema.identity().loginRoleOid());
      ps.setString(5, marker);
      return observe(ps, readOnly ? 1 : 0, true);
    }
  }

  private static Observed observe(PreparedStatement ps, int offset, boolean withMarker)
      throws SQLException {
    try (ResultSet rs = ps.executeQuery()) {
      if (!rs.next()) {
        return new Observed(false, 0, Optional.empty(), Optional.empty());
      }
      boolean inRecovery = rs.getBoolean(1);
      var facts =
          new Facts(
              rs.getLong(2 + offset),
              rs.getLong(3 + offset),
              text(rs.getString(4 + offset)),
              rs.getLong(5 + offset),
              text(rs.getString(6 + offset)),
              text(rs.getString(7 + offset)));
      Optional<String> marker =
          withMarker ? Optional.ofNullable(rs.getString(8 + offset)) : Optional.empty();
      int rows = 1;
      while (rs.next()) {
        rows++;
      }
      return new Observed(inRecovery, rows, Optional.of(facts), marker);
    }
  }

  /** {@code set_config('transaction_read_only', 'on', true)} as the statement's second column. */
  private static final java.util.function.UnaryOperator<String> READ_ONLY_PREFIX =
      sql ->
          sql.replace(
              "SELECT pg_catalog.pg_is_in_recovery(),",
              "SELECT pg_catalog.pg_is_in_recovery(),"
                  + " pg_catalog.set_config('transaction_read_only', 'on', true),");

  private static String text(String value) {
    return value == null ? "" : value;
  }

  /**
   * The names of the facts that differ, in a fixed order, each with the verified and the observed
   * value where the value is a name (database, roles). Oids and the system identifier are never
   * printed.
   */
  List<String> differences(Facts observed) {
    var out = new ArrayList<String>();
    if (systemIdentifier != observed.systemIdentifier()) {
      out.add("cluster");
    }
    if (databaseOid != observed.databaseOid() || !databaseName.equals(observed.databaseName())) {
      out.add(named("database", databaseName, observed.databaseName()));
    }
    if (schemaOid != observed.schemaOid()) {
      out.add("schema");
    }
    if (!sessionUser.equals(observed.sessionUser())) {
      out.add(named("session role", sessionUser, observed.sessionUser()));
    }
    if (!currentUser.equals(observed.currentUser())) {
      out.add(named("current role", currentUser, observed.currentUser()));
    }
    return out;
  }

  private static String named(String fact, String verified, String got) {
    return fact
        + "; verified \""
        + LogText.escape(verified)
        + "\", got \""
        + LogText.escape(got)
        + "\"";
  }

  /**
   * The check every store connection passes before its work (C-PR-1b). Throws {@code
   * SHRED-SCHEMA-012} when the server is in recovery, when the fingerprint returns zero rows or
   * more than one, when any fact differs, or when the query itself fails; the caller rolls back the
   * transaction it began and never runs the work.
   */
  static void require(Connection c, VerifiedSchema schema, boolean readOnly) {
    DatabaseIdentity verified = schema.identity();
    Observed observed;
    try {
      observed = check(c, schema, readOnly);
    } catch (SQLException e) {
      throw unverified("could not be checked (SQLState " + e.getSQLState() + ")", e);
    }
    if (observed.rows() != 1) {
      throw unverified(
          "could not be checked (the fingerprint returned "
              + observed.rows()
              + " rows where exactly one is required)",
          null);
    }
    var different = new ArrayList<String>();
    if (observed.inRecovery()) {
      different.add("server in recovery (a standby or read replica, which can lag the primary)");
    }
    different.addAll(verified.differences(observed.facts().orElseThrow()));
    if (!sameMarker(observed.marker(), schema.loginMarker())) {
      different.add(
          "login role; verified \""
              + LogText.escape(verified.loginRole)
              + "\", got another role (this connection logged in as a role that verification did"
              + " not judge)");
    }
    if (!different.isEmpty()) {
      throw unverified("(different: " + String.join(", ", different) + ")", null);
    }
  }

  private static ShreddingException unverified(String what, Throwable cause) {
    String message =
        "shredding: a connection from the verified DataSource no longer reaches what was verified"
            + " at startup "
            + what
            + ". Nothing was written. The DataSource the module uses must always reach the one"
            + " database it verified: do not route it, refresh it or retarget it. Restart the"
            + " application to verify a new target. ("
            + ErrorCodes.STORE_CONNECTION_UNVERIFIED
            + ")";
    return cause == null
        ? new ShreddingException(ErrorCodes.STORE_CONNECTION_UNVERIFIED, message)
        : new ShreddingException(ErrorCodes.STORE_CONNECTION_UNVERIFIED, message, cause);
  }

  /** Names only: the oids and the system identifier stay out of every log line. */
  @Override
  public String toString() {
    return "DatabaseIdentity[database="
        + LogText.escape(databaseName)
        + ", sessionUser="
        + LogText.escape(sessionUser)
        + ", currentUser="
        + LogText.escape(currentUser)
        + ", loginRole="
        + LogText.escape(loginRole)
        + "]";
  }
}
