package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyUnavailableException;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Plain-JDBC helpers shared by the adapters. No Spring. */
public final class JdbcSupport {

  private static final Logger log = LoggerFactory.getLogger(JdbcSupport.class);

  private JdbcSupport() {}

  @FunctionalInterface
  interface SqlWork<T> {
    T run(Connection c) throws SQLException;
  }

  /**
   * Runs {@code work} in one transaction.
   *
   * <p>A failure of the rollback, or of resetting auto-commit, is added to the original failure as
   * suppressed and never replaces it. On a connection that died mid-transaction both fail too, and
   * letting either escape would report a refusal the work raised on purpose - {@code
   * SHRED-SCHEMA-005} for a catalogue that could not be read, say - as a key-store outage.
   */
  /**
   * C-26-2: an identifier read from the catalogue for a message, escaped as {@link
   * com.housedevinci.shredding.application.LogText#escape} does, so a line break or separator in an
   * operator-chosen name cannot split a refusal or a WARN into lines this module did not write.
   * Applied where the identifier is read for display, never to a composed message, and never to a
   * value that is compared with configuration or bound again (those stay raw).
   */
  static String printed(java.sql.ResultSet rs, String column) throws SQLException {
    String value = rs.getString(column);
    return value == null ? null : com.housedevinci.shredding.application.LogText.escape(value);
  }

  static <T> T inTransaction(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      boolean previous = c.getAutoCommit();
      c.setAutoCommit(false);
      T result;
      try {
        result = work.run(c);
        c.commit();
      } catch (SQLException | RuntimeException e) {
        try {
          c.rollback();
        } catch (SQLException rollback) {
          e.addSuppressed(rollback);
        }
        try {
          c.setAutoCommit(previous);
        } catch (SQLException reset) {
          e.addSuppressed(reset);
        }
        throw e;
      }
      c.setAutoCommit(previous);
      return result;
    } catch (SQLException e) {
      throw unavailable(e);
    }
  }

  /** Read back as the transaction's second statement, to prove the level actually in force. */
  static final String ISOLATION_SQL = "SELECT pg_catalog.current_setting('transaction_isolation')";

  /** The transaction's first statement: transaction-scoped, so the session is never touched. */
  static final String PIN_SQL = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED";

  /**
   * An erasure's transaction, always at {@code READ COMMITTED} (security review C-25-1, C-25-4).
   * Every catalogue check inside an erasure - mapping admission, planner statistics, the copy leg,
   * and the copy leg's second run after the {@code UPDATE} - reads {@code pg_catalog} with plain
   * SQL. Under {@code REPEATABLE READ} or {@code SERIALIZABLE} that uses the snapshot the
   * transaction's first statement took, before the table locks, so a trigger committed while the
   * erasure waited for its lock, or a materialized view created during it, is invisible to every
   * check while the trigger still fires. At {@code READ COMMITTED} each statement takes a fresh
   * snapshot after the locks.
   *
   * <p>The level is set with {@code SET TRANSACTION}, the first statement of the transaction and
   * before any lock, so it covers this transaction only: the session's level, and the pool's idea
   * of it, are never changed and nothing is restored. A connection that arrives inside a caller's
   * transaction (auto-commit off) is refused untouched: that transaction is neither joined nor
   * committed. A level that cannot be set, or does not read back as {@code read committed}, is
   * {@code SHRED-SCHEMA-008}: nothing runs.
   */
  static <T> T inReadCommittedTransaction(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      if (!c.getAutoCommit()) {
        throw notReadCommitted("cannot be set: the connection arrived inside a transaction", null);
      }
      return inTransaction(
          c,
          conn -> {
            try (Statement st = conn.createStatement()) {
              st.execute(PIN_SQL);
            } catch (SQLException e) {
              throw notReadCommitted("could not be set (SQLState " + e.getSQLState() + ")", e);
            }
            String level;
            try (PreparedStatement ps = conn.prepareStatement(ISOLATION_SQL);
                ResultSet rs = ps.executeQuery()) {
              level = rs.next() ? rs.getString(1) : "";
            }
            if (!"read committed".equals(level)) {
              throw notReadCommitted("reads back as \"" + level + "\"", null);
            }
            return work.run(conn);
          });
    } catch (SQLException e) {
      throw unavailable(e);
    }
  }

  private static <T> T inTransaction(Connection c, SqlWork<T> work) throws SQLException {
    boolean previous = c.getAutoCommit();
    c.setAutoCommit(false);
    T result;
    try {
      result = work.run(c);
      c.commit();
    } catch (SQLException | RuntimeException e) {
      try {
        c.rollback();
      } catch (SQLException rollback) {
        e.addSuppressed(rollback);
      }
      try {
        c.setAutoCommit(previous);
      } catch (SQLException reset) {
        e.addSuppressed(reset);
      }
      throw e;
    }
    c.setAutoCommit(previous);
    return result;
  }

  private static ShreddingException notReadCommitted(String why, Throwable cause) {
    return new ShreddingException(
        ErrorCodes.SCHEMA_NAME_ISOLATION,
        "shredding: the erasure's transaction must run at READ COMMITTED, so that every catalogue"
            + " check inside it reads the catalogue as of that check and not as of the"
            + " transaction's first statement; the level "
            + why
            + ". The erasure was not performed: nothing was destroyed, cleared or recorded.",
        cause);
  }

  static <T> T withConnection(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      return work.run(c);
    } catch (SQLException e) {
      throw unavailable(e);
    }
  }

  /**
   * L11: the fixed class id handed to the two-argument {@code pg_advisory_xact_lock(int4, int4)}.
   * {@code pg_advisory_xact_lock(bigint)} - the one-argument form the schema step and {@code
   * JdbcErasureStore}'s chain-append lock both use - is a single flat 64-bit space; a salt folded
   * into a hash changes *which* value in that space a pair lands on, it does not give it a separate
   * namespace, so the previous javadoc's claim that a fixed salt "cannot collide" with those locks
   * was a property the code did not have (the same defect as L5 in the first pass - true collision
   * probability 2^-64, and every collision here is benign: two unrelated pairs, or a pair and the
   * chain lock, simply serialise against each other, which is never a missed exclusion - but the
   * comment claimed more than that). The two-argument form *is* a genuinely separate namespace from
   * the one-argument form and from every other two-argument class id this module uses, so this
   * class id cannot collide with {@code LOCK_KEY} or the schema step's lock at all, by construction
   * rather than by low probability.
   */
  private static final int SUBJECT_LOCK_CLASS = 0x5355424A; // "SUBJ"

  /**
   * Takes a transaction-scoped advisory lock on {@code (tenant, subject)}, in the caller's current
   * transaction. This is what makes the tombstone check in {@code JdbcKeyProvider.mint} and the
   * {@code FOR UPDATE}/tombstone-insert pair in {@code JdbcErasureStore.erase} actually ordered
   * against each other: under READ COMMITTED, a {@code FOR SHARE}/{@code FOR UPDATE} on a row that
   * does not exist yet locks nothing, so a write racing the *first* key mint for a subject and an
   * erasure of that same subject can otherwise interleave with no row for either side to block on
   * (CIPHER-03). The lock exists whether or not any row does, because it is keyed on the pair
   * itself, not on a row.
   *
   * <p>{@code currentForWrite}, {@code rotate} and {@code erase} all take this lock first, before
   * touching {@code shredding_data_key} or {@code shredding_erased_subject}, so the two operations
   * can never observe each other's "nothing here yet" state at the same time.
   */
  public static void lockSubject(Connection c, TenantId tenant, SubjectId subject)
      throws SQLException {
    try (PreparedStatement ps =
        c.prepareStatement("SELECT pg_catalog.pg_advisory_xact_lock(?, pg_catalog.hashtext(?))")) {
      ps.setInt(1, SUBJECT_LOCK_CLASS);
      // L11: length-prefixed, the same canonical form as Pseudonymiser.append and ErasureChain,
      // rather than a "|"-joined string - "a|b" + "c" and "a" + "b|c" hash the same joined string
      // (harmless here, since a collision only serialises two unrelated pairs against each other,
      // but there is no reason to leave the question open when the canonical form is one line).
      ps.setString(2, canonicalPair(tenant.value(), subject.value()));
      ps.execute();
    }
  }

  private static String canonicalPair(String tenant, String subject) {
    var sb = new StringBuilder();
    appendLengthPrefixed(sb, tenant);
    appendLengthPrefixed(sb, subject);
    return sb.toString();
  }

  private static void appendLengthPrefixed(StringBuilder sb, String value) {
    sb.append('|').append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value);
  }

  /**
   * The value the window of {@link #inOneStatementWindow} replaces the session's {@code
   * search_path} with, and the same constant {@code SchemaVerification} pins for its own catalogue
   * reads: one pinned value in this module, not two.
   *
   * <p>{@code pg_temp} is named for a measured reason (T10): the temporary schema precedes the path
   * <em>implicitly</em> for relation references, and naming it late is the only way to demote it.
   * It is safe to name - a role holding {@code TEMPORARY} can create {@code
   * pg_temp.=(varchar,varchar)} and a {@code pg_temp.count(*)}, and neither is ever consulted, even
   * with {@code pg_temp} named first (T8a, T8b): the temporary schema is consulted for relation
   * names only.
   */
  static final String PINNED_PATH = "pg_catalog, pg_temp";

  private static final String READ_SEARCH_PATH = "SELECT pg_catalog.current_setting('search_path')";

  private static final String PIN_SEARCH_PATH =
      "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true)";

  /**
   * The restore. Two properties, both load-bearing.
   *
   * <p><b>The captured bytes are bound, never composed into this text (M2).</b> A role may set its
   * own {@code search_path} to a value containing a quote and a statement terminator, {@code
   * current_setting} returns those bytes verbatim, and a composed restore then either fails to
   * parse or sets the path to the attacker's first token and sends a second statement (A23).
   *
   * <p><b>{@code is_local = false}, which is one deviation from section 4.2's step 5 and was forced
   * by a measurement the design page did not have.</b> A transaction-local restore <em>shadows</em>
   * a non-local {@code SET} issued inside the window for the rest of the transaction - so the
   * step-6 read-back sees the bytes it just sent and nothing else - and at {@code COMMIT} the local
   * value is discarded and the session is left carrying the non-local one. The only way to execute
   * a {@code SET} in there is a plpgsql body the framework-rendered statement reaches (M8), but
   * "the read-back cannot see it" is not a property this restore may have. Sent non-locally, the
   * restore is the last writer either way: on {@code COMMIT} the session carries the bytes it
   * arrived with, and on {@code ROLLBACK} the whole transaction's settings are discarded, which
   * reaches the same place.
   */
  private static final String RESTORE_SEARCH_PATH =
      "SELECT pg_catalog.set_config('search_path', ?, false)";

  /** One statement, run inside the window. */
  @FunctionalInterface
  interface WindowWork<T> {
    T run() throws SQLException;
  }

  /**
   * Runs <b>exactly one statement</b> with this connection's {@code search_path} replaced by {@link
   * #PINNED_PATH} for the duration of that statement, and restores the session to the exact bytes
   * it arrived with (name-resolution design section 4.2, finding C-13-14).
   *
   * <p><b>Why a replacement and not a prefix.</b> PostgreSQL's operator resolution is not ordered
   * by {@code search_path}: it ships no {@code =} with {@code varchar} on either side, so an
   * application-defined {@code =(varchar, varchar)} is an <em>exact</em> match and is selected at
   * step 2 whatever the order (N-1). Only removing the role-writable schema from the candidate set
   * changes the answer, and only a replacement does that. For a relation the same replacement turns
   * a silent decoy read into an error (N-2, T2f), which is fail-closed and loud.
   *
   * <p><b>The invariant, and it is not a recommendation: the unit of work is one statement.</b>
   * Everything that makes this window acceptable rests on it. The erasure's own {@code UPDATE} runs
   * outside it, on the path the transaction arrived with, with every name in it qualified by this
   * module; an application trigger whose body names a relation unqualified therefore still fires
   * and still succeeds (T17), where revision 1's transaction-wide pin broke it (T15b). A second
   * statement inside one window is how the window becomes a transaction again by accident, and it
   * is the one place an exception could be swallowed with the path still replaced. The window is
   * for text this module cannot qualify, which is the framework-rendered read-back and nothing
   * else: the cross-tenant WARN count is module-written, fully qualified, and runs outside it
   * (C-18-6). The name gate ({@code NameQualificationGateTest}) refuses any text-carrying statement
   * call of this module's own inside a window, so the invariant is checked and not merely written
   * down here.
   *
   * <p><b>Six statements, three of them read-backs, because a pin that is not read back is a
   * fiction.</b> In auto-commit, {@code set_config(..., true)} <em>returns</em> the pinned value
   * while the next statement sees the old path (T7), so a form that compared {@code set_config}'s
   * own return value would be exactly the lie it exists to detect. An auto-commit connection is
   * therefore refused before anything is changed, and both the pin and the restore are read back
   * with a separate statement.
   *
   * <p><b>What a {@code SELECT} can still run in here (M8).</b> A row-level-security policy
   * function and a function called from a mapped view resolve their own unqualified names inside
   * this window and fail loudly. So does a string-body {@code LANGUAGE sql} function ({@code AS $$
   * ... $$}), which is parsed again when it runs and behaves like plpgsql here; only a SQL-standard
   * body ({@code BEGIN ATOMIC ... END} or {@code RETURN ...}) binds its names when the function is
   * created. The remedy for either is in SECURITY-NOTES: {@code ALTER FUNCTION ... SET
   * search_path}, or rewriting the function with a SQL-standard body.
   *
   * @throws com.housedevinci.shredding.domain.ShreddingException {@code SHRED-SCHEMA-008} when the
   *     arrived path cannot be captured or the replacement cannot be established (a {@code
   *     SQLException} in steps 1 to 3, attached as the cause; the statement itself, step 4, still
   *     surfaces its own failure), or when the session is not carrying the bytes it arrived with
   *     once the statement has succeeded. The caller's transaction is expected to roll back: there
   *     is no partial state to repair, and a {@code LOCAL} setting is discarded by {@code COMMIT}
   *     as well as by {@code ROLLBACK} (C-17), so a replaced path can never escape onto a pooled
   *     connection either way.
   */
  static <T> T inOneStatementWindow(Connection c, WindowWork<T> work) throws SQLException {
    if (c.getAutoCommit()) {
      throw isolationFailed(
          "the connection reached the independent read-back in auto-commit, so the"
              + " transaction-local search_path this module replaces for that one statement would"
              + " be discarded before the statement ran and the statement would resolve its names"
              + " on the session's own path. Nothing was changed on the connection. Every erasure"
              + " runs inside JdbcSupport.inTransaction, which sets auto-commit off, so this means"
              + " the connection was handed over by something else.",
          null);
    }
    String arrived;
    try {
      arrived = readSearchPath(c);
    } catch (SQLException e) {
      throw isolationFailed(
          "the session's search_path could not be captured (step 1). Nothing was changed on the"
              + " connection.",
          e);
    }
    Throwable primary = null;
    T result = null;
    try {
      // Steps 2 and 3 establish the window. A SQLException here means the window was never
      // established: that is the isolation code (C-18-4). Only what work.run() throws, after this
      // block, surfaces as itself (M3).
      try {
        try (Statement st = c.createStatement()) {
          st.execute(PIN_SEARCH_PATH);
        }
        String pinned = readSearchPath(c);
        if (!PINNED_PATH.equals(pinned)) {
          throw isolationFailed(
              "the independent read-back's search_path was replaced with '"
                  + PINNED_PATH
                  + "' and read back as '"
                  + pinned
                  + "'. The statement was not run.",
              null);
        }
      } catch (SQLException e) {
        throw isolationFailed(
            "the replacement search_path could not be established (steps 2 and 3).", e);
      }
      result = work.run();
    } catch (SQLException | RuntimeException | Error e) {
      primary = e;
      throw e;
    } finally {
      Throwable closing = closeWindow(c, arrived);
      if (closing != null) {
        if (primary == null) {
          throw closing instanceof ShreddingException refusal
              ? refusal
              : isolationFailed(
                  "the session's search_path could not be restored after the independent"
                      + " read-back, and the read-back itself had succeeded, so the replacement"
                      + " may still be in force inside a transaction that is about to commit.",
                  closing);
        }
        // M3: the statement inside the window failed, which aborts the transaction, so the restore
        // is refused with 25P02 - expected, and the rollback is the restore. The failure that
        // actually happened is the one the caller needs; this one is attached to it.
        primary.addSuppressed(closing);
        log.debug(
            "shredding: the search_path restore was refused after a failure inside the"
                + " one-statement window; the transaction is rolling back, which restores it",
            closing);
      }
    }
    return result;
  }

  /**
   * Steps 5 and 6: the restore and its read-back. Returns the failure rather than throwing it, so
   * the caller decides whether it replaces the original exception or is suppressed by it (M3).
   */
  private static Throwable closeWindow(Connection c, String arrived) {
    try {
      try (PreparedStatement ps = c.prepareStatement(RESTORE_SEARCH_PATH)) {
        ps.setString(1, arrived);
        ps.execute();
      }
      String restored = readSearchPath(c);
      if (!arrived.equals(restored)) {
        return isolationFailed(
            "the session's search_path arrived as '"
                + arrived
                + "' and reads as '"
                + restored
                + "' after the independent read-back. Something moved it inside this"
                + " transaction.",
            null);
      }
      return null;
    } catch (SQLException | RuntimeException e) {
      return e;
    }
  }

  private static String readSearchPath(Connection c) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(READ_SEARCH_PATH)) {
      if (!rs.next()) {
        throw isolationFailed("current_setting('search_path') returned no row", null);
      }
      return rs.getString(1);
    }
  }

  private static ShreddingException isolationFailed(String what, Throwable cause) {
    String message =
        "shredding: the module could not isolate the name resolution of its independent"
            + " read-back - "
            + what
            + " The erasure's transaction is rolled back whole: no key is destroyed, no blind"
            + " index is left half-cleared and no record is appended. This is never a schema"
            + " condition and never means re-apply schema-postgresql.sql.";
    return cause == null
        ? new ShreddingException(ErrorCodes.SCHEMA_NAME_ISOLATION, message)
        : new ShreddingException(ErrorCodes.SCHEMA_NAME_ISOLATION, message, cause);
  }

  static OffsetDateTime ts(Instant i) {
    return i == null ? null : i.atOffset(ZoneOffset.UTC);
  }

  static Instant instant(OffsetDateTime t) {
    return t == null ? null : t.toInstant();
  }

  static final String SCHEMA_RESOURCE = "/com/housedevinci/shredding/schema-postgresql.sql";

  /**
   * Runs the bundled PostgreSQL schema; idempotent.
   *
   * <p><b>Owner role only, and never from application boot.</b> This is DDL: the role that runs it
   * ends up owning the four tables, the sequence, the two indexes and the three guard functions,
   * and an owner can {@code ALTER TABLE ... DISABLE TRIGGER} or {@code CREATE OR REPLACE} a guard
   * into a no-op. Run it from a migration step, a Flyway callback or a one-off job that holds its
   * own credential, then point the application at a role that holds only the grants in
   * SECURITY-NOTES.md "Database roles". The starter calls this exactly once, from {@code
   * ShreddingSchemaGate}, and only when {@code shredding.jdbc.initialize-schema=true}, which warns
   * at every startup that the controls are advisory in that configuration.
   */
  public static void initializeSchema(DataSource ds) {
    inTransaction(
        ds,
        c -> {
          initializeSchema(c);
          return null;
        });
  }

  private static void initializeSchema(Connection c) throws SQLException {
    try (Statement st = c.createStatement()) {
      st.execute(schemaScript());
    }
  }

  static String schemaScript() {
    try (InputStream in = JdbcSupport.class.getResourceAsStream(SCHEMA_RESOURCE)) {
      if (in == null) {
        throw new ShreddingException(
            ErrorCodes.SCHEMA_UNVERIFIABLE,
            "the bundled schema resource " + SCHEMA_RESOURCE + " is missing from the classpath");
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "the bundled schema resource " + SCHEMA_RESOURCE + " could not be read",
          e);
    }
  }

  /**
   * Verifies, on one connection and with catalogue reads only, that the schema in {@code
   * current_schema()} is the one this module's controls rest on and that this role cannot remove
   * those controls. Creates nothing, writes nothing, and never repairs a gap.
   *
   * <p>The strict form: a privileged runtime role is a refusal. This is the assertion a non-Spring
   * caller should make at its own startup, right after handing the adapters their {@code
   * DataSource}.
   *
   * @return the schema that was verified. Hand it to {@link JdbcKeyProvider} and {@link
   *     JdbcErasureStore} so that "the schema that was verified" and "the schema that is written
   *     to" are the same name by construction (design §16).
   * @throws com.housedevinci.shredding.domain.ShreddingException {@code SHRED-SCHEMA-001} to {@code
   *     -005} and {@code -007}; see {@link ErrorCodes}
   */
  public static SchemaVerdict verifySchema(DataSource ds) {
    return verifySchema(ds, false);
  }

  /**
   * @param allowPrivilegedRuntimeRole when true, {@code SHRED-SCHEMA-004} is not thrown and the
   *     legs that fired are returned in {@link SchemaVerdict#privilegeLegs()} for the caller to
   *     warn about at every startup. {@code SHRED-SCHEMA-007} is never downgraded.
   */
  public static SchemaVerdict verifySchema(DataSource ds, boolean allowPrivilegedRuntimeRole) {
    try (Connection c = ds.getConnection()) {
      return SchemaVerification.verify(c, allowPrivilegedRuntimeRole);
    } catch (SQLException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the schema could not be verified because no connection could be obtained"
              + " (SQLState "
              + e.getSQLState()
              + "). Unverifiable is not clean, so this is a refusal.",
          e);
    }
  }

  /**
   * Applies the bundled script and verifies the result, in one transaction and therefore inside the
   * script's own {@code pg_advisory_xact_lock}, so two instances starting together cannot
   * interleave create-then-verify. Only the {@code initialize-schema=true} path uses this.
   *
   * <p>A DDL failure is {@code SHRED-SCHEMA-006} carrying the SQLState and nothing else: the
   * driver's message can quote a statement, and the operator needs to be told that the role lacks
   * DDL rights and that the supported path is an owner-applied script, not to be handed a raw
   * {@code permission denied for schema public}.
   */
  public static SchemaVerdict initializeAndVerifySchema(
      DataSource ds, boolean allowPrivilegedRuntimeRole) {
    try (Connection c = ds.getConnection()) {
      boolean previous = c.getAutoCommit();
      c.setAutoCommit(false);
      try {
        try {
          initializeSchema(c);
        } catch (SQLException ddl) {
          c.rollback();
          throw new ShreddingException(
              ErrorCodes.SCHEMA_CREATION_FAILED,
              "shredding: shredding.jdbc.initialize-schema=true, and running the bundled"
                  + " schema-postgresql.sql with this application's own database credentials"
                  + " failed (SQLState "
                  + ddl.getSQLState()
                  + "). The usual cause is that this role cannot run DDL here: CREATE TABLE needs"
                  + " CREATE on the schema, and CREATE INDEX IF NOT EXISTS and CREATE OR REPLACE"
                  + " FUNCTION both need ownership of the object that already exists, so granting"
                  + " CREATE is not enough on a schema someone else created. The supported path is"
                  + " the other way round: apply the script once with a privileged role, grant this"
                  + " role the statements in SECURITY-NOTES.md \"Database roles\", and leave"
                  + " shredding.jdbc.initialize-schema=false. See docs/upgrading-0.2.0.md. The"
                  + " driver's own message is not repeated here because it can quote a statement.",
              ddl);
        }
        // The caller's transaction, which has just run the DDL under the script's advisory lock:
        // not read-only and not a fresh snapshot, and it must not be made either (C-13-4).
        SchemaVerdict verdict =
            SchemaVerification.verifyInCallersTransaction(c, allowPrivilegedRuntimeRole);
        c.commit();
        return verdict;
      } catch (RuntimeException e) {
        c.rollback();
        throw e;
      } finally {
        c.setAutoCommit(previous);
      }
    } catch (SQLException e) {
      throw new ShreddingException(
          ErrorCodes.SCHEMA_UNVERIFIABLE,
          "shredding: the schema step could not run because no connection could be obtained"
              + " (SQLState "
              + e.getSQLState()
              + ").",
          e);
    }
  }

  /**
   * A database failure is a key-store <em>outage</em>, never an erasure (control 16): the caller
   * answers 503 and the health indicator goes DOWN. Conflating the two would turn a database
   * incident into an apparent completed erasure, and with control 11 in place into a real one.
   */
  static KeyUnavailableException unavailable(SQLException cause) {
    // The driver's message can carry a bind value; only the SQLState is kept.
    return new KeyUnavailableException(
        "shredding key store is unavailable ("
            + ErrorCodes.KEY_UNAVAILABLE
            + ", SQLState "
            + cause.getSQLState()
            + ")",
        cause);
  }
}
