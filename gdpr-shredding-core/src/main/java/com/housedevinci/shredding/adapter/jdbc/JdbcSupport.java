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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import javax.sql.DataSource;

/** Plain-JDBC helpers shared by the adapters. No Spring. */
public final class JdbcSupport {

  private JdbcSupport() {}

  @FunctionalInterface
  interface SqlWork<T> {
    T run(Connection c) throws SQLException;
  }

  static <T> T inTransaction(DataSource ds, SqlWork<T> work) {
    try (Connection c = ds.getConnection()) {
      boolean previous = c.getAutoCommit();
      c.setAutoCommit(false);
      try {
        T result = work.run(c);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      } finally {
        c.setAutoCommit(previous);
      }
    } catch (SQLException e) {
      throw unavailable(e);
    }
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
        c.prepareStatement("SELECT pg_advisory_xact_lock(?, hashtext(?))")) {
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
