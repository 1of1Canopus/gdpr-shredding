package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyUnavailableException;
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
   * The fixed salt handed to {@code hashtextextended} so this namespace of advisory locks cannot
   * collide with the schema step's own single-key lock or with {@code JdbcErasureStore}'s chain
   * append lock, which both use plain {@code bigint} keys.
   */
  private static final long SUBJECT_LOCK_SALT = 6072873668427846209L;

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
        c.prepareStatement("SELECT pg_advisory_xact_lock(hashtextextended(?, ?))")) {
      ps.setString(1, tenant.value() + "|" + subject.value());
      ps.setLong(2, SUBJECT_LOCK_SALT);
      ps.execute();
    }
  }

  static OffsetDateTime ts(Instant i) {
    return i == null ? null : i.atOffset(ZoneOffset.UTC);
  }

  static Instant instant(OffsetDateTime t) {
    return t == null ? null : t.toInstant();
  }

  /** Runs the bundled PostgreSQL schema; idempotent. */
  public static void initializeSchema(DataSource ds) {
    String sql;
    try (InputStream in =
        JdbcSupport.class.getResourceAsStream(
            "/com/housedevinci/shredding/schema-postgresql.sql")) {
      if (in == null) {
        throw new IllegalStateException("schema-postgresql.sql missing from classpath");
      }
      sql = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("cannot read schema", e);
    }
    inTransaction(
        ds,
        c -> {
          try (Statement st = c.createStatement()) {
            st.execute(sql);
          }
          return null;
        });
  }

  /** True when the current database role owns the erasure table and could disable its triggers. */
  public static boolean runtimeRoleOwnsErasureTable(DataSource ds) {
    return withConnection(
        ds,
        c -> {
          try (Statement st = c.createStatement();
              var rs =
                  st.executeQuery(
                      "SELECT tableowner = current_user FROM pg_tables"
                          + " WHERE tablename = 'shredding_erasure'")) {
            return rs.next() && rs.getBoolean(1);
          }
        });
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
