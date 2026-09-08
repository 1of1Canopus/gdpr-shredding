package com.housedevinci.shredding.adapter.jdbc;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyUnavailableException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
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
