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
