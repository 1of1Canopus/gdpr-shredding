package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.JdbcSupport.instant;
import static com.housedevinci.shredding.adapter.jdbc.JdbcSupport.ts;

import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.domain.Aes256Gcm;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.KeyState;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/**
 * Data keys in a PostgreSQL table, each wrapped under the master key (control 1, 5).
 *
 * <p>Every key is 256 random bits from {@link RandomSource}. None is derived from the master key: a
 * derived key stays re-derivable by anyone holding the master, which makes erasure a no-op.
 *
 * <p>A key is minted lazily on the first write for a subject. A subject whose key row is {@code
 * DESTROYING} or {@code DESTROYED} is never given a fresh one: that would silently undo the erasure
 * on the next write (control 11).
 */
public final class JdbcKeyProvider implements KeyProvider {

  private final DataSource dataSource;
  private final MasterKey masterKey;
  private final RandomSource random;
  private final Clock clock;

  public JdbcKeyProvider(
      DataSource dataSource, MasterKey masterKey, RandomSource random, Clock clock) {
    this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    this.masterKey = Objects.requireNonNull(masterKey, "masterKey");
    this.random = Objects.requireNonNull(random, "random");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Unwrapped currentForWrite(TenantId tenant, SubjectId subject) {
    return JdbcSupport.inTransaction(
        dataSource,
        c -> {
          Row row = highestVersion(c, tenant, subject, true);
          if (row == null) {
            return mint(c, tenant, subject, 1);
          }
          if (row.state != KeyState.ACTIVE) {
            throw new ShreddingException(
                ErrorCodes.ERASED,
                "the data key for this subject is "
                    + row.state
                    + "; a shredded value cannot be written for an erased subject");
          }
          return unwrap(tenant, subject, row);
        });
  }

  @Override
  public Optional<Unwrapped> forRead(TenantId tenant, SubjectId subject, int version) {
    return JdbcSupport.withConnection(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "SELECT version, wrapped_key, state, encryption_count, created_at"
                      + " FROM shredding_data_key WHERE tenant = ? AND subject = ? AND version = ?")) {
            ps.setString(1, tenant.value());
            ps.setString(2, subject.value());
            ps.setInt(3, version);
            try (ResultSet rs = ps.executeQuery()) {
              if (!rs.next()) {
                // The row is gone. That is a destroyed key, and it is the only reading of a
                // missing row: an outage arrives as a JdbcAccessException, never as an empty
                // result.
                return Optional.empty();
              }
              return Optional.of(unwrap(tenant, subject, map(rs)));
            }
          }
        });
  }

  @Override
  public long recordEncryptions(TenantId tenant, SubjectId subject, int version, int count) {
    return JdbcSupport.inTransaction(
        dataSource,
        c -> {
          try (PreparedStatement ps =
              c.prepareStatement(
                  "UPDATE shredding_data_key SET encryption_count = encryption_count + ?"
                      + " WHERE tenant = ? AND subject = ? AND version = ?"
                      + " RETURNING encryption_count")) {
            ps.setInt(1, count);
            ps.setString(2, tenant.value());
            ps.setString(3, subject.value());
            ps.setInt(4, version);
            try (ResultSet rs = ps.executeQuery()) {
              if (!rs.next()) {
                throw new ShreddingException(
                    ErrorCodes.ERASED, "the data key row is gone; the subject has been erased");
              }
              return rs.getLong(1);
            }
          }
        });
  }

  @Override
  public Unwrapped rotate(TenantId tenant, SubjectId subject) {
    return JdbcSupport.inTransaction(
        dataSource,
        c -> {
          Row row = highestVersion(c, tenant, subject, true);
          if (row != null && row.state != KeyState.ACTIVE) {
            throw new ShreddingException(
                ErrorCodes.ERASED, "cannot rotate the key of an erased subject");
          }
          return mint(c, tenant, subject, row == null ? 1 : row.version + 1);
        });
  }

  @Override
  public boolean healthy() {
    try {
      return JdbcSupport.withConnection(
          dataSource,
          c -> {
            try (PreparedStatement ps =
                c.prepareStatement("SELECT 1 FROM shredding_data_key LIMIT 0")) {
              ps.executeQuery().close();
              return true;
            }
          });
    } catch (RuntimeException e) {
      return false;
    }
  }

  private Unwrapped mint(Connection c, TenantId tenant, SubjectId subject, int version)
      throws SQLException {
    byte[] material = random.dataKey();
    try {
      byte[] wrapped = masterKey.wrap(tenant, subject, version, material, random);
      try (PreparedStatement ps =
          c.prepareStatement(
              "INSERT INTO shredding_data_key"
                  + " (tenant, subject, version, wrapped_key, state, encryption_count, created_at)"
                  + " VALUES (?,?,?,?,?,0,?)")) {
        ps.setString(1, tenant.value());
        ps.setString(2, subject.value());
        ps.setInt(3, version);
        ps.setBytes(4, wrapped);
        ps.setString(5, KeyState.ACTIVE.name());
        ps.setObject(6, ts(clock.instant()));
        ps.executeUpdate();
      }
      return new Unwrapped(material, version, KeyState.ACTIVE);
    } finally {
      Aes256Gcm.wipe(material);
    }
  }

  private Unwrapped unwrap(TenantId tenant, SubjectId subject, Row row) {
    byte[] material = masterKey.unwrap(tenant, subject, row.version, row.wrappedKey);
    try {
      return new Unwrapped(material, row.version, row.state);
    } finally {
      Aes256Gcm.wipe(material);
    }
  }

  private record Row(
      int version,
      byte[] wrappedKey,
      KeyState state,
      long encryptionCount,
      java.time.Instant createdAt) {}

  private static Row highestVersion(
      Connection c, TenantId tenant, SubjectId subject, boolean forUpdate) throws SQLException {
    String sql =
        "SELECT version, wrapped_key, state, encryption_count, created_at FROM shredding_data_key"
            + " WHERE tenant = ? AND subject = ? ORDER BY version DESC LIMIT 1"
            + (forUpdate ? " FOR UPDATE" : "");
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setString(1, tenant.value());
      ps.setString(2, subject.value());
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next() ? map(rs) : null;
      }
    }
  }

  private static Row map(ResultSet rs) throws SQLException {
    return new Row(
        rs.getInt("version"),
        rs.getBytes("wrapped_key"),
        KeyState.valueOf(rs.getString("state")),
        rs.getLong("encryption_count"),
        instant(rs.getObject("created_at", OffsetDateTime.class)));
  }
}
