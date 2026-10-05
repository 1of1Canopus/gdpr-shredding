package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Release-candidate whole-module pass, 0.2.0, lead 2 (a seam of mapping admission's lock and the
 * error mapping). The guide and the release notes tell the operator: "Set a lock_timeout on the
 * erasure's connection if that wait must be bounded." When that bound fires - the erasure waited
 * behind a manual VACUUM, an ANALYZE, a CREATE INDEX CONCURRENTLY or another erasure of the same
 * table - {@code JdbcErasureStore.lock} rethrows SQLState 55P03 unmapped and {@code
 * JdbcSupport.inTransaction} reports it as SHRED-KEY-UNAVAILABLE, "shredding key store is
 * unavailable": the operator is sent to the key store for a lock wait on an application table, the
 * same misdirection C-19-3 and C-18-4 closed for other causes.
 */
@Testcontainers
class CipherProbeRc020LockTimeoutTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final byte[] SECRET =
      "rc-lock-timeout-probe-secret-32b".getBytes(java.nio.charset.StandardCharsets.UTF_8);

  @Test
  void probe_a_lock_timeout_the_guide_recommends_is_reported_as_key_store_unavailable()
      throws Exception {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(POSTGRES.getUsername());
    config.setPassword(POSTGRES.getPassword());
    config.setMaximumPoolSize(2);
    config.setConnectionInitSql("SET lock_timeout = '300ms'");
    try (var ds = new HikariDataSource(config);
        Connection holder =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
      JdbcSupport.initializeSchema(ds);
      VerifiedSchema schema = JdbcSupport.verifySchema(ds, true).schema();
      try (Statement st = holder.createStatement()) {
        st.execute(
            "CREATE TABLE public.rc_lt_note (id bigint PRIMARY KEY, tenant text NOT NULL,"
                + " subject text NOT NULL, email_idx bytea)");
        st.execute("INSERT INTO public.rc_lt_note VALUES (1, 't1', 's1', '\\x01')");
      }
      // Another erasure of the same table (or a manual VACUUM) holds SHARE UPDATE EXCLUSIVE.
      holder.setAutoCommit(false);
      try (Statement st = holder.createStatement()) {
        st.execute("LOCK TABLE public.rc_lt_note IN SHARE UPDATE EXCLUSIVE MODE");
      }
      var column =
          new BlindIndexColumn(
              TableRef.parse("public.rc_lt_note"),
              ColumnRef.unquoted("email_idx"),
              ColumnRef.unquoted("subject"),
              ColumnRef.unquoted("tenant"),
              Optional.of("tenant"),
              Optional.of("subject"));
      var store =
          new JdbcErasureStore(
              ds,
              schema,
              ErasureChain.keyed(SECRET, "k1"),
              List.of(column),
              (c, col, tenant, subject) -> 0L);
      TenantId t = TenantId.of("t1");
      SubjectId s = SubjectId.of("s1");
      Throwable thrown =
          catchThrowable(
              () ->
                  store.erase(
                      t,
                      s,
                      (destroyed, cleared) ->
                          ErasureRecord.of(
                              Instant.now(),
                              t,
                              "0".repeat(64),
                              "dpo",
                              "art 17",
                              destroyed,
                              1,
                              1,
                              cleared,
                              ErasureOutcome.COMPLETE,
                              List.of(),
                              Instant.now().plus(Duration.ofDays(30)))));
      holder.rollback();
      System.out.println("CIPHER-RC lock timeout -> " + thrown);
      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code())
          .describedAs("a lock wait on an application table is not a key-store outage")
          .isNotEqualTo(ErrorCodes.KEY_UNAVAILABLE);
    }
  }
}
