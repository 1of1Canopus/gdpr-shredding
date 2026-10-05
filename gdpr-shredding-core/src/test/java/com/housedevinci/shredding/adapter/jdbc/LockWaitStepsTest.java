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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * RC-10: every wait of the erasure transaction that the connection's lock_timeout (or the deadlock
 * detector) can end is reported as SHRED-ERASURE-LOCK-WAIT naming the step, never as a key-store
 * outage. One test per lock site.
 */
@Testcontainers
class LockWaitStepsTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final byte[] SECRET =
      "rc-lock-steps-test-secret-32byte".getBytes(java.nio.charset.StandardCharsets.UTF_8);

  @Test
  void the_subjects_advisory_lock() throws Exception {
    Throwable thrown =
        withTable(
            "rc_ls_adv",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(1398096458,"
                        + " pg_catalog.hashtext('|2:t1|2:s1'))");
              }
              return catchThrowable(() -> erase(store));
            });
    assertLockWait(thrown, "advisory lock", "55P03");
  }

  @Test
  void the_subjects_key_rows() throws Exception {
    Throwable thrown =
        withTable(
            "rc_ls_key",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute(
                    "INSERT INTO public.shredding_data_key (tenant, subject, version, wrapped_key,"
                        + " state, created_at) VALUES ('t1', 's1', 1, '\\x00'::bytea, 'ACTIVE',"
                        + " now()) ON CONFLICT DO NOTHING");
                holder.commit();
                st.execute(
                    "SELECT version FROM public.shredding_data_key WHERE tenant = 't1'"
                        + " AND subject = 's1' FOR UPDATE");
              }
              return catchThrowable(() -> erase(store));
            });
    assertLockWait(thrown, "key rows", "55P03");
  }

  @Test
  void the_blind_index_update_waiting_on_an_application_row() throws Exception {
    Throwable thrown =
        withTable(
            "rc_ls_row",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("UPDATE public.rc_ls_row SET email_idx = email_idx WHERE id = 1");
              }
              return catchThrowable(() -> erase(store));
            });
    assertLockWait(thrown, "blind-index update", "55P03");
  }

  @Test
  void the_erasure_log_chain_lock() throws Exception {
    Throwable thrown =
        withTable(
            "rc_ls_chain",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("SELECT pg_catalog.pg_advisory_xact_lock(" + 0x5348455241L + ")");
              }
              return catchThrowable(() -> erase(store));
            });
    assertLockWait(thrown, "erasure-log append", "55P03");
  }

  /**
   * 40P01 on a step other than the table lock: the erasure holds the subject lock, waits for the
   * chain lock.
   */
  @Test
  void a_deadlock_on_the_erasure_log_chain_lock() throws Exception {
    Throwable thrown =
        withTable(
            "rc_ls_dl",
            "SET deadlock_timeout = '2s'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("SELECT pg_catalog.pg_advisory_xact_lock(" + 0x5348455241L + ")");
              }
              CompletableFuture<Throwable> erasure =
                  CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store)));
              Thread.sleep(500);
              try (Statement st = holder.createStatement()) {
                st.execute("SET deadlock_timeout = '10s'");
                st.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(1398096458,"
                        + " pg_catalog.hashtext('|2:t1|2:s1'))");
              } catch (java.sql.SQLException holderLost) {
                // the holder may lose the race; the erasure is then not the victim
              }
              return erasure.get(30, TimeUnit.SECONDS);
            });
    assertLockWait(thrown, "erasure-log append", "40P01");
  }

  private static void assertLockWait(Throwable thrown, String step, String state) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.ERASURE_LOCK_WAIT);
    assertThat(thrown.getMessage()).contains(step).contains(state);
  }

  interface Scenario {
    Throwable run(Connection holder, JdbcErasureStore store) throws Exception;
  }

  private static Throwable withTable(String table, String initSql, Scenario scenario)
      throws Exception {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(POSTGRES.getUsername());
    config.setPassword(POSTGRES.getPassword());
    config.setMaximumPoolSize(2);
    config.setConnectionInitSql(initSql);
    try (var ds = new HikariDataSource(config);
        Connection holder =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
      JdbcSupport.initializeSchema(ds);
      VerifiedSchema schema = JdbcSupport.verifySchema(ds, true).schema();
      try (Statement st = holder.createStatement()) {
        st.execute(
            "CREATE TABLE public."
                + table
                + " (id bigint PRIMARY KEY, tenant text NOT NULL,"
                + " subject text NOT NULL, email_idx bytea)");
        st.execute("INSERT INTO public." + table + " VALUES (1, 't1', 's1', '\\x01')");
      }
      holder.setAutoCommit(false);
      var column =
          new BlindIndexColumn(
              TableRef.parse("public." + table),
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
      try {
        return scenario.run(holder, store);
      } finally {
        holder.rollback();
      }
    }
  }

  private static void erase(JdbcErasureStore store) {
    TenantId t = TenantId.of("t1");
    SubjectId s = SubjectId.of("s1");
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
                Instant.now().plus(Duration.ofDays(30))));
  }
}
