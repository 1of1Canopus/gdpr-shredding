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
 * Release-candidate review 0.2.0, pass 2 (PR 21), RC-7 fix attacked. The fix maps 55P03 and 40P01
 * only inside {@code JdbcErasureStore.lock}. The guide and SECURITY-NOTES now say "When that bound
 * fires, or the database picks the erasure as a deadlock victim, the erasure is refused with
 * SHRED-ERASURE-LOCK-WAIT ... It is not a key-store outage." The same lock_timeout also bounds the
 * erasure's other waits: the blind-index UPDATE waiting for the application's own row lock on the
 * subject's row is the commonest, and it is still reported as SHRED-KEY-UNAVAILABLE.
 */
@Testcontainers
class CipherProbeRc020Pass2LockTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final byte[] SECRET =
      "rc-lock-pass2-probe-secret-32b!!".getBytes(java.nio.charset.StandardCharsets.UTF_8);

  /** RC-10: an application transaction holds the subject's row; the erasure's UPDATE times out. */
  @Test
  void probe_a_lock_timeout_on_the_subjects_row_is_still_reported_as_key_store_unavailable()
      throws Exception {
    Throwable thrown =
        withTable(
            "rc_p2_row",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("UPDATE public.rc_p2_row SET email_idx = email_idx WHERE id = 1");
              }
              return catchThrowable(() -> erase(store));
            });
    System.out.println("CIPHER-RC10 row lock timeout -> " + thrown);
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code())
        .describedAs("the bound the guide recommends fired; the guide promises LOCK-WAIT")
        .isEqualTo(ErrorCodes.ERASURE_LOCK_WAIT);
  }

  /** Confirmation of RC-7: 55P03 on the table lock carries exactly the new code. */
  @Test
  void rc_a_lock_timeout_on_the_table_lock_is_exactly_lock_wait() throws Exception {
    Throwable thrown =
        withTable(
            "rc_p2_tbl",
            "SET lock_timeout = '300ms'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("LOCK TABLE public.rc_p2_tbl IN SHARE UPDATE EXCLUSIVE MODE");
              }
              return catchThrowable(() -> erase(store));
            });
    System.out.println("CIPHER-RC7 table lock timeout -> " + thrown);
    assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-ERASURE-LOCK-WAIT");
    assertThat(thrown.getMessage())
        .contains("rc_p2_tbl")
        .contains("SHARE UPDATE EXCLUSIVE MODE")
        .contains("55P03");
  }

  /**
   * Confirmation of RC-7, 40P01: the holder takes SHARE on the table (blocks the erasure's ROW
   * EXCLUSIVE), then asks for the subject's advisory lock the waiting erasure holds. The erasure
   * waited first and checks after 2s, the holder after 10s, so the erasure is the victim.
   */
  @Test
  void rc_a_deadlock_on_the_table_lock_is_exactly_lock_wait() throws Exception {
    Throwable thrown =
        withTable(
            "rc_p2_dl",
            "SET deadlock_timeout = '2s'",
            (holder, store) -> {
              try (Statement st = holder.createStatement()) {
                st.execute("LOCK TABLE public.rc_p2_dl IN SHARE MODE");
              }
              CompletableFuture<Throwable> erasure =
                  CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store)));
              Thread.sleep(300);
              try (Statement st = holder.createStatement()) {
                st.execute("SET deadlock_timeout = '10s'");
                st.execute(
                    "SELECT pg_catalog.pg_advisory_xact_lock(1398096458,"
                        + " pg_catalog.hashtext('|2:t1|2:s1'))");
              } catch (java.sql.SQLException holderLost) {
                System.out.println("CIPHER-RC7 holder was the victim: " + holderLost);
              }
              return erasure.get(30, TimeUnit.SECONDS);
            });
    System.out.println("CIPHER-RC7 deadlock -> " + thrown);
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-ERASURE-LOCK-WAIT");
    assertThat(thrown.getMessage()).contains("40P01");
  }

  // ---------------------------------------------------------------------------------------------

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
