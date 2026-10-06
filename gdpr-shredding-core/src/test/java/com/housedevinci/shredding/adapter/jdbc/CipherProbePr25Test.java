package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, pass 1 of feat/audit-table-coverage (PR 25). C-25-1: the catalogue leg reads
 * pg_catalog with the erasure transaction's snapshot. Under REPEATABLE READ or SERIALIZABLE (a pool
 * or role default the module does not override) that snapshot is taken by the subject's
 * advisory-lock SELECT, before the table locks, so both verdict positions are blind to a trigger or
 * materialized view committed after it. Each probe is the RC-passing k4 / t6 scenario with only the
 * pool's isolation changed; each must refuse with SHRED-SCHEMA-010 like its RC twin.
 */
class CipherProbePr25Test {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withCommand("postgres", "-c", "fsync=off")
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String OWNER = "shred_owner";
  private static final String APP = "shred_app";
  private static final byte[] SECRET =
      "copy-catalogue-chain-secret-32-by".getBytes(StandardCharsets.UTF_8);
  private static final TenantId T1 = TenantId.of("T1");

  private static final List<HikariDataSource> pools = new ArrayList<>();
  private static HikariDataSource su;
  private static HikariDataSource owner;
  private static VerifiedSchema schema;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    su = pool(POSTGRES.getUsername(), POSTGRES.getPassword(), null);
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app TO " + APP);
    owner = pool(OWNER, "pw", null);
    JdbcSupport.initializeSchema(owner);
    exec(
        owner,
        "GRANT USAGE ON SCHEMA public TO " + APP,
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);
    schema = JdbcSupport.verifySchema(pool(APP, "pw", null), true).schema();
  }

  @AfterAll
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  @Test
  void probe_repeatable_read_erasure_misses_a_matview_created_between_update_and_recheck()
      throws Exception {
    matviewDuringErasure("app.rr_mv", "TRANSACTION_REPEATABLE_READ");
  }

  @Test
  void probe_serializable_erasure_misses_a_matview_created_between_update_and_recheck()
      throws Exception {
    matviewDuringErasure("app.sz_mv", "TRANSACTION_SERIALIZABLE");
  }

  @Test
  void probe_repeatable_read_erasure_fires_a_trigger_its_verdicts_cannot_see() throws Exception {
    String table = "app.rr_tg";
    table(table);
    exec(
        owner,
        "CREATE TABLE app.rr_tg_hist (email_idx varchar(64))",
        "CREATE FUNCTION app.rr_tg_copy() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER"
            + " SET search_path = pg_catalog AS $$ BEGIN INSERT INTO app.rr_tg_hist"
            + " VALUES (OLD.email_idx); RETURN NEW; END $$");
    HikariDataSource rr = pool(APP, "pw", "TRANSACTION_REPEATABLE_READ");
    JdbcErasureStore store = store(rr, table, (c, col, tenant, subject) -> 0L);
    long records = records();
    try (Connection ddl = owner.getConnection()) {
      ddl.setAutoCommit(false);
      try (Statement st = ddl.createStatement()) {
        st.execute(
            "CREATE TRIGGER rr_tg_audit AFTER UPDATE ON app.rr_tg FOR EACH ROW"
                + " EXECUTE FUNCTION app.rr_tg_copy()");
      }
      CompletableFuture<Throwable> erasure =
          CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store, table + "-s-1")));
      awaitLockWait();
      ddl.commit();
      Throwable thrown = erasure.get(30, TimeUnit.SECONDS);

      long copied =
          Long.parseLong(
              text(su, "SELECT count(*) FROM app.rr_tg_hist WHERE email_idx IS NOT NULL"));
      assertThat(copied).describedAs("index values the trigger copied").isZero();
      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
      assertThat(records()).isEqualTo(records);
    }
  }

  // ------------------------------------------------------------------------------ helpers

  private void matviewDuringErasure(String table, String isolation) throws Exception {
    table(table);
    HikariDataSource ds = pool(APP, "pw", isolation);
    var during = new BlockingReadBack();
    JdbcErasureStore store = store(ds, table, during);
    long records = records();
    CompletableFuture<Throwable> erasure =
        CompletableFuture.supplyAsync(() -> catchThrowable(() -> erase(store, table + "-s-1")));
    during.awaitInside();
    try {
      exec(owner, "CREATE MATERIALIZED VIEW " + table + "_v AS SELECT email_idx FROM " + table);
    } finally {
      during.release();
    }
    Throwable thrown = erasure.get(30, TimeUnit.SECONDS);
    assertThat(thrown)
        .describedAs("the %s twin of k4 must refuse like the READ COMMITTED one", isolation)
        .isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(records()).isEqualTo(records);
  }

  private static void awaitLockWait() throws InterruptedException {
    for (int i = 0; i < 300; i++) {
      if (Long.parseLong(
              text(
                  su,
                  "SELECT count(*) FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a"
                      + " USING (pid) WHERE NOT l.granted AND a.usename = '"
                      + APP
                      + "'"))
          > 0) {
        return;
      }
      Thread.sleep(50);
    }
    throw new AssertionError("the erasure never waited for the uncommitted CREATE TRIGGER");
  }

  private static final class BlockingReadBack implements BlindIndexResidual {
    private final CountDownLatch inside = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);

    @Override
    public long count(Connection c, BlindIndexColumn column, TenantId tenant, SubjectId subject) {
      inside.countDown();
      try {
        release.await(30, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return 0L;
    }

    void awaitInside() throws InterruptedException {
      assertThat(inside.await(30, TimeUnit.SECONDS)).isTrue();
    }

    void release() {
      release.countDown();
    }
  }

  private static void table(String table) {
    exec(
        owner,
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64),"
            + " note text)",
        "GRANT SELECT, UPDATE ON " + table + " TO " + APP,
        "INSERT INTO "
            + table
            + " (id, tenant, subject, email_idx) SELECT g, 'T1', '"
            + table
            + "-s-' || g, md5(g::text) FROM generate_series(1, 5) g");
  }

  private static JdbcErasureStore store(DataSource ds, String table, BlindIndexResidual residual) {
    return new JdbcErasureStore(
        ds,
        schema,
        ErasureChain.keyed(SECRET, "k1"),
        List.of(
            new BlindIndexColumn(
                TableRef.parse(table),
                ColumnRef.unquoted("email_idx"),
                ColumnRef.unquoted("subject"),
                ColumnRef.unquoted("tenant"),
                Optional.of("tenant"),
                Optional.of("subject"))),
        residual,
        CopySignatures.defaults());
  }

  private static com.housedevinci.shredding.application.ErasureStore.Outcome erase(
      JdbcErasureStore store, String subjectId) {
    SubjectId subject = SubjectId.of(subjectId);
    return store.erase(
        T1,
        subject,
        (destroyed, cleared) ->
            ErasureRecord.of(
                Instant.now(),
                T1,
                new Pseudonymiser(SECRET).pseudonym(T1, subject),
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

  private static long records() {
    return Long.parseLong(text(su, "SELECT count(*) FROM public.shredding_erasure"));
  }

  private static HikariDataSource pool(String user, String password, String isolation) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    if (isolation != null) {
      config.setTransactionIsolation(isolation);
    }
    var ds = new HikariDataSource(config);
    pools.add(ds);
    return ds;
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
