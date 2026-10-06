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
 * Security review, pass 2 of feat/audit-table-coverage (PR 25): attacks on the C-25-1 fix (every
 * erasure pinned to READ COMMITTED). A per-session default set by the pool's init SQL, which the
 * pool does not track, and a connection handed over inside a caller's REPEATABLE READ transaction
 * that has already taken its snapshot (a transaction-aware DataSource under @Transactional).
 */
class CipherProbePr25Pass2Test {

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
  void probe_session_default_serializable_from_init_sql_is_pinned_and_restored() throws Exception {
    String table = "app.p2_sess";
    table(table);
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(APP);
    config.setPassword("pw");
    config.setMaximumPoolSize(1);
    config.setConnectionInitSql(
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    HikariDataSource ds = new HikariDataSource(config);
    pools.add(ds);
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
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(records()).isEqualTo(records);
    assertThat(text(ds, "SHOW transaction_isolation"))
        .describedAs("the application's own session default after an erasure")
        .isEqualTo("serializable");
  }

  @Test
  void probe_connection_inside_a_callers_repeatable_read_transaction_is_refused_not_committed()
      throws Exception {
    String table = "app.p2_caller";
    table(table);
    exec(
        owner,
        "CREATE TABLE app.p2_caller_side (v int)",
        "GRANT INSERT ON app.p2_caller_side TO " + APP);
    HikariDataSource raw = pool(APP, "pw", null);
    Connection bound = raw.getConnection();
    bound.setAutoCommit(false);
    bound.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
    try (Statement st = bound.createStatement()) {
      st.execute("INSERT INTO app.p2_caller_side VALUES (1)");
    }
    // What TransactionAwareDataSourceProxy hands out under @Transactional: the bound connection,
    // and close() does not close it.
    DataSource proxy =
        (DataSource)
            java.lang.reflect.Proxy.newProxyInstance(
                DataSource.class.getClassLoader(),
                new Class<?>[] {DataSource.class},
                (p, m, args) -> {
                  if ("getConnection".equals(m.getName())) {
                    return java.lang.reflect.Proxy.newProxyInstance(
                        Connection.class.getClassLoader(),
                        new Class<?>[] {Connection.class},
                        (cp, cm, cargs) -> {
                          if ("close".equals(cm.getName())) {
                            return null;
                          }
                          try {
                            return cm.invoke(bound, cargs);
                          } catch (java.lang.reflect.InvocationTargetException e) {
                            throw e.getCause();
                          }
                        });
                  }
                  return m.invoke(raw, args);
                });
    JdbcErasureStore store = store(proxy, table, (c, col, tenant, subject) -> 0L);
    long records = records();
    Throwable thrown = catchThrowable(() -> erase(store, table + "-s-1"));
    bound.rollback();
    bound.close();
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_NAME_ISOLATION);
    assertThat(records()).isEqualTo(records);
    assertThat(text(su, "SELECT count(*) FROM app.p2_caller_side"))
        .describedAs("the caller's uncommitted row must not have been committed by the erasure")
        .isEqualTo("0");
  }

  // ------------------------------------------------------------------------------ helpers

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
