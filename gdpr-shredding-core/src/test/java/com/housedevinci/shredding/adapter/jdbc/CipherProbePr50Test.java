package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

/** Security review pass 1 of PR 50 (C-RC021-1 fix): R50-2 and R50-3. */
class CipherProbePr50Test {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static HikariDataSource appDs;
  private static HikariDataSource ownerDs;
  private static final List<String> calls = new CopyOnWriteArrayList<>();

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
    ownerDs = TwoRoleCluster.pool(PG, TwoRoleCluster.OWNER, PASSWORD, PG.getDatabaseName());
    exec(
        ownerDs,
        "CREATE TABLE public.caller_mark (id int)",
        "GRANT SELECT, INSERT ON public.caller_mark TO " + APP);
  }

  @AfterAll
  static void stop() {
    appDs.close();
    ownerDs.close();
    PG.stop();
  }

  private static JdbcKeyProvider keys(DataSource ds) {
    return new JdbcKeyProvider(
        JdbcSupport.verifySchema(ds).schema(),
        MasterKey.fromBytes(new byte[32]),
        RandomSource.secure(),
        Clock.systemUTC());
  }

  /** Records every Connection method the module calls, then delegates. */
  private static DataSource recording(DataSource target) {
    return (DataSource)
        Proxy.newProxyInstance(
            DataSource.class.getClassLoader(),
            new Class<?>[] {DataSource.class},
            (p, m, a) -> {
              if (!m.getName().equals("getConnection")) {
                try {
                  return m.invoke(target, a);
                } catch (InvocationTargetException e) {
                  throw e.getCause();
                }
              }
              Connection real = (Connection) m.invoke(target, a);
              return Proxy.newProxyInstance(
                  Connection.class.getClassLoader(),
                  new Class<?>[] {Connection.class},
                  (cp, cm, ca) -> {
                    calls.add(cm.getName());
                    try {
                      return cm.invoke(real, ca);
                    } catch (InvocationTargetException e) {
                      throw e.getCause();
                    }
                  });
            });
  }

  /** Runs one key write inside a caller transaction; returns the refusal and what it touched. */
  private ShreddingException refusedInside(
      DataSource appSide, java.util.function.Consumer<JdbcKeyProvider> write) throws SQLException {
    var keys = keys(appSide);
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    long before = rows(appDs, "caller_mark");
    var refused =
        tx.execute(
            status -> {
              try (var s = DataSourceUtils.getConnection(appDs).createStatement()) {
                s.execute("INSERT INTO public.caller_mark VALUES (50)");
              } catch (SQLException e) {
                throw new IllegalStateException(e);
              }
              calls.clear();
              var thrown = catchThrowableOfType(ShreddingException.class, () -> write.accept(keys));
              assertThat(advisoryLocks()).describedAs("advisory lock taken").isZero();
              status.setRollbackOnly();
              return thrown;
            });
    assertThat(rows(appDs, "caller_mark")).describedAs("caller rows committed").isEqualTo(before);
    return refused;
  }

  private static long advisoryLocks() {
    try {
      return Long.parseLong(
          scalar(ownerDs, "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory'"));
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void assertRefusedUntouched(ShreddingException e) {
    assertThat(e).describedAs("refused").isNotNull();
    assertThat(e.code()).isEqualTo("SHRED-SCHEMA-008");
    assertThat(calls)
        .describedAs("connection calls before the refusal")
        .containsOnly("getAutoCommit", "close");
  }

  @Test
  void every_key_write_is_refused_before_any_statement_and_lock() throws SQLException {
    var aware = recording(new TransactionAwareDataSourceProxy(appDs));
    var t = TenantId.of("t");
    assertRefusedUntouched(refusedInside(aware, k -> k.currentForWrite(t, SubjectId.of("w1"))));
    assertRefusedUntouched(refusedInside(aware, k -> k.rotate(t, SubjectId.of("w2"))));
    assertRefusedUntouched(
        refusedInside(aware, k -> k.recordEncryptions(t, SubjectId.of("w3"), 1, 1)));
  }

  @Test
  void a_read_inside_the_caller_transaction_still_works() throws SQLException {
    var t = TenantId.of("t");
    var s = SubjectId.of("r1");
    int v = keys(appDs).currentForWrite(t, s).version();
    var aware = keys(new TransactionAwareDataSourceProxy(appDs));
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    Boolean found = tx.execute(status -> aware.forRead(t, s, v).isPresent());
    assertThat(found).isTrue();
  }

  /** initializeSchema opens its own transaction on whatever connection arrives (owner side). */
  @Test
  void probe_initialize_schema_inside_a_caller_transaction_commits_the_caller_rows()
      throws SQLException {
    var aware = new TransactionAwareDataSourceProxy(ownerDs);
    var tx = new TransactionTemplate(new DataSourceTransactionManager(ownerDs));
    long before = rows(ownerDs, "caller_mark");
    ShreddingException refused = null;
    try {
      tx.executeWithoutResult(
          status -> {
            try (var st = DataSourceUtils.getConnection(ownerDs).createStatement()) {
              st.execute("INSERT INTO public.caller_mark VALUES (52)");
            } catch (SQLException e) {
              throw new IllegalStateException(e);
            }
            JdbcSupport.initializeSchema(aware);
            status.setRollbackOnly();
          });
    } catch (ShreddingException e) {
      refused = e;
    }
    assertThat(refused).describedAs("initializeSchema refused").isNotNull();
    assertThat(refused.code()).isEqualTo("SHRED-SCHEMA-008");
    assertThat(rows(ownerDs, "caller_mark"))
        .describedAs("initializeSchema committed a transaction it did not begin")
        .isEqualTo(before);
  }
}
