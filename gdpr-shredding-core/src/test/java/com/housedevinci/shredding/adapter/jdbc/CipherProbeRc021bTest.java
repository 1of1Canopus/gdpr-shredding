package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
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

/**
 * Security review, whole-module pass 0.2.1-b (C-RC021B-1). The verify-only startup path, the
 * default, is the one schema entry point without the caller-transaction refusal of R50-2 and R50-4.
 */
class CipherProbeRc021bTest {

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
        "CREATE TABLE public.caller_mark_b (id int)",
        "GRANT SELECT, INSERT ON public.caller_mark_b TO " + APP);
  }

  @AfterAll
  static void stop() {
    appDs.close();
    ownerDs.close();
    PG.stop();
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

  /**
   * The application wrote a row in its own transaction, then the verify-only gate ran on the same
   * connection (a lazily created gate, or a non-Spring caller asserting at its own startup). The
   * verification is refused, which is right, but it ends the caller's transaction: its SET
   * TRANSACTION fails inside a transaction that already ran a query, and restore() rolls back. The
   * caller, which decides to keep its row after a refused check, finds it gone. R50-2 and R50-4
   * refuse this untouched on the other two schema entry points.
   */
  @Test
  void probe_verify_schema_inside_a_caller_transaction_rolls_back_the_caller_rows()
      throws SQLException {
    var appSide = recording(new TransactionAwareDataSourceProxy(appDs));
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    long before = rows(appDs, "caller_mark_b");
    var refused =
        tx.execute(
            status -> {
              try (var s = DataSourceUtils.getConnection(appDs).createStatement()) {
                s.execute("INSERT INTO public.caller_mark_b VALUES (21)");
              } catch (SQLException e) {
                throw new IllegalStateException(e);
              }
              calls.clear();
              return catchThrowableOfType(
                  ShreddingException.class, () -> JdbcSupport.verifySchema(appSide));
            });
    assertThat(rows(appDs, "caller_mark_b"))
        .describedAs("the caller's committed row")
        .isEqualTo(before + 1);
    assertThat(refused).describedAs("refused").isNotNull();
    assertThat(refused.code()).isEqualTo("SHRED-SCHEMA-008");
    assertThat(calls)
        .describedAs("connection calls before the refusal")
        .containsOnly("getAutoCommit", "close");
  }

  /**
   * The gate runs first in the caller's transaction, before any statement of the caller. It
   * verifies inside that transaction and then calls rollback() and setAutoCommit() on a connection
   * whose transaction it did not begin. Expected: refused untouched, as a key write is.
   */
  @Test
  void probe_verify_schema_at_the_start_of_a_caller_transaction_ends_it() {
    var appSide = recording(new TransactionAwareDataSourceProxy(appDs));
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    var refused =
        tx.execute(
            status -> {
              calls.clear();
              var thrown =
                  catchThrowableOfType(
                      ShreddingException.class, () -> JdbcSupport.verifySchema(appSide));
              status.setRollbackOnly();
              return thrown;
            });
    assertThat(calls)
        .describedAs("connection calls the verification made on the caller's connection")
        .containsOnly("getAutoCommit", "close");
    assertThat(refused).describedAs("refused").isNotNull();
    assertThat(refused.code()).isEqualTo("SHRED-SCHEMA-008");
  }
}
