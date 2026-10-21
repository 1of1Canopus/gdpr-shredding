package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.time.Clock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

/** Whole-module pass for 0.2.1: a key write must not commit the caller transaction. */
class CipherProbeRc021Test {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static HikariDataSource appDs;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
    try (var owner =
        TwoRoleCluster.pool(PG, TwoRoleCluster.OWNER, PASSWORD, PG.getDatabaseName())) {
      exec(
          owner,
          "CREATE TABLE public.caller_mark (id int)",
          "GRANT SELECT, INSERT ON public.caller_mark TO " + APP);
    }
  }

  @AfterAll
  static void stop() {
    appDs.close();
    PG.stop();
  }

  /**
   * RC021-1. The read path joins a caller transaction and never commits it (M21). The write path
   * does not: inTransaction commits whatever transaction the connection arrived in. A key minted
   * inside the application transaction commits the application rows written before it, and the
   * later rollback cannot undo them.
   */
  @Test
  void probe_key_write_inside_a_caller_transaction_commits_the_caller_rows() throws SQLException {
    var aware = new TransactionAwareDataSourceProxy(appDs);
    var keys =
        new JdbcKeyProvider(
            JdbcSupport.verifySchema(aware).schema(),
            MasterKey.fromBytes(new byte[32]),
            RandomSource.secure(),
            Clock.systemUTC());
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    long before = rows(appDs, "caller_mark");

    try {
      tx.executeWithoutResult(
          status -> {
            try {
              var c = DataSourceUtils.getConnection(appDs);
              try (var s = c.createStatement()) {
                s.execute("INSERT INTO public.caller_mark VALUES (1)");
              }
              keys.currentForWrite(TenantId.of("t"), SubjectId.of("s-rc021"));
            } catch (SQLException e) {
              throw new IllegalStateException(e);
            }
            status.setRollbackOnly();
          });
    } catch (RuntimeException refusedIsAlsoAcceptable) {
      // A refusal before any commit is the fix; the assertion below decides.
    }

    assertThat(rows(appDs, "caller_mark"))
        .describedAs("the module committed a transaction it did not begin")
        .isEqualTo(before);
  }

  /** The refusal is typed, comes before any statement, and leaves the caller's transaction open. */
  @Test
  void key_write_inside_a_caller_transaction_is_refused_with_schema_008() throws SQLException {
    var aware = new TransactionAwareDataSourceProxy(appDs);
    var keys =
        new JdbcKeyProvider(
            JdbcSupport.verifySchema(aware).schema(),
            MasterKey.fromBytes(new byte[32]),
            RandomSource.secure(),
            Clock.systemUTC());
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    long before = rows(appDs, "caller_mark");

    var refused =
        tx.execute(
            status -> {
              try (var s = DataSourceUtils.getConnection(appDs).createStatement()) {
                s.execute("INSERT INTO public.caller_mark VALUES (2)");
              } catch (SQLException e) {
                throw new IllegalStateException(e);
              }
              var thrown =
                  org.assertj.core.api.Assertions.catchThrowableOfType(
                      ShreddingException.class,
                      () -> keys.currentForWrite(TenantId.of("t"), SubjectId.of("s-rc021-typed")));
              // The caller's own insert is still pending and still its to commit or roll back.
              status.setRollbackOnly();
              return thrown;
            });

    assertThat(refused).isNotNull();
    assertThat(refused.code()).isEqualTo("SHRED-SCHEMA-008");
    assertThat(rows(appDs, "caller_mark")).isEqualTo(before);
  }
}
