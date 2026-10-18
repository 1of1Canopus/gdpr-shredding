package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.DatabaseIdentityCheckTest.assertRefused;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.Swappable;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.time.Clock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * C-PR-1b, paths M7 and M8: another cluster built by the same script. Same database name, same
 * roles, same {@code public} oid 2200 and, on a fresh cluster, the same database oid. Only the
 * cluster's system identifier tells the two apart, which is why the fingerprint carries it.
 *
 * <p>Ordered: M8 stops the first cluster.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class OtherClusterIdentityTest {

  private static final PostgreSQLContainer<?> FIRST = TwoRoleCluster.container();
  private static final PostgreSQLContainer<?> LOOKALIKE = TwoRoleCluster.container();
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);

  private static HikariDataSource firstApp;
  private static HikariDataSource lookalikeApp;
  private static HikariDataSource lookalikeSu;

  @BeforeAll
  static void start() throws SQLException {
    for (var pg : new PostgreSQLContainer<?>[] {FIRST, LOOKALIKE}) {
      pg.start();
      TwoRoleCluster.roles(pg);
      TwoRoleCluster.install(pg, pg.getDatabaseName());
    }
    firstApp = TwoRoleCluster.app(FIRST, FIRST.getDatabaseName());
    lookalikeApp = TwoRoleCluster.app(LOOKALIKE, LOOKALIKE.getDatabaseName());
    lookalikeSu = TwoRoleCluster.superuser(LOOKALIKE, LOOKALIKE.getDatabaseName());
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {lookalikeSu, lookalikeApp, firstApp}) {
      if (ds != null) {
        ds.close();
      }
    }
    LOOKALIKE.stop();
    FIRST.stop();
  }

  @Test
  @Order(1)
  void lookalike_cluster_from_the_same_script_refuses() throws SQLException {
    // Precondition: every fact but the system identifier is the same on the two clusters.
    String db = "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()";
    String ns = "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'public'";
    String id = "SELECT system_identifier FROM pg_catalog.pg_control_system()";
    assertThat(scalar(lookalikeApp, db)).isEqualTo(scalar(firstApp, db));
    assertThat(scalar(lookalikeApp, ns)).isEqualTo(scalar(firstApp, ns));
    assertThat(scalar(lookalikeApp, id)).isNotEqualTo(scalar(firstApp, id));

    var moving = new Swappable(firstApp);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(lookalikeApp);
    long before = rows(lookalikeSu, "shredding_data_key");

    Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(thrown, "cluster");
    assertThat(thrown.getMessage()).contains("(different: cluster)");
    assertThat(rows(lookalikeSu, "shredding_data_key")).isEqualTo(before);
  }

  @Test
  @Order(2)
  void multi_host_url_failing_over_to_another_cluster_refuses() throws SQLException {
    var multi = new PGSimpleDataSource();
    multi.setURL(
        "jdbc:postgresql://"
            + FIRST.getHost()
            + ":"
            + FIRST.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + ","
            + LOOKALIKE.getHost()
            + ":"
            + LOOKALIKE.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + FIRST.getDatabaseName()
            + "?targetServerType=any&connectTimeout=5");
    multi.setUser(APP);
    multi.setPassword(PASSWORD);
    var keys = keys(JdbcSupport.verifySchema(multi).schema());
    keys.currentForWrite(TenantId.of("t"), subject());

    firstApp.close();
    FIRST.stop();
    long before = rows(lookalikeSu, "shredding_data_key");

    Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(thrown, "cluster");
    assertThat(rows(lookalikeSu, "shredding_data_key")).isEqualTo(before);
  }

  private static JdbcKeyProvider keys(VerifiedSchema schema) {
    return new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), Clock.systemUTC());
  }

  private static SubjectId subject() {
    return SubjectId.of("s-" + System.nanoTime());
  }
}
