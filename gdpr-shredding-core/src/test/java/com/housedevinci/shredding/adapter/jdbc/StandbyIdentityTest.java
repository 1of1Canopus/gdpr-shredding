package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.DatabaseIdentityCheckTest.assertRefused;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.Swappable;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1b, paths M18 and M9, and M16 shown honestly (round 2, items 2 and 8). A physical standby
 * built with {@code pg_basebackup -R} from the verified primary has the same system identifier, the
 * same oids and the same roles. While it is still replaying, it is refused for reads and writes: a
 * lagging replica can serve a data key the primary has already destroyed. Once promoted it is the
 * same database, so it is accepted: failover keeps working, and a physical copy (M16) passes the
 * check by construction.
 *
 * <p>Ordered: the last test promotes the standby. Measured run time is in the PR body.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StandbyIdentityTest {

  private static final Network NET = Network.newNetwork();
  private static final PostgreSQLContainer<?> PRIMARY =
      TwoRoleCluster.container().withNetwork(NET).withNetworkAliases("primary");
  private static final GenericContainer<?> STANDBY =
      new GenericContainer<>(DockerImageName.parse(TwoRoleCluster.IMAGE))
          .withNetwork(NET)
          .withExposedPorts(5432)
          .withCreateContainerCmdModifier(
              cmd ->
                  cmd.withEntrypoint(
                      "sh",
                      "-c",
                      "set -e; mkdir -p /tmp/standby; chown postgres:postgres /tmp/standby;"
                          + " chmod 700 /tmp/standby;"
                          + " gosu postgres env PGPASSWORD=test pg_basebackup -h primary -p 5432"
                          + " -U test -D /tmp/standby -R -X stream;"
                          + " exec gosu postgres postgres -D /tmp/standby -c hot_standby=on"))
          .waitingFor(
              Wait.forLogMessage(".*ready to accept read-only connections.*", 1)
                  .withStartupTimeout(Duration.ofMinutes(2)));
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);

  private static HikariDataSource primaryApp;
  private static HikariDataSource standbyApp;
  private static HikariDataSource standbySu;

  @BeforeAll
  static void start() throws Exception {
    PRIMARY.start();
    TwoRoleCluster.roles(PRIMARY);
    TwoRoleCluster.install(PRIMARY, PRIMARY.getDatabaseName());
    PRIMARY.execInContainer(
        "sh",
        "-c",
        "echo 'host replication all all scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf");
    try (var su = TwoRoleCluster.superuser(PRIMARY, PRIMARY.getDatabaseName())) {
      exec(su, "SELECT pg_catalog.pg_reload_conf()");
    }
    primaryApp = TwoRoleCluster.app(PRIMARY, PRIMARY.getDatabaseName());
    STANDBY.start();
    standbyApp = standby(TwoRoleCluster.APP, TwoRoleCluster.PASSWORD);
    standbySu = standby(PRIMARY.getUsername(), PRIMARY.getPassword());
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {standbySu, standbyApp, primaryApp}) {
      if (ds != null) {
        ds.close();
      }
    }
    STANDBY.stop();
    PRIMARY.stop();
    NET.close();
  }

  @Test
  @Order(1)
  void standby_in_recovery_refuses_reads_and_writes() throws SQLException {
    assertThat(scalar(standbyApp, "SELECT pg_catalog.pg_is_in_recovery()")).isEqualTo("t");
    var moving = new Swappable(primaryApp);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    SubjectId subject = subject();
    int version = keys.currentForWrite(TenantId.of("t"), subject).version();
    moving.target.set(standbyApp);

    Throwable read = catchThrowable(() -> keys.forRead(TenantId.of("t"), subject, version));
    Throwable write = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(read, "server in recovery");
    assertRefused(write, "server in recovery");
  }

  @Test
  @Order(2)
  void verification_on_a_standby_in_recovery_refuses_with_005() {
    Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(standbyApp));

    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(thrown.getMessage()).contains("in recovery");
  }

  @Test
  @Order(3)
  void promoted_standby_is_accepted() throws SQLException {
    String id = "SELECT system_identifier FROM pg_catalog.pg_control_system()";
    assertThat(scalar(standbyApp, id)).isEqualTo(scalar(primaryApp, id));
    var moving = new Swappable(primaryApp);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());

    exec(standbySu, "SELECT pg_catalog.pg_promote(true, 60)");
    standbyApp.getHikariPoolMXBean().softEvictConnections();
    assertThat(scalar(standbyApp, "SELECT pg_catalog.pg_is_in_recovery()")).isEqualTo("f");
    moving.target.set(standbyApp);
    long before = rows(standbySu, "shredding_data_key");

    keys.currentForWrite(TenantId.of("t"), subject());

    assertThat(rows(standbySu, "shredding_data_key")).isEqualTo(before + 1);
  }

  private static HikariDataSource standby(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(
        "jdbc:postgresql://"
            + STANDBY.getHost()
            + ":"
            + STANDBY.getMappedPort(5432)
            + "/"
            + PRIMARY.getDatabaseName());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    config.setMinimumIdle(0);
    return new HikariDataSource(config);
  }

  private static JdbcKeyProvider keys(VerifiedSchema schema) {
    return new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), Clock.systemUTC());
  }

  private static SubjectId subject() {
    return SubjectId.of("s-" + System.nanoTime());
  }
}
