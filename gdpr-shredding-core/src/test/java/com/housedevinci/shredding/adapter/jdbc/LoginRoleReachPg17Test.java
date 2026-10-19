package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.OWNER;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR1c-4 on the module's PostgreSQL 17 pin: {@code MAINTAIN} (new in 17) is refused because the
 * refused-privilege legs are an allow list, not a list of known privilege names. No Java version
 * switch: the same code runs on 16, where the privilege does not exist.
 */
class LoginRoleReachPg17Test {

  private static final PostgreSQLContainer<?> PG =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static HikariDataSource su;
  private static HikariDataSource appDs;
  private static HikariDataSource ownerDs;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    su = TwoRoleCluster.superuser(PG, PG.getDatabaseName());
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
    ownerDs = TwoRoleCluster.pool(PG, OWNER, PASSWORD, PG.getDatabaseName());
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {ownerDs, appDs, su}) {
      if (ds != null) {
        ds.close();
      }
    }
    PG.stop();
  }

  @Test
  void documented_setup_verifies_on_17() {
    assertThatCode(() -> JdbcSupport.verifySchema(appDs)).doesNotThrowAnyException();
  }

  @Test
  void reachable_pg_maintain_refuses_on_17() throws SQLException {
    exec(
        su,
        "CREATE ROLE m LOGIN PASSWORD 'pw'",
        "GRANT " + APP + " TO m",
        "GRANT pg_maintain TO m");
    try (var pool = TwoRoleCluster.pool(PG, "m", PASSWORD, PG.getDatabaseName())) {
      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(pool));

      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code())
          .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(thrown)
          .hasMessageContaining(
              "role pg_maintain, reachable from login role m, is a predefined role this module"
                  + " does not accept");
    } finally {
      exec(su, "DROP OWNED BY m", "DROP ROLE m");
    }
  }

  @Test
  void table_level_maintain_grant_refuses_on_17() throws SQLException {
    exec(ownerDs, "GRANT MAINTAIN ON shredding_erasure TO " + APP);
    try {
      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(appDs));

      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code())
          .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(thrown).hasMessageContaining("holds MAINTAIN on shredding_erasure");
    } finally {
      exec(ownerDs, "REVOKE MAINTAIN ON shredding_erasure FROM " + APP);
    }
  }
}
