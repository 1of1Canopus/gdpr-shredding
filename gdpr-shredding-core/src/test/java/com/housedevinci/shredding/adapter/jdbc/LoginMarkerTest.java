package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.Swappable;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.time.Clock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * C-PR-1c, per call (design R2.7, S5): every store connection is checked against the login role
 * verification read. A backend's login never changes, so the check reads it once per backend and
 * leaves a marker in that backend; later calls on that backend skip the read. Paths P1 to P9 and
 * L13, L14, L17 of the design page.
 *
 * <p>The verified pool logs in as {@code gateway} (NOINHERIT, member of the runtime role only) and
 * runs {@code SET ROLE shredding_app}: verified session role {@code gateway}, current role {@code
 * shredding_app}. The case only this check sees (L14): a pool that logs in as a superuser and
 * restores both roles in its init SQL.
 */
class LoginMarkerTest {

  static final String CODE = "SHRED-SCHEMA-012";
  static final String RESTORE = "SET SESSION AUTHORIZATION gateway; SET ROLE " + APP;

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);

  private static HikariDataSource su;
  private static HikariDataSource gatewayDs;

  private HikariDataSource opened;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    su = TwoRoleCluster.superuser(PG, PG.getDatabaseName());
    exec(
        su,
        "CREATE ROLE gateway LOGIN NOINHERIT PASSWORD '" + PASSWORD + "'",
        "GRANT " + APP + " TO gateway");
    gatewayDs = gateway();
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {gatewayDs, su}) {
      if (ds != null) {
        ds.close();
      }
    }
    PG.stop();
  }

  @AfterEach
  void closeOpened() {
    if (opened != null) {
      opened.close();
      opened = null;
    }
  }

  // ------------------------------------------------------------------ P3 (L14)

  @Test
  void delegate_switching_to_a_superuser_pool_with_restoring_init_sql_refuses_with_012()
      throws SQLException {
    var moving = new Swappable(gatewayDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(superuser(RESTORE));
    // Precondition: 1b's two role columns are exactly the verified ones.
    assertThat(TwoRoleCluster.scalar(moving, "SELECT session_user || '/' || current_user"))
        .isEqualTo("gateway/" + APP);
    long before = rows(su, "shredding_data_key");

    Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(thrown, "login role");
    assertThat(thrown.getMessage()).doesNotContain("session role").doesNotContain("current role");
    assertThat(rows(su, "shredding_data_key")).isEqualTo(before);
  }

  // ------------------------------------------------------------------ P4, P4b

  @Test
  void wrong_marker_in_init_sql_is_read_as_cold() throws SQLException {
    var moving = new Swappable(gatewayDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(superuser(RESTORE + "; SET shredding.login_checked = 'guess'"));

    assertRefused(
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "login role");
  }

  @Test
  void empty_marker_after_reset_is_read_as_cold() throws SQLException {
    var moving = new Swappable(gatewayDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(
        superuser(RESTORE + "; SET shredding.login_checked = 'x'; RESET shredding.login_checked"));
    assertThat(TwoRoleCluster.scalar(moving, "SELECT current_setting('shredding.login_checked')"))
        .describedAs("precondition: the setting exists and is empty")
        .isEmpty();

    assertRefused(
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "login role");
  }

  // ------------------------------------------------------------------ L13, L17

  @Test
  void revoked_pg_stat_get_activity_after_startup_refuses_the_store_call_with_012()
      throws SQLException {
    try (var fresh = gateway()) {
      var keys = keys(JdbcSupport.verifySchema(fresh).schema());
      exec(su, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) FROM PUBLIC");
      try {
        Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));
        assertThat(thrown).isInstanceOf(ShreddingException.class);
        assertThat(((ShreddingException) thrown).code()).isEqualTo(CODE);
        assertThat(thrown).hasMessageContaining("could not be checked (SQLState 42501)");
      } finally {
        exec(su, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) TO PUBLIC");
      }
    }
  }

  @Test
  void renamed_login_role_is_compared_by_oid_and_only_the_session_role_name_differs()
      throws SQLException {
    // L17. 1b compares the session role by name, so a rename after startup refuses: fail closed.
    // The login-role check compares the oid, so it adds no difference of its own.
    try (var fresh = gateway()) {
      var keys = keys(JdbcSupport.verifySchema(fresh).schema());
      exec(su, "ALTER ROLE gateway RENAME TO gateway_renamed");
      try {
        Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));
        assertRefused(thrown, "session role");
        assertThat(thrown.getMessage()).doesNotContain("login role");
      } finally {
        exec(su, "ALTER ROLE gateway_renamed RENAME TO gateway");
      }
    }
  }

  // ------------------------------------------------------------------ helpers

  private static HikariDataSource gateway() {
    return TwoRoleCluster.pool(PG, "gateway", PASSWORD, PG.getDatabaseName(), "SET ROLE " + APP);
  }

  private HikariDataSource superuser(String initSql) {
    opened =
        TwoRoleCluster.pool(PG, PG.getUsername(), PG.getPassword(), PG.getDatabaseName(), initSql);
    return opened;
  }

  static void assertRefused(Throwable thrown, String different) {
    DatabaseIdentityCheckTest.assertRefused(thrown, different);
  }

  private static JdbcKeyProvider keys(VerifiedSchema schema) {
    return new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), Clock.systemUTC());
  }

  private static SubjectId subject() {
    return SubjectId.of("s-" + System.nanoTime());
  }
}
