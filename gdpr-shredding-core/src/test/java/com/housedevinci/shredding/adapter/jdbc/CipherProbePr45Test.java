package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review, pass 1 of PR 45 (C-PR-1c, 2026-10-18). Each probe is RED on 285fd1c: the gate
 * reports the runtime role clean, and the same role then does what the gate exists to prevent. Each
 * probe uses its own database of one container, so one probe's setup cannot hide another's.
 */
class CipherProbePr45Test {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
  }

  @AfterAll
  static void stop() {
    PG.stop();
  }

  /**
   * C-PR45-1. The owner of the verified schema can DROP every table in it, whoever owns the table.
   * That right comes from ownership, not from the schema's ACL, so revoking CREATE from the owner
   * hides it from the allow-list leg, and the schema has no ownership leg.
   */
  @Test
  void probe_schema_owner_with_its_own_create_revoked_passes_and_can_drop_the_erasure_log()
      throws SQLException {
    String db = "p45_schema_owner";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(su, "ALTER SCHEMA public OWNER TO " + APP, "REVOKE CREATE ON SCHEMA public FROM " + APP);
      // Impact, shown first: the runtime role drops the erasure log (rolled back).
      exec(app, "BEGIN", "DROP TABLE public.shredding_erasure CASCADE", "ROLLBACK");

      var refusal = refusal(app);

      assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(refusal).hasMessageContaining("schema public");
    }
  }

  /**
   * C-PR45-2. A column-level REFERENCES grant to the current role itself passes: the column leg
   * skips the current role, and the current role's own column leg checks UPDATE only. A foreign key
   * from a table the role owns then pins a data key: the crypto-shredding DELETE fails. Foreign-key
   * triggers are internal, so the trigger leg does not see them either.
   */
  @Test
  void probe_column_references_grant_to_the_runtime_role_passes_and_blocks_key_destruction()
      throws SQLException {
    String db = "p45_col_refs";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "GRANT REFERENCES (tenant, subject, version) ON shredding_data_key TO " + APP,
          "CREATE SCHEMA mine AUTHORIZATION " + APP,
          "INSERT INTO shredding_data_key (tenant, subject, version, wrapped_key, state, created_at)"
              + " VALUES ('t', 's', 1, '\\x00', 'ACTIVE', now())");
      exec(
          app,
          "CREATE TABLE mine.pin (tenant varchar(255), subject varchar(255), version integer,"
              + " FOREIGN KEY (tenant, subject, version)"
              + " REFERENCES public.shredding_data_key (tenant, subject, version))",
          "INSERT INTO mine.pin VALUES ('t', 's', 1)");
      Throwable delete =
          catchThrowable(
              () -> exec(app, "DELETE FROM public.shredding_data_key WHERE tenant = 't'"));
      assertThat(delete).isInstanceOf(SQLException.class);
      assertThat(((SQLException) delete).getSQLState()).isEqualTo("23503");
      exec(app, "DROP TABLE mine.pin");

      var refusal = refusal(app);

      assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(refusal).hasMessageContaining("REFERENCES on shredding_data_key");
    }
  }

  /**
   * C-PR45-3. EXECUTE on a server-file function, granted to the runtime role, passes, while the
   * predefined role that carries the same right (pg_write_server_files) is refused (C-PR1c-1). The
   * runtime role then writes a file as the server's operating-system user.
   */
  @Test
  void probe_execute_on_lo_export_passes_and_writes_a_server_file() throws SQLException {
    String db = "p45_lo_export";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(pg_catalog.oid, pg_catalog.text) TO "
              + APP);
      String lo = TwoRoleCluster.scalar(app, "SELECT pg_catalog.lo_from_bytea(0, 'x'::bytea)");
      assertThat(
              TwoRoleCluster.scalar(
                  app,
                  "SELECT pg_catalog.lo_export("
                      + lo
                      + ", '/tmp/cipher-pr45-written-by-runtime-role')"))
          .isEqualTo("1");
      assertThat(
              TwoRoleCluster.scalar(
                  su, "SELECT pg_catalog.pg_read_file('/tmp/cipher-pr45-written-by-runtime-role')"))
          .isEqualTo("x");

      var refusal = refusal(app);

      assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(refusal).hasMessageContaining("lo_export");
    }
  }

  /**
   * Confirmation (green on 285fd1c): an owner the login reaches only through a grant with SET FALSE
   * and INHERIT FALSE is still refused, by the ownership leg that the left-out owner entries rely
   * on.
   */
  @Test
  void confirm_owner_reached_only_through_a_set_false_inherit_false_grant_refuses()
      throws SQLException {
    String db = "p45_set_false";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db)) {
      exec(
          su,
          "CREATE ROLE p45_group NOLOGIN",
          "GRANT " + TwoRoleCluster.OWNER + " TO p45_group",
          "CREATE ROLE p45_login LOGIN PASSWORD '" + TwoRoleCluster.PASSWORD + "'",
          "GRANT " + APP + " TO p45_login",
          "GRANT p45_group TO p45_login WITH SET FALSE, INHERIT FALSE");
      try (var login =
          TwoRoleCluster.pool(PG, "p45_login", TwoRoleCluster.PASSWORD, db, "SET ROLE " + APP)) {
        var refusal = refusal(login);

        assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
        assertThat(refusal)
            .hasMessageContaining(
                "login role p45_login owns, or is a member of the owner of, table"
                    + " shredding_erasure");
      }
    }
  }

  /**
   * Confirmation (green on 285fd1c): a backend terminated before verification (SQLState 57P01 or a
   * lost connection) is SHRED-SCHEMA-005, never a pass.
   */
  @Test
  void confirm_terminated_backend_during_verification_is_005() throws SQLException {
    String db = "p45_terminated";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var c =
            java.sql.DriverManager.getConnection(
                TwoRoleCluster.url(PG, db), APP, TwoRoleCluster.PASSWORD)) {
      String pid = scalarOn(c, "SELECT pg_catalog.pg_backend_pid()");
      exec(su, "SELECT pg_catalog.pg_terminate_backend(" + pid + ")");

      var refusal =
          refusal(new org.springframework.jdbc.datasource.SingleConnectionDataSource(c, true));

      assertThat(refusal.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    }
  }

  private static String scalarOn(java.sql.Connection c, String sql) throws SQLException {
    try (var s = c.createStatement();
        var rs = s.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  private static ShreddingException refusal(DataSource ds) {
    Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(ds));
    assertThat(thrown)
        .as("the gate must refuse, it reported the runtime role clean")
        .isInstanceOf(ShreddingException.class);
    return (ShreddingException) thrown;
  }
}
