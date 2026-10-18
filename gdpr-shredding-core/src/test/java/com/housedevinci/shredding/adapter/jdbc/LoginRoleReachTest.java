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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * C-PR-1c: the gate judges the role the connection logged in as, and every role that login can
 * reach, not only the role it moved to. One test per path of the design page ({@code
 * c-pr-1c-login-role-design.md}, sections 3 and R2.3, round-2 items) that the 16 pin can show. The
 * 17-only paths (MAINTAIN, {@code pg_maintain}) are in {@code LoginRoleReachPg17Test}, the per-call
 * paths in {@code LoginMarkerTest}.
 *
 * <p>Words: the <em>login role</em> is the role the connection authenticated as; <em>reach</em> is
 * that role and every role it is a member of, with or without INHERIT or SET.
 */
class LoginRoleReachTest {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();

  private static HikariDataSource su;
  private static HikariDataSource appDs;

  /** Roles a test created, dropped after it with everything granted to them. */
  private final List<String> created = new ArrayList<>();

  /** Pools a test opened, closed after it. */
  private final List<HikariDataSource> pools = new ArrayList<>();

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    su = TwoRoleCluster.superuser(PG, PG.getDatabaseName());
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
    // The owner may SET ROLE to the runtime role (L1).
    exec(su, "GRANT " + APP + " TO " + OWNER);
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {appDs, su}) {
      if (ds != null) {
        ds.close();
      }
    }
    PG.stop();
  }

  @AfterEach
  void dropWhatTheTestCreated() throws SQLException {
    pools.forEach(HikariDataSource::close);
    pools.clear();
    for (String role : created.reversed()) {
      exec(su, "DROP OWNED BY " + role, "DROP ROLE " + role);
    }
    created.clear();
  }

  // ------------------------------------------------------------------ L1, L1b, L26

  @Test
  void owner_login_with_set_role_in_init_sql_refuses_with_004_naming_the_login_role()
      throws SQLException {
    var pool = pool(OWNER, "SET ROLE " + APP);
    assertThat(sessionAndCurrent(pool)).isEqualTo(OWNER + "/" + APP);

    var refusal = refusal(pool);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining("as role " + APP + " (login role " + OWNER + ")")
        .hasMessageContaining(
            "login role "
                + OWNER
                + " owns, or is a member of the owner of, table shredding_erasure")
        .hasMessageContaining("guard function shredding_erasure_append_only")
        .hasMessageContaining("RESET ROLE");
  }

  @Test
  void noinherit_member_of_the_owner_with_set_role_refuses() throws SQLException {
    login("sneaky", "NOINHERIT");
    exec(su, "GRANT " + OWNER + " TO sneaky", "GRANT " + APP + " TO sneaky");
    var pool = pool("sneaky", "SET ROLE " + APP);

    var refusal = refusal(pool);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining(
            "login role sneaky owns, or is a member of the owner of, table shredding_erasure");
  }

  @Test
  void admin_only_member_of_the_owner_refuses() throws SQLException {
    // Round 2 item 2: ADMIN TRUE, INHERIT FALSE, SET FALSE. pg_has_role(.., 'SET') is false, and
    // the role can still grant itself SET and become the owner.
    login("adm", "");
    exec(
        su,
        "GRANT " + APP + " TO adm",
        "GRANT " + OWNER + " TO adm WITH ADMIN TRUE, INHERIT FALSE, SET FALSE");

    var refusal = refusal(pool("adm", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal).hasMessageContaining("owns table shredding_erasure");
  }

  // ------------------------------------------------------------------ L2, L3, L4, L32

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "SET SESSION AUTHORIZATION shredding_app",
        "SET SESSION AUTHORIZATION shredding_app; SET ROLE NONE",
        "SET track_activities = off; SET SESSION AUTHORIZATION shredding_app",
        "SELECT pg_catalog.set_config('session_authorization', 'shredding_app', false)"
      })
  void superuser_login_that_moved_its_session_role_refuses_with_004(String initSql)
      throws SQLException {
    var pool = pool(PG.getUsername(), PG.getPassword(), initSql);
    assertThat(sessionAndCurrent(pool))
        .describedAs("precondition: both roles moved")
        .isEqualTo(APP + "/" + APP);

    var refusal = refusal(pool);

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal).hasMessageContaining("login role " + PG.getUsername() + " is a superuser");
  }

  // ------------------------------------------------------------------ L5

  @Test
  void login_role_is_read_with_track_activities_off_server_wide() throws SQLException {
    exec(su, "ALTER SYSTEM SET track_activities = off", "SELECT pg_catalog.pg_reload_conf()");
    try {
      var pool = pool(OWNER, "SET ROLE " + APP);
      assertThat(TwoRoleCluster.scalar(pool, "SHOW track_activities")).isEqualTo("off");
      assertThat(refusal(pool))
          .hasMessageContaining("login role " + OWNER + " owns, or is a member of the owner of");
      assertThatCode(() -> JdbcSupport.verifySchema(appDs)).doesNotThrowAnyException();
    } finally {
      exec(su, "ALTER SYSTEM RESET track_activities", "SELECT pg_catalog.pg_reload_conf()");
    }
  }

  @Test
  void login_role_is_read_when_the_server_starts_with_track_activities_off() throws SQLException {
    try (PostgreSQLContainer<?> off = TwoRoleCluster.container()) {
      off.withCommand("postgres", "-c", "fsync=off", "-c", "track_activities=off").start();
      TwoRoleCluster.roles(off);
      TwoRoleCluster.install(off, off.getDatabaseName());
      try (var offSu = TwoRoleCluster.superuser(off, off.getDatabaseName())) {
        exec(offSu, "GRANT " + APP + " TO " + OWNER);
      }
      try (var offApp = TwoRoleCluster.app(off, off.getDatabaseName());
          var offOwner =
              TwoRoleCluster.pool(off, OWNER, PASSWORD, off.getDatabaseName(), "SET ROLE " + APP)) {
        assertThat(TwoRoleCluster.scalar(offApp, "SHOW track_activities")).isEqualTo("off");
        assertThatCode(() -> JdbcSupport.verifySchema(offApp)).doesNotThrowAnyException();
        assertThat(catchThrowable(() -> JdbcSupport.verifySchema(offOwner)))
            .hasMessageContaining("login role " + OWNER + " owns, or is a member of the owner of");
      }
    }
  }

  // ------------------------------------------------------------------ L6 to L10

  @Test
  void noinherit_member_of_a_superuser_group_refuses() throws SQLException {
    created.add("su_group");
    exec(su, "CREATE ROLE su_group SUPERUSER NOLOGIN");
    login("climber", "");
    exec(su, "GRANT " + APP + " TO climber", "GRANT su_group TO climber WITH INHERIT FALSE");

    var refusal = refusal(pool("climber", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining("role su_group, reachable from login role climber, is a superuser");
  }

  @Test
  void noinherit_member_of_a_role_with_update_on_the_erasure_log_refuses() throws SQLException {
    created.add("writer");
    exec(su, "CREATE ROLE writer NOLOGIN", "GRANT UPDATE ON shredding_erasure TO writer");
    login("lowly", "");
    exec(su, "GRANT " + APP + " TO lowly", "GRANT writer TO lowly WITH INHERIT FALSE");

    var refusal = refusal(pool("lowly", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining(
            "role writer, reachable from login role lowly, holds UPDATE on shredding_erasure");
  }

  @Test
  void noinherit_member_of_pg_write_all_data_refuses() throws SQLException {
    login("bulk", "");
    exec(su, "GRANT " + APP + " TO bulk", "GRANT pg_write_all_data TO bulk WITH INHERIT FALSE");

    var refusal = refusal(pool("bulk", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining(
            "role pg_write_all_data, reachable from login role bulk, is a predefined role this"
                + " module does not accept");
  }

  @Test
  void reachable_role_with_createrole_refuses() throws SQLException {
    created.add("maker_group");
    exec(su, "CREATE ROLE maker_group CREATEROLE NOLOGIN");
    login("maker", "");
    exec(su, "GRANT " + APP + " TO maker", "GRANT maker_group TO maker WITH INHERIT FALSE");

    assertThat(refusal(pool("maker", null)))
        .hasMessageContaining("role maker_group, reachable from login role maker, has CREATEROLE");
  }

  @Test
  void login_role_with_createrole_refuses() throws SQLException {
    login("maker2", "CREATEROLE");
    exec(su, "GRANT " + APP + " TO maker2");

    assertThat(refusal(pool("maker2", null)))
        .hasMessageContaining("login role maker2 has CREATEROLE");
  }

  @Test
  void reachable_role_with_bypassrls_is_not_a_leg() throws SQLException {
    created.add("rls_group");
    exec(su, "CREATE ROLE rls_group BYPASSRLS NOLOGIN");
    login("rlsuser", "");
    exec(su, "GRANT " + APP + " TO rlsuser", "GRANT rls_group TO rlsuser");

    assertThatCode(() -> JdbcSupport.verifySchema(pool("rlsuser", null)))
        .doesNotThrowAnyException();
  }

  // ------------------------------------------------------------------ L24 (C-PR1c-1)

  @ParameterizedTest(name = "{0}, inherit {1}")
  @CsvSource({
    "pg_execute_server_program, true",
    "pg_execute_server_program, false",
    "pg_write_server_files, true",
    "pg_write_server_files, false",
    "pg_read_server_files, true",
    "pg_read_server_files, false"
  })
  void reachable_server_file_or_program_role_refuses(String serverRole, boolean inherit)
      throws SQLException {
    String login = "srv_" + (inherit ? "i" : "n");
    login(login, "");
    exec(
        su,
        "GRANT " + APP + " TO " + login,
        "GRANT " + serverRole + " TO " + login + " WITH INHERIT " + inherit);

    var refusal = refusal(pool(login, null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining(
            "role "
                + serverRole
                + ", reachable from login role "
                + login
                + ", is a server-file or server-program role");
  }

  // ------------------------------------------------------------------ L25 (C-PR1c-2), L30

  @Test
  void reachable_role_with_alter_system_on_a_parameter_refuses() throws SQLException {
    login("paracl", "");
    exec(
        su,
        "GRANT " + APP + " TO paracl",
        "GRANT ALTER SYSTEM ON PARAMETER archive_command TO paracl");

    assertThat(refusal(pool("paracl", null)))
        .hasMessageContaining("login role paracl holds ALTER SYSTEM on parameter archive_command");
  }

  @Test
  void reachable_role_with_set_on_a_parameter_refuses() throws SQLException {
    created.add("param_group");
    exec(
        su,
        "CREATE ROLE param_group NOLOGIN",
        "GRANT SET ON PARAMETER session_replication_role TO param_group");
    login("paraset", "");
    exec(su, "GRANT " + APP + " TO paraset", "GRANT param_group TO paraset WITH INHERIT FALSE");

    assertThat(refusal(pool("paraset", null)))
        .hasMessageContaining(
            "role param_group, reachable from login role paraset, holds SET on parameter"
                + " session_replication_role");
  }

  @Test
  void public_parameter_grant_refuses() throws SQLException {
    exec(su, "GRANT SET ON PARAMETER log_statement_stats TO PUBLIC");
    try {
      assertThat(refusal(appDs))
          .hasMessageContaining("PUBLIC holds SET on parameter log_statement_stats");
    } finally {
      exec(su, "REVOKE SET ON PARAMETER log_statement_stats FROM PUBLIC");
    }
    assertThatCode(() -> JdbcSupport.verifySchema(appDs)).doesNotThrowAnyException();
  }

  // ------------------------------------------------------------------ L29 (C-PR1c-7)

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "pg_signal_backend",
        "pg_create_subscription",
        "pg_checkpoint",
        "pg_use_reserved_connections",
        "pg_stat_scan_tables"
      })
  void accepted_predefined_roles_in_reach_verify(String predefined) throws SQLException {
    login("accepted", "");
    exec(su, "GRANT " + APP + " TO accepted", "GRANT " + predefined + " TO accepted");

    assertThatCode(() -> JdbcSupport.verifySchema(pool("accepted", null)))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {"pg_read_all_settings", "pg_monitor", "pg_read_all_stats", "pg_read_all_data"})
  void reachable_predefined_role_that_can_read_another_login_refuses(String predefined)
      throws SQLException {
    login("watcher", "");
    exec(su, "GRANT " + APP + " TO watcher", "GRANT " + predefined + " TO watcher");

    var refusal = refusal(pool("watcher", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining(
            "role "
                + predefined
                + ", reachable from login role watcher, is a predefined role this module does not"
                + " accept");
    if (predefined.equals("pg_monitor")) {
      // pg_monitor's members reach pg_read_all_settings, which is refused on its own (C-PR1c-7).
      assertThat(refusal)
          .hasMessageContaining(
              "role pg_read_all_settings, reachable from login role watcher, is a predefined role");
    }
  }

  @Test
  void pg_read_all_data_reads_password_verifiers_which_is_why_it_is_refused() throws SQLException {
    // Round 2 left this open: pg_read_all_data stays accepted only if it reads no credential.
    // Measured on the 16 pin: it reads pg_authid.rolpassword, so it is off the accepted list.
    login("reader", "");
    exec(su, "GRANT pg_read_all_data TO reader");
    assertThat(
            TwoRoleCluster.scalar(
                pool("reader", null),
                "SELECT pg_catalog.count(*) FROM pg_catalog.pg_authid"
                    + " WHERE rolpassword IS NOT NULL"))
        .isNotEqualTo("0");
  }

  // ------------------------------------------------------------------ L11, L12, L21

  @Test
  void noinherit_gateway_login_with_set_role_to_the_runtime_role_verifies() throws SQLException {
    login("gateway", "NOINHERIT");
    exec(su, "GRANT " + APP + " TO gateway");
    var pool = pool("gateway", "SET ROLE " + APP);

    SchemaVerdict verdict = JdbcSupport.verifySchema(pool);

    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
    assertThat(verdict.role()).isEqualTo(APP);
  }

  @Test
  void documented_setup_verifies() {
    assertThat(JdbcSupport.verifySchema(appDs).runtimeRoleIsUnprivileged()).isTrue();
  }

  @Test
  void verification_leaves_session_and_current_role_unchanged() throws SQLException {
    login("gateway", "NOINHERIT");
    exec(su, "GRANT " + APP + " TO gateway");
    var pool = pool("gateway", "SET ROLE " + APP);
    try (Connection c = pool.getConnection()) {
      var holder = new SingleConnectionDataSource(c, true);
      JdbcSupport.verifySchema(holder);
      try (var s = c.createStatement();
          var rs = s.executeQuery("SELECT session_user || '/' || current_user")) {
        rs.next();
        assertThat(rs.getString(1)).isEqualTo("gateway/" + APP);
      }
    }
  }

  // ------------------------------------------------------------------ L13, L28

  @Test
  void revoked_pg_stat_get_activity_refuses_verification_with_005_naming_the_grant()
      throws SQLException {
    exec(su, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) FROM PUBLIC");
    try {
      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(appDs));
      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(thrown)
          .hasMessageContaining("login role")
          .hasMessageContaining(
              "GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) TO " + APP);
    } finally {
      exec(su, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_activity(integer) TO PUBLIC");
    }
  }

  @Test
  void login_role_dropped_while_connected_refuses_verification_with_005() throws SQLException {
    login("doomed", "");
    exec(su, "GRANT " + APP + " TO doomed");
    try (Connection c = connect("doomed")) {
      try (var s = c.createStatement()) {
        // The current role stays a live role, so the first failing read is the login's own.
        s.execute("SET ROLE " + APP);
      }
      exec(su, "DROP ROLE doomed");
      created.remove("doomed");

      var single = new SingleConnectionDataSource(c, true);

      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(single));

      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(thrown)
          .hasMessageContaining("the login role of this connection could not be read");
    }
  }

  // ------------------------------------------------------------------ every leg over reach

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "GRANT DELETE ON shredding_erasure TO writer2|holds DELETE on shredding_erasure",
        "GRANT TRUNCATE ON shredding_erased_subject TO writer2|holds TRUNCATE on"
            + " shredding_erased_subject",
        "GRANT TRIGGER ON shredding_erasure_anchor TO writer2|holds TRIGGER on"
            + " shredding_erasure_anchor",
        "GRANT REFERENCES ON shredding_data_key TO writer2|holds REFERENCES on shredding_data_key",
        "GRANT UPDATE (hash) ON shredding_erasure TO writer2|holds UPDATE on shredding_erasure.hash",
        "GRANT UPDATE ON SEQUENCE shredding_erasure_seq_seq TO writer2|holds UPDATE on sequence"
            + " shredding_erasure_seq_seq",
        "GRANT SELECT ON SEQUENCE shredding_erasure_seq_seq TO writer2|holds SELECT on sequence"
            + " shredding_erasure_seq_seq",
        "GRANT CREATE ON SCHEMA public TO writer2|holds CREATE on schema public",
        "GRANT TEMPORARY ON DATABASE test TO writer2|holds TEMPORARY on database test",
        "GRANT CREATE ON DATABASE test TO writer2|holds CREATE on database test"
      })
  void every_refused_privilege_leg_runs_for_every_reachable_role(String grant, String leg)
      throws SQLException {
    created.add("writer2");
    exec(su, "CREATE ROLE writer2 NOLOGIN");
    String asOwner = grant.contains("DATABASE") ? null : grant;
    if (asOwner == null) {
      exec(su, grant);
    } else {
      try (var owner = TwoRoleCluster.pool(PG, OWNER, PASSWORD, PG.getDatabaseName())) {
        exec(owner, grant);
      }
    }
    login("deep", "");
    exec(su, "GRANT " + APP + " TO deep", "GRANT writer2 TO deep WITH INHERIT FALSE");

    var refusal = refusal(pool("deep", null));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(refusal)
        .hasMessageContaining("role writer2, reachable from login role deep, " + leg);
  }

  @Test
  void refusal_names_the_role_each_leg_fired_for() throws SQLException {
    created.add("w_a");
    created.add("w_b");
    exec(
        su,
        "CREATE ROLE w_a NOLOGIN",
        "CREATE ROLE w_b NOLOGIN",
        "GRANT DELETE ON shredding_erasure TO w_a",
        "GRANT TRUNCATE ON shredding_erasure TO w_b");
    login("two", "");
    exec(
        su,
        "GRANT " + APP + " TO two",
        "GRANT w_a TO two WITH INHERIT FALSE",
        "GRANT w_b TO w_a WITH INHERIT FALSE");

    var refusal = refusal(pool("two", null));

    assertThat(refusal)
        .hasMessageContaining("role w_a, reachable from login role two, holds DELETE")
        .hasMessageContaining("role w_b, reachable from login role two, holds TRUNCATE");
  }

  // ------------------------------------------------------------------ L22

  @Test
  void allow_privileged_runtime_role_returns_the_login_and_reach_legs() throws SQLException {
    login("xprog", "NOINHERIT");
    exec(
        su,
        "GRANT " + APP + " TO xprog",
        "GRANT pg_execute_server_program TO xprog",
        "GRANT ALTER SYSTEM ON PARAMETER archive_command TO xprog");
    var pool = pool("xprog", "SET ROLE " + APP);

    SchemaVerdict verdict = JdbcSupport.verifySchema(pool, true);

    assertThat(verdict.privilegeLegs())
        .anyMatch(l -> l.contains("pg_execute_server_program"))
        .anyMatch(l -> l.contains("ALTER SYSTEM on parameter archive_command"));
  }

  // ------------------------------------------------------------------ helpers

  private void login(String role, String attributes) throws SQLException {
    created.add(role);
    exec(su, "CREATE ROLE " + role + " LOGIN PASSWORD '" + PASSWORD + "' " + attributes);
  }

  private HikariDataSource pool(String user, String initSql) {
    return pool(user, PASSWORD, initSql);
  }

  private HikariDataSource pool(String user, String password, String initSql) {
    var pool =
        initSql == null
            ? TwoRoleCluster.pool(PG, user, password, PG.getDatabaseName())
            : TwoRoleCluster.pool(PG, user, password, PG.getDatabaseName(), initSql);
    pools.add(pool);
    return pool;
  }

  private static Connection connect(String user) throws SQLException {
    return DriverManager.getConnection(
        TwoRoleCluster.url(PG, PG.getDatabaseName()), user, PASSWORD);
  }

  private static String sessionAndCurrent(HikariDataSource pool) throws SQLException {
    return TwoRoleCluster.scalar(pool, "SELECT session_user || '/' || current_user");
  }

  private static ShreddingException refusal(javax.sql.DataSource ds) {
    Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(ds));
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return (ShreddingException) thrown;
  }
}
