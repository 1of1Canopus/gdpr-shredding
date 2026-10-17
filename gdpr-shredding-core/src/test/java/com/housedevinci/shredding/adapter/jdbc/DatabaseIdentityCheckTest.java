package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.Swappable;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
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
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * C-PR-1b: every connection a module store takes reaches the cluster, database, schema and login
 * role verification checked, or the call refuses with {@code SHRED-SCHEMA-012} before its first
 * statement. One test per path of the design page (section 2) that one cluster can show. The
 * other-cluster paths (M7, M8) are in {@code OtherClusterIdentityTest}, the standby paths (M9, M18)
 * in {@code StandbyIdentityTest}.
 *
 * <p>One cluster, two databases in the same two-role posture: {@code test} (verified) and {@code
 * unguarded} (installed and granted the same way, never verified by these stores). The runtime role
 * could write to either, so a store that were not refused would write there; every refusal asserts
 * it did not.
 */
class DatabaseIdentityCheckTest {

  static final String CODE = "SHRED-SCHEMA-012";

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static final byte[] SECRET =
      "erasure-log-secret-that-is-32-bytes-or-more"
          .getBytes(java.nio.charset.StandardCharsets.UTF_8);
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);
  private static final BlindIndexResidual NO_RESIDUE = (c, column, tenant, subject) -> 0L;

  private static HikariDataSource appDs;
  private static HikariDataSource otherDs;
  private static HikariDataSource suOther;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    TwoRoleCluster.install(PG, "unguarded");
    TwoRoleCluster.install(PG, "swapdb");
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
    otherDs = TwoRoleCluster.app(PG, "unguarded");
    suOther = TwoRoleCluster.superuser(PG, "unguarded");
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {suOther, otherDs, appDs}) {
      if (ds != null) {
        ds.close();
      }
    }
    PG.stop();
  }

  // ------------------------------------------------------------------ M4, M6

  @Test
  void plain_delegate_retargeted_after_verification_refuses_and_writes_nothing_key_provider()
      throws SQLException {
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(otherDs);
    long before = rows(suOther, "shredding_data_key");

    Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(thrown, "database");
    assertThat(rows(suOther, "shredding_data_key")).isEqualTo(before);
  }

  @Test
  void plain_delegate_retargeted_after_verification_refuses_and_writes_nothing_erasure_store()
      throws SQLException {
    var moving = new Swappable(appDs);
    var store = store(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(otherDs);
    long before = rows(suOther, "shredding_erasure");

    Throwable thrown = catchThrowable(() -> store.append(record("m4-store")));

    assertRefused(thrown, "database");
    assertThat(rows(suOther, "shredding_erasure")).isEqualTo(before);
    assertThat(rows(suOther, "shredding_erasure_anchor")).isZero();
  }

  @Test
  void other_database_on_the_same_server_refuses() throws SQLException {
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(otherDs);
    // Precondition: the other database is a clean installation the same role could verify, so
    // only the database differs (same cluster, same public oid 2200, same roles).
    JdbcSupport.verifySchema(otherDs);

    Throwable read = catchThrowable(() -> keys.forRead(TenantId.of("t"), SubjectId.of("s"), 1));
    Throwable write = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(read, "database");
    assertRefused(write, "database");
    String ns = "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'public'";
    assertThat(scalar(otherDs, ns)).isEqualTo(scalar(appDs, ns));
    assertThat(((ShreddingException) write).getMessage())
        .describedAs("only the database differs")
        .contains(
            "(different: database; verified \"" + PG.getDatabaseName() + "\", got \"unguarded\")");
  }

  // ------------------------------------------------------------------ M5

  @Test
  void driver_manager_datasource_url_changed_after_verification_refuses() throws SQLException {
    var plain =
        new DriverManagerDataSource(TwoRoleCluster.url(PG, PG.getDatabaseName()), APP, PASSWORD);
    var keys = keys(JdbcSupport.verifySchema(plain).schema());
    plain.setUrl(TwoRoleCluster.url(PG, "unguarded"));
    long before = rows(suOther, "shredding_data_key");

    assertRefused(
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "database");
    assertThat(rows(suOther, "shredding_data_key")).isEqualTo(before);
  }

  @Test
  void pg_simple_datasource_url_changed_after_verification_refuses() throws SQLException {
    var plain = new PGSimpleDataSource();
    plain.setURL(TwoRoleCluster.url(PG, PG.getDatabaseName()));
    plain.setUser(APP);
    plain.setPassword(PASSWORD);
    var keys = keys(JdbcSupport.verifySchema(plain).schema());
    plain.setURL(TwoRoleCluster.url(PG, "unguarded"));
    long before = rows(suOther, "shredding_data_key");

    assertRefused(
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "database");
    assertThat(rows(suOther, "shredding_data_key")).isEqualTo(before);
  }

  // ------------------------------------------------------------------ M11

  /**
   * A pool over a mutable DataSource: the connections it opened before the URL moved still reach
   * the verified database and keep working; a connection opened after the move is refused.
   */
  @Test
  void connections_opened_before_the_move_still_work() throws SQLException {
    var plain = new PGSimpleDataSource();
    plain.setURL(TwoRoleCluster.url(PG, PG.getDatabaseName()));
    plain.setUser(APP);
    plain.setPassword(PASSWORD);
    var config = new HikariConfig();
    config.setDataSource(plain);
    config.setMaximumPoolSize(1);
    config.setMinimumIdle(1);
    try (var pool = new HikariDataSource(config)) {
      var keys = keys(JdbcSupport.verifySchema(pool).schema());
      plain.setURL(TwoRoleCluster.url(PG, "unguarded"));

      // The one pooled connection was opened before the move.
      keys.currentForWrite(TenantId.of("t"), subject());

      pool.getHikariPoolMXBean().softEvictConnections();
      long before = rows(suOther, "shredding_data_key");
      assertRefused(
          catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "database");
      assertThat(rows(suOther, "shredding_data_key")).isEqualTo(before);
    }
  }

  // ------------------------------------------------------------------ M17

  @Test
  void revoked_pg_control_system_refuses_verification_with_005() throws SQLException {
    try (var su = TwoRoleCluster.superuser(PG, PG.getDatabaseName())) {
      // Precondition: PostgreSQL grants it to PUBLIC by default, so the runtime role can read it.
      assertThat(
              scalar(
                  appDs,
                  "SELECT pg_catalog.has_function_privilege('pg_catalog.pg_control_system()',"
                      + " 'EXECUTE')"))
          .isEqualTo("t");
      exec(su, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC");
      try {
        Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(appDs));
        assertThat(thrown).isInstanceOf(ShreddingException.class);
        var refusal = (ShreddingException) thrown;
        assertThat(refusal.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
        assertThat(refusal.getMessage())
            .contains("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO " + APP)
            .contains("SQLState 42501");
      } finally {
        exec(su, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO PUBLIC");
      }
    }
  }

  // ------------------------------------------------------------------ M19 (round 2, item 3)

  /**
   * On the moved target, the runtime role owns a schema ahead of {@code pg_catalog} on its path and
   * defines {@code =(name, name)} there, answering true for the verified database's name only. An
   * unqualified {@code d.datname = current_database()} would then select the verified database's
   * row, whose oid and name match, on the same cluster with the same roles: the check would pass on
   * the wrong database. Qualified, it reads the row of the database it is in.
   */
  @Test
  void operator_spoof_on_the_moved_target_cannot_select_the_verified_row() throws SQLException {
    String verifiedName = PG.getDatabaseName();
    exec(
        suOther,
        "CREATE SCHEMA IF NOT EXISTS spoof AUTHORIZATION " + APP,
        "GRANT USAGE ON SCHEMA spoof TO " + APP);
    exec(
        otherDs,
        "CREATE OR REPLACE FUNCTION spoof.eq(pg_catalog.name, pg_catalog.name)"
            + " RETURNS boolean LANGUAGE sql IMMUTABLE"
            + " AS $$ SELECT $1 OPERATOR(pg_catalog.=) '"
            + verifiedName
            + "'::pg_catalog.name $$",
        "DROP OPERATOR IF EXISTS spoof.= (pg_catalog.name, pg_catalog.name)",
        "CREATE OPERATOR spoof.= (LEFTARG = pg_catalog.name, RIGHTARG = pg_catalog.name,"
            + " FUNCTION = spoof.eq)");
    var spoofed = new PGSimpleDataSource();
    spoofed.setURL(TwoRoleCluster.url(PG, "unguarded"));
    spoofed.setUser(APP);
    spoofed.setPassword(PASSWORD);
    spoofed.setOptions("-c search_path=spoof,pg_catalog,public");
    // Precondition: on that path an unqualified comparison really is the role's operator.
    assertThat(
            scalar(
                spoofed,
                "SELECT count(*) FROM pg_catalog.pg_database d"
                    + " WHERE d.datname = pg_catalog.current_database()"
                    + " AND d.datname OPERATOR(pg_catalog.=) '"
                    + verifiedName
                    + "'"))
        .isEqualTo("1");

    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(spoofed);
    long before = rows(suOther, "shredding_data_key");

    assertRefused(
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject())), "database");
    assertThat(rows(suOther, "shredding_data_key")).isEqualTo(before);
  }

  // ------------------------------------------------------------------ M21 (round 2, item 4)

  @Test
  void transaction_aware_proxy_inside_a_caller_transaction_reads_without_committing_it()
      throws SQLException {
    try (var owner =
        TwoRoleCluster.pool(PG, TwoRoleCluster.OWNER, PASSWORD, PG.getDatabaseName())) {
      exec(
          owner,
          "CREATE TABLE IF NOT EXISTS public.caller_mark (id int)",
          "GRANT SELECT, INSERT ON public.caller_mark TO " + APP);
    }
    var aware = new TransactionAwareDataSourceProxy(appDs);
    var keys = keys(JdbcSupport.verifySchema(aware).schema());
    var store = store(JdbcSupport.verifySchema(aware).schema());
    var tx = new TransactionTemplate(new DataSourceTransactionManager(appDs));
    long before = rows(appDs, "caller_mark");

    tx.executeWithoutResult(
        status -> {
          try {
            var c = DataSourceUtils.getConnection(appDs);
            try (var s = c.createStatement()) {
              s.execute("INSERT INTO public.caller_mark VALUES (1)");
            }
            assertThat(keys.forRead(TenantId.of("t"), SubjectId.of("none"), 1)).isEmpty();
            assertThat(store.anchor()).isNotNull();
            // Still inside the caller's transaction, and not made read-only by the module.
            assertThat(c.getAutoCommit()).isFalse();
            try (var s = c.createStatement()) {
              s.execute("INSERT INTO public.caller_mark VALUES (2)");
            }
          } catch (SQLException e) {
            throw new IllegalStateException(e);
          }
          status.setRollbackOnly();
        });

    assertThat(rows(appDs, "caller_mark"))
        .describedAs("the module committed a transaction it did not begin")
        .isEqualTo(before);
  }

  // ------------------------------------------------------------------ C-PR42-2: one test per leg

  /**
   * Leg {@code current_user}. A mutable delegate moves to a data source on the same database and
   * the same login, whose startup option sets another role ({@code -c role=...}, which PostgreSQL
   * accepts from any member of the role). Only {@code current_user} differs. Removing the {@code
   * current_user} comparison turns this red.
   */
  @Test
  void current_role_moved_by_a_startup_option_refuses() throws SQLException {
    exec(suOther, "CREATE ROLE shadow NOLOGIN", "GRANT shadow TO " + APP);
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());

    var shadowed = new PGSimpleDataSource();
    shadowed.setURL(TwoRoleCluster.url(PG, PG.getDatabaseName()));
    shadowed.setUser(APP);
    shadowed.setPassword(PASSWORD);
    shadowed.setOptions("-c role=shadow");
    // Precondition: same login, another current role.
    assertThat(scalar(shadowed, "SELECT session_user || '/' || current_user"))
        .isEqualTo(APP + "/shadow");
    moving.target.set(shadowed);

    Throwable read = catchThrowable(() -> keys.forRead(TenantId.of("t"), SubjectId.of("s"), 1));
    Throwable write = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(read, "current role");
    assertRefused(write, "current role");
    assertThat(((ShreddingException) write).getMessage())
        .describedAs("only the current role differs")
        .doesNotContain("database;")
        .doesNotContain("login role")
        .doesNotContain("cluster");
  }

  /**
   * Leg schema oid. Same pool, same database, same roles; the verified schema's name now resolves
   * to another schema object (the owner renamed the verified one and created a new one of that
   * name). Removing the schema oid comparison turns this from 012 into a key-store outage (42P01 on
   * the first statement).
   */
  @Test
  void schema_recreated_under_the_verified_name_refuses() throws SQLException {
    try (var swapApp = TwoRoleCluster.app(PG, "swapdb");
        var swapSu = TwoRoleCluster.superuser(PG, "swapdb")) {
      var keys = keys(JdbcSupport.verifySchema(swapApp).schema());
      exec(
          swapSu,
          "ALTER SCHEMA public RENAME TO public_verified",
          "CREATE SCHEMA public AUTHORIZATION " + TwoRoleCluster.OWNER,
          "GRANT USAGE ON SCHEMA public TO " + APP);

      Throwable write = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

      assertRefused(write, "schema");
      assertThat(((ShreddingException) write).getMessage())
          .doesNotContain("database;")
          .doesNotContain("login role")
          .doesNotContain("cluster");
    }
  }

  /**
   * The M21 branch of {@code readVerified}: a connection that arrives inside the application's own
   * transaction. The application's {@code @Transactional} runs on a delegate that has moved to
   * another database, through {@code TransactionAwareDataSourceProxy}. The module's read must still
   * refuse. Removing the check from that branch returns the other database's answer.
   */
  @Test
  void read_inside_a_caller_transaction_on_a_moved_target_refuses() throws SQLException {
    var moving = new Swappable(appDs);
    var aware = new TransactionAwareDataSourceProxy(moving);
    var keys = keys(JdbcSupport.verifySchema(aware).schema());
    moving.target.set(otherDs);
    var tx = new TransactionTemplate(new DataSourceTransactionManager(moving));

    Throwable thrown =
        catchThrowable(
            () ->
                tx.executeWithoutResult(
                    status -> keys.forRead(TenantId.of("t"), SubjectId.of("s"), 1)));

    assertRefused(thrown, "database");
  }

  // ------------------------------------------------------------------ messages, regression

  @Test
  void refusal_message_holds_no_url_host_password_or_identifier() throws SQLException {
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(otherDs);
    String systemIdentifier =
        scalar(appDs, "SELECT system_identifier FROM pg_catalog.pg_control_system()");
    String databaseOid =
        scalar(appDs, "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()");
    String otherOid =
        scalar(
            otherDs, "SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()");

    Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), subject()));

    assertRefused(thrown, "database");
    assertThat(thrown.getMessage())
        .doesNotContain("jdbc:")
        .doesNotContain(PG.getHost() + ":")
        .doesNotContain(String.valueOf(PG.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)))
        .doesNotContain(PASSWORD + " ")
        .doesNotContain(systemIdentifier)
        .doesNotContain(databaseOid)
        .doesNotContain(otherOid)
        .contains("Nothing was written")
        .endsWith("(" + CODE + ")");
  }

  @Test
  void unchanged_target_writes_normally() throws SQLException {
    var steady = new Swappable(appDs);
    VerifiedSchema schema = JdbcSupport.verifySchema(steady).schema();
    var keys = keys(schema);
    var store = store(schema);
    long keysBefore = rows(appDs, "shredding_data_key");
    long logBefore = rows(appDs, "shredding_erasure");

    SubjectId s = subject();
    var minted = keys.currentForWrite(TenantId.of("t"), s);
    assertThat(keys.forRead(TenantId.of("t"), s, minted.version())).isPresent();
    assertThat(keys.healthy()).isTrue();
    store.append(record("unchanged"));
    assertThat(store.latestForSubject(TenantId.of("t1"), pseudonym("unchanged"))).isPresent();
    assertThat(store.readAfter(0, 10)).isNotEmpty();
    assertThat(store.anchor()).isPresent();

    assertThat(rows(appDs, "shredding_data_key")).isEqualTo(keysBefore + 1);
    assertThat(rows(appDs, "shredding_erasure")).isEqualTo(logBefore + 1);
  }

  @Test
  void health_reports_down_on_a_moved_target() {
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    assertThat(keys.healthy()).isTrue();
    moving.target.set(otherDs);
    assertThat(keys.healthy()).isFalse();
  }

  // ------------------------------------------------------------------ helpers

  static void assertRefused(Throwable thrown, String different) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    var refusal = (ShreddingException) thrown;
    assertThat(refusal.code()).isEqualTo(CODE);
    assertThat(refusal.getMessage())
        .startsWith("shredding: a connection from the verified DataSource no longer reaches")
        .contains("different: ")
        .contains(different);
  }

  private static JdbcKeyProvider keys(VerifiedSchema schema) {
    return new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), Clock.systemUTC());
  }

  private static JdbcErasureStore store(VerifiedSchema schema) {
    return new JdbcErasureStore(schema, ErasureChain.keyed(SECRET, "k1"), List.of(), NO_RESIDUE);
  }

  private static SubjectId subject() {
    return SubjectId.of("s-" + System.nanoTime());
  }

  static String pseudonym(String name) {
    return String.format("%-64s", name).replace(' ', '0');
  }

  static ErasureRecord record(String name) {
    return ErasureRecord.of(
        Instant.now(),
        TenantId.of("t1"),
        pseudonym(name),
        "tester",
        "test",
        1,
        1,
        1,
        0,
        ErasureOutcome.COMPLETE,
        List.of(),
        Instant.now().plusSeconds(60));
  }
}
