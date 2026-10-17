package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.OWNER;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
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
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of PR 42 (C-PR-1b), pass 1. Finding C-PR42-2 and confirmations.
 *
 * <p>Three legs of the per-connection check have no test in the PR that fails when the leg is
 * removed: the schema oid, {@code current_user}, and the check on a connection that arrives inside
 * a caller's transaction (the M21 branch of {@code readVerified}). Removing each leg keeps the PR's
 * whole suite green (mutations A, B and G of the review). Each test below is a path on which
 * exactly that leg is the one that refuses. They pass on the PR's code; they are the witness for
 * the mutations, and the builder moves them into {@code DatabaseIdentityCheckTest}.
 *
 * <p>The last two tests confirm two angles of the review brief that are not findings: a {@code
 * search_path} on the moved connection cannot redirect the schema bind, and {@code
 * pg_control_system()} revoked after startup refuses every call, not only boot.
 */
class CipherProbePr42Test {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);
  private static final List<HikariDataSource> POOLS = new ArrayList<>();

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    TwoRoleCluster.install(PG, "unguarded");
    TwoRoleCluster.install(PG, "swapdb");
    TwoRoleCluster.install(PG, "revokedb");
  }

  @AfterAll
  static void stop() {
    POOLS.forEach(HikariDataSource::close);
    PG.stop();
  }

  private static HikariDataSource pool(HikariDataSource ds) {
    POOLS.add(ds);
    return ds;
  }

  private static JdbcKeyProvider keys(VerifiedSchema schema) {
    return new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), Clock.systemUTC());
  }

  private static PGSimpleDataSource simple(String database, String options) {
    var ds = new PGSimpleDataSource();
    ds.setURL(TwoRoleCluster.url(PG, database));
    ds.setUser(APP);
    ds.setPassword(PASSWORD);
    if (options != null) {
      ds.setOptions(options);
    }
    return ds;
  }

  private static void assertRefused(Throwable thrown, String different) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    var refusal = (ShreddingException) thrown;
    assertThat(refusal.code()).isEqualTo("SHRED-SCHEMA-012");
    assertThat(refusal.getMessage()).contains("different: ").contains(different);
  }

  /**
   * Leg {@code current_user}. A mutable delegate moves to a data source on the same database and
   * the same login, whose startup option sets another role ({@code -c role=...}, which PostgreSQL
   * accepts from any member of the role). Only {@code current_user} differs. Mutation B (drop the
   * {@code current_user} comparison) turns this red; no PR test does.
   */
  @Test
  void probe_current_role_moved_by_a_startup_option_is_refused_only_by_the_current_user_leg()
      throws SQLException {
    var su = pool(TwoRoleCluster.superuser(PG, PG.getDatabaseName()));
    exec(su, "CREATE ROLE shadow NOLOGIN", "GRANT shadow TO " + APP);
    var appDs = pool(TwoRoleCluster.app(PG, PG.getDatabaseName()));
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());

    var shadowed = simple(PG.getDatabaseName(), "-c role=shadow");
    // Precondition: same login, another current role.
    assertThat(scalar(shadowed, "SELECT session_user || '/' || current_user"))
        .isEqualTo(APP + "/shadow");
    moving.target.set(shadowed);

    Throwable read = catchThrowable(() -> keys.forRead(TenantId.of("t"), SubjectId.of("s"), 1));
    Throwable write =
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), SubjectId.of("cr")));

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
   * name). Mutation A (drop the schema oid comparison) turns this from 012 into a key-store outage
   * (42P01 on the first statement); no PR test sees the difference.
   */
  @Test
  void probe_schema_recreated_under_the_verified_name_is_refused_only_by_the_schema_leg()
      throws SQLException {
    var appDs = pool(TwoRoleCluster.app(PG, "swapdb"));
    var keys = keys(JdbcSupport.verifySchema(appDs).schema());
    var su = pool(TwoRoleCluster.superuser(PG, "swapdb"));
    exec(
        su,
        "ALTER SCHEMA public RENAME TO public_verified",
        "CREATE SCHEMA public AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA public TO " + APP);

    Throwable write =
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), SubjectId.of("sc")));

    assertRefused(write, "schema");
    assertThat(((ShreddingException) write).getMessage())
        .doesNotContain("database;")
        .doesNotContain("login role")
        .doesNotContain("cluster");
  }

  /**
   * The M21 branch of {@code readVerified}: a connection that arrives inside the application's own
   * transaction. The application's {@code @Transactional} runs on a delegate that has moved to
   * another database, through {@code TransactionAwareDataSourceProxy}. The module's read must still
   * refuse. Mutation G (no check in that branch) returns the other database's answer; the PR's M21
   * test runs on the verified database only, so it stays green.
   */
  @Test
  void probe_read_inside_a_caller_transaction_on_a_moved_target_is_refused() throws SQLException {
    var appDs = pool(TwoRoleCluster.app(PG, PG.getDatabaseName()));
    var otherDs = pool(TwoRoleCluster.app(PG, "unguarded"));
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

  /**
   * Confirmation, not a finding. The moved connection's session {@code search_path} puts a schema
   * the runtime role owns, holding a table of the module's name, ahead of {@code public}. The
   * fingerprint binds the verified schema by name and every module statement qualifies its
   * relations, so the check passes (same database, same roles) and the row lands in the verified
   * schema, not in the role's.
   */
  @Test
  void confirm_search_path_on_the_moved_connection_cannot_redirect_the_schema_bind()
      throws SQLException {
    var su = pool(TwoRoleCluster.superuser(PG, PG.getDatabaseName()));
    exec(
        su,
        "CREATE SCHEMA IF NOT EXISTS evil AUTHORIZATION " + APP,
        "CREATE TABLE IF NOT EXISTS evil.shredding_data_key (LIKE public.shredding_data_key)",
        "ALTER TABLE evil.shredding_data_key OWNER TO " + APP);
    var appDs = pool(TwoRoleCluster.app(PG, PG.getDatabaseName()));
    var moving = new Swappable(appDs);
    var keys = keys(JdbcSupport.verifySchema(moving).schema());
    moving.target.set(simple(PG.getDatabaseName(), "-c search_path=evil,public"));
    long verifiedBefore = rows(su, "shredding_data_key");

    keys.currentForWrite(TenantId.of("t"), SubjectId.of("sp-" + System.nanoTime()));

    assertThat(rows(su, "shredding_data_key")).isEqualTo(verifiedBefore + 1);
    assertThat(scalar(su, "SELECT count(*) FROM evil.shredding_data_key")).isEqualTo("0");
  }

  /**
   * Confirmation, not a finding. {@code pg_control_system()} revoked after startup: every store
   * call refuses with 012 and writes nothing. Fail closed at runtime, as at boot (M17).
   */
  @Test
  void confirm_pg_control_system_revoked_after_startup_refuses_every_call() throws SQLException {
    var appDs = pool(TwoRoleCluster.app(PG, "revokedb"));
    var keys = keys(JdbcSupport.verifySchema(appDs).schema());
    var su = pool(TwoRoleCluster.superuser(PG, "revokedb"));
    long before = rows(su, "shredding_data_key");
    exec(su, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC");
    try {
      Throwable write =
          catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), SubjectId.of("rv")));
      Throwable read = catchThrowable(() -> keys.forRead(TenantId.of("t"), SubjectId.of("rv"), 1));
      for (Throwable thrown : List.of(write, read)) {
        assertThat(thrown).isInstanceOf(ShreddingException.class);
        assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-SCHEMA-012");
        assertThat(thrown.getMessage()).contains("could not be checked (SQLState 42501)");
      }
      assertThat(keys.healthy()).isFalse();
      assertThat(rows(su, "shredding_data_key")).isEqualTo(before);
    } finally {
      exec(su, "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO PUBLIC");
    }
  }
}
