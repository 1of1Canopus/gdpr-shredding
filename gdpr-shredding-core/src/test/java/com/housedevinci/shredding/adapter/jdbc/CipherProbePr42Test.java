package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
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
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of PR 42 (C-PR-1b), pass 1. Confirmations.
 *
 * <p>The three witnesses for C-PR42-2 (schema oid, {@code current_user}, the check inside a
 * caller's transaction) now live in {@code DatabaseIdentityCheckTest}.
 *
 * <p>The two tests here confirm two angles of the review brief that are not findings: a {@code
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
