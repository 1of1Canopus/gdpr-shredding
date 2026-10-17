package com.housedevinci.shredding.adapter.jdbc;

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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of the C-PR-1 design page (2026-10-15), the C-PR-1b probe, moved into the test
 * tree by the C-PR-1b build and tightened: the refusal must be {@code SHRED-SCHEMA-012} and the
 * unguarded database must hold no row. RED on main 48e0516 and on 801d651. The review's other three
 * probes belong to C-PR-1c and C-PR-1d.
 *
 * <p>Setup as in the review: the verified database in the two-role posture, and a second database
 * on the same server whose tables the superuser owns and nobody verified. The DataSource is a
 * ten-line application delegate, not a Spring class: a refusal by class name does not reach it.
 */
class CipherProbeCPr1DesignReviewTest {

  private static final PostgreSQLContainer<?> POSTGRES = TwoRoleCluster.container();

  private static HikariDataSource appDs;
  private static HikariDataSource unguardedDs;

  @BeforeAll
  static void start() throws SQLException {
    POSTGRES.start();
    TwoRoleCluster.roles(POSTGRES);
    TwoRoleCluster.install(POSTGRES, POSTGRES.getDatabaseName());
    try (var su = TwoRoleCluster.superuser(POSTGRES, POSTGRES.getDatabaseName())) {
      TwoRoleCluster.exec(su, "CREATE DATABASE unguarded");
    }
    unguardedDs = TwoRoleCluster.superuser(POSTGRES, "unguarded");
    JdbcSupport.initializeSchema(unguardedDs);
    appDs = TwoRoleCluster.app(POSTGRES, POSTGRES.getDatabaseName());
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {unguardedDs, appDs}) {
      if (ds != null) {
        ds.close();
      }
    }
    POSTGRES.stop();
  }

  @Test
  @SuppressWarnings("removal")
  void probe_datasource_whose_target_changes_after_verification_writes_unverified()
      throws SQLException {
    var swappable = new Swappable(appDs);
    VerifiedSchema schema = JdbcSupport.verifySchema(swappable).schema();
    // Same object the schema was verified on: an identity check is satisfied, before and after.
    var keys =
        new JdbcKeyProvider(
            swappable,
            schema,
            MasterKey.fromBytes(new byte[32]),
            RandomSource.secure(),
            Clock.systemUTC());
    swappable.target.set(unguardedDs);

    Throwable thrown =
        catchThrowable(() -> keys.currentForWrite(TenantId.of("t1"), SubjectId.of("s1")));

    assertThat(rows(unguardedDs, "shredding_data_key"))
        .describedAs("C-PR-1b: a data key was written to a database whose guards nobody checked")
        .isZero();
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-SCHEMA-012");
  }
}
