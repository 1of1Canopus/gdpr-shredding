package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.rows;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.Swappable;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of the C-PR-1 design page (2026-10-15), the C-PR-1b probe, moved into the test
 * tree by the C-PR-1b build and tightened: the refusal must be {@code SHRED-SCHEMA-012} and the
 * unguarded database must hold no row. RED on main 48e0516 and on 801d651. The two C-PR-1c probes
 * follow, moved in unchanged by the C-PR-1c build, RED on d842a19; their tightened forms are in
 * {@code LoginRoleReachTest}.
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
      // The owner may SET ROLE to the runtime role: the shape of "connect as the owner, drop to
      // the app role in connection-init-sql" (C-PR-1c).
      TwoRoleCluster.exec(su, "CREATE DATABASE unguarded", "GRANT shredding_app TO shred_owner");
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

  // ------------------------------------------------------------------ C-PR-1c

  @Test
  void probe_set_role_in_init_sql_passes_as_unprivileged_while_session_is_the_owner()
      throws SQLException {
    var ownerDroppedToApp =
        TwoRoleCluster.pool(
            POSTGRES,
            TwoRoleCluster.OWNER,
            TwoRoleCluster.PASSWORD,
            POSTGRES.getDatabaseName(),
            "SET ROLE " + TwoRoleCluster.APP);
    try {
      // Impact first: on a connection of this very pool, RESET ROLE reaches the owner, and the
      // owner can switch off the append-only guard. Rolled back, so nothing persists.
      try (Connection c = ownerDroppedToApp.getConnection()) {
        c.setAutoCommit(false);
        try (var s = c.createStatement()) {
          s.execute("RESET ROLE");
          s.execute("ALTER TABLE public.shredding_erasure DISABLE TRIGGER ALL");
        }
        c.rollback();
      }

      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(ownerDroppedToApp));

      assertThat(thrown)
          .describedAs(
              "C-PR-1c: the session user owns every guarded object; the gate verified current_user"
                  + " only and called the runtime role unprivileged")
          .isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code())
          .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    } finally {
      ownerDroppedToApp.close();
    }
  }

  @Test
  void probe_set_session_authorization_in_init_sql_passes_while_login_is_superuser()
      throws SQLException {
    // Checking session_user instead of current_user is not enough: SET SESSION AUTHORIZATION
    // moves session_user too, and RESET SESSION AUTHORIZATION returns to the login role.
    var superuserDroppedToApp =
        TwoRoleCluster.pool(
            POSTGRES,
            POSTGRES.getUsername(),
            POSTGRES.getPassword(),
            POSTGRES.getDatabaseName(),
            "SET SESSION AUTHORIZATION " + TwoRoleCluster.APP);
    try {
      try (Connection c = superuserDroppedToApp.getConnection()) {
        c.setAutoCommit(false);
        try (var s = c.createStatement()) {
          var rs = s.executeQuery("SELECT session_user = current_user");
          rs.next();
          assertThat(rs.getBoolean(1)).describedAs("precondition: session_user moved").isTrue();
          s.execute("RESET SESSION AUTHORIZATION");
          s.execute("ALTER TABLE public.shredding_erasure DISABLE TRIGGER ALL");
        }
        c.rollback();
      }

      Throwable thrown = catchThrowable(() -> JdbcSupport.verifySchema(superuserDroppedToApp));

      assertThat(thrown)
          .describedAs(
              "C-PR-1c: the login role is a superuser; the gate saw only the role the session"
                  + " moved to")
          .isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code())
          .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    } finally {
      superuserDroppedToApp.close();
    }
  }
}
