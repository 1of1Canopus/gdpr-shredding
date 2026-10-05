package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Release-candidate whole-module pass, 0.2.0, lead 4: the upgrade path from a real 0.1.1 install.
 *
 * <p>{@code SchemaVerificationTest.t30} upgrades an install made by the <em>0.2.0</em> script. This
 * class installs with the script the 0.1.1 jar actually shipped (extracted from tag {@code v0.1.1}
 * into {@code cipherrc/schema-postgresql-0.1.1.sql}), applied the way 0.1.1 applied it: by the
 * application role, in one transaction, at boot. Then it runs {@code docs/upgrading-0.2.0.md} steps
 * 2 to 5 as written, and boots 0.2.0's verification.
 */
@Testcontainers
class CipherProbeRc020UpgradeTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "rc_owner";
  private static final String APP = "rc_app";

  @BeforeEach
  void a011InstallWithLiveRows() throws Exception {
    su(
        "DROP SCHEMA IF EXISTS public CASCADE",
        "DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['"
            + APP
            + "', '"
            + OWNER
            + "']"
            + " LOOP IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN"
            + " EXECUTE 'DROP OWNED BY ' || r; EXECUTE 'DROP ROLE ' || r; END IF; END LOOP; END $$",
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE SCHEMA public AUTHORIZATION " + APP,
        "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE "
            + POSTGRES.getDatabaseName()
            + " TO "
            + APP);
    // 0.1.1's boot: JdbcSupport.initializeSchema(applicationDataSource), one transaction.
    inTx(APP, script011());
    exec(
        APP,
        "INSERT INTO shredding_data_key (tenant, subject, version, wrapped_key, state,"
            + " created_at) VALUES ('t1', 's1', 1, '\\x00'::bytea, 'ACTIVE', now())",
        "INSERT INTO shredding_erased_subject (tenant, subject, erased_at)"
            + " VALUES ('t1', 's0', now())");
  }

  /** Steps 2 to 5 of docs/upgrading-0.2.0.md, verbatim in substance. */
  private void upgradeSteps() throws Exception {
    su(
        "ALTER TABLE    shredding_data_key                     OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erased_subject               OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erasure                      OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erasure_anchor               OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_append_only()        OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()   OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO " + OWNER,
        "ALTER SCHEMA public OWNER TO " + OWNER);
    JdbcSupport.initializeSchema(ds(OWNER));
    su(
        "REVOKE CREATE    ON SCHEMA   public   FROM " + APP,
        "REVOKE CREATE    ON SCHEMA   public   FROM PUBLIC",
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP + ", PUBLIC",
        "REVOKE CREATE    ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP + ", PUBLIC");
    exec(
        OWNER,
        "GRANT USAGE ON SCHEMA public TO " + APP,
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);
  }

  /**
   * Confirmation, not a finding: the guide's steps take a real 0.1.1 install to a clean 0.2.0 boot
   * under the unprivileged role, and the 0.1.1 rows survive.
   */
  @Test
  void rc_a_real_0_1_1_install_upgraded_by_the_guide_verifies_clean() throws Exception {
    upgradeSteps();
    SchemaVerdict verdict = JdbcSupport.verifySchema(ds(APP));
    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
    assertThat(scalar("SELECT count(*) FROM public.shredding_data_key")).isEqualTo(1);
    assertThat(scalar("SELECT count(*) FROM public.shredding_erased_subject")).isEqualTo(1);
  }

  /**
   * RC-0.2.0-4. The release notes and the guide say "Rolling back to 0.1.1 is safe with nothing to
   * undo in the database". 0.1.1 runs its bundled script with the application's credentials at
   * every boot, with no property to skip it; after steps 2 and 4 that role owns no guard function
   * and holds no CREATE on the schema, so 0.1.1's boot DDL fails and the rolled-back application
   * does not start. The first half characterises that (green); the second asserts the guide no
   * longer promises the opposite (red until the text is corrected).
   */
  @Test
  void probe_rollback_to_0_1_1_after_the_upgrade_does_not_boot_but_the_guide_says_it_is_safe()
      throws Exception {
    upgradeSteps();
    Throwable boot011 = catchThrowable(() -> inTx(APP, script011()));
    assertThat(boot011)
        .describedAs("0.1.1's unconditional boot DDL, run as the post-upgrade runtime role")
        .isNotNull();
    System.out.println("CIPHER-RC rollback: 0.1.1 boot DDL as runtime role -> " + boot011);

    String guide = Files.readString(moduleRoot().resolve("docs/upgrading-0.2.0.md"));
    String rollback = guide.substring(guide.indexOf("## Rolling back"));
    assertThat(rollback)
        .describedAs(
            "the guide's rollback section must not promise a rollback with nothing to undo")
        .doesNotContain("nothing to undo");
  }

  /**
   * RC-0.2.0-6. Step 7 of the guide is the table an operator reads when the first 0.2.0 boot
   * refuses. It lists SHRED-SCHEMA-001 to -007 and SHRED-CONFIG-001, but not SHRED-SCHEMA-009, the
   * refusal the release notes call "the one change most installations will meet" (a uuid tenant or
   * subject column), and the guide gives the exact message only for SHRED-CONFIG-001.
   */
  @Test
  void probe_upgrade_guide_step_7_omits_the_mapping_admission_refusal() throws IOException {
    String guide = Files.readString(moduleRoot().resolve("docs/upgrading-0.2.0.md"));
    String step7 =
        guide.substring(guide.indexOf("### 7. Deploy 0.2.0"), guide.indexOf("### 8. Only if"));
    assertThat(step7).contains("SHRED-SCHEMA-009");
  }

  // ------------------------------------------------------------------------------------- helpers

  private static Path moduleRoot() {
    Path p = Path.of("").toAbsolutePath();
    while (p != null && !Files.exists(p.resolve("docs/upgrading-0.2.0.md"))) {
      p = p.getParent();
    }
    return p;
  }

  private static String script011() throws IOException {
    try (InputStream in =
        CipherProbeRc020UpgradeTest.class.getResourceAsStream(
            "/cipherrc/schema-postgresql-0.1.1.sql")) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static Connection connect(String user) throws SQLException {
    if (user == null) {
      return DriverManager.getConnection(
          POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
    return DriverManager.getConnection(POSTGRES.getJdbcUrl(), user, "pw");
  }

  private static void su(String... sql) throws SQLException {
    exec(null, sql);
  }

  private static void exec(String user, String... sql) throws SQLException {
    try (Connection c = connect(user);
        Statement st = c.createStatement()) {
      for (String s : sql) {
        st.execute(s);
      }
    }
  }

  private static void inTx(String user, String sql) throws SQLException {
    try (Connection c = connect(user)) {
      c.setAutoCommit(false);
      try (Statement st = c.createStatement()) {
        st.execute(sql);
        c.commit();
      } catch (SQLException e) {
        c.rollback();
        throw e;
      }
    }
  }

  private static long scalar(String sql) throws SQLException {
    try (Connection c = connect(null);
        Statement st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  /** A fresh session per connection: role and search_path changes always apply. */
  private static DataSource ds(String user) {
    return new DataSource() {
      @Override
      public Connection getConnection() throws SQLException {
        return connect(user);
      }

      @Override
      public Connection getConnection(String u, String p) throws SQLException {
        return connect(user);
      }

      @Override
      public PrintWriter getLogWriter() {
        return null;
      }

      @Override
      public void setLogWriter(PrintWriter out) {}

      @Override
      public void setLoginTimeout(int seconds) {}

      @Override
      public int getLoginTimeout() {
        return 0;
      }

      @Override
      public Logger getParentLogger() {
        return Logger.getGlobal();
      }

      @Override
      public <T> T unwrap(Class<T> iface) throws SQLException {
        throw new SQLException("not a wrapper");
      }

      @Override
      public boolean isWrapperFor(Class<?> iface) {
        return false;
      }
    };
  }
}
