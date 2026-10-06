package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * RC-4: the rollback procedure written in docs/upgrading-0.2.0.md is executed here, statement by
 * statement, against a real 0.1.1 install that was upgraded by steps 2 to 5: after either variant
 * the 0.1.1 boot script runs to completion as the role 0.1.1 is configured with.
 */
@Testcontainers
class RollbackTo011ProcedureTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "rb_owner";
  private static final String APP = "rb_app";

  @BeforeEach
  void upgradedInstall() throws Exception {
    su(
        "DROP SCHEMA IF EXISTS public CASCADE",
        "DO $$ DECLARE r text; BEGIN FOREACH r IN ARRAY ARRAY['"
            + APP
            + "', '"
            + OWNER
            + "'] LOOP IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN"
            + " EXECUTE 'DROP OWNED BY ' || r; EXECUTE 'DROP ROLE ' || r; END IF; END LOOP; END $$",
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE SCHEMA public AUTHORIZATION " + APP,
        "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE "
            + POSTGRES.getDatabaseName()
            + " TO "
            + APP);
    inTx(APP, script011());
    // Steps 2 to 5 of the guide.
    su(
        "ALTER TABLE    shredding_data_key                     OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erased_subject               OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erasure                      OWNER TO " + OWNER,
        "ALTER TABLE    shredding_erasure_anchor               OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_append_only()        OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()   OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO " + OWNER,
        "ALTER SCHEMA public OWNER TO " + OWNER);
    try (var owner = ds(OWNER)) {
      JdbcSupport.initializeSchema(owner);
    }
    su(
        "REVOKE CREATE ON SCHEMA public FROM " + APP,
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        // Step 5's schema grant; the runtime role keeps USAGE through a rollback.
        "GRANT USAGE ON SCHEMA public TO " + APP);
  }

  /** The guide's variant A: boot 0.1.1 with the owner role's credentials, nothing to undo. */
  @Test
  void variant_a_boot_011_as_the_owner_role() {
    assertThatCode(() -> inTx(OWNER, script011())).doesNotThrowAnyException();
  }

  /** The guide's variant B: the statements that undo steps 2 and 4, then boot 0.1.1 as before. */
  @Test
  void variant_b_undo_ownership_and_create_then_boot_011_as_the_application_role()
      throws Exception {
    su(
        "ALTER TABLE    shredding_data_key                     OWNER TO " + APP,
        "ALTER TABLE    shredding_erased_subject               OWNER TO " + APP,
        "ALTER TABLE    shredding_erasure                      OWNER TO " + APP,
        "ALTER TABLE    shredding_erasure_anchor               OWNER TO " + APP,
        "ALTER FUNCTION shredding_erasure_append_only()        OWNER TO " + APP,
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()   OWNER TO " + APP,
        "ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO " + APP,
        "GRANT CREATE ON SCHEMA public TO " + APP);
    assertThatCode(() -> inTx(APP, script011())).doesNotThrowAnyException();
  }

  private static String script011() throws Exception {
    try (InputStream in =
        RollbackTo011ProcedureTest.class.getResourceAsStream(
            "/cipherrc/schema-postgresql-0.1.1.sql")) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static Connection connect(String user) throws SQLException {
    return user == null
        ? DriverManager.getConnection(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
        : DriverManager.getConnection(POSTGRES.getJdbcUrl(), user, "pw");
  }

  private static void su(String... sql) throws SQLException {
    try (Connection c = connect(null);
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

  private static com.zaxxer.hikari.HikariDataSource ds(String user) {
    var config = new com.zaxxer.hikari.HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword("pw");
    config.setMaximumPoolSize(1);
    return new com.zaxxer.hikari.HikariDataSource(config);
  }
}
