package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1d: core logs one line per verification, at every call. INFO with the summary in strict
 * mode, WARN naming the privilege legs in the privileged mode. A team that uses core without the
 * starter must not get the weaker mode silently.
 */
@Testcontainers
class SchemaVerificationLoggingTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "shred_owner";
  private static final String APP = "shredding_app";

  private static final List<String> GRANT_BLOCK =
      List.of(
          "GRANT USAGE ON SCHEMA public TO shredding_app",
          "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO shredding_app",
          "GRANT UPDATE (encryption_count) ON shredding_data_key TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erased_subject TO shredding_app",
          "GRANT UPDATE (erased_at) ON shredding_erased_subject TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erasure TO shredding_app",
          "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO shredding_app",
          "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO shredding_app");

  private static HikariDataSource superuserDs;
  private static HikariDataSource ownerDs;
  private static HikariDataSource appDs;

  @BeforeAll
  static void start() throws SQLException {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    exec(
        superuserDs,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    ownerDs = pool(OWNER, "pw");
    appDs = pool(APP, "pw");
    JdbcSupport.initializeSchema(ownerDs);
    exec(ownerDs, GRANT_BLOCK.toArray(String[]::new));
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {appDs, ownerDs, superuserDs}) {
      if (ds != null) {
        ds.close();
      }
    }
    POSTGRES.stop();
  }

  @Test
  void probe_core_privileged_mode_mints_a_verified_schema_without_any_warn() {
    var out = new StringBuilder();
    SchemaVerdict verdict = capture(out, () -> JdbcSupport.verifySchema(ownerDs, true));
    assertThat(verdict.privilegeLegs())
        .describedAs("precondition: owner is privileged")
        .isNotEmpty();
    assertThat(out.toString())
        .describedAs("C-PR-1d: the weaker mode produced a capability and printed nothing")
        .contains("WARN");
  }

  @Test
  void privileged_mode_logs_exactly_one_warn_naming_every_leg_and_no_info() {
    var out = new StringBuilder();
    SchemaVerdict verdict = capture(out, () -> JdbcSupport.verifySchema(ownerDs, true));
    String text = out.toString();
    assertThat(lines(text, "WARN")).hasSize(1);
    assertThat(lines(text, "INFO")).isEmpty();
    for (String leg : verdict.privilegeLegs()) {
      assertThat(text).contains(leg);
    }
    assertThat(text).contains(OWNER);
  }

  @Test
  void initialize_and_verify_logs_the_warn_once_in_privileged_mode() {
    var out = new StringBuilder();
    capture(out, () -> JdbcSupport.initializeAndVerifySchema(ownerDs, true));
    assertThat(lines(out.toString(), "WARN")).hasSize(1);
    assertThat(lines(out.toString(), "INFO")).isEmpty();
  }

  @Test
  void strict_mode_logs_exactly_one_info_summary_and_no_warn() {
    var out = new StringBuilder();
    SchemaVerdict verdict = capture(out, () -> JdbcSupport.verifySchema(appDs));
    assertThat(lines(out.toString(), "INFO")).hasSize(1);
    assertThat(lines(out.toString(), "WARN")).isEmpty();
    assertThat(out.toString()).contains(verdict.summary());
  }

  private static List<String> lines(String text, String level) {
    return text.lines()
        .filter(l -> l.contains(" " + level + " ") && l.contains("shredding:"))
        .toList();
  }

  private static <T> T capture(StringBuilder sink, Supplier<T> action) {
    PrintStream original = System.err;
    var captured = new ByteArrayOutputStream();
    try {
      System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
      return action.get();
    } finally {
      System.setErr(original);
      sink.append(captured.toString(StandardCharsets.UTF_8));
    }
  }

  private static void exec(HikariDataSource ds, String... sql) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      for (String each : sql) {
        s.execute(each);
      }
    }
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(
        "jdbc:postgresql://"
            + POSTGRES.getHost()
            + ":"
            + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + POSTGRES.getDatabaseName());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    return new HikariDataSource(config);
  }
}
