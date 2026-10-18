package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 41 pass 1 (C-PR-1d fix). Core side; confirmations, expected green.
 *
 * <p>(a) the line is printed at every call, not once per pool; (b) the line carries no secret and
 * no JDBC URL, even when the password rides in the URL.
 */
class CipherProbePr41CoreTest {

  private static final String SECRET = "pr41SecretPw9z";

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withPassword(SECRET)
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static HikariDataSource urlPasswordDs;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    var config = new HikariConfig();
    config.setJdbcUrl(
        "jdbc:postgresql://"
            + POSTGRES.getHost()
            + ":"
            + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + POSTGRES.getDatabaseName()
            + "?user="
            + POSTGRES.getUsername()
            + "&password="
            + SECRET);
    config.setMaximumPoolSize(2);
    urlPasswordDs = new HikariDataSource(config);
    JdbcSupport.initializeSchema(urlPasswordDs);
  }

  @AfterAll
  static void stop() {
    if (urlPasswordDs != null) {
      urlPasswordDs.close();
    }
    POSTGRES.stop();
  }

  @Test
  void probe_second_verification_on_the_same_pool_is_silent() {
    var out = new StringBuilder();
    capture(
        out,
        () -> {
          JdbcSupport.verifySchema(urlPasswordDs, true);
          JdbcSupport.verifySchema(urlPasswordDs, true);
          return JdbcSupport.initializeAndVerifySchema(urlPasswordDs, true);
        });
    long warns =
        out.toString()
            .lines()
            .filter(l -> l.contains(" WARN ") && l.contains("is privileged over the shredding"))
            .count();
    assertThat(warns).describedAs("one WARN per call, three calls, same pool").isEqualTo(3);
  }

  @Test
  void probe_verification_line_leaks_the_password_or_the_url() {
    var out = new StringBuilder();
    capture(out, () -> JdbcSupport.verifySchema(urlPasswordDs, true));
    String text = out.toString();
    assertThat(text).contains("is privileged over the shredding");
    assertThat(text).doesNotContain(SECRET).doesNotContain("jdbc:").doesNotContain("password=");
  }

  /**
   * C-PR41-2. A core-only caller (no Spring) in strict mode with a privileged role is told to set
   * the starter property shredding.jdbc.allow-privileged-runtime-role=true, which core never reads;
   * the core switch, the boolean argument of verifySchema, is not named.
   */
  @Test
  void probe_core_refusal_points_a_core_only_caller_at_a_property_core_never_reads() {
    Throwable refused =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> JdbcSupport.verifySchema(urlPasswordDs));
    assertThat(refused).isInstanceOf(com.housedevinci.shredding.domain.ShreddingException.class);
    assertThat(refused.getMessage()).contains("shredding.jdbc.allow-privileged-runtime-role");
    assertThat(refused.getMessage())
        .describedAs("C-PR41-2: the core switch is named next to the starter property")
        .containsAnyOf("verifySchema(ds, true)", "allowPrivilegedRuntimeRole");
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
}
