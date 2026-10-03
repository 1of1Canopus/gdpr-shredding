package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.namegate.SqlSites;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 18 (feat/read-back-bracket), first pass. Every case is RED on f3fc861.
 *
 * <p>Copy into gdpr-shredding-core/src/test/java/com/housedevinci/shredding/adapter/jdbc/ before
 * touching production code; each case names the finding it belongs to.
 */
class CipherProbePr18Test {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(Duration.ofMinutes(2));

  /** The module root, wherever surefire runs from (module dir or reactor root). */
  private static Path moduleRoot() {
    Path here = Path.of("").toAbsolutePath();
    return Files.exists(here.resolve("SECURITY-NOTES.md")) ? here : here.getParent();
  }

  @BeforeAll
  static void start() {
    POSTGRES.start();
  }

  @AfterAll
  static void stop() {
    POSTGRES.stop();
  }

  /**
   * C-18-3. SECURITY-NOTES, docs/upgrading-0.2.0.md and the window's javadoc tell an operator that
   * a {@code LANGUAGE sql} function body "resolves its names at creation time" and is "immune" /
   * "unaffected" inside the window. That holds only for a SQL-standard body ({@code BEGIN ATOMIC}
   * or {@code RETURN}, PostgreSQL 14+). The ordinary string body ({@code AS $$ ... $$}) is parsed
   * again when it runs, with the search_path in force then - inside the window, {@code pg_catalog,
   * pg_temp} - so it fails exactly like a plpgsql body. The design's own source for the claim (its
   * C-12) was a creation-time validation error, not a binding.
   *
   * <p>Measured here first (both halves), then the three texts are held to it: every sentence that
   * calls a {@code LANGUAGE sql} body immune or unaffected must name the SQL-standard form.
   */
  @Test
  void probe_a_string_body_sql_function_is_not_immune_inside_the_window() throws Exception {
    try (Connection su = superuser()) {
      exec(
          su,
          "CREATE TABLE IF NOT EXISTS public.pr18_allow (x int)",
          "INSERT INTO public.pr18_allow VALUES (1)",
          "CREATE OR REPLACE FUNCTION public.pr18_string_body() RETURNS bigint"
              + " AS $$ SELECT count(*) FROM pr18_allow $$ LANGUAGE sql",
          "CREATE OR REPLACE FUNCTION public.pr18_atomic_body() RETURNS bigint LANGUAGE sql"
              + " BEGIN ATOMIC SELECT count(*) FROM pr18_allow; END");
    }
    String stringBody = insideWindow("SELECT public.pr18_string_body()");
    String atomicBody = insideWindow("SELECT public.pr18_atomic_body()");

    assertThat(atomicBody)
        .describedAs("a SQL-standard body is bound at creation: it answers inside the window")
        .isEqualTo("1");
    assertThat(stringBody)
        .describedAs(
            "a string-body LANGUAGE sql function is re-parsed at run time on the window's path")
        .startsWith("42P01");

    var claims = new ArrayList<String>();
    for (String file :
        List.of(
            "SECURITY-NOTES.md",
            "docs/upgrading-0.2.0.md",
            "gdpr-shredding-core/src/main/java/com/housedevinci/shredding/adapter/jdbc/JdbcSupport.java")) {
      String text =
          Files.readString(moduleRoot().resolve(file), StandardCharsets.UTF_8)
              .replaceAll("\\s*\\*\\s+", " ")
              .replaceAll("\\s+", " ");
      for (String sentence : text.split("(?<=[.;])\\s")) {
        String s = sentence.toLowerCase(Locale.ROOT);
        if (s.contains("language sql")
            && (s.contains("immune") || s.contains("unaffected") || s.contains("creation time"))
            && !s.contains("begin atomic")) {
          claims.add(file + ": " + sentence.strip());
        }
      }
    }
    assertThat(claims)
        .describedAs(
            "a sentence that tells an operator a LANGUAGE sql body is immune to the window, while"
                + " the string body measured above fails inside it with 42P01")
        .isEmpty();
  }

  /**
   * C-18-4. Design section 4.4: "a SQLException on any of the six is SHRED-SCHEMA-008", and the
   * window's own javadoc: "-008 when the replacement cannot be established". A failure of the pin
   * itself (step 2) propagates as the raw SQLException instead, which inTransaction then reports as
   * a key-store outage - not the code whose remedy page is the window's. Step 4's failure (M3) is
   * the only one that is meant to surface itself.
   */
  @Test
  void probe_a_failure_to_establish_the_pin_is_reported_as_the_isolation_code() {
    Connection c = connectionWhosePinFails();
    Throwable thrown = null;
    try {
      JdbcSupport.inOneStatementWindow(c, () -> 1L);
    } catch (Throwable t) {
      thrown = t;
    }
    assertThat(thrown)
        .describedAs("the pin (step 2) failed, so the window was never established")
        .isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.SCHEMA_NAME_ISOLATION);
    assertThat(thrown.getCause()).isInstanceOf(SQLException.class);
  }

  /**
   * C-18-5. {@code BlindIndexResidual} is a public SPI ({@code JdbcErasureStore} is
   * {@code @ConditionalOnMissingBean} and takes any implementation), and as of this PR every call
   * to it runs inside the one-statement window. Its "strict contract" lists three rules and says
   * nothing about the window: that the path is {@code pg_catalog, pg_temp}, that the unit is one
   * statement, that an unqualified relation fails, and that the implementation must not change
   * {@code search_path}. An implementer reading the interface cannot know.
   */
  @Test
  void probe_the_residual_spi_states_the_window_it_runs_in() throws Exception {
    String spi =
        Files.readString(
                moduleRoot()
                    .resolve(
                        "gdpr-shredding-core/src/main/java/com/housedevinci/shredding/adapter/jdbc/BlindIndexResidual.java"),
                StandardCharsets.UTF_8)
            .replaceAll("\\s*\\*\\s+", " ");
    assertThat(spi)
        .describedAs("the SPI names the path its implementation runs under")
        .contains("pg_catalog, pg_temp");
    assertThat(spi.toLowerCase(Locale.ROOT))
        .describedAs("and the one-statement rule the window rests on")
        .contains("one statement")
        .contains("search_path");
  }

  /**
   * C-18-6 (the ruling on the PR's QUESTION 2). The cross-tenant WARN count is written by this
   * module and, since C-A-6, every name in it is pg_catalog's and its relation is two-part: the
   * name gate verifies it with the window's relaxation switched off (mutation row 12, GREEN). The
   * window around it therefore changes no answer any test can observe, and it puts text this module
   * writes under the gate's keyword-operator relaxation, which exists only for text the module
   * cannot qualify. The window is for framework-rendered text; a module-written statement inside
   * one is a control that cannot be shown to work.
   */
  @Test
  void probe_no_statement_this_module_writes_sits_inside_the_window() {
    var scan =
        SqlSites.scan(
            List.of(
                moduleRoot()
                    .resolve(
                        "gdpr-shredding-core/src/main/java/com/housedevinci/shredding/adapter/jdbc/JdbcErasureStore.java")));
    assertThat(scan.windows())
        .describedAs("the framework read-back's window is still found")
        .isNotEmpty();
    assertThat(scan.windows().stream().filter(w -> w.statements() > 0).toList())
        .describedAs("a window that encloses a statement this module wrote itself")
        .isEmpty();
  }

  // ---------------------------------------------------------------------------------------------

  private static String insideWindow(String sql) throws SQLException {
    try (Connection c = superuser()) {
      c.setAutoCommit(false);
      try {
        return JdbcSupport.inOneStatementWindow(
            c,
            () -> {
              try (Statement st = c.createStatement();
                  ResultSet rs = st.executeQuery(sql)) {
                rs.next();
                return rs.getString(1);
              }
            });
      } catch (SQLException e) {
        return e.getSQLState() + " " + e.getMessage();
      } finally {
        c.rollback();
      }
    }
  }

  private static Connection superuser() throws SQLException {
    return DriverManager.getConnection(
        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  private static void exec(Connection c, String... sql) throws SQLException {
    try (Statement st = c.createStatement()) {
      for (String s : sql) {
        st.execute(s);
      }
    }
  }

  /**
   * A connection that is in a transaction, answers the capture with a path, and refuses the pin the
   * way a dropped connection or a statement_timeout would. Every other call answers the minimum the
   * window needs.
   */
  private static Connection connectionWhosePinFails() {
    ResultSet path =
        (ResultSet)
            Proxy.newProxyInstance(
                CipherProbePr18Test.class.getClassLoader(),
                new Class<?>[] {ResultSet.class},
                (p, m, a) ->
                    switch (m.getName()) {
                      case "next" -> true;
                      case "getString" -> "\"$user\", public";
                      default -> null;
                    });
    Statement st =
        (Statement)
            Proxy.newProxyInstance(
                CipherProbePr18Test.class.getClassLoader(),
                new Class<?>[] {Statement.class},
                (p, m, a) ->
                    switch (m.getName()) {
                      case "executeQuery" -> path;
                      case "execute" ->
                          throw new SQLException("pin refused: connection reset", "08006");
                      default -> null;
                    });
    var prepared =
        Proxy.newProxyInstance(
            CipherProbePr18Test.class.getClassLoader(),
            new Class<?>[] {java.sql.PreparedStatement.class},
            (p, m, a) -> m.getName().equals("execute") ? Boolean.TRUE : null);
    return (Connection)
        Proxy.newProxyInstance(
            CipherProbePr18Test.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAutoCommit" -> false;
                  case "createStatement" -> st;
                  case "prepareStatement" -> prepared;
                  default -> null;
                });
  }
}
