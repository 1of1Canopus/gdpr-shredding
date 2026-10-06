package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.application.LogText;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * C-26-3: a statement printed inside a refusal runs as printed and acts on the object the catalogue
 * holds, whatever the name contains (a quote, a line break, a backslash).
 */
class PrintedSqlIdentifierTest {

  @Test
  void unchanged_when_nothing_was_escaped() {
    assertThat(JdbcSupport.sqlIdentifier("app.\"Mixed Case\"")).isEqualTo("app.\"Mixed Case\"");
  }

  @Test
  void control_characters_come_back_as_a_unicode_escape_on_one_line() {
    String printed = LogText.escape("\"a\"\"q\nx\\y\"");

    assertThat(JdbcSupport.sqlIdentifier("app." + printed + ".z"))
        .isEqualTo("app.U&\"a\"\"q\\000Ax\\\\y\".z");
  }

  @Test
  void a_literal_backslash_u_text_stays_literal() {
    String printed = LogText.escape("\"a\\u000Ab\"");

    assertThat(JdbcSupport.sqlIdentifier(printed)).isEqualTo("U&\"a\\\\u000Ab\"");
  }

  @Test
  void a_list_of_names_is_converted_name_by_name() {
    String printed = LogText.escape("\"r\nx\"") + ", PUBLIC, " + LogText.escape("\"y\"");

    assertThat(JdbcSupport.sqlIdentifier(printed)).isEqualTo("U&\"r\\000Ax\", PUBLIC, \"y\"");
  }

  @Test
  void printed_disable_trigger_runs_as_printed_and_spares_the_decoy() {
    exec(
        owner,
        "CREATE TABLE app.c263q (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64), note text)",
        "GRANT SELECT, UPDATE ON app.c263q TO " + APP,
        "CREATE FUNCTION app.c263q_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;"
            + " END $$",
        "CREATE TRIGGER \"g\"\"q\nx\" AFTER UPDATE ON app.c263q FOR EACH ROW EXECUTE"
            + " FUNCTION app.c263q_f()",
        "CREATE TRIGGER \"g\"\"q\\u000Ax\" AFTER UPDATE ON app.c263q FOR EACH ROW"
            + " EXECUTE FUNCTION app.c263q_f()");
    String message = ((Copied) verdict("app.c263q")).message();
    int start = message.indexOf("ALTER TABLE ");
    String statement = message.substring(start, message.indexOf(". Or, if", start));

    assertThat(statement).describedAs("one line").doesNotContain("\n");
    exec(owner, statement);

    assertThat(
            text(
                "SELECT string_agg(tgenabled::text, ',' ORDER BY tgname) FROM pg_trigger WHERE"
                    + " tgrelid = 'app.c263q'::regclass AND NOT tgisinternal"))
        .describedAs("real trigger disabled, decoy enabled: " + statement)
        .isEqualTo("D,O");
  }

  // ---- fixtures

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withCommand("postgres", "-c", "fsync=off")
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String OWNER = "shred_owner";
  private static final String APP = "shred_app";
  private static final byte[] SECRET =
      "printed-sql-identifier-secret-32b".getBytes(StandardCharsets.UTF_8);
  private static final Pseudonymiser PSEUDONYMS = new Pseudonymiser(SECRET);
  private static final TenantId T1 = TenantId.of("T1");

  private static final List<HikariDataSource> pools = new ArrayList<>();
  private static HikariDataSource su;
  private static HikariDataSource owner;
  private static HikariDataSource app;
  private static VerifiedSchema schema;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    su = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app TO " + APP);
    owner = pool(OWNER, "pw");
    JdbcSupport.initializeSchema(owner);
    exec(
        owner,
        "GRANT USAGE ON SCHEMA public TO " + APP,
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);
    app = pool(APP, "pw");
    schema = JdbcSupport.verifySchema(app, true).schema();
  }

  @AfterAll
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  private static Verdict verdict(String table) {
    try (Connection c = app.getConnection()) {
      return MappingAdmission.verdict(
          c,
          new Target(
              Optional.of("Note"),
              TableRef.parse(table),
              List.of(
                  new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, MappingAdmission.TENANT),
                  new Column(ColumnRef.unquoted("subject"), Use.COMPARED, MappingAdmission.SUBJECT),
                  new Column(ColumnRef.unquoted("id"), Use.COMPARED, MappingAdmission.IDENTIFIER),
                  new Column(
                      ColumnRef.unquoted("email_idx"),
                      Use.ASSIGNED,
                      MappingAdmission.BLIND_INDEX,
                      Optional.of("@BlindIndex Note.emailIndex")))),
          CopySignatures.defaults(),
          List.of());
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    var ds = new HikariDataSource(config);
    pools.add(ds);
    return ds;
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  private static String text(String sql) {
    try (Connection c = su.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
