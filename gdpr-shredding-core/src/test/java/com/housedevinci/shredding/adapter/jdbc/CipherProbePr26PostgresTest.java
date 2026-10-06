package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Refused;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
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
import java.time.Instant;
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
 * Security review, PR 26 pass 1, against PostgreSQL 16 (the module's pinned digest).
 *
 * <ul>
 *   <li>C-26-1: {@code JdbcErasureStore.append} accepts a {@code COMPLETE} record that reports the
 *       subject's outstanding hook as failed: the guard checks that a name is answered, not that a
 *       {@code COMPLETE} answers it with success.
 *   <li>C-26-2 (#C-31): the {@code SHRED-SCHEMA-010} trigger finding and the {@code
 *       SHRED-SCHEMA-009} ancestor refusal print a quoted identifier raw, so a name holding a line
 *       break splits the exception message (and every log line that prints it) in two. Rev 5 item
 *       3 requires every message that prints an operator-chosen identifier to escape it.
 * </ul>
 *
 * Fixture as {@code AcknowledgedCopiesPostgresTest}.
 */
class CipherProbePr26PostgresTest {

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
      "cipher-probe-pr26-jdbc-secret-32b".getBytes(StandardCharsets.UTF_8);
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

  // ------------------------------------------------------------------------------- C-26-1

  @Test
  void probe_jdbc_append_accepts_complete_reporting_the_outstanding_hook_failed() {
    table("app.c261");
    JdbcErasureStore store = store("app.c261");
    String subject = "app.c261-s-1";
    store.erase(
        T1,
        SubjectId.of(subject),
        (destroyed, cleared) ->
            record(subject, ErasureOutcome.PARTIAL, new HookOutcome("h1", false, "pending")));
    String anchor = anchor();
    long rows = records();

    Throwable thrown =
        catchThrowable(
            () ->
                store.append(
                    record(
                        subject,
                        ErasureOutcome.COMPLETE,
                        HookOutcome.failed("h1", "java.lang.IllegalStateException"))));

    assertThat(thrown)
        .describedAs("a COMPLETE that reports the outstanding hook failed must be refused")
        .isInstanceOf(ShreddingException.class);
    assertThat(records()).isEqualTo(rows);
    assertThat(anchor()).isEqualTo(anchor);
  }

  // ------------------------------------------------------------------------------- C-26-2

  @Test
  void probe_trigger_finding_prints_a_line_break_in_the_trigger_name_raw() {
    table("app.c262t");
    exec(
        owner,
        "CREATE TABLE app.c262t_log (LIKE app.c262t)",
        "CREATE FUNCTION app.c262t_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO"
            + " app.c262t_log SELECT OLD.*; RETURN NULL; END $$",
        "CREATE TRIGGER \"c262\nforged line\" AFTER UPDATE ON app.c262t FOR EACH ROW EXECUTE"
            + " FUNCTION app.c262t_f()");

    Verdict verdict = verdict("app.c262t");

    assertThat(verdict).isInstanceOf(Copied.class);
    assertThat(((Copied) verdict).message())
        .describedAs("SHRED-SCHEMA-010 must print the trigger name escaped, on one line")
        .doesNotContain("\n");
  }

  @Test
  void probe_ancestor_refusal_prints_a_line_break_in_the_parent_name_raw() {
    exec(
        owner,
        "CREATE TABLE app.\"c262\nparent\" (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64), note text)",
        "CREATE TABLE app.c262c () INHERITS (app.\"c262\nparent\")",
        "GRANT SELECT, UPDATE ON app.c262c TO " + APP);

    Verdict verdict = verdict("app.c262c");

    assertThat(verdict).isInstanceOf(Refused.class);
    assertThat(((Refused) verdict).message())
        .describedAs("SHRED-SCHEMA-009 must print the ancestor's name escaped, on one line")
        .doesNotContain("\n");
  }

  // ----------------------------------------------------------------------------- fixtures

  private static void table(String table) {
    exec(
        owner,
        "CREATE TABLE "
            + table
            + " (id bigint, tenant varchar(64), subject varchar(64), email_idx varchar(64),"
            + " note text)",
        "GRANT SELECT, UPDATE ON " + table + " TO " + APP,
        "INSERT INTO "
            + table
            + " (id, tenant, subject, email_idx) SELECT g, 'T1', '"
            + table
            + "-s-' || g, md5(g::text) FROM generate_series(1, 3) g");
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
                  new Column(
                      ColumnRef.unquoted("subject"), Use.COMPARED, MappingAdmission.SUBJECT),
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

  private static JdbcErasureStore store(String table) {
    return new JdbcErasureStore(
        app,
        schema,
        ErasureChain.keyed(SECRET, "k1"),
        List.of(
            new BlindIndexColumn(
                TableRef.parse(table),
                ColumnRef.unquoted("email_idx"),
                ColumnRef.unquoted("subject"),
                ColumnRef.unquoted("tenant"),
                Optional.of("tenant"),
                Optional.of("subject"))),
        (c, col, tenant, subject) -> 0L,
        CopySignatures.defaults(),
        List.of());
  }

  private static ErasureRecord record(
      String subjectId, ErasureOutcome outcome, HookOutcome... outcomes) {
    return ErasureRecord.of(
        Instant.now(),
        T1,
        PSEUDONYMS.pseudonym(T1, SubjectId.of(subjectId)),
        "dpo",
        "art 17",
        0,
        1,
        1,
        1,
        outcome,
        List.of(outcomes),
        Instant.now());
  }

  private static long records() {
    return Long.parseLong(text("SELECT count(*) FROM public.shredding_erasure"));
  }

  private static String anchor() {
    return text("SELECT head_hash || '/' || row_count FROM public.shredding_erasure_anchor");
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
