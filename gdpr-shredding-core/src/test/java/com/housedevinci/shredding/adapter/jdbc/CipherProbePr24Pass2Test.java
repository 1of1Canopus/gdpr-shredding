package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TableRef;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
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
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 24 (feat/statistics-admission), pass 2. Each probe failed on 33599c2.
 *
 * <p>Fixture as in {@link CipherProbePr24Test}: superuser, owner {@code shred_owner} of schema
 * {@code app}, runtime role {@code shred_app} with SELECT, UPDATE.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CipherProbePr24Pass2Test {

  private static final String OWNER = "shred_owner";
  private static final String APP = "shred_app";

  private final PostgreSQLContainer<?> postgres =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(Duration.ofMinutes(2));

  private final List<HikariDataSource> pools = new ArrayList<>();
  private HikariDataSource su;
  private HikariDataSource owner;
  private HikariDataSource app;

  @BeforeAll
  void start() {
    postgres.start();
    su = pool(postgres.getUsername(), postgres.getPassword());
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app, public TO " + APP);
    owner = pool(OWNER, "pw");
    app = pool(APP, "pw");
  }

  @AfterAll
  void stop() {
    pools.forEach(HikariDataSource::close);
    postgres.stop();
  }

  // --------------- P2-1: a refusal inside the caller's transaction leaves the path pinned

  @Test
  void probe_refusal_inside_a_caller_transaction_leaves_search_path_pinned() throws SQLException {
    exec(
        owner,
        "CREATE TABLE app.q1 (id bigint PRIMARY KEY, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.q1 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.q1 TO " + APP,
        "CREATE FUNCTION app.q1_peek(i bigint) RETURNS varchar LANGUAGE sql IMMUTABLE"
            + " AS $$ SELECT email_idx FROM app.q1 WHERE id = i $$",
        "CREATE INDEX q1_peek ON app.q1 (app.q1_peek(id))");

    try (Connection c = app.getConnection()) {
      c.setAutoCommit(false);
      String arrived = read(c, "SELECT pg_catalog.current_setting('search_path')");

      Throwable refused =
          catchThrowable(
              () ->
                  MappingAdmission.verdict(
                      c, new Target(Optional.of("Note"), TableRef.parse("app.q1"), cols())));
      assertThat(refused).isInstanceOf(ShreddingException.class);

      String after = read(c, "SELECT pg_catalog.current_setting('search_path')");
      c.rollback();
      assertThat(after)
          .describedAs(
              "a refusal the caller catches must leave its transaction on the path it arrived with")
          .isEqualTo(arrived);
    }
  }

  // ------------- P2-2: named remedy skips a stored generated column on an inheritance child

  @Test
  void probe_named_remedy_leaves_a_child_generated_column_sampling() {
    exec(
        owner,
        "CREATE TABLE app.q2r (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE TABLE app.q2c (g varchar(80) GENERATED ALWAYS AS (email_idx || '-') STORED)"
            + " INHERITS (app.q2r)",
        "GRANT SELECT, UPDATE ON app.q2r, app.q2c TO " + APP,
        "CREATE VIEW app.q2v AS SELECT id, email_idx FROM app.q2r",
        // a column comment on the view sends the remedy to the named branch
        "COMMENT ON COLUMN app.q2v.email_idx IS 'blind index'");

    String message = copied(app, "app.q2r");
    exec(fresh(OWNER), remedy(message));
    exec(
        su,
        "DELETE FROM pg_catalog.pg_statistic WHERE starelid IN"
            + " ('app.q2r'::regclass, 'app.q2c'::regclass)");

    Throwable thrown = catchThrowable(() -> verdict(app, "app.q2r"));
    Object outcome = thrown != null ? thrown : verdict(app, "app.q2r");
    assertThat(outcome)
        .describedAs(
            "after the printed remedy and the clearing step, nothing still samples the column;"
                + " remedy was: %s",
            remedy(message))
        .isNotInstanceOf(Copied.class);
  }

  // ------------------------- P2-3: a partial index predicate is read by neither scan

  @Test
  void probe_partial_index_predicate_on_the_blind_index_is_not_read() {
    exec(
        owner,
        "CREATE TABLE app.q3 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.q3 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.q3 TO " + APP,
        "CREATE INDEX q3_px ON app.q3 ((pg_catalog.lower(subject)))"
            + " WHERE email_idx = pg_catalog.md5('1')",
        "INSERT INTO app.q3 SELECT g, 'T1', 's-' || (g % 50), md5((g % 7)::text)"
            + " FROM generate_series(1, 700) g",
        "ANALYZE app.q3");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename = 'q3_px'"
                    + " AND (most_common_vals IS NOT NULL OR histogram_bounds IS NOT NULL)"))
        .describedAs("the index statistics list exactly the subjects whose blind index is md5('1')")
        .isEqualTo("1");

    assertRefused("app.q3");
  }

  @Test
  void probe_partial_index_predicate_through_a_user_function_is_not_read() {
    exec(
        owner,
        "CREATE TABLE app.q4 (id bigint PRIMARY KEY, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.q4 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.q4 TO " + APP,
        "CREATE FUNCTION app.q4_peek(i bigint) RETURNS boolean LANGUAGE sql IMMUTABLE"
            + " AS $$ SELECT email_idx = pg_catalog.md5('1') FROM app.q4 WHERE id = i $$",
        "CREATE INDEX q4_px ON app.q4 ((pg_catalog.lower(subject))) WHERE app.q4_peek(id)");

    assertRefused("app.q4");
  }

  // ------ P2-5: a pg_catalog function that runs SQL, in an extended-statistics expression

  @Test
  void probe_extended_statistics_through_a_catalogue_query_executor_is_admitted() {
    exec(
        owner,
        "CREATE TABLE app.q5 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.q5 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.q5 TO " + APP,
        // CREATE STATISTICS does not require an immutable expression; query_to_xml is volatile
        // and lives in pg_catalog, so the namespace rule passes it
        "CREATE STATISTICS app.q5_leak ON (pg_catalog.query_to_xml('SELECT email_idx FROM app.q5"
            + " WHERE id = ' OPERATOR(pg_catalog.||) id, false, false, '')::text), id FROM app.q5",
        "INSERT INTO app.q5 SELECT g, 'T1', 's-' || g, md5((g % 7)::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE app.q5");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_stats_ext_exprs WHERE statistics_name = 'q5_leak'"
                    + " AND most_common_vals::text LIKE '%' || md5('1') || '%'"))
        .describedAs("the expression statistics hold the blind-index values")
        .isEqualTo("1");

    Throwable thrown = catchThrowable(() -> verdict(app, "app.q5"));
    Object outcome = thrown != null ? thrown : verdict(app, "app.q5");
    assertThat(
            outcome instanceof Copied
                || (outcome instanceof ShreddingException e
                    && "SHRED-SCHEMA-005".equals(e.code())))
        .describedAs("a non-immutable call in a statistics expression is refused, got %s", outcome)
        .isTrue();
  }

  // ------------------------------------------------------------------------------ helpers

  private void assertRefused(String table) {
    Throwable thrown = catchThrowable(() -> verdict(app, table));
    Object outcome = thrown != null ? thrown : verdict(app, table);
    assertThat(
            outcome instanceof Copied
                || (outcome instanceof ShreddingException e
                    && "SHRED-SCHEMA-005".equals(e.code())))
        .describedAs("a partial index selecting rows by the blind index is refused, got %s", outcome)
        .isTrue();
  }

  private HikariDataSource fresh(String user) {
    return pool(user, "pw");
  }

  private static String read(Connection c, String sql) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  private static String remedy(String message) {
    int start = message.indexOf("As the table owner run: ");
    assertThat(start)
        .describedAs("the message prints a remedy: %s", message)
        .isGreaterThanOrEqualTo(0);
    String rest = message.substring(start + "As the table owner run: ".length());
    int end = rest.startsWith("BEGIN;") ? rest.indexOf("COMMIT;") + 7 : rest.indexOf(" The ");
    return rest.substring(0, end);
  }

  private static List<Column> cols() {
    return List.of(
        new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, MappingAdmission.TENANT),
        new Column(ColumnRef.unquoted("subject"), Use.COMPARED, MappingAdmission.SUBJECT),
        new Column(ColumnRef.unquoted("id"), Use.COMPARED, MappingAdmission.IDENTIFIER),
        new Column(
            ColumnRef.unquoted("email_idx"),
            Use.ASSIGNED,
            MappingAdmission.BLIND_INDEX,
            Optional.of("@BlindIndex Note.emailIndex")));
  }

  private static Verdict verdict(DataSource ds, String table) {
    try (Connection c = ds.getConnection()) {
      return MappingAdmission.verdict(
          c, new Target(Optional.of("Note"), TableRef.parse(table), cols()));
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String copied(DataSource ds, String table) {
    Verdict verdict = verdict(ds, table);
    assertThat(verdict).describedAs("verdict: %s", verdict).isInstanceOf(Copied.class);
    return ((Copied) verdict).message();
  }

  private HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(postgres.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
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

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      ResultSet rs = st.executeQuery(sql);
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
