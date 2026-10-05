package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Copied;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.ColumnRef;
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
 * Security review, PR 24 (feat/statistics-admission), pass 1. Each probe failed on 463b4dd.
 *
 * <p>Fixture as in {@code PlannerStatisticsPostgresTest}: superuser, owner {@code shred_owner} of
 * schemas {@code app} and {@code public}, runtime role {@code shred_app} with SELECT, UPDATE. No
 * test-only statistics trigger.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CipherProbePr24Test {

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
    su = pool(postgres.getUsername(), postgres.getPassword(), "");
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS",
        "CREATE ROLE shred_reader LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE shred_snoop LOGIN PASSWORD 'pw' NOSUPERUSER",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + OWNER,
        "CREATE SCHEMA p24dp AUTHORIZATION " + OWNER,
        "GRANT USAGE ON SCHEMA app, p24dp, public TO " + APP + ", shred_reader, shred_snoop");
    owner = pool(OWNER, "pw", "");
    app = pool(APP, "pw", "");
  }

  @AfterAll
  void stop() {
    pools.forEach(HikariDataSource::close);
    postgres.stop();
  }

  // ------------------------------------------------- F1: ancestors of the erased table

  @Test
  @org.junit.jupiter.api.Disabled(
      "C-24-1 design stop, QUESTIONS #C-29: enabled by the ancestor-statistics build once the"
          + " security review rules on the design")
  void probe_inheritance_parent_statistics_keep_the_child_index_values() {
    exec(
        owner,
        "CREATE TABLE app.p24par (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "CREATE TABLE app.p24kid () INHERITS (app.p24par)",
        "ALTER TABLE ONLY app.p24kid ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.p24kid TO " + APP,
        "GRANT SELECT ON app.p24par TO " + APP + ", shred_reader",
        "INSERT INTO app.p24kid SELECT g, 'T1', 's-' || g, md5((g % 7)::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE app.p24kid",
        "ANALYZE app.p24par");
    assertThat(
            text(
                pool("shred_reader", "pw", ""),
                "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename = 'p24par'"
                    + " AND attname = 'email_idx' AND inherited AND most_common_vals IS NOT NULL"))
        .describedAs("any role with SELECT on the parent reads the child's index values")
        .isEqualTo("1");

    Verdict verdict = verdict(app, "app.p24kid");

    assertThat(verdict)
        .describedAs("verdict on app.p24kid: %s", verdict)
        .isInstanceOf(Copied.class);
  }

  @Test
  @org.junit.jupiter.api.Disabled(
      "C-24-1 design stop, QUESTIONS #C-29: enabled by the ancestor-statistics build once the"
          + " security review rules on the design")
  void probe_partition_erased_directly_parent_statistics_keep_its_index_values() {
    exec(
        owner,
        "CREATE TABLE app.p24pp (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64)) PARTITION BY LIST (tenant)",
        "CREATE TABLE app.p24pp_t1 PARTITION OF app.p24pp FOR VALUES IN ('T1')",
        "ALTER TABLE ONLY app.p24pp_t1 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.p24pp_t1 TO " + APP,
        "GRANT SELECT ON app.p24pp TO " + APP,
        "INSERT INTO app.p24pp SELECT g, 'T1', 's-' || g, md5((g % 7)::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE app.p24pp");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename = 'p24pp'"
                    + " AND attname = 'email_idx' AND most_common_vals IS NOT NULL"))
        .isEqualTo("1");

    Verdict verdict = verdict(app, "app.p24pp_t1");

    assertThat(verdict)
        .describedAs("verdict on app.p24pp_t1: %s", verdict)
        .isInstanceOf(Copied.class);
  }

  // ---------------------------------- F2: printed definitions depend on the role's search_path

  @Test
  void probe_printed_remedy_recreates_the_view_over_another_table() {
    exec(
        owner,
        "CREATE TABLE app.p24s (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "GRANT SELECT, UPDATE ON app.p24s TO " + APP,
        "INSERT INTO app.p24s SELECT g, 'T1', 's-' || g, md5(g::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE app.p24s",
        "CREATE VIEW app.p24s_v AS SELECT id, email_idx FROM app.p24s",
        "GRANT SELECT ON app.p24s_v TO shred_reader",
        // an unrelated table of the same name on the operator's default search_path
        "CREATE TABLE public.p24s (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO public.p24s VALUES (1, 'X', 'x', 'decoy')");
    // the application connects with currentSchema=app, as a Spring datasource commonly does
    DataSource appInApp = pool(APP, "pw", "&currentSchema=app");

    String message = copied(appInApp, "app.p24s");
    exec(owner, remedy(message));

    assertThat(text(su, "SELECT count(*) FROM app.p24s_v"))
        .describedAs("the re-created view must read app.p24s; remedy was: %s", remedy(message))
        .isEqualTo("300");
  }

  @Test
  void probe_printed_remedy_rebinds_the_policy_function() {
    exec(
        owner,
        "CREATE FUNCTION app.p24_allowed(t varchar) RETURNS boolean LANGUAGE sql STABLE"
            + " AS $$ SELECT t = 'T1' $$",
        "CREATE FUNCTION public.p24_allowed(t varchar) RETURNS boolean LANGUAGE sql STABLE"
            + " AS $$ SELECT true $$",
        "CREATE TABLE app.p24r (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "GRANT SELECT, UPDATE ON app.p24r TO " + APP,
        "GRANT SELECT ON app.p24r TO shred_reader",
        "INSERT INTO app.p24r SELECT g, CASE WHEN g <= 10 THEN 'T1' ELSE 'T2' END, 's-' || g,"
            + " md5(g::text) FROM generate_series(1, 300) g",
        "ANALYZE app.p24r",
        "ALTER TABLE app.p24r ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY p24r_tenant ON app.p24r FOR SELECT TO shred_reader"
            + " USING (app.p24_allowed(tenant) AND email_idx IS NOT NULL)");
    DataSource reader = pool("shred_reader", "pw", "");
    assertThat(text(reader, "SELECT count(*) FROM app.p24r")).isEqualTo("10");
    DataSource appInApp = pool(APP, "pw", "&currentSchema=app");

    String message = copied(appInApp, "app.p24r");
    exec(owner, remedy(message));

    assertThat(text(reader, "SELECT count(*) FROM app.p24r"))
        .describedAs("the re-created policy must still filter; remedy was: %s", remedy(message))
        .isEqualTo("10");
  }

  // ------------------------------------- F3: re-created view picks up default privileges

  @Test
  void probe_recreated_view_gains_default_privileges_it_never_had() {
    exec(
        owner,
        "CREATE TABLE p24dp.t (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "GRANT SELECT, UPDATE ON p24dp.t TO " + APP,
        "INSERT INTO p24dp.t SELECT g, 'T1', 's-' || g, md5(g::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE p24dp.t",
        "CREATE VIEW p24dp.v AS SELECT id, email_idx FROM p24dp.t",
        "GRANT SELECT ON p24dp.v TO shred_reader",
        // set later, for tables created from now on; the existing view is not granted to snoop
        "ALTER DEFAULT PRIVILEGES IN SCHEMA p24dp GRANT SELECT ON TABLES TO shred_snoop");
    assertThat(text(su, "SELECT has_table_privilege('shred_snoop', 'p24dp.v', 'SELECT')"))
        .isEqualTo("f");

    String message = copied(app, "p24dp.t");
    exec(owner, remedy(message));

    assertThat(text(su, "SELECT has_table_privilege('shred_snoop', 'p24dp.v', 'SELECT')"))
        .describedAs("the remedy must not widen the view's grants; remedy was: %s", remedy(message))
        .isEqualTo("f");
  }

  // --------------------------- F4: an expression whose function reads the column elsewhere

  @Test
  void probe_expression_index_through_a_user_function_hides_the_column() {
    exec(
        owner,
        "CREATE TABLE app.p24f (id bigint PRIMARY KEY, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.p24f ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.p24f TO " + APP,
        "CREATE FUNCTION app.p24_peek(i bigint) RETURNS varchar LANGUAGE sql IMMUTABLE"
            + " AS $$ SELECT email_idx FROM app.p24f WHERE id = i $$",
        "CREATE INDEX p24f_peek ON app.p24f (app.p24_peek(id))",
        "INSERT INTO app.p24f SELECT g, 'T1', 's-' || g, md5((g % 7)::text)"
            + " FROM generate_series(1, 300) g",
        "ANALYZE app.p24f");
    assertThat(
            text(
                su,
                "SELECT count(*) FROM pg_stats WHERE schemaname = 'app' AND tablename = 'p24f_peek'"
                    + " AND most_common_vals IS NOT NULL"))
        .describedAs("the index's own statistics hold the blind-index values")
        .isEqualTo("1");

    Throwable thrown =
        org.assertj.core.api.Assertions.catchThrowable(() -> verdict(app, "app.p24f"));
    Object outcome = thrown != null ? thrown : verdict(app, "app.p24f");

    assertThat(
            outcome instanceof Copied
                || (outcome instanceof com.housedevinci.shredding.domain.ShreddingException e
                    && "SHRED-SCHEMA-005".equals(e.code())))
        .describedAs("an expression this module cannot see into is refused, got %s", outcome)
        .isTrue();
  }

  // ------------------------------------------------------------------------------ helpers

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

  private HikariDataSource pool(String user, String password, String urlSuffix) {
    var config = new HikariConfig();
    config.setJdbcUrl(postgres.getJdbcUrl() + urlSuffix);
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
      st.execute(sql);
      ResultSet rs = st.getResultSet();
      while (rs == null && (st.getMoreResults() || st.getUpdateCount() != -1)) {
        rs = st.getResultSet();
      }
      return rs != null && rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
