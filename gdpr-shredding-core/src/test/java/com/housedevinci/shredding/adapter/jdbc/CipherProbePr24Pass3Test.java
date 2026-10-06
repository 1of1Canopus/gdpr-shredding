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
class CipherProbePr24Pass3Test {

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

  // ------- P3-1: R-i's "several parents" remedy maps one top; another top keeps the values

  @Test
  void probe_second_parent_of_a_root_descendant_keeps_the_index_values() {
    exec(
        owner,
        "CREATE TABLE app.m1 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))",
        "ALTER TABLE app.m1 ALTER COLUMN email_idx SET STATISTICS 0",
        "CREATE TABLE app.m2 (email_idx varchar(64))",
        "CREATE TABLE app.mkid () INHERITS (app.m1, app.m2)",
        "ALTER TABLE app.m1 ALTER COLUMN email_idx SET STATISTICS 0",
        "GRANT SELECT, UPDATE ON app.m1, app.mkid TO " + APP,
        "GRANT SELECT ON app.m2 TO " + APP,
        "INSERT INTO app.mkid SELECT g, 't', 's' || g, 'idx-' || (g % 7) FROM generate_series(1, 500) g",
        "ANALYZE app.m2");

    // the child is refused by R-i, which tells the operator to map "the table at the top of the
    // hierarchy"; app.m1 is such a table, so the operator maps it
    Verdict child = verdict(app, "app.mkid");
    assertThat(child).isInstanceOf(MappingAdmission.Refused.class);

    String leaked =
        text(
            app,
            "SELECT most_common_vals::text FROM pg_catalog.pg_stats WHERE schemaname = 'app'"
                + " AND tablename = 'm2' AND attname = 'email_idx' AND inherited");
    assertThat(leaked).describedAs("fixture: app.m2 holds the child's values").contains("idx-");

    Throwable thrown = catchThrowable(() -> verdict(app, "app.m1"));
    Object outcome = thrown != null ? thrown : verdict(app, "app.m1");
    assertThat(outcome)
        .describedAs(
            "mapping one top while a descendant's other parent %s holds its blind-index values"
                + " in pg_stats must not be admitted, got %s",
            leaked,
            outcome)
        .isNotInstanceOf(MappingAdmission.Admitted.class);
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
