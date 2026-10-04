package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Column;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Refused;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Target;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Use;
import com.housedevinci.shredding.adapter.jdbc.MappingAdmission.Verdict;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TableRef;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
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
 * Security review of PR 19, second pass: attacks on clause C-i (tenant and subject columns are
 * text, varchar or char(n) by oid) and on the closed role set it is decided by. Same fixture as the
 * first pass: runtime role {@code shred_app}, owner of schema {@code app}.
 */
class CipherProbePr19SecondPassTest {
  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String APP = "shred_app";
  private static final String OWNER = "shred_owner";
  private static final byte[] SECRET =
      "cipher-probe-pr19-chain-secret-32".getBytes(StandardCharsets.UTF_8);

  private static HikariDataSource su;
  private static HikariDataSource app;
  private static HikariDataSource unspecified;
  private static VerifiedSchema schema;
  private static final List<HikariDataSource> pools = new ArrayList<>();

  @BeforeAll
  static void start() {
    POSTGRES.start();
    su = pool(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword(), null);
    exec(
        su,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA app AUTHORIZATION " + APP);
    HikariDataSource owner = pool(POSTGRES.getJdbcUrl(), OWNER, "pw", null);
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
    String path = "SET search_path = public, app, pg_catalog";
    app = pool(POSTGRES.getJdbcUrl(), APP, "pw", path);
    String url = POSTGRES.getJdbcUrl();
    unspecified =
        pool(url + (url.contains("?") ? "&" : "?") + "stringtype=unspecified", APP, "pw", path);
    schema = JdbcSupport.verifySchema(app, true).schema();
  }

  @AfterAll
  static void stop() {
    pools.forEach(HikariDataSource::close);
    POSTGRES.stop();
  }

  // ------------------------------------------------------------------------------- C-i shapes

  private static void createTable(String name, String tenantType, String subjectType) {
    exec(
        app,
        "CREATE TABLE app."
            + name
            + " (id bigint, tenant "
            + tenantType
            + ", subject "
            + subjectType
            + ", email_idx varchar(64))");
  }

  private static String clause(Verdict v) {
    return v instanceof Refused r
        ? r.rule() + " (" + r.message() + ")"
        : v.getClass().getSimpleName();
  }

  @Test
  void ci_domain_chains_arrays_and_citext() {
    exec(
        su,
        "CREATE EXTENSION IF NOT EXISTS citext SCHEMA public",
        "GRANT USAGE ON SCHEMA public TO " + APP);
    exec(
        app,
        "CREATE DOMAIN app.d1 AS text",
        "CREATE DOMAIN app.d2 AS app.d1",
        "CREATE DOMAIN app.dchk AS varchar(64) CHECK (VALUE <> 'forbidden')",
        "CREATE DOMAIN app.dcit AS public.citext");
    createTable("s2a", "varchar(64)", "app.d2");
    createTable("s2b", "varchar(64)", "app.dchk");
    createTable("s2c", "varchar(64)", "text[]");
    createTable("s2d", "public.citext", "varchar(64)");
    createTable("s2e", "varchar(64)", "app.dcit");
    createTable("s2f", "varchar(64)", "char(16)");
    var out = new java.util.LinkedHashMap<String, String>();
    for (String t : List.of("s2a", "s2b", "s2c", "s2d", "s2e", "s2f")) {
      out.put(t, clause(verdict(app, target("app." + t))));
    }
    System.out.println("CIPHER-B2 C-i shapes: " + out);
    assertThat(out.get("s2a")).isEqualTo("Admitted");
    assertThat(out.get("s2b")).isEqualTo("Admitted");
    assertThat(out.get("s2c")).isNotEqualTo("Admitted");
    assertThat(out.get("s2d")).matches("C-[bi] .*");
    assertThat(out.get("s2e")).matches("C-[bi] .*");
    assertThat(out.get("s2f")).isEqualTo("Admitted");
  }

  /** char(n): stored padded; the erasure must still clear it, under both driver settings. */
  @Test
  void ci_char_n_subject_is_cleared_under_both_driver_settings() {
    createTable("s2g", "char(16)", "char(16)");
    exec(
        app,
        "INSERT INTO app.s2g VALUES (1, 'T1', 'abc', 'R1'), (2, 'T1', 'abcd', 'R2'),"
            + " (3, 'T2', 'abc', 'R3')");
    assertThat(sameTextUpdate(app, "app.s2g", "T1", "abc")).isEqualTo(1);
    assertThat(sameTextUpdate(unspecified, "app.s2g", "T1", "abc")).isEqualTo(1);
    erase(app, "app.s2g", "T1", "abc");
    assertThat(
            text(
                su,
                "SELECT string_agg(id::text, ',' ORDER BY id) FROM app.s2g"
                    + " WHERE email_idx IS NOT NULL"))
        .isEqualTo("2,3");
    erase(unspecified, "app.s2g", "T1", "abcd");
    assertThat(
            text(
                su,
                "SELECT string_agg(id::text, ',' ORDER BY id) FROM app.s2g"
                    + " WHERE email_idx IS NOT NULL"))
        .isEqualTo("3");
  }

  /** varchar(n) shorter than an id: the write fails loudly, nothing is silently truncated. */
  @Test
  void ci_short_varchar_refuses_the_write_and_does_not_truncate() {
    createTable("s2h", "varchar(64)", "varchar(4)");
    Throwable t =
        catchThrowable(
            () -> {
              try (Connection c = app.getConnection();
                  PreparedStatement ps =
                      c.prepareStatement("INSERT INTO app.s2h VALUES (1, 'T1', ?, 'R')")) {
                ps.setString(1, "abcdef");
                ps.executeUpdate();
              }
            });
    assertThat(t).isInstanceOf(SQLException.class);
    assertThat(((SQLException) t).getSQLState()).isEqualTo("22001");
    assertThat(sameTextUpdate(app, "app.s2h", "T1", "abcdef")).isZero();
    assertThat(sameTextUpdate(unspecified, "app.s2h", "T1", "abcdef")).isZero();
  }

  /**
   * A case-insensitive nondeterministic collation on the column or on its domain: same class as
   * C-19-5.
   */
  @Test
  void ci_nondeterministic_collation_on_column_or_domain_is_refused() {
    exec(
        app,
        "CREATE COLLATION app.ci (provider = icu, locale = 'und-u-ks-level2',"
            + " deterministic = false)",
        "CREATE DOMAIN app.dci AS text COLLATE app.ci",
        "CREATE DOMAIN app.dci2 AS app.dci");
    createTable("s2i", "varchar(64)", "text COLLATE app.ci");
    createTable("s2j", "varchar(64)", "app.dci");
    createTable("s2k", "app.dci2", "varchar(64)");
    createTable("s2l", "char(16) COLLATE app.ci", "varchar(64)");
    exec(app, "INSERT INTO app.s2j VALUES (1, 'T1', 'Alice', 'R')");
    // The harm, measured: an erasure for 'alice' would clear 'Alice'.
    assertThat(sameTextUpdate(app, "app.s2j", "T1", "alice")).isEqualTo(1);
    var out = new java.util.LinkedHashMap<String, String>();
    for (String t : List.of("s2i", "s2j", "s2k", "s2l")) {
      out.put(t, clause(verdict(app, target("app." + t))));
    }
    System.out.println("CIPHER-B2 collation: " + out);
    assertThat(out.values()).allMatch(v -> !v.equals("Admitted"));
    Throwable thrown = catchThrowable(() -> erase(app, "app.s2j", "T1", "alice"));
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(text(su, "SELECT count(*) FROM app.s2j WHERE email_idx IS NOT NULL")).isEqualTo("1");
  }

  /** The role string acts as an enum: anything not exactly one of the four is refused. */
  @Test
  void ci_role_string_is_a_closed_set() {
    for (String role :
        List.of(
            "Tenant Column",
            "tenant",
            " tenant column",
            "tenant column ",
            "subject  column",
            "SUBJECT COLUMN",
            "tenant column",
            "")) {
      Throwable t = catchThrowable(() -> new Column(ColumnRef.unquoted("x"), Use.COMPARED, role));
      assertThat(t).describedAs("[" + role + "]").isInstanceOf(ShreddingException.class);
    }
    // A non-interned equal string is the role, not a bypass.
    String fresh = new String("subject column".toCharArray());
    assertThat(new Column(ColumnRef.unquoted("x"), Use.COMPARED, fresh).comparedAsText()).isTrue();
    // Every BlindIndexColumn-derived target carries the tenant and subject roles.
    var col =
        new BlindIndexColumn(
            TableRef.parse("app.x"),
            ColumnRef.unquoted("email_idx"),
            ColumnRef.unquoted("subject"),
            ColumnRef.unquoted("tenant"),
            Optional.of("tenant"),
            Optional.of("subject"));
    assertThat(Target.forErasure(List.of(col)).get(0).columns())
        .filteredOn(Column::comparedAsText)
        .hasSize(2);
  }

  // ---------------------------------------------------------------------------------- helpers

  private static List<Column> cols() {
    return List.of(
        new Column(ColumnRef.unquoted("tenant"), Use.COMPARED, "tenant column"),
        new Column(ColumnRef.unquoted("subject"), Use.COMPARED, "subject column"),
        new Column(ColumnRef.unquoted("id"), Use.COMPARED, "identifier column"),
        new Column(ColumnRef.unquoted("email_idx"), Use.ASSIGNED, "blind-index column"));
  }

  private static Target target(String table) {
    return new Target(Optional.of("Note"), TableRef.parse(table), cols());
  }

  private static Verdict verdict(DataSource ds, Target target) {
    try (Connection c = ds.getConnection()) {
      return MappingAdmission.verdict(c, target);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The erasure's own UPDATE as the module renders and binds it, rolled back. */
  private static int sameTextUpdate(DataSource ds, String table, String tenant, String subject) {
    try (Connection c = ds.getConnection()) {
      c.setAutoCommit(false);
      try (PreparedStatement ps =
          c.prepareStatement(
              "UPDATE "
                  + TableRef.parse(table).sql()
                  + " SET email_idx = NULL WHERE (tenant OPERATOR(pg_catalog.=) ?)"
                  + " AND (subject OPERATOR(pg_catalog.=) ?) AND email_idx IS NOT NULL")) {
        ps.setString(1, tenant);
        ps.setString(2, subject);
        return ps.executeUpdate();
      } finally {
        c.rollback();
        c.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The framework's shape: bare operators, on the erasure's connection, values as Strings. */
  private static BlindIndexResidual frameworkResidual() {
    return (c, col, tenant, subject) -> {
      try (PreparedStatement ps =
          c.prepareStatement(
              "SELECT count(*) FROM "
                  + col.table().sql()
                  + " WHERE "
                  + col.tenantColumn().sql()
                  + " = ? AND "
                  + col.subjectColumn().sql()
                  + " = ? AND "
                  + col.column().sql()
                  + " IS NOT NULL")) {
        ps.setString(1, tenant.value());
        ps.setString(2, subject.value());
        try (ResultSet rs = ps.executeQuery()) {
          return rs.next() ? rs.getLong(1) : 0L;
        }
      } catch (SQLException e) {
        throw new IllegalStateException(e.getMessage(), e);
      }
    };
  }

  private static void erase(DataSource ds, String table, String tenant, String subject) {
    var column =
        new BlindIndexColumn(
            TableRef.parse(table),
            ColumnRef.unquoted("email_idx"),
            ColumnRef.unquoted("subject"),
            ColumnRef.unquoted("tenant"),
            Optional.of("tenant"),
            Optional.of("subject"));
    var store =
        new JdbcErasureStore(
            ds, schema, ErasureChain.keyed(SECRET, "k1"), List.of(column), frameworkResidual());
    TenantId t = TenantId.of(tenant);
    SubjectId s = SubjectId.of(subject);
    store.erase(
        t,
        s,
        (destroyed, cleared) ->
            ErasureRecord.of(
                Instant.now(),
                t,
                new Pseudonymiser(SECRET).pseudonym(t, s),
                "dpo",
                "art 17",
                destroyed,
                1,
                1,
                cleared,
                ErasureOutcome.COMPLETE,
                List.of(),
                Instant.now().plus(Duration.ofDays(30))));
  }

  private static HikariDataSource pool(String url, String user, String password, String init) {
    var config = new HikariConfig();
    config.setJdbcUrl(url);
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    if (init != null) {
      config.setConnectionInitSql(init);
    }
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
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }
}
