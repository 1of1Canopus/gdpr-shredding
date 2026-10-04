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
import com.housedevinci.shredding.domain.ErrorCodes;
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
 * Security review of PR 19 (mapping admission), first pass. Every probe is red on head 6d34cd5 and
 * must turn green on the fix. Fixture: the runtime role {@code shred_app} NOSUPERUSER NOCREATEDB
 * NOCREATEROLE, owner of schema {@code app}, the module's schema installed by an owner role with
 * the SECURITY-NOTES grant block, the application's path with {@code pg_catalog} named last. Where
 * a probe's point is a falsehood the three legs agree on, the falsehood is measured with plain SQL
 * first, so the fixture is an attack and not a formality.
 */
class CipherProbePr19Test {

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

  // ---------------------------------------------------------------------------------- C-19-1

  /**
   * C-19-1 (MEDIUM). An enum is admitted by C-d, and C-h looks only for an operator named {@code
   * =}. The runtime role owns its enum, so it may create an IMPLICIT cast from it to {@code text}
   * with a function of its own. The module's {@code tenant OPERATOR(pg_catalog.=) ?} then resolves
   * to {@code pg_catalog.=(text, text)} through that function - no 42883 any more, under the
   * driver's default too - and the bracketed framework read-back resolves the same way, because a
   * cast is not found through {@code search_path}. All three legs answer 0 while the row is there.
   */
  @Test
  void probe_an_enum_with_a_role_owned_implicit_cast_is_admitted_and_its_erasure_clears_nothing() {
    exec(
        app,
        "CREATE TYPE app.c191_e AS ENUM ('T1', 'T2')",
        "CREATE FUNCTION app.c191_lie(app.c191_e) RETURNS text LANGUAGE sql IMMUTABLE"
            + " AS $$ SELECT 'nope'::text $$",
        "CREATE CAST (app.c191_e AS text) WITH FUNCTION app.c191_lie(app.c191_e) AS IMPLICIT",
        "CREATE TABLE app.c191 (id bigint, tenant app.c191_e, subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.c191 VALUES (1, 'T1', 's-c191', 'HMAC-RESIDUE')");
    // The falsehood, measured: the truth through the enum's own equality is 1, the module's own
    // UPDATE text (bound as the module binds it) matches 0.
    assertThat(
            text(
                su,
                "SELECT count(*) FROM app.c191 WHERE pg_catalog.enum_eq(tenant,"
                    + " CAST('T1' AS app.c191_e)) AND email_idx IS NOT NULL"))
        .isEqualTo("1");
    assertThat(sameTextUpdate(app, "app.c191", "T1", "s-c191")).isZero();

    Verdict verdict = verdict(app, target("app.c191"));
    assertThat(verdict)
        .describedAs("a compared column whose type carries a role-defined implicit cast")
        .isInstanceOf(Refused.class);

    Throwable thrown = catchThrowable(() -> erase(app, "app.c191", "T1", "s-c191"));
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(text(su, "SELECT count(*) FROM app.c191 WHERE email_idx IS NOT NULL"))
        .isEqualTo("1");
  }

  // ---------------------------------------------------------------------------------- C-19-2

  /**
   * C-19-2 (MEDIUM). {@code name} (and {@code "char"}) truncate their input silently: a subject id
   * longer than 63 bytes is stored truncated, and the erasure's {@code subject
   * OPERATOR(pg_catalog.=) ?} compares the stored value with the untruncated one through {@code
   * =(name, text)}. Both read-backs compare the same way. The erasure reports success while the row
   * keeps its index. {@code name} is admitted: own equality in {@code pg_catalog}, collation {@code
   * C}.
   */
  @Test
  void probe_a_name_typed_subject_is_admitted_and_a_long_subject_is_never_erased() {
    String longSubject = "auth0:user-0123456789abcdef0123456789abcdef0123456789abcdef-tail";
    exec(
        app,
        "CREATE TABLE app.c192 (id bigint, tenant varchar(64), subject name,"
            + " email_idx varchar(64))",
        "CREATE TABLE app.c192c (id bigint, tenant \"char\", subject varchar(64),"
            + " email_idx varchar(64))");
    // Written the way the application writes it: a bound String.
    try (Connection c = app.getConnection();
        PreparedStatement ps =
            c.prepareStatement("INSERT INTO app.c192 VALUES (1, 'T1', ?, 'HMAC-RESIDUE')")) {
      ps.setString(1, longSubject);
      ps.executeUpdate();
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    assertThat(text(su, "SELECT length(subject::text) FROM app.c192")).isEqualTo("63");
    assertThat(sameTextUpdate(app, "app.c192", "T1", longSubject)).isZero();

    assertThat(verdict(app, target("app.c192")))
        .describedAs("a compared column whose type truncates its input")
        .isInstanceOf(Refused.class);
    assertThat(verdict(app, target("app.c192c")))
        .describedAs("\"char\" keeps one byte of its input")
        .isInstanceOf(Refused.class);

    Throwable thrown = catchThrowable(() -> erase(app, "app.c192", "T1", longSubject));
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(text(su, "SELECT count(*) FROM app.c192 WHERE email_idx IS NOT NULL"))
        .isEqualTo("1");
  }

  // ---------------------------------------------------------------------------------- C-19-3

  /**
   * C-19-3 (LOW). Admitted mappings the erasure can never execute. A {@code uuid} tenant (which a
   * JPA application maps as {@code java.util.UUID} and writes with no driver setting at all) under
   * the driver's default, and a domain over an enum under {@code stringtype=unspecified} too, are
   * admitted at startup with no WARN; every erasure then fails 42883 and is reported as {@code
   * SHRED-KEY-UNAVAILABLE}, a key-store outage, which sends the operator to the wrong remedy and
   * invites a retry that can never succeed. The admission must refuse what the erasure's own
   * comparison cannot resolve, naming the column type; clause C-i (tenant and subject must be
   * {@code text}, {@code varchar} or {@code char(n)}) does that for every shape here.
   */
  @Test
  void probe_an_admitted_mapping_the_erasure_cannot_execute_is_reported_as_a_key_store_outage() {
    String tenant = "6f1c1c4e-2f0e-4c55-9a59-0c7a3c1f2b11";
    exec(
        app,
        "CREATE TABLE app.c193u (id bigint, tenant uuid, subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.c193u VALUES (1, '" + tenant + "', 's-c193u', 'HMAC-RESIDUE')",
        "CREATE TYPE app.c193_e AS ENUM ('T1', 'T2')",
        "CREATE DOMAIN app.c193_d AS app.c193_e",
        "CREATE TABLE app.c193d (id bigint, tenant app.c193_d, subject varchar(64),"
            + " email_idx varchar(64))",
        "INSERT INTO app.c193d VALUES (1, 'T1', 's-c193d', 'HMAC-RESIDUE')");

    // uuid under the driver's default: refused before the first statement, by the mapping code.
    Throwable uuidDefault = catchThrowable(() -> erase(app, "app.c193u", tenant, "s-c193u"));
    assertThat(uuidDefault).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) uuidDefault).code())
        .describedAs("an unresolvable comparison is a mapping refusal, not a key-store outage")
        .isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(verdict(app, target("app.c193u")))
        .describedAs("startup must not admit what no erasure on this DataSource can run")
        .isInstanceOf(Refused.class);
    // Under stringtype=unspecified the uuid mapping executes, and C-19-5 shows what it then
    // compares; the prescribed clause C-i refuses it on both DataSources.
    assertThat(verdict(unspecified, target("app.c193u"))).isInstanceOf(Refused.class);

    // A domain over an enum fails even under stringtype=unspecified, which the docs say fixes it.
    assertThat(verdict(unspecified, target("app.c193d"))).isInstanceOf(Refused.class);
    Throwable domainEnum = catchThrowable(() -> erase(unspecified, "app.c193d", "T1", "s-c193d"));
    assertThat(domainEnum).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) domainEnum).code()).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
  }

  // ---------------------------------------------------------------------------------- C-19-4

  /**
   * C-19-4 (INFO). The descendant walk's javadoc says the set is a tree. It is a DAG: legacy
   * inheritance allows several parents, so a relation is visited once per path. Twelve stacked
   * diamonds of plain tables (36 relations) take the walk past its 10 000-visit bound, and an
   * admissible table is reported unverifiable ({@code SHRED-SCHEMA-005}) at startup and at every
   * erasure. Fail-closed, so INFO; the fix is a visited set keyed by oid and a corrected javadoc.
   */
  @Test
  void probe_a_diamond_inheritance_is_walked_once_per_relation() {
    var ddl = new ArrayList<String>();
    ddl.add(
        "CREATE TABLE app.c194 (id bigint, tenant varchar(64), subject varchar(64),"
            + " email_idx varchar(64))");
    String previous = "app.c194";
    for (int i = 1; i <= 12; i++) {
      ddl.add("CREATE TABLE app.c194_a" + i + " () INHERITS (" + previous + ")");
      ddl.add("CREATE TABLE app.c194_b" + i + " () INHERITS (" + previous + ")");
      ddl.add(
          "CREATE TABLE app.c194_n"
              + i
              + " () INHERITS (app.c194_a"
              + i
              + ", app.c194_b"
              + i
              + ")");
      previous = "app.c194_n" + i;
    }
    exec(app, ddl.toArray(String[]::new));
    assertThat(text(su, "SELECT count(*) FROM pg_catalog.pg_inherits")).isEqualTo("48");

    Throwable thrown = catchThrowable(() -> verdict(app, target("app.c194")));
    assertThat(thrown).describedAs("36 plain tables are admissible").isNull();
  }

  // ---------------------------------------------------------------------------------- C-19-5

  /**
   * C-19-5 (LOW). A non-string tenant or subject column canonicalises the erasure's bound text
   * before comparing it. Under {@code stringtype=unspecified} (the setting the docs prescribe for
   * {@code uuid}), an erasure requested for {@code A0EEBC99-...} - a different subject id to this
   * module, which keys data by the exact string - clears the blind index of subject {@code
   * a0eebc99-...}, whose data key survives. The same holds for {@code 0042} against a {@code
   * bigint} subject 42. This is clause C-e's harm (an erasure for one subject clears another's row)
   * through a type's input function instead of a collation.
   */
  @Test
  void probe_a_uuid_subject_lets_an_erasure_for_another_spelling_clear_this_subjects_index() {
    String lower = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11";
    String upper = lower.toUpperCase(java.util.Locale.ROOT);
    exec(
        app,
        "CREATE TABLE app.c195 (id bigint, tenant varchar(64), subject uuid,"
            + " email_idx varchar(64))",
        "INSERT INTO app.c195 VALUES (1, 'T1', '" + lower + "', 'HMAC-OF-THE-LOWER-SUBJECT')",
        "CREATE TABLE app.c195n (id bigint, tenant varchar(64), subject bigint,"
            + " email_idx varchar(64))",
        "INSERT INTO app.c195n VALUES (1, 'T1', 42, 'HMAC-OF-SUBJECT-42')");

    assertThat(verdict(unspecified, target("app.c195")))
        .describedAs("a subject column whose type canonicalises the bound text")
        .isInstanceOf(Refused.class);
    assertThat(verdict(unspecified, target("app.c195n"))).isInstanceOf(Refused.class);

    Throwable byAlias = catchThrowable(() -> erase(unspecified, "app.c195", "T1", upper));
    Throwable byPadding = catchThrowable(() -> erase(unspecified, "app.c195n", "T1", "0042"));
    assertThat(List.of(Optional.ofNullable(byAlias), Optional.ofNullable(byPadding)))
        .allSatisfy(
            t ->
                assertThat(t)
                    .get()
                    .isInstanceOfSatisfying(
                        ShreddingException.class,
                        e -> assertThat(e.code()).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE)));
    assertThat(text(su, "SELECT count(*) FROM app.c195 WHERE email_idx IS NOT NULL"))
        .describedAs("an erasure for another subject id must not clear this subject's index")
        .isEqualTo("1");
    assertThat(text(su, "SELECT count(*) FROM app.c195n WHERE email_idx IS NOT NULL"))
        .isEqualTo("1");
  }

  // ---------------------------------------------------------------------------------- C-19-6

  /**
   * C-19-6 (INFO). Step 1b's cost statement names a manual VACUUM, ANALYZE and CREATE INDEX
   * CONCURRENTLY, and the PR states that autovacuum yields. An autovacuum "to prevent wraparound"
   * does not yield: measured on 16.15, the erasure's SHARE UPDATE EXCLUSIVE waited past a 6 s lock
   * timeout (deadlock_timeout 1 s) behind it, while holding the subject's advisory lock and its key
   * rows FOR UPDATE. Both public cost paragraphs must say so.
   */
  @Test
  void probe_the_lock_cost_statement_names_the_wraparound_autovacuum() throws Exception {
    for (String file : List.of("../SECURITY-NOTES.md", "../docs/upgrading-0.2.0.md")) {
      String text = java.nio.file.Files.readString(java.nio.file.Path.of(file));
      assertThat(text).describedAs(file).containsIgnoringCase("wraparound");
    }
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
