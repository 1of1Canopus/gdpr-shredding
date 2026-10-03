package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ColumnRef;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.RandomSource;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR B1: the <b>framework-rendered</b> read-back, which is the one
 * statement of this module whose text the module did not write (P3 of the name-resolution design,
 * section 4). Every other statement is covered by qualification (Property B, PR A); this one can
 * only be covered by the session, because there is nothing in the text for this module to qualify.
 *
 * <p><b>What stands in for Hibernate here, and why that is honest.</b> {@link BlindIndexResidual}
 * is a port: core does not know Hibernate, and the statement that reaches the server is whatever
 * the implementation renders. Each case below hands {@code JdbcErasureStore} a residual that
 * renders one of the shapes the design review measured - a bare {@code =} on a {@code varchar}
 * column (T1a/T2a), a {@code LIKE} (T1b/T2b), a bare {@code count(*)} (T2c), an unqualified
 * relation (T1c/T2f) - and measures what the erasure then does. The real Hibernate rendering is
 * measured in the starter, against a real mapping, by {@code CipherProbeWindowPr14StarterTest}; the
 * cases here exist because a port is exactly where the shapes can be enumerated one at a time.
 *
 * <p><b>How a wrong answer is observed.</b> {@code verifyCleared} runs the framework-rendered count
 * <em>first</em> and the module's own qualified same-text count second, and both refuse with {@code
 * SHRED-ERASURE-004}. The fixture leaves a residue the erasure cannot clear (a {@code BEFORE
 * UPDATE} trigger puts the index straight back), so the truthful answer to both is 1 and the
 * refusal is certain either way. What distinguishes the two is the <b>message</b>: only the
 * framework-rendered leg says "read back through the entity's own mapping". A shadow that makes
 * that leg answer zero is therefore visible as the second leg's message, which is the same
 * observation the design review's T1a/T1b made at the SQL level.
 *
 * <p>Fixture: the hardened two-role posture of SECURITY-NOTES "Database roles", the same shape as
 * {@link CipherProbeNamePr13eTest}. The runtime role is {@code NOSUPERUSER NOCREATEDB
 * NOCREATEROLE}, holds no {@code CREATE} on {@code public} and no {@code TEMPORARY} on the
 * database, and owns one schema of its own in which it defines the shadow and sets its own {@code
 * search_path} - neither of which a hardened deployment can take away from it.
 *
 * <p>All of these are RED on {@code d1289db}, the head of PR A.
 */
@Testcontainers
class CipherProbeWindowPr14Test {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(Duration.ofMinutes(2));

  private static final String APP = "probe_window_app";
  private static final String OWNER = "probe_window_owner";

  /** The role's own schema: the one thing it needs to own to run any of these. */
  private static final String OWN = "app";

  private static final byte[] SECRET =
      "probe-window-secret-0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final TenantId TENANT = TenantId.of("t1");
  private static final SubjectId SUBJECT = SubjectId.of("s1");

  /** The message only the framework-rendered leg carries. */
  private static final String INDEPENDENT_LEG = "read back through the entity's own mapping";

  private static HikariDataSource superuserDs;
  private final List<HikariDataSource> perTest = new ArrayList<>();

  @BeforeAll
  static void start() {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    su(
        "DROP ROLE IF EXISTS " + APP,
        "DROP ROLE IF EXISTS " + OWNER,
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE",
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER");
  }

  @AfterAll
  static void stop() {
    close(superuserDs);
    POSTGRES.stop();
  }

  @BeforeEach
  void freshDatabase() {
    su(
        "ALTER ROLE " + APP + " RESET search_path",
        "ALTER ROLE " + OWNER + " RESET search_path",
        "DROP SCHEMA IF EXISTS " + OWN + " CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "CREATE SCHEMA " + OWN + " AUTHORIZATION " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
  }

  @AfterEach
  void closePerTestPools() {
    perTest.forEach(CipherProbeWindowPr14Test::close);
    perTest.clear();
  }

  // ------------------------------------- N-1: an exact-type shadow, which no order can demote

  /**
   * T1a/T2a and test N15. PostgreSQL ships no {@code =} with {@code varchar} on either side -
   * {@code varchar = varchar} reaches {@code texteq} by coercion - so an {@code
   * app.=(varchar,varchar)} is an <b>exact</b> match and is selected at step 2 of operator
   * resolution whatever the path order. The design review measured the consequence on the real
   * Hibernate-rendered shape: 0 against one residue row with {@code pg_catalog} named first, 1 only
   * when the role's own schema was not on the path at all.
   *
   * <p>A {@code text} fixture is <b>not</b> sufficient and this comment is part of the test: with
   * {@code text} columns the shadow is not an exact match, {@code pg_catalog.texteq} wins, and the
   * case passes with no mechanism at all.
   */
  @Test
  void probe_a_shadowed_varchar_equality_cannot_make_the_framework_read_back_answer_zero() {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    shadow(
        fixture.own,
        "CREATE FUNCTION "
            + OWN
            + ".vc(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vc)");

    assertThatThrownBy(
            () ->
                erase(
                    hostilePath(),
                    fixture.schema,
                    frameworkCount(
                        "SELECT count(*) FROM public.customer WHERE tenant_id = ?"
                            + " AND customer_id = ? AND email_bidx IS NOT NULL",
                        TENANT.value(),
                        SUBJECT.value())))
        .isInstanceOf(ShreddingException.class)
        .hasFieldOrPropertyWithValue("code", ErrorCodes.ERASURE_INDEX_RESIDUAL)
        .describedAs(
            "the framework-rendered leg must be the one that refuses: with app.=(varchar,varchar)"
                + " -> false it answers 0, and the only refusal left is the module's own qualified"
                + " same-text count - a different message, and no independent leg at all")
        .hasMessageContaining(INDEPENDENT_LEG);

    assertThat(keyRows()).describedAs("the whole transaction rolled back").isEqualTo(1);
  }

  /**
   * T1b/T2b. {@code LIKE} is the operator {@code ~~} and has no {@code OPERATOR(pg_catalog....)}
   * spelling at all, so a statement that contains one cannot be made sound by qualification - which
   * is why the module builds none, and why a framework that renders one can only be covered by
   * replacing the candidate set. The shadow here is {@code app.~~(varchar,varchar) -> false}; the
   * statement's {@code =} is left alone, so this case measures the keyword-operator class on its
   * own.
   */
  @Test
  void probe_a_shadowed_like_cannot_make_the_framework_read_back_answer_zero() {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    shadow(
        fixture.own,
        "CREATE FUNCTION "
            + OWN
            + ".lk(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".~~ (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".lk)");

    assertThatThrownBy(
            () ->
                erase(
                    hostilePath(),
                    fixture.schema,
                    frameworkCount(
                        "SELECT count(*) FROM public.customer WHERE tenant_id = ?"
                            + " AND customer_id LIKE ? AND email_bidx IS NOT NULL",
                        TENANT.value(),
                        SUBJECT.value())))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining(INDEPENDENT_LEG);
  }

  /**
   * T2c. The aggregate is a name too: a role that owns a schema can define {@code app.count(*)},
   * and {@code count(*)} is what every ORM renders for a count query. Hibernate gives no way to
   * write {@code pg_catalog.count(*)} in HQL, which is the residual {@code
   * HibernateBlindIndexResidual}'s javadoc has carried since C-13-11.
   */
  @Test
  void probe_a_lying_count_aggregate_cannot_make_the_framework_read_back_answer_zero() {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    shadow(
        fixture.own,
        "CREATE FUNCTION "
            + OWN
            + ".zero(pg_catalog.int8) RETURNS pg_catalog.int8"
            + " AS $$ SELECT 0::pg_catalog.int8 $$ LANGUAGE sql",
        "CREATE AGGREGATE "
            + OWN
            + ".count(*) (SFUNC = "
            + OWN
            + ".zero,"
            + " STYPE = pg_catalog.int8, INITCOND = '0')");

    assertThatThrownBy(
            () ->
                erase(
                    hostilePath(),
                    fixture.schema,
                    frameworkCount(
                        "SELECT count(*) FROM public.customer WHERE tenant_id = ?"
                            + " AND customer_id = ? AND email_bidx IS NOT NULL",
                        TENANT.value(),
                        SUBJECT.value())))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining(INDEPENDENT_LEG);
  }

  // ------------------------------------- N-2: the arrived path is the attacker's own

  /**
   * T1c/T2f. Relation names are exactly the names that do not exist in {@code pg_catalog}, so
   * prepending {@code pg_catalog} leaves the role's own decoy first: a prefix pin cannot move a
   * relation at all. Replacing the path can, and what it produces for an <b>unqualified</b>
   * relation is not a different table but an error - fail-closed and loud, the opposite of the
   * prefix form, which read the decoy silently.
   *
   * <p>This is also the measurement behind the mapping requirement of section 3.2: the only way the
   * framework-rendered statement names a relation at all inside the window is for the mapping to
   * carry its schema.
   */
  @Test
  void probe_an_unqualified_relation_in_the_window_fails_rather_than_reading_the_decoy() {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    exec(
        fixture.own,
        "CREATE TABLE "
            + OWN
            + ".customer (id bigserial PRIMARY KEY,"
            + " tenant_id varchar(255), customer_id varchar(255), email_bidx varchar(255))");

    assertThatThrownBy(
            () ->
                erase(
                    decoyFirstPath(),
                    fixture.schema,
                    frameworkCount(
                        "SELECT pg_catalog.count(*) FROM customer WHERE (tenant_id OPERATOR(pg_catalog.=) ?)"
                            + " AND (customer_id OPERATOR(pg_catalog.=) ?) AND email_bidx IS NOT NULL",
                        TENANT.value(),
                        SUBJECT.value())))
        .describedAs(
            "inside the replaced path the role's own schema is not a candidate, so an unqualified"
                + " relation is an error. On the arrived path it is the empty decoy, which answers"
                + " 0 and lets an erasure that cleared nothing be recorded as complete")
        .hasMessageContaining("does not exist");

    assertThat(keyRows()).describedAs("nothing was destroyed and nothing recorded").isEqualTo(1);
  }

  // ------------------------------------- M2: the restore is an injection sink

  /**
   * N17b, and the shapes the second security review measured as A23. The arrived path is set by the
   * <b>role itself</b>, which can put a quote and a statement terminator in it:
   *
   * <pre>
   *   ALTER ROLE ... SET search_path = "x', true); SELECT pg_catalog.pg_sleep(0", app, pg_catalog
   * </pre>
   *
   * {@code current_setting} returns those bytes verbatim. A restore composed into statement text
   * then sets {@code search_path} to {@code x} - the control is not restored - and sends the
   * attacker's text as a second statement; the shape {@code "a'b", app, pg_catalog} raises a syntax
   * error instead. Bound, both disappear, and {@code set_config} accepts a 200 003-character path,
   * so length is no bound either.
   *
   * <p>The window has to be measurably open for the restore assertion to mean anything, so the
   * {@code varchar} shadow of N-1 is installed here too: the erasure must refuse through the
   * framework-rendered leg <em>and</em> the connection must come back carrying the bytes it arrived
   * with.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "\"a'b\", app, pg_catalog",
        "\"x', true); SELECT pg_catalog.pg_sleep(0\", app, pg_catalog"
      })
  void probe_the_window_restores_an_arrived_path_that_contains_a_quote_and_a_statement(
      String arrived) {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    shadow(
        fixture.own,
        "CREATE FUNCTION "
            + OWN
            + ".vc(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vc)");
    su("ALTER ROLE " + APP + " SET search_path = " + arrived);
    HikariDataSource shadowed = oneConnectionPool(APP);
    String before = text(shadowed, "SELECT pg_catalog.current_setting('search_path')");

    assertThatThrownBy(
            () ->
                erase(
                    shadowed,
                    fixture.schema,
                    frameworkCount(
                        "SELECT count(*) FROM public.customer WHERE tenant_id = ?"
                            + " AND customer_id = ? AND email_bidx IS NOT NULL",
                        TENANT.value(),
                        SUBJECT.value())))
        .describedAs("the window was open for the arrived path <%s>", arrived)
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining(INDEPENDENT_LEG);

    assertThat(text(shadowed, "SELECT pg_catalog.current_setting('search_path')"))
        .describedAs(
            "the one connection of this pool must come back carrying the bytes it arrived with,"
                + " for the arrived path <%s>",
            arrived)
        .isEqualTo(before);
  }

  // ------------------------------------- M3: 25P02 must not mask the real error

  /**
   * N18b, measured as C-19. A statement that fails inside the window aborts the transaction, so the
   * restore is itself refused with {@code 25P02 current transaction is aborted} - and after the
   * rollback the session's path is back to what it arrived as, because the rollback <em>is</em> the
   * restore. What the caller must see is the failure that actually happened: an erasure that failed
   * on a missing column reports that missing column, never {@code SHRED-SCHEMA-008}, and the
   * refused restore is attached with {@code addSuppressed} rather than thrown in its place.
   */
  @Test
  void probe_a_failure_inside_the_window_surfaces_itself_with_the_refused_restore_suppressed() {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    HikariDataSource shadowed = oneConnectionPool(APP);
    String before = text(shadowed, "SELECT pg_catalog.current_setting('search_path')");

    Throwable thrown =
        catchAnything(
            () ->
                erase(
                    shadowed,
                    fixture.schema,
                    frameworkCount(
                        "SELECT pg_catalog.count(*) FROM public.customer"
                            + " WHERE (no_such_column OPERATOR(pg_catalog.=) ?)",
                        TENANT.value())));

    assertThat(messagesOf(thrown))
        .describedAs("the failure the caller sees is the missing column, not an isolation refusal")
        .anyMatch(m -> m.contains("no_such_column"))
        .noneMatch(m -> m.contains("SHRED-SCHEMA-008"));
    assertThat(suppressedMessagesOf(thrown))
        .describedAs(
            "the restore was attempted and refused with 25P02 inside the aborted transaction, and"
                + " it is attached to the real failure rather than replacing it")
        .anyMatch(m -> m.contains("25P02") || m.contains("current transaction is aborted"));
    assertThat(text(shadowed, "SELECT pg_catalog.current_setting('search_path')"))
        .describedAs("after the rollback the session carries the path it arrived with")
        .isEqualTo(before);
    assertThat(keyRows()).isEqualTo(1);
  }

  // ------------------------------------- the window itself, on its own API

  /**
   * N17 and T19. The restore sends back the bytes {@code current_setting} returned, so it is
   * byte-exact for every shape a session can arrive carrying - including the two that do not round
   * trip through any re-composed spelling (T18): the empty path, which reports as {@code ""}, and
   * the stock default set as one quoted literal, which reports as {@code """$user"", public"}.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "decoy, app, pg_catalog",
        "''",
        "'\"$user\", public'",
        "\"My Shred\", \"s\"\"q\", app, pg_catalog",
        "pg_temp, decoy, app"
      })
  void probe_the_window_restores_every_arrived_path_shape(String arrived) throws Exception {
    DataSource app = freshPool(APP);
    try (Connection c = app.getConnection()) {
      c.setAutoCommit(false);
      exec(c, "SET search_path = " + arrived);
      String before = searchPathOf(c);

      long answer =
          JdbcSupport.inOneStatementWindow(
              c, () -> one(c, "SELECT pg_catalog.count(*) FROM pg_catalog.pg_class"));

      assertThat(answer).describedAs("the statement ran inside the window").isPositive();
      assertThat(searchPathOf(c))
          .describedAs("byte-equal, for the arrived shape <%s>", arrived)
          .isEqualTo(before);
      c.rollback();
    }
  }

  /**
   * N18, measured as T7. In auto-commit a {@code set_config(..., true)} <em>returns</em> the pinned
   * value while the next statement sees the old path, so a window opened there would be the fiction
   * it exists to detect. It is refused before anything on the connection is touched.
   */
  @Test
  void probe_the_window_refuses_an_auto_commit_connection_and_changes_nothing() throws Exception {
    DataSource app = freshPool(APP);
    try (Connection c = app.getConnection()) {
      exec(c, "SET search_path = app, pg_catalog");
      String before = searchPathOf(c);

      assertThatThrownBy(() -> JdbcSupport.inOneStatementWindow(c, () -> 1L))
          .isInstanceOf(ShreddingException.class)
          .hasFieldOrPropertyWithValue("code", "SHRED-SCHEMA-008")
          .hasMessageContaining("auto-commit")
          .hasMessageContaining("independent read-back");
      assertThat(searchPathOf(c)).isEqualTo(before);
    }
  }

  /**
   * C-20, and the measurement that changed the restore. The design page expected a non-local {@code
   * SET} inside the window to be "read by step 6 and refused by the comparison". It is not: a
   * transaction-local {@code set_config} shadows a non-local {@code SET} for the rest of the
   * transaction, so a local restore reads back exactly the bytes it sent and sees nothing - and at
   * {@code COMMIT} the local value is discarded and the session keeps the attacker's. The restore
   * is therefore sent with {@code is_local = false}, which makes it the last writer either way, and
   * this test is what holds it there: with a local restore the final assertion reads {@code
   * pg_temp}.
   *
   * <p>The only way to execute a {@code SET} inside the window at all is a plpgsql body the
   * framework-rendered statement reaches - an RLS policy function, or a function called from a
   * mapped view (M8).
   */
  @Test
  void probe_a_non_local_set_inside_the_window_does_not_survive_the_window() throws Exception {
    DataSource app = freshPool(APP);
    try (Connection c = app.getConnection()) {
      c.setAutoCommit(false);
      String arrived = searchPathOf(c);

      long answer =
          JdbcSupport.inOneStatementWindow(
              c,
              () -> {
                exec(c, "SET search_path = pg_temp");
                return 1L;
              });

      assertThat(answer).isEqualTo(1L);
      assertThat(searchPathOf(c)).isEqualTo(arrived);
      c.commit();
      assertThat(searchPathOf(c))
          .describedAs(
              "after the commit too: a transaction-local restore would have been discarded here and"
                  + " the session would have kept the SET issued inside the window")
          .isEqualTo(arrived);
    }
  }

  /**
   * T3c and T2e, at the SQL level, which is where this statement's exposure can be seen at all: the
   * cross-tenant WARN count's {@code IS DISTINCT FROM} reaches the type's own {@code =} and has no
   * {@code OPERATOR(pg_catalog....)} spelling. The shape below is the one {@code verifyCleared}
   * builds, with the same conjuncts and the same bind positions.
   *
   * <p>Two parameter typings, because they do not answer the same (and the design page claimed only
   * the first): with {@code stringtype=varchar} the driver declares the parameter {@code varchar},
   * the shadow is an exact match and the count answers <b>2</b> where the truth is 1; with pgjdbc's
   * default {@code unspecified} the server resolves the keyword operator to {@code pg_catalog}
   * anyway and the count is already truthful. Inside the window both answer 1, which is the only
   * posture that does not depend on a driver setting the application chose.
   */
  @Test
  void probe_the_cross_tenant_shape_is_only_correct_inside_the_window() throws Exception {
    var fixture = fixtureWithResidueThatCannotBeCleared();
    shadow(
        fixture.own,
        "CREATE FUNCTION "
            + OWN
            + ".vc(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = "
            + OWN
            + ".vc)");
    exec(
        superuserDs,
        "INSERT INTO public.customer (tenant_id, customer_id, email_bidx)"
            + " VALUES ('t2', 's1', 'other-tenant-residue')");
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    String sql =
        "SELECT pg_catalog.count(*) FROM public.customer"
            + " WHERE (customer_id OPERATOR(pg_catalog.=) ?)"
            + " AND tenant_id IS DISTINCT FROM ? AND email_bidx IS NOT NULL";

    for (boolean declared : List.of(true, false)) {
      HikariDataSource ds = declared ? declaredVarcharPool() : oneConnectionPool(APP);
      try (Connection c = ds.getConnection()) {
        c.setAutoCommit(false);
        long outside = crossTenant(c, sql);
        long inside = JdbcSupport.inOneStatementWindow(c, () -> crossTenant(c, sql));

        assertThat(inside)
            .describedAs(
                "inside the window the keyword operator can only resolve from pg_catalog, so the"
                    + " count is the truth - one row, under t2 (declared parameter: %s)",
                declared)
            .isEqualTo(1L);
        if (declared) {
          assertThat(outside)
              .describedAs(
                  "with the parameter declared varchar the shadow is an exact match and the row"
                      + " this erasure is about to clear is counted as another tenant's leftover")
              .isEqualTo(2L);
        }
        c.rollback();
      }
    }
  }

  private static long crossTenant(Connection c, String sql) throws SQLException {
    try (PreparedStatement ps = c.prepareStatement(sql)) {
      ps.setString(1, SUBJECT.value());
      ps.setString(2, TENANT.value());
      try (ResultSet rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    }
  }

  private static long one(Connection c, String sql) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getLong(1) : 0L;
    }
  }

  private static String searchPathOf(Connection c) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT pg_catalog.current_setting('search_path')")) {
      return rs.next() ? rs.getString(1) : null;
    }
  }

  private static void exec(Connection c, String sql) throws SQLException {
    try (Statement st = c.createStatement()) {
      st.execute(sql);
    }
  }

  /** A pool whose driver declares every {@code setString} parameter as {@code varchar}. */
  private HikariDataSource declaredVarcharPool() {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl() + "?stringtype=varchar");
    config.setUsername(APP);
    config.setPassword("pw");
    config.setMaximumPoolSize(1);
    var ds = new HikariDataSource(config);
    perTest.add(ds);
    return ds;
  }

  // ------------------------------------------------------------------ the fixture

  private record Fixture(VerifiedSchema schema, HikariDataSource own) {}

  /**
   * The module's schema installed by the owner with the SECURITY-NOTES grant block, one customer
   * row holding a blind-index residue, one live data key for that subject, and a {@code BEFORE
   * UPDATE} trigger that puts the index straight back - so the truthful answer to both read-backs
   * after the erasure's {@code UPDATE} is 1 and the refusal is certain whichever leg sees it.
   */
  private Fixture fixtureWithResidueThatCannotBeCleared() {
    HikariDataSource owner = freshPool(OWNER);
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
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP,
        "CREATE TABLE public.customer (id bigserial PRIMARY KEY,"
            + " tenant_id varchar(255) NOT NULL, customer_id varchar(255) NOT NULL,"
            + " email_bidx varchar(255))",
        "GRANT SELECT, INSERT, UPDATE ON public.customer TO " + APP,
        "GRANT USAGE ON SEQUENCE public.customer_id_seq TO " + APP,
        "CREATE FUNCTION public.keep_idx() RETURNS trigger AS $$ BEGIN"
            + " NEW.email_bidx := OLD.email_bidx; RETURN NEW; END; $$ LANGUAGE plpgsql",
        "CREATE TRIGGER keep_idx BEFORE UPDATE ON public.customer"
            + " FOR EACH ROW EXECUTE FUNCTION public.keep_idx()");

    DataSource clean = freshPool(APP);
    var schema = JdbcSupport.verifySchema(clean, false).schema();
    keyProvider(clean, schema).currentForWrite(TENANT, SUBJECT);
    exec(
        clean,
        "INSERT INTO public.customer (tenant_id, customer_id, email_bidx)"
            + " VALUES ('t1', 's1', 'residue')");
    return new Fixture(schema, freshPool(APP));
  }

  /**
   * The stand-in for the framework: a residual that issues exactly the statement given, on the
   * erasure's own connection, with the values bound. This is the only place in these probes where
   * statement text is written by hand, and that is the point - the text is the framework's shape,
   * not the module's.
   */
  private static BlindIndexResidual frameworkCount(String sql, String... values) {
    return (connection, column, tenant, subject) -> {
      try (PreparedStatement ps = connection.prepareStatement(sql)) {
        for (int i = 0; i < values.length; i++) {
          ps.setString(i + 1, values[i]);
        }
        try (ResultSet rs = ps.executeQuery()) {
          return rs.next() ? rs.getLong(1) : 0L;
        }
      } catch (SQLException e) {
        throw new IllegalStateException(e.getMessage(), e);
      }
    };
  }

  private com.housedevinci.shredding.application.ErasureStore.Outcome erase(
      DataSource ds, VerifiedSchema schema, BlindIndexResidual residual) {
    var store =
        new JdbcErasureStore(
            ds,
            schema,
            ErasureChain.keyed(SECRET, "k1"),
            List.of(
                new BlindIndexColumn(
                    TableRef.parse("public.customer"),
                    ColumnRef.unquoted("email_bidx"),
                    ColumnRef.unquoted("customer_id"),
                    ColumnRef.unquoted("tenant_id"),
                    Optional.of("tenantId"),
                    Optional.of("customerId"))),
            residual);
    return store.erase(
        TENANT, SUBJECT, (destroyed, cleared) -> record(SUBJECT, destroyed, cleared));
  }

  private JdbcKeyProvider keyProvider(DataSource ds, VerifiedSchema schema) {
    return new JdbcKeyProvider(
        ds, schema, MasterKey.fromBytes(new byte[32]), RandomSource.secure(), Clock.systemUTC());
  }

  private ErasureRecord record(SubjectId subject, int destroyed, int cleared) {
    return ErasureRecord.of(
        Instant.now(),
        TENANT,
        new Pseudonymiser(SECRET).pseudonym(TENANT, subject),
        "dpo",
        "art 17",
        destroyed,
        1,
        1,
        cleared,
        ErasureOutcome.COMPLETE,
        List.of(),
        Instant.now().plus(Duration.ofDays(30)));
  }

  /**
   * The role's own path with its own schema <b>first</b>: the shape a relation shadow needs. Order
   * decides nothing for an exact-type operator shadow (T1a/T2a) and it decides everything for a
   * relation, which is the one name class that does not exist in {@code pg_catalog} at all (T1c).
   */
  private DataSource decoyFirstPath() {
    su("ALTER ROLE " + APP + " SET search_path = " + OWN + ", public, pg_catalog");
    return oneConnectionPool(APP);
  }

  /** The role's own path, with {@code pg_catalog} demoted by being named late. */
  private DataSource hostilePath() {
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    return oneConnectionPool(APP);
  }

  private void shadow(DataSource own, String... sql) {
    exec(own, sql);
  }

  private static Throwable catchAnything(Runnable work) {
    try {
      work.run();
    } catch (Throwable t) {
      return t;
    }
    throw new AssertionError("the erasure was expected to fail and did not");
  }

  private static List<String> messagesOf(Throwable thrown) {
    var out = new ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      out.add(String.valueOf(t.getMessage()));
    }
    return out;
  }

  private static List<String> suppressedMessagesOf(Throwable thrown) {
    var out = new ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      for (Throwable s : t.getSuppressed()) {
        out.addAll(messagesOf(s));
      }
    }
    return out;
  }

  private static int keyRows() {
    return Integer.parseInt(
        text(superuserDs, "SELECT count(*)::text FROM public.shredding_data_key"));
  }

  private static String text(DataSource ds, String sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : null;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * A new pool every time, never a soft eviction: a role-level {@code search_path} is resolved when
   * the session starts, so a pooled connection opened before {@code ALTER ROLE} still answers the
   * old value.
   */
  private HikariDataSource freshPool(String user) {
    HikariDataSource ds = pool(user, "pw");
    perTest.add(ds);
    return ds;
  }

  /**
   * One connection, so "the connection the erasure used" and "the connection the assertion reads"
   * are the same session and a restore can be observed at all.
   */
  private HikariDataSource oneConnectionPool(String user) {
    HikariDataSource ds = pool(user, "pw", 1);
    perTest.add(ds);
    return ds;
  }

  private static HikariDataSource pool(String user, String password) {
    return pool(user, password, 3);
  }

  private static HikariDataSource pool(String user, String password, int size) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(size);
    return new HikariDataSource(config);
  }

  private static void close(HikariDataSource ds) {
    if (ds != null) {
      ds.close();
    }
  }

  private static void su(String... sql) {
    exec(superuserDs, sql);
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
