package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR 13, <b>fourth pass</b>: the surfaces the C-13-9 to C-13-12 fix left
 * open, all of them the same class as the finding it closed.
 *
 * <p>The fix pinned {@code search_path} to {@code pg_catalog} for the verification transaction and
 * put a {@code pg_catalog.} prefix on every catalogue <em>function</em> and <em>relation</em> name
 * in {@link SchemaVerification}, in {@link JdbcErasureStore} and in the bundled script. An
 * <em>operator</em> name is resolved the same way a function name is - {@code =}, {@code <>},
 * {@code +} and {@code ||} are entries in {@code pg_operator}, looked up along {@code search_path},
 * and a role that owns one schema may define any of them. Three statements that the fix leaves
 * resolving operators in the role's own path:
 *
 * <ol>
 *   <li>the one statement that necessarily runs <b>before</b> the pin, the session capture, whose
 *       {@code n.nspname = pg_catalog.current_schema()} decides which namespace every later leg
 *       reads;
 *   <li>the bodies of the three guard functions, which are not {@code SECURITY DEFINER} and which
 *       verification positively <b>requires</b> to carry no {@code SET search_path} ({@code
 *       proconfig IS NULL}), so they resolve their operators in the session of whoever writes;
 *   <li>the bundled script's {@code DO} blocks, whose {@code ||} builds the name that {@code
 *       pg_catalog.to_regclass} then resolves.
 * </ol>
 *
 * <p>Fixture throughout: the role holds no privilege the hardened deployment refuses to grant. It
 * is {@code NOSUPERUSER NOCREATEDB NOCREATEROLE}, holds no {@code CREATE} and no {@code TEMPORARY}
 * on the database and none on {@code public}; it owns one schema of its own, which SECURITY-NOTES
 * "Database roles" treats as the normal shape, and it sets its own default {@code search_path},
 * which is not a privilege and cannot be revoked.
 *
 * <p>Each test asserts the property the design claims. All three are RED on d25f30a.
 */
@Testcontainers
class CipherProbeNoDdlPr13dTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String APP = "probe_op_app";
  private static final String OWNER = "probe_op_owner";

  /** The role's own schema, and the only thing it needs to own to run any of these. */
  private static final String OWN = "app";

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
    perTest.forEach(CipherProbeNoDdlPr13dTest::close);
    perTest.clear();
  }

  // --------------------------------------------------------- C-13-13: the pre-pin capture

  /**
   * The capture is statement 1 and the pin is statement 2, necessarily in that order: after the pin
   * {@code current_schema()} answers {@code pg_catalog}, so the module's own schema has to be read
   * first. That one statement therefore still resolves names in the role's path, and the only name
   * left in it is the {@code =} of {@code n.nspname = pg_catalog.current_schema()}. {@code name =
   * name} is {@code pg_catalog.=}, and a role that owns a schema ahead of {@code pg_catalog} may
   * define its own {@code =(name, name)}, which hides it.
   *
   * <p>What that buys: the verdict's schema name comes from column 1 and the namespace oid every
   * later leg reads comes from the subquery. Split them and the gate verifies one schema while
   * {@link VerifiedSchema#qualify} sends every write to another. Here the owner's clean install
   * sits in {@code public}; the role's own copy, which it owns outright, sits in {@code app}; the
   * module writes to {@code app} and the twelve privilege legs read {@code public}.
   */
  @Test
  void probe_a_shadowed_equality_operator_cannot_redirect_the_captured_namespace_oid() {
    ownerInstallsInPublicAndGrantsTheBlock();
    DataSource own = roleInstallsInItsOwnSchema();
    exec(
        own,
        "CREATE FUNCTION "
            + OWN
            + ".name_eq(name, name) RETURNS boolean AS $$"
            + " SELECT $1 OPERATOR(pg_catalog.=) 'public'::name $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = name, RIGHTARG = name,"
            + " FUNCTION = "
            + OWN
            + ".name_eq)");
    DataSource shadowed = freshPool(APP);

    SchemaVerdict verdict;
    try {
      verdict = JdbcSupport.verifySchema(shadowed, false);
    } catch (ShreddingException refused) {
      return; // nothing was claimed, the gate held
    }
    assertThat(verdict.schema().name())
        .describedAs("the module will qualify every write to this schema")
        .isEqualTo(OWN);
    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();

    try (Connection c = shadowed.getConnection();
        Statement st = c.createStatement()) {
      st.execute(insertOneErasureRow(OWN));
      assertThatThrownBy(
              () -> {
                st.execute("ALTER TABLE " + OWN + ".shredding_erasure DISABLE TRIGGER ALL");
                st.executeUpdate("DELETE FROM " + OWN + ".shredding_erasure");
              })
          .describedAs(
              "verification returned '%s' for schema %s and the role then emptied that log",
              verdict.summary(), verdict.schema().name())
          .isInstanceOf(SQLException.class);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  // ------------------------------------------------- C-13-14: the guard function bodies

  /**
   * The documented two-role posture, verifying clean, with nothing shadowed in the gate at all: the
   * owner owns the four tables and the three guard functions, the role holds exactly the grant
   * block, and {@code SHRED-SCHEMA-004} is satisfied truthfully. The anchor is then rewritten
   * anyway.
   *
   * <p>{@code shredding_erasure_anchor_monotonic} is plain {@code plpgsql}, is not {@code SECURITY
   * DEFINER}, and - because {@link SchemaExpectations} requires {@code proconfig IS NULL} - carries
   * no {@code SET search_path}. A trigger function with no {@code SET} clause resolves its body in
   * the session of the role performing the write. Its whole guard is three operators: the {@code =}
   * that {@code IS DISTINCT FROM} expands to, the {@code <>} on {@code row_count} and the {@code +}
   * that makes it monotonic, and the {@code =} on {@code head_hash}. Three operators in the role's
   * own schema and the anchor - the module's external, attacker-unwritable record of the trail's
   * length, head and keyed mode - takes any value the role likes, with {@code UPDATE} on the anchor
   * being part of the documented grant block.
   */
  @Test
  void probe_a_shadowed_operator_cannot_disarm_the_anchor_monotonic_guard() {
    ownerInstallsInPublicAndGrantsTheBlock();
    DataSource app = freshPool(APP);
    assertThatCode(() -> JdbcSupport.verifySchema(app, false))
        .describedAs("the honest hardened posture, which must verify")
        .doesNotThrowAnyException();
    exec(
        app,
        "INSERT INTO public.shredding_erasure_anchor"
            + " VALUES (1, "
            + hash('a')
            + ", 7, pg_catalog.now(), true)");

    exec(
        app,
        "CREATE FUNCTION "
            + OWN
            + ".t(boolean, boolean) RETURNS boolean"
            + " AS $$ SELECT true $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = boolean, RIGHTARG = boolean,"
            + " FUNCTION = "
            + OWN
            + ".t)",
        "CREATE FUNCTION "
            + OWN
            + ".f(bigint, bigint) RETURNS boolean"
            + " AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".<> (LEFTARG = bigint, RIGHTARG = bigint,"
            + " FUNCTION = "
            + OWN
            + ".f)",
        "CREATE FUNCTION "
            + OWN
            + ".g(bpchar, bpchar) RETURNS boolean"
            + " AS $$ SELECT false $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".= (LEFTARG = bpchar, RIGHTARG = bpchar,"
            + " FUNCTION = "
            + OWN
            + ".g)");
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    DataSource shadowed = freshPool(APP);

    assertThatThrownBy(
            () ->
                exec(
                    shadowed,
                    "UPDATE public.shredding_erasure_anchor"
                        + " SET row_count = 1, head_hash = "
                        + hash('b')
                        + ", keyed = false"
                        + " WHERE id = 1"))
        .describedAs(
            "the anchor is the trail's tamper evidence: keyed is documented immutable and"
                + " row_count documented to advance by exactly one")
        .isInstanceOf(RuntimeException.class);

    assertThat(anchorRowCount())
        .describedAs("the anchor still records the seven rows the trail actually has")
        .isEqualTo(7L);
  }

  // --------------------------------------------------- C-13-15: the bundled script's DO blocks

  /**
   * C-13-12 closed the {@code to_regclass} half. The string that {@code to_regclass} is handed is
   * still built with an unqualified {@code ||}: {@code pg_catalog.quote_ident(current_schema()) ||
   * '.shredding_erasure'}. An {@code app.||(text, text)} returning a name that resolves to nothing
   * puts both oids back to NULL, which is exactly the state C-13-12 described - the
   * keyed-from-birth guard cannot {@code RAISE}, and the five trigger guards below lose the {@code
   * tgrelid} scoping that CIPHER-05 added. Reachable on {@code initialize-schema=true}, where the
   * runtime role runs the script itself.
   */
  @Test
  void probe_a_shadowed_concatenation_operator_cannot_silence_the_keyed_from_birth_guard() {
    su("GRANT USAGE, CREATE ON SCHEMA public TO " + APP);
    DataSource app = freshPool(APP);
    exec(
        app,
        "CREATE TABLE public.shredding_erasure"
            + " (seq bigserial PRIMARY KEY, ts timestamptz NOT NULL)",
        "CREATE FUNCTION "
            + OWN
            + ".cat(text, text) RETURNS text"
            + " AS $$ SELECT 'pg_catalog.no_such_relation_here' $$ LANGUAGE sql",
        "CREATE OPERATOR "
            + OWN
            + ".|| (LEFTARG = text, RIGHTARG = text,"
            + " FUNCTION = "
            + OWN
            + ".cat)");
    su("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    DataSource shadowed = freshPool(APP);

    assertThatThrownBy(() -> JdbcSupport.initializeSchema(shadowed))
        .describedAs("an erasure log with no key_id column must be refused by the pre-flight guard")
        .hasStackTraceContaining("predates keyed-from-birth");
  }

  // ------------------------------------------------------------------ controls

  /**
   * The control for the first probe: the same two installs, the same role, the same path, and no
   * shadowed operator. The gate must refuse, because the schema the module writes to is owned
   * outright by the role writing to it. A green first probe with a red control would mean nothing.
   */
  @Test
  void control_without_the_operator_the_role_owned_schema_is_refused_as_privileged() {
    ownerInstallsInPublicAndGrantsTheBlock();
    roleInstallsInItsOwnSchema();
    DataSource plain = freshPool(APP);

    assertThatThrownBy(() -> JdbcSupport.verifySchema(plain, false))
        .describedAs("the role owns the nine objects in the schema it writes to")
        .isInstanceOf(ShreddingException.class);
  }

  /** The control for the second probe: without the operators the anchor guard refuses. */
  @Test
  void control_without_the_operators_the_anchor_guard_refuses_the_same_update() {
    ownerInstallsInPublicAndGrantsTheBlock();
    DataSource app = freshPool(APP);
    exec(
        app,
        "INSERT INTO public.shredding_erasure_anchor"
            + " VALUES (1, "
            + hash('a')
            + ", 7, pg_catalog.now(), true)");

    assertThatThrownBy(
            () ->
                exec(
                    app,
                    "UPDATE public.shredding_erasure_anchor"
                        + " SET row_count = 1, head_hash = "
                        + hash('b')
                        + ", keyed = false"
                        + " WHERE id = 1"))
        .isInstanceOf(RuntimeException.class);
    assertThat(anchorRowCount()).isEqualTo(7L);
  }

  // ------------------------------------------------------------------ fixture

  /** The hardened posture of SECURITY-NOTES "Database roles", applied to {@code public}. */
  private void ownerInstallsInPublicAndGrantsTheBlock() {
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
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);
  }

  /**
   * The role applies the script inside the schema it owns, which needs no privilege beyond owning
   * that schema, and makes it the first entry on its own default path - the ordinary shape for an
   * application that owns the tables its entities live in.
   */
  private DataSource roleInstallsInItsOwnSchema() {
    su("ALTER ROLE " + APP + " SET search_path = " + OWN + ", pg_catalog");
    HikariDataSource own = freshPool(APP);
    JdbcSupport.initializeSchema(own);
    return own;
  }

  private long anchorRowCount() {
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery("SELECT row_count FROM public.shredding_erasure_anchor")) {
      return rs.next() ? rs.getLong(1) : -1L;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String hash(char c) {
    return "'" + String.valueOf(c).repeat(64) + "'";
  }

  private static String insertOneErasureRow(String schema) {
    return "INSERT INTO "
        + schema
        + ".shredding_erasure (ts, tenant, subject_pseudonym, outcome,"
        + " backup_clear_at, chain_version, key_id, prev_hash, hash)"
        + " VALUES (pg_catalog.now(), 'tenant', "
        + hash('x')
        + ", 'COMPLETE', pg_catalog.now(), 'v2', 'k', "
        + hash('0')
        + ", "
        + hash('1')
        + ")";
  }

  /**
   * A new pool every time, never a soft eviction: a role-level {@code search_path} and role
   * membership are resolved when the session starts, so a pooled connection opened before {@code
   * ALTER ROLE} still answers the old values (the same reason {@code SchemaVerificationTest}
   * rebuilds its pools synchronously).
   */
  private HikariDataSource freshPool(String user) {
    HikariDataSource ds = pool(user, "pw");
    perTest.add(ds);
    return ds;
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
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
