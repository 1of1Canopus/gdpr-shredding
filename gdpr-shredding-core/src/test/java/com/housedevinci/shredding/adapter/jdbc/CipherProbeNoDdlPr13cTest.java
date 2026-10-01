package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
 * Security review probes, PR 13, <b>third pass, one class of attack only</b>: the B-38-10 class
 * found on module B's no-DDL design page, carried over to this module's shipped {@link
 * SchemaVerification}.
 *
 * <p>The threat model is the one the no-DDL redesign exists for, with nothing added: the
 * application connects as a runtime role that holds only the grant block of SECURITY-NOTES.md, and
 * that role owns its own business schema - the normal shape of a deployment, since the application
 * owns the tables its own entities live in. Two facts about PostgreSQL do the rest. A role may
 * always set its own {@code search_path} ({@code ALTER ROLE <itself> SET search_path = ...}); there
 * is no privilege to revoke. And {@code pg_catalog}, when it is named explicitly in a {@code
 * search_path}, is searched in the position it is named rather than first - so a schema named
 * before it shadows any catalogue function or relation name that the server-side SQL writes
 * unqualified.
 *
 * <p>{@link SchemaVerification} writes every one of them unqualified: {@code pg_has_role}, {@code
 * has_table_privilege}, {@code has_column_privilege}, {@code has_schema_privilege}, {@code
 * has_database_privilege}, {@code has_sequence_privilege}, {@code current_setting}, {@code
 * format_type}, {@code pg_get_constraintdef}, {@code pg_get_function_result}, {@code count}, {@code
 * current_schema}. So does the bundled script ({@code to_regclass}, {@code quote_ident}, {@code
 * pg_advisory_xact_lock}) and so does the erasure store's blind-index read-back ({@code count},
 * {@code now}). The verdict is an answer the verified role supplies.
 *
 * <p>Each test asserts the property the design claims, so each is RED on 970e67b and green once
 * every call is qualified and the verification transaction pins its own {@code search_path}.
 */
@Testcontainers
class CipherProbeNoDdlPr13cTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String APP = "probe_shadow_app";

  /** The role's own business schema, and the only thing it needs to own to run the attack. */
  private static final String OWN = "app";

  private static HikariDataSource superuserDs;
  private static HikariDataSource appDs;
  private final List<HikariDataSource> perTest = new ArrayList<>();

  @BeforeAll
  static void start() {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    su(
        "DROP ROLE IF EXISTS " + APP,
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE");
  }

  @AfterAll
  static void stop() {
    close(appDs);
    close(superuserDs);
    POSTGRES.stop();
  }

  @BeforeEach
  void freshDatabase() {
    close(appDs);
    su(
        "DROP SCHEMA IF EXISTS " + OWN + " CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + APP,
        "CREATE SCHEMA " + OWN + " AUTHORIZATION " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP,
        "ALTER ROLE " + APP + " RESET search_path");
    appDs = pool(APP, "pw");
  }

  @AfterEach
  void closePerTestPools() {
    perTest.forEach(CipherProbeNoDdlPr13cTest::close);
    perTest.clear();
  }

  // ------------------------------------------------------------------ the privilege legs

  /**
   * The §4.6 legs - "the role owns none of the 9 objects, holds no privilege on them beyond the
   * documented grant set, and holds no CREATE or TEMPORARY in this database" - are twelve calls to
   * functions the verified role can replace. Here the role owns all nine objects and holds every
   * privilege on them, which is the exact state {@code SHRED-SCHEMA-004} exists to refuse, and
   * eight small SQL functions in its own schema turn every one of those legs into {@code false}.
   */
  @Test
  void probe_shadowed_privilege_functions_cannot_make_the_role_legs_answer_clean() {
    roleOwnsEverything();
    shadowPrivilegeFunctions();
    DataSource shadowed = shadowedPool();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(shadowed, false))
        .describedAs(
            "the role owns the erasure log and holds DELETE, UPDATE, TRUNCATE and TRIGGER on it;"
                + " 004 must not be answerable by the role being verified")
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
  }

  /**
   * The same state read from the other end, and the sentence that matters to an auditor: a verdict
   * that was returned rather than thrown is a claim that this role cannot remove the guards. If the
   * gate refuses, nothing is claimed and the test holds. If it returns a verdict, the role must not
   * then be able to disarm the append-only trigger and empty the trail.
   */
  @Test
  void probe_a_clean_verdict_implies_the_erasure_log_guards_cannot_be_disabled() {
    roleOwnsEverything();
    shadowPrivilegeFunctions();
    DataSource shadowed = shadowedPool();

    SchemaVerdict verdict;
    try {
      verdict = JdbcSupport.verifySchema(shadowed, false);
    } catch (ShreddingException refused) {
      return; // nothing was claimed
    }
    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
    assertThat(verdict.summary()).contains("owns none of the 9 objects");

    try (Connection c = shadowed.getConnection();
        Statement st = c.createStatement()) {
      st.execute(insertOneErasureRow());
      assertThatThrownBy(
              () -> {
                st.execute("ALTER TABLE public.shredding_erasure DISABLE TRIGGER ALL");
                st.executeUpdate("DELETE FROM public.shredding_erasure");
              })
          .describedAs(
              "verification returned '%s' and the same role then emptied the erasure log",
              verdict.summary())
          .isInstanceOf(SQLException.class);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  // ------------------------------------------------------------------ the shape legs

  /**
   * {@code pg_get_constraintdef} is the whole of the constraint leg: the check is deliberately on
   * the definition and not on the name, because "a UNIQUE moved to another column keeps its name".
   * The same is true of a CHECK relaxed in place. {@code CHECK ((id = 1))} is what keeps the anchor
   * a single row; replaced by {@code CHECK ((id >= 1))} the trail can carry a second head anchor,
   * and three lines of SQL make the leg report the original text.
   */
  @Test
  void probe_a_shadowed_pg_get_constraintdef_cannot_hide_a_weakened_anchor_check() {
    roleOwnsEverything();
    shadowPrivilegeFunctions();
    app(
        "ALTER TABLE public.shredding_erasure_anchor"
            + " DROP CONSTRAINT shredding_erasure_anchor_id_check",
        "ALTER TABLE public.shredding_erasure_anchor"
            + " ADD CONSTRAINT shredding_erasure_anchor_id_check CHECK (id >= 1)",
        "CREATE FUNCTION "
            + OWN
            + ".pg_get_constraintdef(oid) RETURNS text AS $$"
            + " SELECT CASE WHEN (SELECT conname FROM pg_catalog.pg_constraint WHERE oid = $1)"
            + "   = 'shredding_erasure_anchor_id_check' THEN 'CHECK ((id = 1))'"
            + "   ELSE pg_catalog.pg_get_constraintdef($1) END $$ LANGUAGE sql");
    DataSource shadowed = shadowedPool();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(shadowed, false))
        .describedAs("the anchor's single-row CHECK has been relaxed to id >= 1")
        .isInstanceOf(ShreddingException.class);
  }

  /**
   * {@code format_type} is the whole of the column-type leg. {@code character(64)} on {@code hash}
   * is what makes the chain's hash column fixed width and blank-padded; widened to {@code
   * varchar(100)} it accepts a 100-character hash and compares without padding. {@code format_type}
   * is called with the type oid and the type modifier only, so the lie has to be exact: no other
   * column of the four tables is {@code varchar(100)}, so one {@code CASE} on the pair reports
   * {@code character(64)} for this column and the truth for the other 43.
   */
  @Test
  void probe_a_shadowed_format_type_cannot_hide_a_widened_hash_column() {
    roleOwnsEverything();
    shadowPrivilegeFunctions();
    app(
        "ALTER TABLE public.shredding_erasure ALTER COLUMN hash TYPE varchar(100)",
        "CREATE FUNCTION "
            + OWN
            + ".format_type(oid, integer) RETURNS text AS $$"
            + " SELECT CASE WHEN $1 = 'character varying'::regtype AND $2 = 104"
            + "   THEN 'character(64)'"
            + "   ELSE pg_catalog.format_type($1, $2) END $$ LANGUAGE sql");
    DataSource shadowed = shadowedPool();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(shadowed, false))
        .describedAs("shredding_erasure.hash is character varying(100), not character(64)")
        .isInstanceOf(ShreddingException.class);
  }

  // ------------------------------------------------------------------ the adapters

  /**
   * Not the gate: {@link JdbcErasureStore}'s own blind-index read-back, the control that refuses an
   * erasure which left an HMAC of the erased plaintext behind. It is three {@code SELECT count(*)}
   * statements built in Java and run on the same connection, so the same role that can shadow a
   * catalogue function can shadow the aggregate and have every read-back answer zero. This test
   * runs the module's own statement text against a shadowed {@code count}.
   */
  @Test
  void probe_a_shadowed_count_cannot_hide_blind_index_residue_from_the_read_back() {
    app(
        "CREATE TABLE " + OWN + ".invoice (tenant varchar(255), subject varchar(255), bi bytea)",
        "INSERT INTO " + OWN + ".invoice VALUES ('t', 's', '\\x01')",
        "CREATE FUNCTION "
            + OWN
            + ".always_zero(bigint) RETURNS bigint AS $$"
            + " SELECT 0::bigint $$ LANGUAGE sql",
        "CREATE AGGREGATE "
            + OWN
            + ".count(*) (sfunc = "
            + OWN
            + ".always_zero, stype = bigint, initcond = '0')");
    DataSource shadowed = shadowedPool();

    // JdbcErasureStore, the "sameText" read-back, verbatim in shape.
    String readBack =
        "SELECT count(*) FROM "
            + OWN
            + ".invoice"
            + " WHERE tenant = ? AND subject = ? AND bi IS NOT NULL";
    try (Connection c = shadowed.getConnection();
        PreparedStatement ps = c.prepareStatement(readBack)) {
      ps.setString(1, "t");
      ps.setString(2, "s");
      try (ResultSet rs = ps.executeQuery()) {
        rs.next();
        assertThat(rs.getLong(1))
            .describedAs("one row still holds a blind index value for this subject")
            .isEqualTo(1L);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  // ------------------------------------------------------------------ the bundled script

  /**
   * The script's own catalogue reads. Its first guard refuses a database written before
   * keyed-from-birth, and resolves both oids through {@code to_regclass} - unqualified, inside a
   * {@code DO} block, which resolves functions against the session {@code search_path} like
   * anything else. Shadowed to return NULL, both oids are NULL, the {@code RAISE} cannot fire, and
   * the five trigger guards below it lose their {@code tgrelid} scoping in the same move. Reachable
   * on the {@code initialize-schema=true} path, where the runtime role runs the script itself.
   */
  @Test
  void probe_a_shadowed_to_regclass_cannot_silence_the_scripts_keyed_from_birth_preflight() {
    app(
        "CREATE TABLE public.shredding_erasure ("
            + " seq bigserial PRIMARY KEY, ts timestamptz NOT NULL)",
        "CREATE FUNCTION "
            + OWN
            + ".to_regclass(text) RETURNS regclass AS $$"
            + " SELECT NULL::regclass $$ LANGUAGE sql");
    DataSource shadowed = shadowedPool();

    assertThatThrownBy(() -> JdbcSupport.initializeSchema(shadowed))
        .describedAs("an erasure log with no key_id column must be refused by the pre-flight guard")
        .hasStackTraceContaining("predates keyed-from-birth");
  }

  // ------------------------------------------------------------------ control

  /**
   * The control. Same role, same ownership, same twelve legs, no shadowing: the gate refuses with
   * {@code 004}. Without this, a green run of the five probes above could be anything.
   */
  @Test
  void control_without_shadowing_the_same_state_is_refused_as_privileged() {
    roleOwnsEverything();
    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
  }

  /** The control's mirror: the honest hardened deployment still passes in this fixture. */
  @Test
  void control_the_hardened_two_role_deployment_still_verifies() {
    su(
        "DROP ROLE IF EXISTS probe_shadow_owner",
        "CREATE ROLE probe_shadow_owner LOGIN PASSWORD 'pw' NOSUPERUSER",
        "ALTER SCHEMA public OWNER TO probe_shadow_owner");
    HikariDataSource owner = pool("probe_shadow_owner", "pw");
    perTest.add(owner);
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
    assertThatCode(() -> JdbcSupport.verifySchema(appDs, false)).doesNotThrowAnyException();
  }

  // ------------------------------------------------------------------ fixture

  /**
   * The 004 state, reached with no privilege the no-DDL design refuses to grant: the role is given
   * CREATE on its schema for the length of one script run, applies the bundled script, and the
   * grant is taken back. It now owns the four tables, the two indexes, the sequence and the three
   * guard functions, and holds every privilege an owner holds.
   */
  private void roleOwnsEverything() {
    su("GRANT CREATE ON SCHEMA public TO " + APP);
    JdbcSupport.initializeSchema(appDs);
    su("REVOKE CREATE ON SCHEMA public FROM " + APP);
  }

  /**
   * The eight functions, in the role's own schema, that answer every §4.6 leg the way a hardened
   * deployment would. Nothing here needs a privilege the role does not hold on a normal deployment:
   * it owns the schema.
   */
  private void shadowPrivilegeFunctions() {
    app(
        // ownership: the four tables, the two indexes, the sequence, the three functions, the db
        "CREATE FUNCTION "
            + OWN
            + ".pg_has_role(name, oid, text) RETURNS boolean"
            + " AS $$ SELECT false $$ LANGUAGE sql",
        // is_superuser
        "CREATE FUNCTION "
            + OWN
            + ".current_setting(text) RETURNS text"
            + " AS $$ SELECT CASE WHEN $1 = 'is_superuser' THEN 'off'"
            + "   ELSE pg_catalog.current_setting($1) END $$ LANGUAGE sql",
        // USAGE yes, CREATE no
        "CREATE FUNCTION "
            + OWN
            + ".has_schema_privilege(name, text, text) RETURNS boolean"
            + " AS $$ SELECT $3 = 'USAGE' $$ LANGUAGE sql",
        // no TEMP, no CREATE on the database
        "CREATE FUNCTION "
            + OWN
            + ".has_database_privilege(name, text, text) RETURNS boolean"
            + " AS $$ SELECT false $$ LANGUAGE sql",
        // USAGE on the sequence, no SELECT, no UPDATE
        "CREATE FUNCTION "
            + OWN
            + ".has_sequence_privilege(name, oid, text) RETURNS boolean"
            + " AS $$ SELECT $3 = 'USAGE' $$ LANGUAGE sql",
        // exactly the documented per-table matrix of SchemaExpectations.PRIVILEGES
        "CREATE FUNCTION "
            + OWN
            + ".has_table_privilege(name, oid, text) RETURNS boolean AS $$"
            + " SELECT CASE (SELECT relname FROM pg_catalog.pg_class WHERE oid = $2)"
            + "   WHEN 'shredding_data_key' THEN $3 IN ('SELECT','INSERT','DELETE')"
            + "   WHEN 'shredding_erased_subject' THEN $3 IN ('SELECT','INSERT')"
            + "   WHEN 'shredding_erasure' THEN $3 IN ('SELECT','INSERT')"
            + "   WHEN 'shredding_erasure_anchor' THEN $3 IN ('SELECT','INSERT','UPDATE')"
            + "   ELSE false END $$ LANGUAGE sql",
        // exactly the one updatable column per table, and none on the erasure log
        "CREATE FUNCTION "
            + OWN
            + ".has_column_privilege(name, oid, smallint, text) RETURNS boolean AS $$"
            + " SELECT (SELECT c.relname || '.' || a.attname FROM pg_catalog.pg_class c"
            + "   JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid"
            + "   WHERE c.oid = $2 AND a.attnum = $3)"
            + " IN ('shredding_data_key.encryption_count',"
            + "     'shredding_erased_subject.erased_at') $$ LANGUAGE sql");
  }

  /**
   * The role sets its own default {@code search_path} with {@code pg_catalog} last and takes a new
   * pool, so the attack needs nothing that lives in the application's configuration: a connection
   * opened by any client, with any driver, carries it.
   */
  private HikariDataSource shadowedPool() {
    app("ALTER ROLE " + APP + " SET search_path = public, " + OWN + ", pg_catalog");
    HikariDataSource ds = pool(APP, "pw");
    perTest.add(ds);
    return ds;
  }

  private static String repeat(char c) {
    return "'" + String.valueOf(c).repeat(64) + "'";
  }

  private static String insertOneErasureRow() {
    return "INSERT INTO public.shredding_erasure (ts, tenant, subject_pseudonym, outcome,"
        + " backup_clear_at, chain_version, key_id, prev_hash, hash)"
        + " VALUES (now(), 'tenant', "
        + repeat('x')
        + ", 'COMPLETE', now(), 'v2', 'k', "
        + repeat('0')
        + ", "
        + repeat('1')
        + ")";
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

  private void app(String... sql) {
    exec(appDs, sql);
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
