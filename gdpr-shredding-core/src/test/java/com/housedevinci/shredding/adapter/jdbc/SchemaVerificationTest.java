package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Design §7 of {@code no-ddl-at-runtime-design.md}, version 2.1: one test per path, at the level
 * the path lives on. Everything here runs without Spring, against a real PostgreSQL pinned by the
 * same digest the rest of the module's tests pin, in the two-role posture the documentation
 * prescribes: the container role owns nothing this module uses, {@code shred_owner} applies the
 * script and owns the objects, and {@code shredding_app} holds exactly the grant block of
 * SECURITY-NOTES.md "Database roles".
 *
 * <p>Two of these tests are the ones the whole mechanism exists for. {@link
 * #t2_the_documented_two_role_posture_boots_and_erases} is the configuration that did not exist
 * before this change: 0.1.1 ran DDL from the application's own credentials unconditionally, so the
 * only role that could start the starter was the owner, and an owner can disable its own guards.
 * {@link #t40_a_shadow_in_a_schema_the_runtime_role_owns_does_not_receive_the_append} is the half
 * of the fix the second security pass added: refusing the privilege at boot is not the same as
 * making the statement land in the right table.
 */
@Testcontainers
class SchemaVerificationTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "shred_owner";
  private static final String APP = "shredding_app";

  /** The corrected grant block (C-12-2 to C-12-5). Kept here in the exact text the docs ship. */
  private static final List<String> GRANT_BLOCK =
      List.of(
          "GRANT USAGE ON SCHEMA public TO shredding_app",
          "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO shredding_app",
          "GRANT UPDATE (encryption_count) ON shredding_data_key TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erased_subject TO shredding_app",
          "GRANT UPDATE (erased_at) ON shredding_erased_subject TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erasure TO shredding_app",
          "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO shredding_app",
          "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO shredding_app");

  private static HikariDataSource superuserDs;
  private static HikariDataSource ownerDs;
  private static HikariDataSource appDs;

  @BeforeAll
  static void startContainer() {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword(), POSTGRES.getDatabaseName());
    su(
        "DROP ROLE IF EXISTS " + APP,
        "DROP ROLE IF EXISTS " + OWNER,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER");
    ownerDs = pool(OWNER, "pw", POSTGRES.getDatabaseName());
    appDs = pool(APP, "pw", POSTGRES.getDatabaseName());
  }

  @AfterAll
  static void stopContainer() {
    close(appDs);
    close(ownerDs);
    close(superuserDs);
    POSTGRES.stop();
  }

  private static void close(HikariDataSource ds) {
    if (ds != null) {
      ds.close();
    }
  }

  @BeforeEach
  void freshTwoRoleSchema() {
    su(
        "ALTER ROLE " + APP + " RESET search_path",
        "ALTER ROLE " + OWNER + " RESET search_path",
        "DROP SCHEMA IF EXISTS shadow CASCADE",
        "DROP SCHEMA IF EXISTS shred2 CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "GRANT SELECT ON pg_trigger TO PUBLIC",
        "GRANT SELECT ON pg_proc TO PUBLIC",
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    JdbcSupport.initializeSchema(ownerDs);
    owner(GRANT_BLOCK.toArray(String[]::new));
  }

  // ------------------------------------------------------------------ T1, T2

  @Test
  void t1_an_empty_schema_is_refused_and_nothing_is_created() {
    su(
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER);
    owner("GRANT USAGE ON SCHEMA public TO " + APP);
    long before = relationCount();

    assertThat(codeOf(() -> JdbcSupport.verifySchema(appDs))).isEqualTo(ErrorCodes.SCHEMA_ABSENT);
    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs))
        .hasMessageContaining("shredding.jdbc.initialize-schema")
        .hasMessageContaining("schema-postgresql.sql")
        .hasMessageContaining("docs/upgrading-0.2.0.md");

    assertThat(relationCount())
        .describedAs("verification must create nothing, on any path")
        .isEqualTo(before);
  }

  @Test
  void t2_the_documented_two_role_posture_boots_and_erases() {
    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);

    assertThat(verdict.schema().name()).isEqualTo("public");
    assertThat(verdict.role()).isEqualTo(APP);
    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
    assertThat(verdict.privilegeLegs()).isEmpty();
    assertThat(verdict.indexWarnings()).isEmpty();
    assertThat(verdict.summary())
        .contains("schema verified in schema public")
        .contains("4 tables, 32 columns, 6 constraints")
        .contains("7 triggers ENABLE ALWAYS")
        .contains("owns none of the 9 objects")
        .contains("qualified to schema public");

    // The round trip the 0.1.1 documentation promised and no role could actually perform.
    var store = store(verdict.schema());
    var keys =
        new JdbcKeyProvider(
            appDs,
            verdict.schema(),
            MasterKey.fromBytes(new byte[32]),
            RandomSource.secure(),
            Clock.systemUTC());
    keys.currentForWrite(TenantId.of("t1"), SubjectId.of("s1"));
    store.append(record("pseudonym-one"));

    assertThat(count("public.shredding_erasure")).isEqualTo(1);
    assertThat(count("public.shredding_erasure_anchor")).isEqualTo(1);
    assertThat(count("public.shredding_data_key")).isEqualTo(1);
  }

  // ------------------------------------------------------- T3-T6, T36, T39, T4

  @Test
  void t3_a_dropped_anchor_table_is_incomplete_and_names_only_that_table() {
    owner("DROP TABLE shredding_erasure_anchor CASCADE");
    long before = relationCount();
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_INCOMPLETE);
    assertThat(thrown).hasMessageContaining("table shredding_erasure_anchor does not exist");
    assertThat(thrown.getMessage()).doesNotContain("table shredding_erasure does not exist");
    assertThat(relationCount()).isEqualTo(before);
  }

  @Test
  void t4_an_erasure_table_without_its_bigserial_sequence_is_incomplete() {
    owner(
        "DROP TABLE shredding_erasure CASCADE",
        "CREATE TABLE shredding_erasure (seq bigint PRIMARY KEY, ts timestamptz NOT NULL,"
            + " tenant varchar(255) NOT NULL, subject_pseudonym char(64) NOT NULL,"
            + " requested_by varchar(1000) NOT NULL, reason varchar(1000) NOT NULL,"
            + " keys_destroyed integer NOT NULL, entity_count integer NOT NULL,"
            + " field_count integer NOT NULL, blind_index_cleared integer NOT NULL,"
            + " outcome varchar(16) NOT NULL, hook_outcomes text NOT NULL,"
            + " backup_clear_at timestamptz NOT NULL, chain_version varchar(8) NOT NULL,"
            + " key_id varchar(64) NOT NULL, prev_hash char(64) NOT NULL,"
            + " hash char(64) NOT NULL UNIQUE)");
    assertThat(refusal()).hasMessageContaining("shredding_erasure_seq_seq");
  }

  @Test
  void sequence_with_the_default_dropped_is_refused() {
    owner("ALTER TABLE shredding_erasure ALTER COLUMN seq DROP DEFAULT");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_INCOMPLETE);
    assertThat(thrown).hasMessageContaining("no default wired to shredding_erasure_seq_seq");
  }

  @Test
  void t5_a_dropped_hash_unique_constraint_is_incomplete() {
    owner("ALTER TABLE shredding_erasure DROP CONSTRAINT shredding_erasure_hash_key");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_INCOMPLETE);
    assertThat(thrown)
        .hasMessageContaining("shredding_erasure_hash_key")
        .hasMessageContaining("UNIQUE (hash)");
  }

  @Test
  void t5b_a_unique_constraint_moved_to_another_column_does_not_pass_on_the_name() {
    owner(
        "ALTER TABLE shredding_erasure DROP CONSTRAINT shredding_erasure_hash_key",
        "ALTER TABLE shredding_erasure ADD CONSTRAINT shredding_erasure_hash_key UNIQUE (prev_hash)");
    assertThat(refusal()).hasMessageContaining("UNIQUE (prev_hash), expected UNIQUE (hash)");
  }

  @Test
  void t6_a_guard_function_dropped_with_cascade_takes_its_triggers_and_is_refused() {
    owner("DROP FUNCTION shredding_erasure_append_only() CASCADE");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown)
        .hasMessageContaining("guard function shredding_erasure_append_only does not exist")
        .hasMessageContaining(
            "trigger shredding_erasure_append_only on shredding_erasure is missing")
        .hasMessageContaining("trigger shredding_erased_subject_no_truncate");
  }

  @Test
  void t36_a_missing_column_is_named() {
    owner("ALTER TABLE shredding_erasure DROP COLUMN hook_outcomes");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_INCOMPLETE);
    assertThat(thrown).hasMessageContaining("hook_outcomes");
  }

  @Test
  void t36b_the_pinned_constant_equals_what_the_bundled_script_creates() {
    // The test that keeps SchemaExpectations honest instead of a DDL parser at run time (§14.1).
    assertThat(actualColumns()).isEqualTo(SchemaExpectations.COLUMNS);
    assertThat(actualConstraints())
        .containsExactlyInAnyOrderElementsOf(SchemaExpectations.CONSTRAINTS);
    assertThat(actualTriggers()).containsExactlyInAnyOrderElementsOf(SchemaExpectations.TRIGGERS);
    assertThat(SchemaExpectations.COLUMN_COUNT).isEqualTo(32);
    // N7 of the name-resolution design: the proconfig expectation is a constant too, and the
    // script is the only supported producer of it.
    for (String guard : SchemaExpectations.GUARD_FUNCTIONS) {
      assertThat(actualProconfig(guard))
          .describedAs("pg_proc.proconfig of %s, as the bundled script creates it", guard)
          .isEqualTo(SchemaExpectations.GUARD_PROCONFIG);
    }
  }

  /**
   * N24 of the name-resolution design, measured as E6b. A {@code CHECK (id = 1)} created while an
   * {@code =(smallint, integer)} of the role's own is on the applying session's path <b>binds the
   * shadow</b>: the constraint then accepts {@code id = 2}, so the anchor can hold a second head
   * row. The constraint-definition leg catches it, and it catches it <em>because</em> of the
   * verification pin: read with {@code search_path} pinned, {@code pg_get_constraintdef} renders
   * the shadowed operator with its schema, and read on the role's own path both render {@code CHECK
   * ((id = 1))} and the leg is blind. This is the pin covering a path nothing else does.
   */
  @Test
  void t36d_an_anchor_check_bound_to_a_shadowed_operator_is_refused_and_quoted() {
    owner(
        "CREATE FUNCTION public.yes(pg_catalog.int2, pg_catalog.int4) RETURNS boolean"
            + " AS $$ SELECT true $$ LANGUAGE sql",
        "CREATE OPERATOR public.= (LEFTARG = pg_catalog.int2,"
            + " RIGHTARG = pg_catalog.int4, FUNCTION = public.yes)",
        "ALTER TABLE shredding_erasure_anchor DROP CONSTRAINT shredding_erasure_anchor_id_check",
        "ALTER TABLE shredding_erasure_anchor ADD CONSTRAINT shredding_erasure_anchor_id_check"
            + " CHECK (id OPERATOR(public.=) 1)");

    // The constraint now accepts a second head row, which is the C-13-10 outcome reached at
    // creation time instead of at verification time.
    assertThatCode(
            () ->
                exec(
                    ownerDs,
                    "INSERT INTO shredding_erasure_anchor"
                        + " VALUES (2, "
                        + "'"
                        + "b".repeat(64)
                        + "'"
                        + ", 1,"
                        + " pg_catalog.now(), true)"))
        .describedAs("the shadow is bound into the constraint, so it is not a check any more")
        .doesNotThrowAnyException();

    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_INCOMPLETE);
    assertThat(thrown)
        .hasMessageContaining("shredding_erasure_anchor_id_check")
        .hasMessageContaining("OPERATOR(public.=)");
  }

  /**
   * N3 and N4 of the name-resolution design: the leg accepts exactly one array, so a hostile value,
   * an extra setting and a spelling that means the same thing to the server but stores different
   * bytes are all refused. The last one is a documented fail-closed false refusal: the bundled
   * script is the one supported producer of the clause.
   */
  @Test
  void t36c_the_proconfig_leg_accepts_exactly_the_one_array_the_script_creates() {
    owner(
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()"
            + " SET search_path = app_decoy, pg_catalog, pg_temp");
    var hostile = refusal();
    assertThat(hostile.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(hostile)
        .hasMessageContaining("shredding_erasure_anchor_monotonic")
        .hasMessageContaining("pg_proc.proconfig is [search_path=app_decoy, pg_catalog, pg_temp]");

    owner(
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()"
            + " SET search_path = pg_catalog, pg_temp",
        "ALTER FUNCTION shredding_erasure_anchor_monotonic() SET statement_timeout = '1s'");
    assertThat(refusal())
        .describedAs("a second setting makes the array two elements long")
        .hasMessageContaining("statement_timeout=1s");

    owner(
        "ALTER FUNCTION shredding_erasure_anchor_monotonic() RESET statement_timeout",
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()"
            + " SET search_path TO 'pg_catalog, pg_temp'");
    assertThat(refusal())
        .describedAs(
            "the same meaning, different stored bytes: refused, and the message names the script"
                + " as the one supported producer")
        .hasMessageContaining("search_path=\"pg_catalog, pg_temp\"")
        .hasMessageContaining("Re-apply the bundled schema-postgresql.sql as the owner role");

    owner(
        "ALTER FUNCTION shredding_erasure_anchor_monotonic()"
            + " SET search_path = pg_catalog,pg_temp");
    assertThatCode(() -> JdbcSupport.verifySchema(appDs))
        .describedAs("a spelling that stores the identical text is accepted")
        .doesNotThrowAnyException();
  }

  @Test
  void t39_an_unlogged_or_view_substitution_for_the_erasure_log_is_refused() {
    owner("ALTER TABLE shredding_erasure SET UNLOGGED");
    assertThat(refusal()).hasMessageContaining("shredding_erasure is not a permanent table");

    owner(
        "ALTER TABLE shredding_erasure SET LOGGED",
        "ALTER TABLE shredding_erasure RENAME TO shredding_erasure_real",
        "CREATE VIEW shredding_erasure AS SELECT * FROM shredding_erasure_real");
    assertThat(refusal()).hasMessageContaining("shredding_erasure is not an ordinary table");
  }

  // ------------------------------------------------------------- T7-T9, T37, T28

  @Test
  void t7_a_disabled_trigger_is_unguarded_with_the_remedy_in_the_message() {
    owner("ALTER TABLE shredding_erasure DISABLE TRIGGER shredding_erasure_append_only");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown)
        .hasMessageContaining("shredding_erasure_append_only")
        .hasMessageContaining("tgenabled='D'")
        .hasMessageContaining("DISABLE TRIGGER")
        .hasMessageContaining("ENABLE ALWAYS TRIGGER");
  }

  @Test
  void t8_a_replica_only_trigger_is_unguarded() {
    owner("ALTER TABLE shredding_erasure ENABLE REPLICA TRIGGER shredding_erasure_append_only");
    assertThat(refusal()).hasMessageContaining("tgenabled='R'");
  }

  @Test
  void t37_a_trigger_at_origin_is_unguarded_and_the_script_repairs_it() {
    owner("ALTER TABLE shredding_erasure ENABLE TRIGGER shredding_erasure_append_only");
    assertThat(refusal()).hasMessageContaining("tgenabled='O'");

    // The remedy the message gives is the remedy that works (D-10): re-applying is a repair now.
    JdbcSupport.initializeSchema(ownerDs);
    assertThatCode(() -> JdbcSupport.verifySchema(appDs)).doesNotThrowAnyException();
  }

  @Test
  void t9_a_trigger_repointed_at_a_same_shaped_no_op_is_unguarded() {
    owner(
        "CREATE FUNCTION shredding_noop() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$"
            + " LANGUAGE plpgsql",
        "DROP TRIGGER shredding_erasure_append_only ON shredding_erasure",
        "CREATE TRIGGER shredding_erasure_append_only BEFORE UPDATE OR DELETE ON shredding_erasure"
            + " FOR EACH ROW EXECUTE FUNCTION shredding_noop()",
        "ALTER TABLE shredding_erasure ENABLE ALWAYS TRIGGER shredding_erasure_append_only");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown)
        .hasMessageContaining("calls shredding_noop, expected shredding_erasure_append_only");
  }

  @Test
  void t28_an_eighth_trigger_and_a_user_constraint_trigger_are_both_refused() {
    owner(
        "CREATE FUNCTION zz_quiet() RETURNS trigger AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE plpgsql",
        "CREATE TRIGGER zz_quiet BEFORE INSERT ON shredding_erasure FOR EACH ROW"
            + " EXECUTE FUNCTION zz_quiet()");
    assertThat(refusal()).hasMessageContaining("unexpected trigger zz_quiet on shredding_erasure");

    owner(
        "DROP TRIGGER zz_quiet ON shredding_erasure",
        "CREATE CONSTRAINT TRIGGER zz_constraint AFTER INSERT ON shredding_erasure"
            + " FOR EACH ROW EXECUTE FUNCTION zz_quiet()");
    var constraintTrigger = refusal();
    assertThat(constraintTrigger.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(constraintTrigger).hasMessageContaining("unexpected trigger zz_constraint");
  }

  @Test
  void a_foreign_key_onto_the_erasure_log_adds_only_internal_triggers_and_is_not_refused() {
    // The negative control for T28: tgisinternal is deliberately outside the checked set.
    owner("CREATE TABLE fk_holder (seq bigint REFERENCES shredding_erasure (seq))");
    assertThat(codeOf(() -> JdbcSupport.verifySchema(appDs))).isNull();
  }

  // ------------------------------------------------------------- T22, T22b, T23

  @Test
  void t22_a_replaced_guard_body_with_the_same_oid_is_refused_without_quoting_the_body() {
    long oidBefore = functionOid("shredding_erasure_append_only");
    owner(
        "CREATE OR REPLACE FUNCTION shredding_erasure_append_only() RETURNS trigger AS $$"
            + " BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql"
            + " SET search_path = pg_catalog, pg_temp");
    assertThat(functionOid("shredding_erasure_append_only"))
        .describedAs("CREATE OR REPLACE keeps the oid; that is why identity checks are not enough")
        .isEqualTo(oidBefore);

    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown)
        .hasMessageContaining("guard function shredding_erasure_append_only does not have the body")
        .hasMessageContaining("characters, md5");
    assertThat(thrown.getMessage())
        .describedAs("the message must never quote a body, expected or actual")
        .doesNotContain("RETURN NEW")
        .doesNotContain("RAISE EXCEPTION");
  }

  @Test
  void t22b_a_lone_carriage_return_in_a_guard_body_is_refused_and_crlf_still_passes() {
    String bundled = GuardBodies.fromBundledScript().get("shredding_erasure_anchor_monotonic");

    // Three shapes a lone CR can take, each invisible to "drop every \r" normalisation and visible
    // to PostgreSQL's lexer, which ends a -- comment at CR as well as at LF.
    List<String> refusedVariants =
        List.of(
            bundled.replaceFirst("\n", "\r"),
            bundled.replace("-- `keyed` is checked first", "-- `keyed` is checked first\r"),
            bundled.replace("\n  IF (NEW.row_count", "\r  IF (NEW.row_count"));
    for (String variant : refusedVariants) {
      installMonotonic(variant);
      assertThat(refusal())
          .describedAs("variant with a lone CR must be refused, not normalised away")
          .hasMessageContaining("shredding_erasure_anchor_monotonic")
          .hasMessageContaining("carriage return");
    }

    // Three shapes a CRLF checkout produces, all of which mean exactly the bundled body.
    List<String> acceptedVariants =
        List.of(
            bundled.replace("\n", "\r\n"),
            "\r\n" + bundled.replace("\n", "\r\n") + "\r\n",
            bundled.replaceFirst("\n", "\r\n"));
    for (String variant : acceptedVariants) {
      installMonotonic(variant);
      assertThatCode(() -> JdbcSupport.verifySchema(appDs))
          .describedAs("a body applied from a CRLF checkout is the same body")
          .doesNotThrowAnyException();
    }
  }

  @Test
  void t23_the_expectation_follows_the_resource_and_is_never_a_hard_coded_digest() {
    var fromScript = GuardBodies.extract(JdbcSupport.schemaScript());
    assertThat(GuardBodies.fromBundledScript()).isEqualTo(fromScript);

    String edited =
        JdbcSupport.schemaScript()
            .replace("shredding_erasure_anchor only advances by one row", "edited for this test");
    assertThat(GuardBodies.extract(edited).get("shredding_erasure_anchor_monotonic"))
        .contains("edited for this test");
    assertThat(GuardBodies.extract(edited)).isNotEqualTo(fromScript);
  }

  @Test
  void t23b_a_resource_that_does_not_yield_the_three_guard_functions_is_unverifiable() {
    String truncated =
        JdbcSupport.schemaScript()
            .replace(
                "CREATE OR REPLACE FUNCTION shredding_erasure_anchor_append_only()",
                "CREATE OR REPLACE FUNCTION shredding_something_else()");
    assertThatThrownBy(() -> GuardBodies.extract(truncated))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("shredding_something_else")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
  }

  // ------------------------------------------------------------------ T27, T29

  @Test
  void t27_row_level_security_and_an_armed_policy_are_both_refused() {
    owner("ALTER TABLE shredding_erased_subject ENABLE ROW LEVEL SECURITY");
    assertThat(refusal())
        .hasMessageContaining("shredding_erased_subject has row-level security enabled");

    owner(
        "ALTER TABLE shredding_erased_subject DISABLE ROW LEVEL SECURITY",
        "CREATE POLICY hide_everything ON shredding_erased_subject USING (false)");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown)
        .describedAs("a policy sits armed with relrowsecurity=false; the two booleans miss it")
        .hasMessageContaining("row-level-security policy");
  }

  @Test
  void t29_a_do_instead_rule_on_any_of_the_four_tables_is_refused() {
    owner("CREATE RULE swallow AS ON DELETE TO shredding_data_key DO INSTEAD NOTHING");
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
    assertThat(thrown).hasMessageContaining("shredding_data_key carries a rewrite rule");
  }

  // ---------------------------------------------------- T10-T12, T24-T26, T31-T32

  @Test
  void t10_the_owner_itself_is_a_privileged_runtime_role() {
    var thrown = refusalAs(ownerDs);
    assertThat(thrown.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(thrown)
        .hasMessageContaining("owns table shredding_erasure")
        .hasMessageContaining("owns guard function shredding_erasure_append_only")
        .hasMessageContaining("has_table_privilege")
        .hasMessageContaining("docs/upgrading-0.2.0.md");
  }

  @Test
  void t11_a_noinherit_member_of_the_owner_is_privileged() {
    // The shape a careful DBA creates, and the shape version 1's pg_has_role(..,'USAGE') passed:
    // USAGE answers "without SET ROLE", which is false here, while the role can still SET ROLE and
    // disable every trigger.
    // PostgreSQL 16 fixes a grant's INHERIT at GRANT time, so the role property and the grant
    // option are set together here; the shape being modelled is the one a careful DBA creates, a
    // member that must SET ROLE deliberately rather than carry the owner's rights by default.
    su("ALTER ROLE " + APP + " NOINHERIT");
    su("GRANT " + OWNER + " TO " + APP + " WITH INHERIT FALSE");
    try {
      assertThat(usageMode()).describedAs("USAGE mode, version 1's predicate").isFalse();
      assertThat(refusal().code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(refusal()).hasMessageContaining("owns table shredding_erasure");
    } finally {
      su("ALTER ROLE " + APP + " INHERIT", "REVOKE " + OWNER + " FROM " + APP);
    }
  }

  @Test
  void t11b_an_inherit_member_of_the_owner_is_privileged() {
    su("GRANT " + OWNER + " TO " + APP);
    try {
      assertThat(usageMode()).isTrue();
      assertThat(refusal().code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    } finally {
      su("REVOKE " + OWNER + " FROM " + APP);
    }
  }

  @Test
  void t12_a_superuser_runtime_role_is_privileged_even_when_it_is_a_member_of_nothing() {
    su("ALTER ROLE " + APP + " SUPERUSER");
    try {
      assertThat(refusal()).hasMessageContaining("is a superuser");
    } finally {
      su("ALTER ROLE " + APP + " NOSUPERUSER");
    }
  }

  @Test
  void t24_owning_only_a_guard_function_is_enough_to_be_privileged() {
    // D-3: ALTER TABLE ... OWNER TO does not move the functions, so this is the state of every
    // 0.1.x install after a naive ownership transfer - and it is enough to CREATE OR REPLACE all
    // four append-only guards into no-ops.
    su("ALTER FUNCTION shredding_erasure_append_only() OWNER TO " + APP);
    try {
      var thrown = refusal();
      assertThat(thrown.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(thrown).hasMessageContaining("owns guard function shredding_erasure_append_only");
    } finally {
      su("ALTER FUNCTION shredding_erasure_append_only() OWNER TO " + OWNER);
    }
  }

  @Test
  void t25_create_on_the_schema_is_privileged() {
    owner("GRANT CREATE ON SCHEMA public TO " + APP);
    assertThat(refusal()).hasMessageContaining("holds CREATE on schema public");
  }

  @Test
  void t26_owning_the_erasure_table_names_its_sequence_and_its_indexes_as_well() {
    // PostgreSQL refuses ALTER SEQUENCE ... OWNER TO on an owned sequence and ties an index's
    // owner to its table's, so these three legs cannot be armed separately: ownership of the table
    // carries them. What matters is that each is measured and named, because an operator who
    // transfers the tables and stops there leaves the three functions behind (T24).
    su("ALTER TABLE shredding_erasure OWNER TO " + APP);
    try {
      var thrown = refusal();
      assertThat(thrown.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(thrown)
          .hasMessageContaining("owns table shredding_erasure")
          .hasMessageContaining("owns index shredding_erasure_subject")
          .hasMessageContaining("owns sequence shredding_erasure_seq_seq");
    } finally {
      su("ALTER TABLE shredding_erasure OWNER TO " + OWNER);
    }
  }

  @Test
  void t31_trigger_on_the_erasure_log_is_privileged() {
    owner("GRANT TRIGGER ON shredding_erasure TO " + APP);
    assertThat(refusal()).hasMessageContaining("holds TRIGGER on shredding_erasure");
  }

  @Test
  void t32_table_wide_update_on_the_log_is_refused_and_the_one_column_grant_is_not() {
    owner("GRANT UPDATE ON shredding_erasure TO " + APP);
    var thrown = refusal();
    assertThat(thrown).hasMessageContaining("holds UPDATE on shredding_erasure");
    assertThat(thrown).hasMessageContaining("holds UPDATE on shredding_erasure.hash");

    owner("REVOKE UPDATE ON shredding_erasure FROM " + APP);
    assertThatCode(() -> JdbcSupport.verifySchema(appDs))
        .describedAs("UPDATE (erased_at) on the tombstone is the legitimate column grant")
        .doesNotThrowAnyException();
  }

  @Test
  void t32b_a_missing_required_privilege_is_007_and_the_property_does_not_suppress_it() {
    owner("REVOKE USAGE ON SEQUENCE shredding_erasure_seq_seq FROM " + APP);
    var thrown = refusal();
    assertThat(thrown.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_UNDERPRIVILEGED);
    assertThat(thrown).hasMessageContaining("USAGE on sequence shredding_erasure_seq_seq");

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, true))
        .describedAs("allow-privileged-runtime-role never downgrades 007")
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.RUNTIME_ROLE_UNDERPRIVILEGED);
  }

  @Test
  void a_privilege_held_through_public_is_visible_to_the_check() {
    // C-D2-3: has_table_privilege accounts for PUBLIC and for group roles, which is why the
    // messages say so - an operator who greps the grant scripts finds nothing.
    owner("GRANT DELETE ON shredding_erased_subject TO PUBLIC");
    try {
      assertThat(refusal()).hasMessageContaining("holds DELETE on shredding_erased_subject");
    } finally {
      owner("REVOKE DELETE ON shredding_erased_subject FROM PUBLIC");
    }
  }

  @Test
  void t13_allow_privileged_runtime_role_returns_the_legs_instead_of_throwing() {
    SchemaVerdict verdict = JdbcSupport.verifySchema(ownerDs, true);
    assertThat(verdict.runtimeRoleIsUnprivileged()).isFalse();
    assertThat(verdict.privilegeLegs()).contains("owns table shredding_erasure");
    assertThat(verdict.summary())
        .describedAs("the success line drops the role clause it did not earn (C-D2-4)")
        .doesNotContain("owns none of the 9 objects");
  }

  // ------------------------------------------------------------------ T38, T43, T44

  @Test
  void t38_temporary_on_the_database_is_privileged_and_revoking_it_keeps_the_round_trip() {
    su("GRANT TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    try {
      assertThat(refusal())
          .hasMessageContaining("holds TEMPORARY on database " + POSTGRES.getDatabaseName());
    } finally {
      su("REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP);
    }

    // The negative control: without the privilege the full round trip still works.
    assertThat(codeOf(() -> app("CREATE TEMP TABLE t (i int)")))
        .describedAs("CREATE TEMP TABLE is refused once TEMPORARY is revoked")
        .isNotNull();
    var verdict = JdbcSupport.verifySchema(appDs);
    store(verdict.schema()).append(record("after-revoke"));
    assertThat(count("public.shredding_erasure")).isEqualTo(1);
  }

  @Test
  void t43_create_on_the_database_is_privileged() {
    su("GRANT CREATE ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    try {
      assertThat(refusal())
          .describedAs("CREATE on a database is CREATE SCHEMA, which is the whole shadow primitive")
          .hasMessageContaining("holds CREATE on database " + POSTGRES.getDatabaseName());
    } finally {
      su("REVOKE CREATE ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP);
    }
  }

  @Test
  void t44_a_runtime_role_that_owns_the_database_is_privileged_and_qualification_still_holds() {
    su("DROP DATABASE IF EXISTS appowned", "CREATE DATABASE appowned OWNER " + APP);
    try (HikariDataSource ownerInAppOwned = pool(OWNER, "pw", "appowned");
        HikariDataSource appInAppOwned = pool(APP, "pw", "appowned");
        HikariDataSource suInAppOwned =
            pool(POSTGRES.getUsername(), POSTGRES.getPassword(), "appowned")) {
      exec(suInAppOwned, "ALTER SCHEMA public OWNER TO " + OWNER);
      JdbcSupport.initializeSchema(ownerInAppOwned);
      exec(ownerInAppOwned, GRANT_BLOCK.toArray(String[]::new));
      exec(suInAppOwned, "REVOKE TEMPORARY ON DATABASE appowned FROM PUBLIC, " + APP);

      var thrown =
          (ShreddingException)
              org.assertj.core.api.Assertions.catchThrowable(
                  () -> JdbcSupport.verifySchema(appInAppOwned));
      assertThat(thrown.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
      assertThat(thrown).hasMessageContaining("owner of database appowned");

      // The durability half of C-D2-1/S6: a database owner re-grants itself TEMPORARY after boot,
      // and the REVOKE the upgrade steps prescribe does not bind it. Qualification is what makes
      // that privilege buy nothing.
      SchemaVerdict verdict = JdbcSupport.verifySchema(appInAppOwned, true);
      exec(appInAppOwned, "GRANT TEMPORARY ON DATABASE appowned TO " + APP);
      try (Connection pinned = appInAppOwned.getConnection()) {
        exec(
            pinned,
            "CREATE TEMP TABLE shredding_erasure (LIKE public.shredding_erasure INCLUDING ALL)");
        new JdbcErasureStore(
                pinnedDataSource(pinned),
                verdict.schema(),
                ErasureChain.unkeyed(),
                List.of(),
                (c, column, tenant, subject) -> 0L)
            .append(record("db-owner"));
        assertThat(scalar(pinned, "SELECT count(*) FROM pg_temp.shredding_erasure")).isZero();
        assertThat(scalar(pinned, "SELECT count(*) FROM public.shredding_erasure")).isEqualTo(1);
      } catch (SQLException e) {
        throw new IllegalStateException(e);
      }
    } finally {
      su("DROP DATABASE IF EXISTS appowned WITH (FORCE)");
    }
  }

  // ------------------------------------------------------------- T16, T40, T41, T42

  @Test
  void t16_verification_answers_about_current_schema_only_in_both_directions() {
    su("CREATE SCHEMA shred2 AUTHORIZATION " + OWNER);
    exec(ownerDs, "GRANT USAGE, CREATE ON SCHEMA shred2 TO " + OWNER);
    exec(
        ownerDs,
        "CREATE TABLE shred2.shredding_erasure (LIKE public.shredding_erasure INCLUDING ALL)",
        "GRANT USAGE ON SCHEMA shred2 TO " + APP);

    // Pointed at the unguarded copy, the guarded one in public does not rescue it.
    su("ALTER ROLE " + APP + " SET search_path = shred2, public");
    var thrown = refusal();
    assertThat(thrown).hasMessageContaining("in shred2");
    assertThat(thrown.code()).isIn(ErrorCodes.SCHEMA_INCOMPLETE, ErrorCodes.SCHEMA_UNGUARDED);

    // And pointed back at public it answers about public, with shred2 still there.
    su("ALTER ROLE " + APP + " SET search_path = public, shred2");
    assertThat(JdbcSupport.verifySchema(appDs).schema().name()).isEqualTo("public");
  }

  @Test
  void t40_a_shadow_in_a_schema_the_runtime_role_owns_does_not_receive_the_append() {
    // Reviewer's S3, reproduced and then closed. Verification runs clean first - the role owns
    // none of the nine objects and holds no CREATE anywhere the check looks - and only afterwards
    // does the session's search_path change, which no privilege is needed for.
    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "CREATE TABLE shadow.shredding_erasure (LIKE public.shredding_erasure INCLUDING ALL)",
        "CREATE TABLE shadow.shredding_erasure_anchor"
            + " (LIKE public.shredding_erasure_anchor INCLUDING ALL)");
    su("ALTER ROLE " + APP + " SET search_path = shadow, public");

    store(verdict.schema()).append(record("shadowed"));

    assertThat(count("shadow.shredding_erasure"))
        .describedAs("the shadow must stay empty: the statement names the verified relation")
        .isZero();
    assertThat(count("public.shredding_erasure")).isEqualTo(1);
    assertThat(count("public.shredding_erasure_anchor")).isEqualTo(1);
  }

  @Test
  void t41_a_pg_temp_shadow_on_the_adapter_s_own_connection_does_not_receive_the_append() {
    // Reviewer's S7 / the builder's N-1: no owner involved, no DDL on the verified schema, and
    // every privilege leg of the design answered clean before the TEMPORARY leg existed.
    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
    su("GRANT TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    try (Connection pinned = appDs.getConnection()) {
      exec(
          pinned,
          "CREATE TEMP TABLE shredding_erasure (LIKE public.shredding_erasure INCLUDING ALL)");
      assertThat(scalar(pinned, "SELECT (current_schema() = 'public')::int"))
          .describedAs("current_schema() still answers public while the temp copy shadows it")
          .isEqualTo(1);

      new JdbcErasureStore(
              pinnedDataSource(pinned),
              verdict.schema(),
              ErasureChain.unkeyed(),
              List.of(),
              (c, column, tenant, subject) -> 0L)
          .append(record("temp-shadowed"));

      assertThat(scalar(pinned, "SELECT count(*) FROM pg_temp.shredding_erasure")).isZero();
      assertThat(scalar(pinned, "SELECT count(*) FROM public.shredding_erasure")).isEqualTo(1);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    } finally {
      su("REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP);
    }
  }

  @Test
  void t42_a_search_path_change_between_two_adapter_calls_moves_nothing() {
    // search_path is a property of the session at the instant a statement parses, not of the pool.
    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "CREATE TABLE shadow.shredding_erasure (LIKE public.shredding_erasure INCLUDING ALL)",
        "CREATE TABLE shadow.shredding_erasure_anchor"
            + " (LIKE public.shredding_erasure_anchor INCLUDING ALL)");

    try (Connection pinned = appDs.getConnection()) {
      var store =
          new JdbcErasureStore(
              pinnedDataSource(pinned),
              verdict.schema(),
              ErasureChain.unkeyed(),
              List.of(),
              (c, column, tenant, subject) -> 0L);
      store.append(record("before-the-set"));
      exec(pinned, "SET search_path = shadow, public");
      store.append(record("after-the-set"));

      assertThat(scalar(pinned, "SELECT count(*) FROM shadow.shredding_erasure")).isZero();
      assertThat(scalar(pinned, "SELECT count(*) FROM public.shredding_erasure")).isEqualTo(2);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  // ------------------------------------------------------------------ T17, T17b

  @Test
  void t17_a_refused_catalogue_read_is_unverifiable_and_never_a_warning() {
    su("REVOKE SELECT ON pg_trigger FROM PUBLIC");
    try {
      var thrown = refusal();
      assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(thrown).hasMessageContaining("pg_trigger").hasMessageContaining("migration");
      assertThat(thrown.getMessage())
          .describedAs("the driver's message can carry a bind value; only the SQLState is kept")
          .doesNotContain("permission denied");
    } finally {
      su("GRANT SELECT ON pg_trigger TO PUBLIC");
    }
  }

  @Test
  void t17b_pg_proc_is_its_own_catalogue_dependency_and_its_refusal_is_005_too() {
    su("REVOKE SELECT ON pg_proc FROM PUBLIC");
    try {
      assertThat(refusal().code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    } finally {
      su("GRANT SELECT ON pg_proc TO PUBLIC");
    }
  }

  // ------------------------------------------------------------------ T15, T30

  @Test
  void t15_creation_mode_as_a_non_owner_is_006_and_never_a_raw_permission_denied() {
    su(
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER);
    owner("GRANT USAGE ON SCHEMA public TO " + APP);

    var thrown =
        (ShreddingException)
            org.assertj.core.api.Assertions.catchThrowable(
                () -> JdbcSupport.initializeAndVerifySchema(appDs, true));
    assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_CREATION_FAILED);
    assertThat(thrown)
        .hasMessageContaining("shredding.jdbc.initialize-schema=true")
        .hasMessageContaining("docs/upgrading-0.2.0.md");
    assertThat(thrown.getMessage()).doesNotContain("permission denied for schema");
  }

  @Test
  void t14_creation_mode_as_the_owner_creates_verifies_and_is_idempotent() {
    su(
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER);

    SchemaVerdict first = JdbcSupport.initializeAndVerifySchema(ownerDs, true);
    assertThat(first.runtimeRoleIsUnprivileged()).isFalse();
    SchemaVerdict second = JdbcSupport.initializeAndVerifySchema(ownerDs, true);
    assertThat(second.schema()).isEqualTo(first.schema());
    assertThat(triggerStates()).containsOnly("A");
  }

  @Test
  void t30_the_upgrade_steps_executed_in_order_leave_a_schema_that_boots_clean() {
    // A 0.1.x-shaped install: the application role applied the schema itself and therefore owns
    // everything, and someone disabled a trigger along the way.
    su("DROP SCHEMA public CASCADE", "CREATE SCHEMA public", "ALTER SCHEMA public OWNER TO " + APP);
    JdbcSupport.initializeSchema(appDs);
    app("ALTER TABLE shredding_erasure DISABLE TRIGGER shredding_erasure_append_only");

    // Step 2: seven explicit statements. The three functions do not move with the tables (D-3).
    su(
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "ALTER TABLE shredding_data_key OWNER TO " + OWNER,
        "ALTER TABLE shredding_erased_subject OWNER TO " + OWNER,
        "ALTER TABLE shredding_erasure OWNER TO " + OWNER,
        "ALTER TABLE shredding_erasure_anchor OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_append_only() OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_monotonic() OWNER TO " + OWNER,
        "ALTER FUNCTION shredding_erasure_anchor_append_only() OWNER TO " + OWNER);
    // Step 4: take DDL and shadowing privileges away. Step 5: the runtime role's grant block.
    su(
        "REVOKE CREATE ON SCHEMA public FROM " + APP,
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP + ", PUBLIC",
        "REVOKE CREATE ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP + ", PUBLIC");
    owner(GRANT_BLOCK.toArray(String[]::new));

    assertThat(codeOf(() -> JdbcSupport.verifySchema(appDs)))
        .describedAs("step 3 skipped: the disabled trigger is still disabled, and that is 003")
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);

    // Step 3, the one that was skipped.
    JdbcSupport.initializeSchema(ownerDs);

    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
    assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
    store(verdict.schema()).append(record("after-upgrade"));
    assertThat(count("public.shredding_erasure")).isEqualTo(1);
  }

  // ----------------------------------------------- T50 to T57: verification's own names (§4.9)

  /**
   * C-13-9, promoted from the review's probe. The role owns the four tables, the two indexes, the
   * sequence and the three guard functions - the exact state {@code SHRED-SCHEMA-004} exists to
   * refuse - and then answers every one of §4.6's legs itself: a function name resolves along
   * {@code search_path} exactly as a relation name does, any role may {@code ALTER ROLE <itself>
   * SET search_path} (no privilege, nothing to revoke), and an application role that owns its own
   * business schema may define functions in it. Before the fix this booted clean and the §4.8 INFO
   * line said "the role owns none of the 9 objects".
   */
  @Test
  void t50_a_role_that_shadows_the_privilege_functions_is_still_refused_as_privileged() {
    appOwnsEverything();
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(honestLookingShadow("shadow"));
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    assertThat(codeOf(() -> JdbcSupport.verifySchema(appDs)))
        .describedAs("004's subject must not be 004's witness")
        .isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
  }

  /**
   * The same primitive, used the other way round: on the documented two-role posture the role
   * shadows every catalogue call with one that answers <em>dangerously</em> - it owns everything,
   * it is a superuser, every privilege is held, every type and every constraint definition is
   * wrong. A clean verdict here is the proof that none of the twelve legs reads an answer the
   * verified role wrote. Without it, a role could also force a false refusal and keep an
   * application down.
   */
  @Test
  void t51_a_shadow_cannot_force_a_false_refusal_on_the_honest_posture() {
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(alarmingShadow("shadow"));
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    assertThatCode(() -> JdbcSupport.verifySchema(appDs)).doesNotThrowAnyException();
  }

  /**
   * C-13-10, first half. The constraint leg is deliberately on the definition and never on the
   * name, because "a UNIQUE moved to another column keeps its name" - and {@code
   * pg_get_constraintdef} is the whole of that leg. {@code CHECK ((id = 1))} is what keeps the
   * anchor a single row; relaxed in place to {@code CHECK ((id >= 1))} the trail can carry a second
   * head.
   */
  @Test
  void t52_a_shadowed_pg_get_constraintdef_cannot_hide_a_relaxed_anchor_check() {
    appOwnsEverything();
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "ALTER TABLE public.shredding_erasure_anchor"
            + " DROP CONSTRAINT shredding_erasure_anchor_id_check",
        "ALTER TABLE public.shredding_erasure_anchor"
            + " ADD CONSTRAINT shredding_erasure_anchor_id_check CHECK (id >= 1)",
        "CREATE FUNCTION shadow.pg_get_constraintdef(oid) RETURNS text AS $$"
            + " SELECT CASE WHEN (SELECT conname FROM pg_catalog.pg_constraint WHERE oid = $1)"
            + "   = 'shredding_erasure_anchor_id_check' THEN 'CHECK ((id = 1))'"
            + "   ELSE pg_catalog.pg_get_constraintdef($1) END $$ LANGUAGE sql");
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    assertThat(refusal().getMessage()).contains("shredding_erasure_anchor_id_check");
  }

  /**
   * C-13-10, second half. {@code format_type} is the whole of the column-type leg. {@code
   * character(64)} is what makes the chain's hash column fixed width and blank-padded; widened to
   * {@code varchar(100)} it accepts a longer hash and compares without padding. The shadow receives
   * only the type oid and the modifier, so the lie has to be exact - no other column of the four
   * tables is {@code varchar(100)} - and one {@code CASE} on that pair is exact.
   */
  @Test
  void t53_a_shadowed_format_type_cannot_hide_a_widened_hash_column() {
    appOwnsEverything();
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "ALTER TABLE public.shredding_erasure ALTER COLUMN hash TYPE varchar(100)",
        "CREATE FUNCTION shadow.format_type(oid, integer) RETURNS text AS $$"
            + " SELECT CASE WHEN $1 = 'character varying'::regtype AND $2 = 104"
            + "   THEN 'character(64)'"
            + "   ELSE pg_catalog.format_type($1, $2) END $$ LANGUAGE sql");
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    assertThat(refusal().getMessage()).contains("character varying(100)");
  }

  /**
   * The pin's own backstop, §4.9 rule 3. {@code set_config} returns the value it was asked to set
   * whether or not the setting took: with {@code is_local = true} outside a transaction block it
   * does nothing at all, raises nothing, and leaves every later leg qualified in text and
   * unqualified in substance. Only a read-back against the literal {@code pg_catalog} sees that,
   * and it is {@code SHRED-SCHEMA-005} - the pin not taking is the one case where the failure
   * itself is the finding.
   */
  @Test
  void t54_a_pin_that_cannot_take_is_unverifiable_and_never_a_pass() {
    try (Connection c = appDs.getConnection()) {
      c.setAutoCommit(true);
      var thrown =
          org.assertj.core.api.Assertions.catchThrowableOfType(
              ShreddingException.class,
              () -> SchemaVerification.verifyInCallersTransaction(c, false));
      assertThat(thrown.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
      assertThat(thrown).hasMessageContaining("pin its own search_path");
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Why the captured schema is bound as a namespace oid rather than cast with {@code
   * '<name>'::regnamespace}. {@code regnamespacein} parses its argument as an SQL identifier, so a
   * schema whose name needs quoting - which {@link VerifiedSchema} deliberately supports, and which
   * {@code qualify()} has always handled - would turn every leg into {@code SHRED-SCHEMA-005} under
   * the cast. An exact {@code nspname} match has no parser in it.
   */
  @Test
  void t55_a_schema_whose_name_needs_quoting_is_verified_not_unverifiable() {
    try {
      su("CREATE SCHEMA \"My Shred\" AUTHORIZATION " + OWNER);
      su(
          "ALTER ROLE " + OWNER + " SET search_path = \"My Shred\"",
          "ALTER ROLE " + APP + " SET search_path = \"My Shred\"");
      JdbcSupport.initializeSchema(ownerDs);
      owner("GRANT USAGE ON SCHEMA \"My Shred\" TO " + APP);
      owner(GRANT_BLOCK.toArray(String[]::new));

      SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
      assertThat(verdict.schema().name()).isEqualTo("My Shred");
      assertThat(verdict.runtimeRoleIsUnprivileged()).isTrue();
      store(verdict.schema()).append(record("quoted-schema"));
      assertThat(count("\"My Shred\".shredding_erasure")).isEqualTo(1);
    } finally {
      su(
          "ALTER ROLE " + OWNER + " RESET search_path",
          "ALTER ROLE " + APP + " RESET search_path",
          "DROP SCHEMA IF EXISTS \"My Shred\" CASCADE");
    }
  }

  /**
   * C-13-12. The bundled script's first guard refuses a database written before keyed-from-birth,
   * and resolved both oids through an unqualified {@code to_regclass} inside a {@code DO} block -
   * which resolves function names against the session {@code search_path} like anything else. On
   * the {@code initialize-schema=true} path the runtime role runs that script itself, so the role
   * the guard is about could make both oids NULL, both arms of the {@code IF} false, and the {@code
   * RAISE} unreachable.
   */
  @Test
  void t56_a_shadowed_to_regclass_cannot_silence_the_scripts_keyed_from_birth_guard() {
    su("DROP SCHEMA public CASCADE", "CREATE SCHEMA public", "ALTER SCHEMA public OWNER TO " + APP);
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "CREATE TABLE public.shredding_erasure (seq bigserial PRIMARY KEY, ts timestamptz NOT NULL)",
        "CREATE FUNCTION shadow.to_regclass(text) RETURNS regclass AS $$"
            + " SELECT NULL::regclass $$ LANGUAGE sql");
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    assertThatThrownBy(() -> JdbcSupport.initializeSchema(appDs))
        .hasStackTraceContaining("predates keyed-from-birth");
  }

  /**
   * C-13-11, and the one leg of the addendum that is not the gate: {@link JdbcErasureStore}'s
   * same-text blind-index read-back, the control that refuses an erasure which left an HMAC of the
   * erased plaintext behind. {@code count} is an unqualified aggregate name and resolves through
   * the same {@code search_path}, so an aggregate that returns its state unchanged makes the
   * read-back answer zero over a table that still holds the index, and the erasure is recorded
   * {@code COMPLETE}.
   *
   * <p>The residue is produced the way the control's own javadoc says it is produced: a {@code
   * BEFORE UPDATE} trigger on the application's table repopulates the column the erasure just
   * cleared. The independent read-back is stubbed to zero here on purpose, so the only thing that
   * can refuse this erasure is the same-text count.
   */
  @Test
  void t57_a_shadowed_count_cannot_hide_blind_index_residue_from_the_read_back() {
    SchemaVerdict verdict = JdbcSupport.verifySchema(appDs);
    owner(
        "CREATE TABLE public.invoice (tenant varchar(255), subject varchar(255), bi bytea)",
        "INSERT INTO public.invoice VALUES ('t1', 's1', '\\x01')",
        "CREATE FUNCTION public.invoice_keep_bi() RETURNS trigger AS $$"
            + " BEGIN NEW.bi := '\\x01'::bytea; RETURN NEW; END; $$ LANGUAGE plpgsql",
        "CREATE TRIGGER invoice_keep_bi BEFORE UPDATE ON public.invoice"
            + " FOR EACH ROW EXECUTE FUNCTION public.invoice_keep_bi()",
        "GRANT SELECT, UPDATE ON public.invoice TO " + APP);
    su("CREATE SCHEMA shadow AUTHORIZATION " + APP);
    app(
        "CREATE FUNCTION shadow.always_zero(bigint) RETURNS bigint AS $$"
            + " SELECT 0::bigint $$ LANGUAGE sql",
        "CREATE AGGREGATE shadow.count(*)"
            + " (sfunc = shadow.always_zero, stype = bigint, initcond = '0')");
    su("ALTER ROLE " + APP + " SET search_path = public, shadow, pg_catalog");

    var store =
        new JdbcErasureStore(
            appDs,
            verdict.schema(),
            ErasureChain.unkeyed(),
            List.of(
                new com.housedevinci.shredding.domain.BlindIndexColumn(
                    com.housedevinci.shredding.domain.TableRef.of("invoice"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("bi"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("subject"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("tenant"),
                    java.util.Optional.of("tenant"),
                    java.util.Optional.of("subject"))),
            (c, column, tenant, subject) -> 0L);

    var thrown =
        org.assertj.core.api.Assertions.catchThrowableOfType(
            ShreddingException.class,
            () ->
                store.erase(
                    TenantId.of("t1"),
                    SubjectId.of("s1"),
                    (destroyed, cleared) -> record("residue")));
    assertThat(thrown.code()).isEqualTo(ErrorCodes.ERASURE_INDEX_RESIDUAL);
    assertThat(count("public.shredding_erasure"))
        .describedAs("the whole transaction is rolled back, so nothing claims a completion")
        .isZero();
  }

  /** The 0.1.x-shaped install: the application role applied the script and owns everything. */
  private void appOwnsEverything() {
    su("DROP SCHEMA public CASCADE", "CREATE SCHEMA public", "ALTER SCHEMA public OWNER TO " + APP);
    JdbcSupport.initializeSchema(appDs);
  }

  /**
   * The shadow that answers every §4.6 leg the way a hardened deployment would: it needs no
   * privilege the design refuses to grant, because the role owns the schema it writes them into.
   */
  private static String[] honestLookingShadow(String schema) {
    return new String[] {
      "CREATE FUNCTION "
          + schema
          + ".pg_has_role(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT false $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".current_setting(text) RETURNS text"
          + " AS $$ SELECT CASE WHEN $1 = 'is_superuser' THEN 'off'"
          + "   ELSE pg_catalog.current_setting($1) END $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_schema_privilege(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT $3 = 'USAGE' $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_database_privilege(name, text, text) RETURNS boolean"
          + " AS $$ SELECT false $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_sequence_privilege(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT $3 = 'USAGE' $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_table_privilege(name, oid, text) RETURNS boolean AS $$"
          + " SELECT CASE (SELECT relname FROM pg_catalog.pg_class WHERE oid = $2)"
          + "   WHEN 'shredding_data_key' THEN $3 IN ('SELECT','INSERT','DELETE')"
          + "   WHEN 'shredding_erased_subject' THEN $3 IN ('SELECT','INSERT')"
          + "   WHEN 'shredding_erasure' THEN $3 IN ('SELECT','INSERT')"
          + "   WHEN 'shredding_erasure_anchor' THEN $3 IN ('SELECT','INSERT','UPDATE')"
          + "   ELSE false END $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_column_privilege(name, oid, smallint, text)"
          + " RETURNS boolean AS $$"
          + " SELECT (SELECT c.relname || '.' || a.attname FROM pg_catalog.pg_class c"
          + "   JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid"
          + "   WHERE c.oid = $2 AND a.attnum = $3)"
          + " IN ('shredding_data_key.encryption_count',"
          + "     'shredding_erased_subject.erased_at') $$ LANGUAGE sql"
    };
  }

  /**
   * The mirror: every leg answered the most alarming way, to prove a shadow cannot refuse either.
   */
  private static String[] alarmingShadow(String schema) {
    return new String[] {
      "CREATE FUNCTION "
          + schema
          + ".pg_has_role(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT true $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".current_setting(text) RETURNS text"
          + " AS $$ SELECT 'on'::pg_catalog.text $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_schema_privilege(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT $3 <> 'USAGE' $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_database_privilege(name, text, text) RETURNS boolean"
          + " AS $$ SELECT true $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_sequence_privilege(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT true $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_table_privilege(name, oid, text) RETURNS boolean"
          + " AS $$ SELECT true $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".has_column_privilege(name, oid, smallint, text)"
          + " RETURNS boolean AS $$ SELECT true $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".format_type(oid, integer) RETURNS text"
          + " AS $$ SELECT 'not the type you expected'::pg_catalog.text $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".pg_get_constraintdef(oid) RETURNS text"
          + " AS $$ SELECT 'CHECK (true)'::pg_catalog.text $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".pg_get_function_result(oid) RETURNS text"
          + " AS $$ SELECT 'void'::pg_catalog.text $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".current_schema() RETURNS name"
          + " AS $$ SELECT 'shadow'::name $$ LANGUAGE sql",
      "CREATE FUNCTION "
          + schema
          + ".always_thousand(bigint) RETURNS bigint AS $$"
          + " SELECT $1 + 1000 $$ LANGUAGE sql",
      "CREATE AGGREGATE "
          + schema
          + ".count(*)"
          + " (sfunc = "
          + schema
          + ".always_thousand, stype = bigint, initcond = '0')"
    };
  }

  // ------------------------------------------------------------------ helpers

  private JdbcErasureStore store(VerifiedSchema schema) {
    return new JdbcErasureStore(
        appDs, schema, ErasureChain.unkeyed(), List.of(), (c, column, tenant, subject) -> 0L);
  }

  private static ErasureRecord record(String pseudonym) {
    return ErasureRecord.of(
        Instant.now(),
        TenantId.of("t1"),
        String.format("%-64s", pseudonym).replace(' ', '0'),
        "tester",
        "test",
        1,
        1,
        1,
        0,
        ErasureOutcome.COMPLETE,
        List.of(),
        Instant.now().plusSeconds(60));
  }

  private ShreddingException refusal() {
    return refusalAs(appDs);
  }

  private ShreddingException refusalAs(DataSource ds) {
    Throwable thrown =
        org.assertj.core.api.Assertions.catchThrowable(() -> JdbcSupport.verifySchema(ds));
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    return (ShreddingException) thrown;
  }

  private static String codeOf(Runnable work) {
    try {
      work.run();
      return null;
    } catch (ShreddingException e) {
      return e.code();
    } catch (RuntimeException e) {
      return e.getClass().getSimpleName();
    }
  }

  private void installMonotonic(String body) {
    // check_function_bodies=off is how a lone CR gets past CREATE FUNCTION's own parser, and the
    // owner sets that GUC freely.
    exec(
        ownerDs,
        "SET check_function_bodies = off",
        "CREATE OR REPLACE FUNCTION shredding_erasure_anchor_monotonic() RETURNS trigger AS "
            + literal(body)
            + " LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp");
  }

  private static String literal(String value) {
    return "'" + value.replace("'", "''") + "'";
  }

  /**
   * PostgreSQL resolves {@code is_superuser}, role membership and a role-level {@code search_path}
   * when the session starts, so a pooled connection opened before {@code ALTER ROLE} still answers
   * the old values. The two role pools are therefore <em>closed and rebuilt</em> after every
   * superuser statement, not soft-evicted.
   *
   * <p>Soft eviction was the first version and it is a race: {@code softEvictConnections()} marks
   * connections for retirement, and a connection that has already been handed back is closed on the
   * housekeeper's schedule rather than before the next {@code getConnection()}. On a loaded machine
   * the next call can still get the old session, {@code current_schema()} answers with the old
   * {@code search_path}, and T16 sees a clean verification where it expects a refusal. Closing the
   * pool is synchronous, so the next connection is necessarily a new session. Found by {@code
   * scripts/verify-reproducible.sh}, which fails on a flaky test on purpose.
   */
  private static void su(String... sql) {
    exec(superuserDs, sql);
    appDs = rebuild(appDs, APP);
    ownerDs = rebuild(ownerDs, OWNER);
  }

  private static HikariDataSource rebuild(HikariDataSource pool, String user) {
    if (pool == null) {
      return null;
    }
    pool.close();
    return pool(user, "pw", POSTGRES.getDatabaseName());
  }

  private static void owner(String... sql) {
    exec(ownerDs, sql);
  }

  private static void app(String... sql) {
    exec(appDs, sql);
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection()) {
      exec(c, sql);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void exec(Connection c, String... sql) {
    try (Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long count(String relation) {
    try (Connection c = superuserDs.getConnection()) {
      return scalar(c, "SELECT count(*) FROM " + relation);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long scalar(Connection c, String sql) {
    try (Statement st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getLong(1);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long relationCount() {
    try (Connection c = superuserDs.getConnection()) {
      return scalar(c, "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace");
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long functionOid(String name) {
    try (Connection c = superuserDs.getConnection()) {
      return scalar(
          c,
          "SELECT oid FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname = '"
              + name
              + "'");
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static boolean usageMode() {
    try (Connection c = appDs.getConnection()) {
      return scalar(
              c,
              "SELECT pg_has_role(current_user, (SELECT relowner FROM pg_class"
                  + " WHERE relnamespace = 'public'::regnamespace"
                  + " AND relname = 'shredding_erasure'), 'USAGE')::int")
          == 1;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static List<String> triggerStates() {
    var out = new ArrayList<String>();
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT t.tgenabled FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid"
                    + " WHERE r.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal")) {
      while (rs.next()) {
        out.add(rs.getString(1));
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    assertThat(out).hasSize(7);
    return out;
  }

  private static java.util.Map<String, List<SchemaExpectations.Column>> actualColumns() {
    var out = new java.util.LinkedHashMap<String, List<SchemaExpectations.Column>>();
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT r.relname, a.attname, a.attnotnull,"
                    + " format_type(a.atttypid, a.atttypmod) FROM pg_class r"
                    + " JOIN pg_attribute a ON a.attrelid = r.oid"
                    + " WHERE r.relnamespace = 'public'::regnamespace AND r.relkind = 'r'"
                    + " AND a.attnum > 0 AND NOT a.attisdropped ORDER BY r.relname, a.attnum")) {
      while (rs.next()) {
        out.computeIfAbsent(rs.getString(1), k -> new ArrayList<>())
            .add(new SchemaExpectations.Column(rs.getString(2), rs.getBoolean(3), rs.getString(4)));
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    return out;
  }

  private static List<SchemaExpectations.Constraint> actualConstraints() {
    var out = new ArrayList<SchemaExpectations.Constraint>();
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT r.relname, con.conname, con.contype, pg_get_constraintdef(con.oid)"
                    + " FROM pg_constraint con JOIN pg_class r ON r.oid = con.conrelid"
                    + " WHERE r.relnamespace = 'public'::regnamespace")) {
      while (rs.next()) {
        out.add(
            new SchemaExpectations.Constraint(
                rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    return out;
  }

  private static List<String> actualProconfig(String guard) {
    try (var c = ownerDs.getConnection();
        var ps =
            c.prepareStatement(
                "SELECT p.proconfig FROM pg_catalog.pg_proc p"
                    + " JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace"
                    + " WHERE n.nspname = 'public' AND p.proname = ?")) {
      ps.setString(1, guard);
      try (var rs = ps.executeQuery()) {
        if (!rs.next() || rs.getArray(1) == null) {
          return List.of();
        }
        return List.of((String[]) rs.getArray(1).getArray());
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static List<SchemaExpectations.Trigger> actualTriggers() {
    var out = new ArrayList<SchemaExpectations.Trigger>();
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT t.tgname, r.relname, p.proname, t.tgtype FROM pg_trigger t"
                    + " JOIN pg_class r ON r.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid"
                    + " WHERE r.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal")) {
      while (rs.next()) {
        out.add(
            new SchemaExpectations.Trigger(
                rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4)));
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    return out;
  }

  private static HikariDataSource pool(String user, String password, String database) {
    var config = new HikariConfig();
    config.setJdbcUrl(
        "jdbc:postgresql://"
            + POSTGRES.getHost()
            + ":"
            + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + database);
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(4);
    return new HikariDataSource(config);
  }

  /**
   * A {@code DataSource} that hands out the same physical connection every time and ignores {@code
   * close()}. Needed for T41, T42 and T44: {@code pg_temp} and {@code search_path} are properties
   * of one session, so a test that proves a statement did not follow them has to run on the very
   * session that was rigged.
   */
  private static DataSource pinnedDataSource(Connection connection) {
    Connection nonClosing =
        (Connection)
            Proxy.newProxyInstance(
                SchemaVerificationTest.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                (InvocationHandler)
                    (proxy, method, args) ->
                        "close".equals(method.getName()) ? null : invoke(connection, method, args));
    return (DataSource)
        Proxy.newProxyInstance(
            SchemaVerificationTest.class.getClassLoader(),
            new Class<?>[] {DataSource.class},
            (InvocationHandler)
                (proxy, method, args) ->
                    "getConnection".equals(method.getName())
                        ? nonClosing
                        : invoke(null, method, args));
  }

  private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
    if (target == null) {
      throw new UnsupportedOperationException(method.getName());
    }
    try {
      return method.invoke(target, args);
    } catch (java.lang.reflect.InvocationTargetException e) {
      throw e.getCause();
    }
  }
}
