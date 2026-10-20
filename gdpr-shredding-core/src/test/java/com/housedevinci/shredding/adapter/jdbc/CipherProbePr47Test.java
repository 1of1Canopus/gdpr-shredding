package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review, pass 1 of PR 47 (caller objects, R6 and R7, 2026-10-20). Methods named {@code
 * probe_*} are RED on d461403: the gate verifies, and the runtime role then makes the server run
 * code it holds no EXECUTE on. Methods named {@code confirms_*} are GREEN on d461403: attacks from
 * the review brief that the build already refuses, kept as evidence. Every case runs on both pins,
 * each in its own database.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CipherProbePr47Test {

  private final Map<Integer, PostgreSQLContainer<?>> pins = new HashMap<>();
  private int counter;

  @BeforeAll
  void start() throws SQLException {
    for (int major : new int[] {16, 17}) {
      var pg = TwoRoleCluster.container(major);
      pg.start();
      TwoRoleCluster.roles(pg);
      pins.put(major, pg);
    }
  }

  @AfterAll
  void stop() {
    pins.values().forEach(PostgreSQLContainer::stop);
  }

  private record Db(DataSource su, DataSource app) {}

  private Db db(int major) throws SQLException {
    var pg = pins.get(major);
    String name = "p47_" + major + "_" + (counter++);
    TwoRoleCluster.install(pg, name);
    return new Db(TwoRoleCluster.superuser(pg, name), TwoRoleCluster.app(pg, name));
  }

  private static final String WRAPPER =
      "CREATE FUNCTION public.w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
          + " AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)'";
  private static final String REVOKE_WRAPPER =
      "REVOKE EXECUTE ON FUNCTION public.w(text, boolean) FROM PUBLIC";

  // ------------------------------------------------------------- C-PR47-1 (LOW)

  /**
   * C-PR47-1. A language validator runs with no EXECUTE check at all, not with the owner's. R6
   * still skips a language whose owner is in reach, as if the owner's rights were checked. A
   * superuser makes a trusted language over a withheld validator and gives it to the runtime role.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_language_owned_by_the_runtime_role_with_a_withheld_validator_passes(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE TRUSTED LANGUAGE p47lang HANDLER pg_catalog.plpgsql_call_handler"
            + " VALIDATOR pg_catalog.pg_ls_tmpdir",
        "ALTER LANGUAGE p47lang OWNER TO " + APP,
        "CREATE SCHEMA p47 AUTHORIZATION " + APP);
    // Impact, shown first: the direct call is refused, the validator call is made.
    assertThatThrownBy(() -> scalar(db.app(), "SELECT pg_catalog.pg_ls_tmpdir(1::pg_catalog.oid)"))
        .hasMessageContaining("permission denied for function pg_ls_tmpdir");
    assertThatThrownBy(
            () -> exec(db.app(), "CREATE FUNCTION p47.f() RETURNS integer LANGUAGE p47lang AS 'x'"))
        .hasMessageContaining("tablespace with OID");
    exec(db.su(), "DROP SCHEMA p47");

    var e = FunctionGrantsCases.refusal(db.app());

    assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(e).hasMessageContaining("whose validator is function pg_catalog.pg_ls_tmpdir(");
  }

  /** C-PR47-1, second path: an operator's estimator is also called with no check. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_operator_owned_by_the_runtime_role_with_a_hand_made_estimator_passes(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE FUNCTION public.p47_sel(internal, oid, internal, integer) RETURNS float8"
            + " LANGUAGE internal STRICT AS 'eqsel'",
        "REVOKE EXECUTE ON FUNCTION public.p47_sel(internal, oid, internal, integer) FROM PUBLIC",
        "CREATE OPERATOR public.=== (LEFTARG = text, RIGHTARG = text,"
            + " FUNCTION = pg_catalog.texteq, RESTRICT = public.p47_sel)",
        "ALTER OPERATOR public.=== (text, text) OWNER TO " + APP);

    var e = FunctionGrantsCases.refusal(db.app());

    assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(e).hasMessageContaining("whose oprrest is function public.p47_sel(");
  }

  // ------------------------------------------------------------ C-PR47-2 (MEDIUM)

  /**
   * C-PR47-2. A SECURITY DEFINER wrapper that nobody in reach may execute, named in a slot of an
   * aggregate owned outside reach. R6 skips the slot (the wrapper is not native, so statement 2 has
   * no row for it), and limit L19 covers only wrappers reach may execute: its published audit query
   * filters on PUBLIC or a role of the login, so it does not list this one either.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_aggregate_over_a_revoked_security_definer_wrapper_passes_and_reads_a_file(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        WRAPPER,
        REVOKE_WRAPPER,
        "CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text,"
            + " initcond = 'PG_VERSION')");
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
        .hasMessageContaining("permission denied for function w");
    assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));

    var e = FunctionGrantsCases.refusal(db.app());

    assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(e).hasMessageContaining("aggregate public.agg_w(boolean)");
  }

  /** C-PR47-2, a core aggregate rewritten in place over the same wrapper: oid and symbol stay. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_core_aggregate_rewritten_over_a_revoked_wrapper_passes_and_leaks_a_file(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        WRAPPER,
        REVOKE_WRAPPER,
        "CREATE FUNCTION public.leak(text) RETURNS boolean LANGUAGE plpgsql"
            + " AS $f$BEGIN RAISE EXCEPTION 'leak: %', $1; END$f$",
        "CREATE OR REPLACE AGGREGATE pg_catalog.bool_or(boolean) (sfunc = public.w,"
            + " stype = text, initcond = 'PG_VERSION', finalfunc = public.leak)");
    assertThatThrownBy(() -> scalar(db.app(), "SELECT pg_catalog.bool_or(true)"))
        .hasMessageContaining("leak: " + major);

    var e = FunctionGrantsCases.refusal(db.app());

    assertThat(e).hasMessageContaining("pg_catalog.bool_or(boolean)");
  }

  /**
   * C-PR47-2, a contrib aggregate re-created over a wrapper of the same key in another schema. The
   * manifest's support column writes keys without a schema, so R5b sees the shipped support set.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_contrib_aggregate_over_a_same_key_wrapper_in_another_schema_passes(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE EXTENSION citext",
        "CREATE SCHEMA evil",
        "CREATE FUNCTION evil.citext_larger(public.citext, public.citext) RETURNS public.citext"
            + " LANGUAGE sql STRICT SECURITY DEFINER"
            + " AS 'SELECT pg_catalog.pg_read_file($2::text)::public.citext'",
        "REVOKE EXECUTE ON FUNCTION evil.citext_larger(public.citext, public.citext) FROM PUBLIC",
        "ALTER EXTENSION citext DROP AGGREGATE public.max(public.citext)",
        "DROP AGGREGATE public.max(public.citext)",
        "CREATE AGGREGATE public.max(public.citext) (sfunc = evil.citext_larger,"
            + " stype = public.citext, combinefunc = evil.citext_larger)",
        "ALTER EXTENSION citext ADD AGGREGATE public.max(public.citext)");
    assertThat(
            scalar(
                db.app(),
                "SELECT public.max(x) FROM (VALUES ('a'::public.citext), ('PG_VERSION')) v(x)"))
        .startsWith(Integer.toString(major));

    var e = FunctionGrantsCases.refusal(db.app());

    assertThat(e).hasMessageContaining("public.max(public.citext)");
  }

  // ------------------------------------------------- confirms: green on d461403

  /** The brief's minvfunc-only attack: the inverse transition reads the file; R6 refuses slot 7. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_moving_aggregate_with_only_minvfunc_withheld_refuses(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE FUNCTION public.keeps(text, boolean) RETURNS text LANGUAGE sql STRICT"
            + " AS 'SELECT $1'",
        "CREATE AGGREGATE public.agg_mi(boolean) (sfunc = public.keeps, stype = text,"
            + " initcond = 'x', msfunc = public.keeps, minvfunc = pg_catalog.pg_read_file,"
            + " mstype = text, minitcond = 'PG_VERSION')");
    assertThat(
            scalar(
                db.app(),
                "SELECT pg_catalog.max(m) FROM (SELECT public.agg_mi(b) OVER (ROWS BETWEEN"
                    + " 1 PRECEDING AND CURRENT ROW) AS m FROM (VALUES (true), (true), (true))"
                    + " AS v(b)) AS w WHERE m <> 'PG_VERSION'"))
        .startsWith(Integer.toString(major));
    FunctionGrantsCases.refuses(db.app(), "whose minvtransfn is function pg_catalog.pg_read_file(");
  }

  /** A core aggregate rewritten in place over a withheld sfunc: R7 is silent, R6 refuses. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_core_aggregate_rewritten_over_a_withheld_sfunc_refuses(int major)
      throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE FUNCTION public.tobool(text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "CREATE OR REPLACE AGGREGATE pg_catalog.bool_or(boolean) (sfunc = pg_catalog.pg_read_file,"
            + " stype = text, initcond = 'PG_VERSION', finalfunc = public.tobool)");
    FunctionGrantsCases.refuses(
        db.app(), "aggregate pg_catalog.bool_or(boolean)", "whose transfn is function");
  }

  /** A core function renamed keeps its oid: R7 reports the recorded one missing (005). */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_core_function_renamed_and_replaced_refuses_with_005(int major) throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "ALTER FUNCTION pg_catalog.lower(text) RENAME TO lower_x",
        "CREATE FUNCTION pg_catalog.lower(text) RETURNS text LANGUAGE c"
            + " AS '$libdir/pg_trgm', 'similarity'");
    var e = FunctionGrantsCases.refusal(db.app());
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    assertThat(e).hasMessageContaining("pg_catalog.lower(text)");
    assertThat(e).hasMessageContaining("pg_catalog.lower_x(text)");
  }

  /**
   * C-PR47-3 (measured, no probe): dblink_connect_u(text, text) is an extension-withheld function
   * that fits the combine shape. R6 reads the combine slot, so it refuses.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_combine_over_dblink_connect_u_refuses(int major) throws SQLException {
    var db = db(major);
    exec(
        db.su(),
        "CREATE EXTENSION dblink",
        "CREATE AGGREGATE public.agg_c(text) (sfunc = pg_catalog.textcat, stype = text,"
            + " combinefunc = public.dblink_connect_u)");
    FunctionGrantsCases.refuses(db.app(), "whose combinefn is function public.dblink_connect_u(");
  }

  /** A role in reach cannot make the aggregate: the server checks EXECUTE at CREATE AGGREGATE. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_runtime_role_cannot_create_an_aggregate_over_pg_read_file(int major)
      throws SQLException {
    var db = db(major);
    exec(db.su(), "CREATE SCHEMA p47 AUTHORIZATION " + APP);
    assertThatThrownBy(
            () ->
                exec(
                    db.app(),
                    "CREATE AGGREGATE p47.a(boolean) (sfunc = pg_catalog.pg_read_file,"
                        + " stype = text, initcond = 'PG_VERSION')"))
        .hasMessageContaining("permission denied for function pg_read_file");
  }

  /** A reach-owned wrapper behind an aggregate owned outside reach runs as reach: denied. */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_reach_owned_wrapper_behind_a_foreign_aggregate_is_denied_at_run_time(int major)
      throws SQLException {
    var db = db(major);
    exec(db.su(), "CREATE SCHEMA p47 AUTHORIZATION " + APP);
    exec(
        db.app(),
        "CREATE FUNCTION p47.w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)'");
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_w(boolean) (sfunc = p47.w, stype = text,"
            + " initcond = 'PG_VERSION')");
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.agg_w(true)"))
        .hasMessageContaining("permission denied for function pg_read_file");
  }
}
