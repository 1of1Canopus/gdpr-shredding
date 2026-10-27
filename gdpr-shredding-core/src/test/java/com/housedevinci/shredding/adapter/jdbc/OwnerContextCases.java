package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.FunctionGrantsCases.refusal;
import static com.housedevinci.shredding.adapter.jdbc.FunctionGrantsCases.refuses;
import static com.housedevinci.shredding.adapter.jdbc.FunctionGrantsCases.verifies;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * The paths of the owner-context design page, Rev 2 (C-RC021-2c, -2e, -2f, -2g, -2h), run on one
 * pinned image per subclass: code the server runs as a role outside reach because the runtime role
 * wrote a row. Every test makes its own database; the superuser plants the path, the runtime role
 * triggers it where the path is shown, and the gate's verdict is asserted.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class OwnerContextCases {

  /** The container's superuser, who plants every path: a role outside reach. */
  static final String SU = "test";

  private final int major;
  private PostgreSQLContainer<?> pg;
  private HikariDataSource admin;
  private int counter;
  private final List<String> databases = new ArrayList<>();
  private final List<HikariDataSource> pools = new ArrayList<>();

  OwnerContextCases(int major) {
    this.major = major;
  }

  record Db(String name, HikariDataSource su, HikariDataSource app) {}

  @BeforeAll
  void start() throws SQLException {
    pg = TwoRoleCluster.container(major);
    pg.start();
    TwoRoleCluster.roles(pg);
    admin = TwoRoleCluster.superuser(pg, pg.getDatabaseName());
  }

  @AfterAll
  void stop() {
    if (admin != null) {
      admin.close();
    }
    pg.stop();
  }

  @AfterEach
  void dropWhatTheTestMade() throws SQLException {
    pools.forEach(HikariDataSource::close);
    pools.clear();
    for (String db : databases) {
      exec(admin, "DROP DATABASE IF EXISTS " + db + " WITH (FORCE)");
    }
    databases.clear();
    if (major >= 17) {
      exec(admin, "REVOKE pg_maintain FROM " + APP);
    }
  }

  int major() {
    return major;
  }

  Db db() throws SQLException {
    String name = "oc" + major + "_" + (counter++);
    TwoRoleCluster.install(pg, name);
    databases.add(name);
    var su = keep(TwoRoleCluster.superuser(pg, name));
    var app = keep(TwoRoleCluster.app(pg, name));
    return new Db(name, su, app);
  }

  private HikariDataSource keep(HikariDataSource ds) {
    pools.add(ds);
    return ds;
  }

  /** As the superuser: one statement per item, split on '|'. */
  static void plant(Db db, String statements) throws SQLException {
    exec(db.su(), statements.split("\\|"));
  }

  /**
   * A referenced table {@code public.par} (rows 1 and 2, the runtime role may update and delete
   * them) and a referencing table {@code public.ch} built from {@code columns}, both owned by the
   * bootstrap superuser: outside reach.
   */
  static final String PARENT =
      "CREATE TABLE public.par (id int PRIMARY KEY)|INSERT INTO public.par VALUES (1), (2)"
          + "|GRANT SELECT, UPDATE, DELETE ON public.par TO "
          + APP;

  /** A revoked SQL SECURITY DEFINER function, IMMUTABLE so an index or a key may use it. */
  static final String SDI =
      "CREATE FUNCTION public.sdi(int) RETURNS int LANGUAGE sql IMMUTABLE SECURITY DEFINER"
          + " AS 'SELECT $1'|REVOKE EXECUTE ON FUNCTION public.sdi(int) FROM PUBLIC";

  static final String SDI_LABEL = "public.sdi(integer)";
  static final String PRF = "pg_catalog.pg_read_file(text)";
  static final String READ = "length(pg_catalog.pg_read_file('PG_VERSION')) > 0";

  /** An O1 line, up to the source: "function F as the SLOT of SOURCE". */
  static String o1(String fn, String slot, String source) {
    return "function " + fn + " as the " + slot + " of " + source;
  }

  static void refusesO1(HikariDataSource app, String fn, String slot, String source) {
    var e = refusal(app);
    assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    assertThat(e)
        .hasMessageContaining(o1(fn, slot, source))
        .hasMessageContaining("(O1, C-RC021-2e)");
  }

  // ------------------------------------------------------------- Q2: O1, expressions

  @Test
  void fk_set_default_expression_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE TABLE public.par (k text PRIMARY KEY)|INSERT INTO public.par VALUES ('a')"
            + "|GRANT SELECT, DELETE ON public.par TO "
            + APP
            + "|CREATE TABLE public.ch (k text DEFAULT trim(pg_catalog.pg_read_file('PG_VERSION'))"
            + " REFERENCES public.par ON DELETE SET DEFAULT)|INSERT INTO public.ch VALUES ('a')"
            + "|GRANT SELECT ON public.ch TO "
            + APP);
    // M1: the runtime role may not call it, but the action runs it as the owner, and the FK error
    // hands back the file's content.
    assertThatThrownBy(() -> scalar(db.app(), "SELECT pg_catalog.pg_read_file('PG_VERSION')"))
        .hasMessageContaining("permission denied");
    assertThatThrownBy(() -> exec(db.app(), "DELETE FROM public.par"))
        .hasMessageContaining("=(" + major);
    refusesO1(db.app(), PRF, "column default", "column k of public.ch");
  }

  @Test
  void fk_domain_default_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE TABLE public.par (k text PRIMARY KEY)|GRANT SELECT, DELETE ON public.par TO "
            + APP
            + "|CREATE DOMAIN public.dleak AS text DEFAULT trim(pg_catalog.pg_read_file('PG_VERSION'))"
            + "|CREATE TABLE public.ch (k public.dleak REFERENCES public.par ON DELETE SET DEFAULT)");
    refusesO1(db.app(), PRF, "domain default", "domain public.dleak, a type in table public.ch");
  }

  @Test
  void fk_generated_column_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON UPDATE CASCADE,"
            + " g int GENERATED ALWAYS AS (public.sdi(pid)) STORED)");
    refusesO1(db.app(), SDI_LABEL, "generated column", "column g of public.ch");
  }

  @Test
  void fk_check_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " CONSTRAINT leak CHECK ("
            + READ
            + "))");
    refusesO1(db.app(), PRF, "constraint", "constraint leak on public.ch");
  }

  @Test
  void fk_domain_check_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE DOMAIN public.dchk AS int CONSTRAINT leak CHECK ("
            + READ
            + ")|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE,"
            + " x public.dchk)");
    refusesO1(
        db.app(), PRF, "domain check", "constraint leak on domain public.dchk, a type in table");
  }

  @Test
  void fk_index_expression_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON UPDATE CASCADE)"
            + "|CREATE INDEX chx ON public.ch ((public.sdi(pid)))");
    refusesO1(db.app(), SDI_LABEL, "index expression or predicate", "index public.chx");
  }

  @Test
  void fk_partial_predicate_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL)"
            + "|CREATE INDEX chp ON public.ch (pid) WHERE public.sdi(pid) > 0");
    refusesO1(db.app(), SDI_LABEL, "index expression or predicate", "index public.chp");
  }

  static final String INVOKER_TRIGGER =
      "CREATE FUNCTION public.inv() RETURNS trigger LANGUAGE plpgsql AS"
          + " 'BEGIN RETURN COALESCE(NEW, OLD); END'";

  @Test
  void fk_before_trigger_when_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + INVOKER_TRIGGER
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON UPDATE CASCADE)"
            + "|CREATE TRIGGER bw BEFORE UPDATE ON public.ch FOR EACH ROW WHEN ("
            + READ
            + ") EXECUTE FUNCTION public.inv()");
    refusesO1(db.app(), PRF, "BEFORE trigger WHEN", "trigger bw on public.ch");
  }

  @Test
  void fk_after_trigger_when_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + INVOKER_TRIGGER
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|CREATE TRIGGER aw AFTER DELETE ON public.ch FOR EACH ROW WHEN ("
            + READ
            + ") EXECUTE FUNCTION public.inv()");
    refusesO1(db.app(), PRF, "AFTER trigger WHEN", "trigger aw on public.ch");
  }

  @Test
  void fk_rule_action_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|CREATE TABLE public.rlog (t text)"
            + "|CREATE RULE r AS ON DELETE TO public.ch DO ALSO INSERT INTO public.rlog"
            + " VALUES (pg_catalog.pg_read_file('PG_VERSION'))");
    refusesO1(db.app(), PRF, "rule", "rule r on public.ch");
  }

  @Test
  void fk_partition_key_expression_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON UPDATE CASCADE)"
            + " PARTITION BY RANGE ((public.sdi(pid)))"
            + "|CREATE TABLE public.ch1 PARTITION OF public.ch FOR VALUES FROM (0) TO (100)");
    // Measured first (assumption 1): the key runs as the owner when the action moves a row.
    refusesO1(
        db.app(),
        SDI_LABEL,
        "partition key",
        "table public.ch, written by a foreign-key" + " action on table public.ch1");
  }

  @Test
  void fk_domain_in_array_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE DOMAIN public.dchk AS int CONSTRAINT leak CHECK ("
            + READ
            + ")|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " xs public.dchk[])");
    refusesO1(db.app(), PRF, "domain check", "constraint leak on domain public.dchk");
  }

  @Test
  void fk_domain_in_composite_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE DOMAIN public.dchk AS int CONSTRAINT leak CHECK ("
            + READ
            + ")|CREATE TYPE public.cty AS (d public.dchk)"
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " c public.cty)");
    refusesO1(db.app(), PRF, "domain check", "constraint leak on domain public.dchk");
  }

  @Test
  void fk_operator_in_check_over_withheld_function_refuses() throws SQLException {
    // An operator is judged as its oprcode: the CHECK names no function, only the operator.
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE FUNCTION public.sdeq(int, int) RETURNS boolean LANGUAGE sql IMMUTABLE"
            + " SECURITY DEFINER AS 'SELECT $1 = $2'"
            + "|REVOKE EXECUTE ON FUNCTION public.sdeq(int, int) FROM PUBLIC"
            + "|CREATE OPERATOR public.=== (LEFTARG = int, RIGHTARG = int,"
            + " FUNCTION = public.sdeq)"
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " CONSTRAINT op CHECK (pid OPERATOR(public.===) pid))");
    refusesO1(
        db.app(), "public.sdeq(integer, integer)", "constraint", "constraint op on public.ch");
  }

  @Test
  void fk_exclusion_operator_over_withheld_function_refuses() throws SQLException {
    // A stored expression carries an operator's function oid, but an exclusion constraint keeps
    // only the operator (conexclop): the only path to the function is the operator's oprcode.
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE FUNCTION public.sdeq(int, int) RETURNS boolean LANGUAGE sql IMMUTABLE"
            + " SECURITY DEFINER AS 'SELECT $1 = $2'"
            + "|REVOKE EXECUTE ON FUNCTION public.sdeq(int, int) FROM PUBLIC"
            + "|CREATE OPERATOR public.=== (LEFTARG = int, RIGHTARG = int,"
            + " FUNCTION = public.sdeq, COMMUTATOR = OPERATOR(public.===))"
            + "|CREATE OPERATOR CLASS public.eq_ops FOR TYPE int USING btree AS"
            + " OPERATOR 3 public.===, FUNCTION 1 pg_catalog.btint4cmp(int, int)"
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " CONSTRAINT ex EXCLUDE USING btree (pid public.eq_ops WITH OPERATOR(public.===)))");
    refusesO1(
        db.app(), "public.sdeq(integer, integer)", "constraint", "constraint ex on public.ch");
  }

  @Test
  void o1_is_not_relaxed_by_allow_privileged_runtime_role() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " CONSTRAINT leak CHECK ("
            + READ
            + "))");
    assertThatThrownBy(() -> JdbcSupport.verifySchema(db.app(), true, List.of()))
        .hasMessageContaining(o1(PRF, "constraint", "constraint leak on public.ch"))
        .hasMessageContaining("not relaxed by allow-privileged-runtime-role");
  }

  @Test
  void o2_is_relaxed_by_allow_privileged_runtime_role() throws SQLException {
    var db = db();
    plant(db, FK + "|CREATE SCHEMA appsch AUTHORIZATION " + APP);
    var verdict = JdbcSupport.verifySchema(db.app(), true, List.of());
    assertThat(verdict.privilegeLegs()).anyMatch(l -> l.contains("owns schema appsch"));
  }

  @Test
  void fk_target_owned_in_reach_is_not_judged_by_o1() throws SQLException {
    // Control: an expression on a table reach owns runs as reach, whose own EXECUTE is checked.
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE SET NULL,"
            + " CONSTRAINT leak CHECK ("
            + READ
            + "))|ALTER TABLE public.ch OWNER TO "
            + APP);
    var e = refusal(db.app());
    assertThat(e).hasMessageNotContaining("(O1, C-RC021-2e)");
    assertThat(e).hasMessageContaining("owns table public.ch"); // O2 instead
  }

  // ------------------------------------------------------------- Q1, Q1c: triggers

  /**
   * The six FK actions that write the target. Each: the action clause, then the runtime role's
   * statement on the referenced table.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "ON DELETE CASCADE;DELETE FROM public.par WHERE id = 1",
        "ON DELETE SET NULL;DELETE FROM public.par WHERE id = 1",
        "ON DELETE SET DEFAULT;DELETE FROM public.par WHERE id = 1",
        "ON UPDATE CASCADE;UPDATE public.par SET id = 3 WHERE id = 1",
        "ON UPDATE SET NULL;UPDATE public.par SET id = 3 WHERE id = 1",
        "ON UPDATE SET DEFAULT;UPDATE public.par SET id = 3 WHERE id = 1"
      })
  void before_trigger_on_fk_action_target_resolving_reach_schema_refuses(String path)
      throws SQLException {
    String[] p = path.split(";");
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE SCHEMA appsch AUTHORIZATION "
            + APP
            + "|CREATE FUNCTION public.aud() RETURNS trigger LANGUAGE plpgsql AS"
            + " 'BEGIN INSERT INTO audit_log VALUES (current_user); RETURN COALESCE(NEW, OLD); END'"
            + "|CREATE TABLE public.ch (pid int DEFAULT 2 REFERENCES public.par "
            + p[0]
            + ")|INSERT INTO public.ch VALUES (1)"
            + "|CREATE TRIGGER b BEFORE INSERT OR UPDATE OR DELETE ON public.ch FOR EACH ROW"
            + " EXECUTE FUNCTION public.aud()");
    // S1: the owner's trigger resolves its unqualified name into a schema the runtime role owns.
    exec(
        db.app(),
        "CREATE TABLE appsch.audit_log (who text)",
        "SET search_path = appsch, public",
        p[1],
        "RESET search_path");
    assertThat(scalar(db.app(), "SELECT who FROM appsch.audit_log")).isEqualTo(SU);
    refuses(
        db.app(),
        "login role " + APP + " owns schema appsch, and this database runs code as a role outside",
        "login role " + APP + " owns table appsch.audit_log",
        "(O2, C-RC021-2c, C-RC021-2g)");
  }

  @Test
  void plpgsql_before_trigger_on_fk_cascade_target_resolving_pg_temp_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|GRANT TEMPORARY ON DATABASE "
            + db.name()
            + " TO "
            + APP
            + "|CREATE FUNCTION public.aud() RETURNS trigger LANGUAGE plpgsql AS"
            + " 'BEGIN INSERT INTO audit_log VALUES (current_user); RETURN OLD; END'"
            + "|CREATE TABLE public.audit_log (who text)"
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|INSERT INTO public.ch VALUES (1)"
            + "|CREATE TRIGGER b BEFORE DELETE ON public.ch FOR EACH ROW"
            + " EXECUTE FUNCTION public.aud()");
    // M3: pg_temp is searched first, so the owner's trigger writes the runtime role's temp table.
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      s.execute("CREATE TEMP TABLE audit_log (who text)");
      s.execute("DELETE FROM public.par WHERE id = 1");
      try (var rs = s.executeQuery("SELECT who FROM pg_temp.audit_log")) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getString(1)).isEqualTo(SU);
      }
      s.execute("DROP TABLE pg_temp.audit_log");
    }
    refuses(db.app(), "holds TEMPORARY on database " + db.name());
  }

  @Test
  void after_trigger_in_fk_cascade_runs_as_caller() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.alog (who text)|GRANT INSERT ON public.alog TO "
            + APP
            + "|CREATE FUNCTION public.mark() RETURNS trigger LANGUAGE plpgsql AS"
            + " 'BEGIN INSERT INTO public.alog VALUES (current_user); RETURN NULL; END'"
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|INSERT INTO public.ch VALUES (1)"
            + "|CREATE TRIGGER a AFTER DELETE ON public.ch FOR EACH ROW"
            + " EXECUTE FUNCTION public.mark()");
    exec(db.app(), "DELETE FROM public.par WHERE id = 1");
    assertThat(scalar(db.su(), "SELECT who FROM public.alog")).isEqualTo(APP);
    verifies(db.app());
  }

  // ------------------------------------------------------------- Q3, Q3b, Q3c, Q4: O2

  static final String FK = PARENT + "|CREATE TABLE public.ch (pid int REFERENCES public.par)";

  @Test
  void runtime_role_owning_a_schema_refuses() throws SQLException {
    var db = db();
    plant(db, FK + "|CREATE SCHEMA appsch AUTHORIZATION " + APP);
    refuses(
        db.app(),
        "login role " + APP + " owns schema appsch",
        "foreign key ch_pid_fkey on public.ch referencing public.par has a table owned outside"
            + " reach");
  }

  @Test
  void runtime_role_with_create_on_a_schema_refuses() throws SQLException {
    var db = db();
    plant(db, SDI + "|CREATE SCHEMA s|GRANT USAGE, CREATE ON SCHEMA s TO " + APP);
    refuses(
        db.app(),
        "login role " + APP + " holds CREATE on schema s",
        "function public.sdi(integer) is SECURITY DEFINER, owned by " + SU + " outside reach");
  }

  @Test
  void public_create_on_a_schema_refuses() throws SQLException {
    var db = db();
    plant(db, FK + "|CREATE SCHEMA s|GRANT USAGE, CREATE ON SCHEMA s TO PUBLIC");
    refuses(db.app(), "PUBLIC holds CREATE on schema s");
  }

  @Test
  void runtime_role_with_temp_refuses() throws SQLException {
    var db = db();
    plant(db, "GRANT TEMPORARY ON DATABASE " + db.name() + " TO " + APP);
    refuses(db.app(), "holds TEMPORARY on database " + db.name());
  }

  @Test
  void runtime_role_owning_a_table_written_by_owner_code_refuses() throws SQLException {
    // R3 as written: no CREATE, no TEMP, no name trick.
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.olog (who text, leak text)|ALTER TABLE public.olog OWNER TO "
            + APP
            + "|CREATE FUNCTION public.aud() RETURNS trigger LANGUAGE plpgsql AS"
            + " 'BEGIN INSERT INTO public.olog (who) VALUES (current_user); RETURN OLD; END'"
            + "|CREATE TABLE public.c3 (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|INSERT INTO public.c3 VALUES (1)"
            + "|CREATE TRIGGER b BEFORE DELETE ON public.c3 FOR EACH ROW"
            + " EXECUTE FUNCTION public.aud()");
    exec(
        db.app(),
        "ALTER TABLE public.olog ALTER leak SET DEFAULT trim(pg_catalog.pg_read_file('PG_VERSION'))",
        "DELETE FROM public.par WHERE id = 1");
    assertThat(scalar(db.app(), "SELECT who || ' ' || leak FROM public.olog"))
        .startsWith(SU + " " + major);
    refuses(db.app(), "login role " + APP + " owns table public.olog, and this database runs code");
  }

  @Test
  void single_login_owning_every_table_with_no_entry_point_verifies() throws SQLException {
    // Q3c: reach owns its own tables (a foreign key between two of them too) and may create in
    // its schema; no definer function and no foreign key involves a role outside reach.
    var db = db();
    plant(db, "CREATE SCHEMA appsch AUTHORIZATION " + APP);
    exec(
        db.app(),
        "CREATE TABLE appsch.p (id int PRIMARY KEY)",
        "CREATE TABLE appsch.c (pid int REFERENCES appsch.p ON DELETE CASCADE)",
        "CREATE FUNCTION appsch.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'");
    verifies(db.app());
  }

  @Test
  void definer_function_outside_reach_makes_o2_apply() throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE SCHEMA appsch AUTHORIZATION "
            + APP
            + "|CREATE FUNCTION public.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'");
    refuses(
        db.app(),
        "login role " + APP + " owns schema appsch",
        "function public.f() is SECURITY DEFINER, owned by " + SU + " outside reach");
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void sql_definer_trigger_makes_o2_apply_revoked_or_public(boolean revoked) throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE SCHEMA appsch AUTHORIZATION "
            + APP
            + "|CREATE FUNCTION public.audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER"
            + " AS 'BEGIN RETURN NEW; END'"
            + (revoked ? "|REVOKE EXECUTE ON FUNCTION public.audit() FROM PUBLIC" : "")
            + "|CREATE TABLE public.t (id int)|CREATE TRIGGER x BEFORE INSERT ON public.t"
            + " FOR EACH ROW EXECUTE FUNCTION public.audit()");
    refuses(
        db.app(),
        "login role " + APP + " owns schema appsch",
        "function public.audit() is SECURITY DEFINER, owned by " + SU + " outside reach");
  }

  /**
   * Ruling 9, measured first, and it does not hold as written: RESTRICT and NO ACTION write
   * nothing, but the check query is planned as the queried table's owner, and the planner folds an
   * immutable call with constant arguments in that table's index expressions. So a table a check
   * queries has its planner sources judged by O1 (the tests below), and both actions count as O2
   * entry points. The page named this test restrict_fk_check_runs_only_fk_operators.
   */
  @Test
  void restrict_fk_check_plans_as_the_owner_and_folds_its_index_expressions() throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE FUNCTION public.spy(text) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
            + " 'BEGIN RAISE NOTICE ''SPY % as %'', $1, current_user; RETURN 1; END'"
            + "|CREATE TABLE public.rp (id int PRIMARY KEY, d int DEFAULT public.spy('RP_DEFAULT'),"
            + " CHECK (public.spy('RP_CHECK') = 1))|CREATE INDEX ON public.rp ((public.spy('RP_IDX') + id))"
            + "|INSERT INTO public.rp (id) VALUES (1), (2)"
            + "|GRANT SELECT, DELETE ON public.rp TO "
            + APP
            + "|CREATE TABLE public.rc (id int REFERENCES public.rp ON DELETE RESTRICT,"
            + " n int REFERENCES public.rp ON DELETE NO ACTION,"
            + " CHECK (public.spy('RC_CHECK') = 1))"
            + "|CREATE INDEX ON public.rc ((public.spy('RC_IDX') + id))"
            + "|INSERT INTO public.rc VALUES (1, 1)"
            + "|GRANT SELECT, INSERT ON public.rc TO "
            + APP
            + "|CREATE SCHEMA appsch AUTHORIZATION "
            + APP);
    var notices = new ArrayList<String>();
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      // A NO ACTION or RESTRICT check on delete of an unreferenced row, then an insert into the
      // referencing table: the check queries run on both tables as their owner.
      s.execute("DELETE FROM public.rp WHERE id = 2");
      for (SQLWarning w = s.getWarnings(); w != null; w = w.getNextWarning()) {
        notices.add(w.getMessage());
      }
      s.clearWarnings();
      s.execute("INSERT INTO public.rc VALUES (1, 1)");
      for (SQLWarning w = s.getWarnings(); w != null; w = w.getNextWarning()) {
        notices.add(w.getMessage());
      }
    }
    // The role's own insert runs the referencing table's expressions as itself: the control.
    assertThat(notices).anyMatch(n -> n.contains("SPY RC_CHECK as " + APP));
    // The delete's check query on the referencing table is planned as its owner.
    assertThat(notices).contains("SPY RC_IDX as " + SU);
    // Nothing that writes runs as the owner: no default, no CHECK.
    assertThat(notices)
        .noneMatch(n -> n.contains("as " + SU) && (n.contains("DEFAULT") || n.contains("CHECK")));
    refuses(db.app(), "login role " + APP + " owns schema appsch", "foreign key rc_id_fkey");
  }

  @Test
  void fk_check_index_expression_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.rc (pid int REFERENCES public.par ON DELETE RESTRICT)"
            + "|CREATE INDEX rcx ON public.rc ((public.sdi(1) + pid))");
    refusesO1(
        db.app(),
        SDI_LABEL,
        "index expression or predicate",
        "index public.rcx, planned by a foreign-key check on table public.rc");
  }

  @Test
  void fk_check_on_referenced_table_constraint_over_withheld_function_refuses()
      throws SQLException {
    var db = db();
    plant(
        db,
        SDI
            + "|CREATE TABLE public.rp (id int PRIMARY KEY, CONSTRAINT k CHECK (public.sdi(1) > 0))"
            + "|CREATE TABLE public.rc (pid int REFERENCES public.rp)"
            + "|GRANT INSERT ON public.rc TO "
            + APP);
    refusesO1(
        db.app(),
        SDI_LABEL,
        "constraint",
        "constraint k on public.rp, planned by a foreign-key check on table public.rp");
  }

  // ------------------------------------------------------------- pass 1 fixes (PR 53)

  @Test
  void fk_statistics_expression_over_withheld_function_refuses() throws SQLException {
    // C-PR53-2: the planner folds an extended statistics expression as the target's owner.
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|CREATE STATISTICS public.chd ON (public.sdi(2) + pid) FROM public.ch");
    refusesO1(
        db.app(),
        SDI_LABEL,
        "statistics expression",
        "statistics object public.chd on public.ch, written by a foreign-key action");
  }

  @Test
  void fk_check_statistics_expression_over_withheld_function_refuses() throws SQLException {
    var db = db();
    plant(
        db,
        PARENT
            + "|"
            + SDI
            + "|CREATE TABLE public.rc (pid int REFERENCES public.par ON DELETE RESTRICT)"
            + "|CREATE STATISTICS public.rcd ON (public.sdi(1) + pid) FROM public.rc");
    refusesO1(
        db.app(),
        SDI_LABEL,
        "statistics expression",
        "statistics object public.rcd on public.rc, planned by a foreign-key check");
  }

  @Test
  void trigger_grant_on_a_table_owned_outside_reach_refuses() throws SQLException {
    // C-PR53-1: the runtime role may add a trigger whose WHEN runs as the owner on a cascade.
    var db = db();
    plant(
        db,
        PARENT
            + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
            + "|GRANT TRIGGER ON public.ch TO "
            + APP);
    refuses(
        db.app(),
        "login role " + APP + " holds TRIGGER on relation public.ch, owned by " + SU,
        "(O3, C-PR53-1)");
  }

  @Test
  void trigger_grant_to_public_refuses() throws SQLException {
    var db = db();
    plant(db, "CREATE TABLE public.t (i int)|GRANT TRIGGER ON public.t TO PUBLIC");
    refuses(db.app(), "PUBLIC holds TRIGGER on relation public.t");
  }

  @Test
  void trigger_grant_is_not_relaxed_by_allow_privileged_runtime_role() throws SQLException {
    var db = db();
    plant(db, "CREATE TABLE public.t (i int)|GRANT TRIGGER ON public.t TO " + APP);
    assertThatThrownBy(() -> JdbcSupport.verifySchema(db.app(), true, List.of()))
        .hasMessageContaining("(O3, C-PR53-1)");
  }

  @Test
  void owned_partitioned_parent_over_partition_owned_outside_reach_refuses() throws SQLException {
    // C-PR53-3: REINDEX on the parent the runtime role owns rebuilds the partition's index as
    // the partition's owner. Shown first, then refused.
    var db = db();
    plant(
        db,
        "CREATE FUNCTION public.spy(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
            + " 'BEGIN RAISE NOTICE ''SPY as %'', current_user; RETURN $1; END'"
            + "|REVOKE EXECUTE ON FUNCTION public.spy(int) FROM PUBLIC"
            + "|CREATE TABLE public.pp (i int) PARTITION BY RANGE (i)"
            + "|CREATE TABLE public.pp1 (i int)|INSERT INTO public.pp1 VALUES (1)"
            + "|CREATE INDEX pp1x ON public.pp1 ((public.spy(i)))"
            + "|ALTER TABLE public.pp ATTACH PARTITION public.pp1 FOR VALUES FROM (0) TO (10)"
            + "|ALTER TABLE public.pp OWNER TO "
            + APP);
    var seen = new ArrayList<String>();
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      s.execute("REINDEX TABLE public.pp");
      for (SQLWarning w = s.getWarnings(); w != null; w = w.getNextWarning()) {
        seen.add(w.getMessage());
      }
    }
    assertThat(seen).contains("SPY as " + SU);
    refuses(
        db.app(),
        "login role " + APP + " owns partitioned relation public.pp, whose partition public.pp1",
        "(O3, C-PR53-3)");
  }

  static final String OWNED_SCHEMA_OVER_FOREIGN_TABLE =
      "CREATE FUNCTION public.spy(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
          + " 'BEGIN RAISE NOTICE ''SPY as %'', current_user; RETURN $1; END'"
          + "|REVOKE EXECUTE ON FUNCTION public.spy(int) FROM PUBLIC"
          + "|CREATE SCHEMA s2 AUTHORIZATION "
          + APP
          + "|CREATE TABLE s2.t (i int)|INSERT INTO s2.t VALUES (1)"
          + "|CREATE INDEX tx ON s2.t ((public.spy(i)))";

  @Test
  void owned_schema_holding_a_relation_owned_outside_reach_refuses() throws SQLException {
    // C-PR53-6: REINDEX SCHEMA by the schema's owner rebuilds s2.t's index as t's owner, while
    // REINDEX TABLE on it is refused. Shown first, then refused.
    var db = db();
    plant(db, OWNED_SCHEMA_OVER_FOREIGN_TABLE);
    assertThatThrownBy(() -> exec(db.app(), "REINDEX TABLE s2.t"))
        .hasMessageMatching("(?s).*(must be owner|permission denied).*");
    var seen = new ArrayList<String>();
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      s.execute("REINDEX SCHEMA s2");
      for (SQLWarning w = s.getWarnings(); w != null; w = w.getNextWarning()) {
        seen.add(w.getMessage());
      }
    }
    assertThat(seen).contains("SPY as " + SU);
    refuses(
        db.app(),
        "login role " + APP + " owns schema s2, which holds relation s2.t, owned by " + SU,
        "(O3, C-PR53-6)");
  }

  @Test
  void owned_schema_rule_is_not_relaxed_by_allow_privileged_runtime_role() throws SQLException {
    var db = db();
    plant(db, OWNED_SCHEMA_OVER_FOREIGN_TABLE);
    assertThatThrownBy(() -> JdbcSupport.verifySchema(db.app(), true, List.of()))
        .hasMessageContaining("(O3, C-PR53-6)");
  }

  // ------------------------------------------------------------- Q5: O3 and the existing legs

  @Test
  void database_owner_in_reach_refuses() throws SQLException {
    var db = db();
    plant(db, "ALTER DATABASE " + db.name() + " OWNER TO " + APP);
    refuses(db.app(), "is, or is a member of, the owner of database " + db.name());
  }

  // ------------------------------------------------------------- closure

  @Test
  void call_site_record_is_for_the_pinned_server_version() throws IOException, SQLException {
    String version = scalar(admin, "SHOW server_version");
    try (InputStream in = getClass().getResourceAsStream("/owner-context/grep-" + major + ".txt")) {
      assertThat(in).isNotNull();
      String first =
          new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().findFirst().orElse("");
      assertThat(first)
          .describedAs("rerun tools/owner-context-call-sites.sh on the pinned release's sources")
          .isEqualTo("# postgresql " + version.split(" ")[0]);
    }
  }
}
