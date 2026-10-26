package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.PASSWORD;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.images.builder.Transferable;

/**
 * The paths of the function-grants leg (C-PR45-3, design section 3 and section 7), run on one
 * pinned image per subclass. Every test makes its own database, so a grant, a rewritten record or
 * an extension never reaches another test; roles are cluster-wide and dropped after each test.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class FunctionGrantsCases {

  static final String EXT_DIR = "/usr/local/share/postgresql/extension/";

  private final int major;
  private PostgreSQLContainer<?> pg;
  private HikariDataSource admin;
  private int counter;

  private final List<String> databases = new ArrayList<>();
  private final List<String> roles = new ArrayList<>();
  private final List<HikariDataSource> pools = new ArrayList<>();

  FunctionGrantsCases(int major) {
    this.major = major;
  }

  /** One test database: the superuser's pool and the runtime role's pool on it. */
  record Db(String name, HikariDataSource su, HikariDataSource app) {}

  @BeforeAll
  void start() throws SQLException {
    pg = TwoRoleCluster.container(major);
    pg.start();
    TwoRoleCluster.roles(pg);
    admin = TwoRoleCluster.superuser(pg, pg.getDatabaseName());
    // A test-only third-party extension: one native function over pg_trgm's similarity.
    pg.copyFileToContainer(
        Transferable.of("default_version = '1.0'\nrelocatable = true\n"), EXT_DIR + "tp.control");
    pg.copyFileToContainer(
        Transferable.of(
            "CREATE FUNCTION tp_similarity(text, text) RETURNS real"
                + " AS '$libdir/pg_trgm', 'similarity' LANGUAGE c STRICT;\n"),
        EXT_DIR + "tp--1.0.sql");
    // A test-only extension that withholds one function with an internal argument (C-PR47-3).
    pg.copyFileToContainer(
        Transferable.of("default_version = '1.0'\nrelocatable = true\n"), EXT_DIR + "tpi.control");
    pg.copyFileToContainer(
        Transferable.of(
            "CREATE FUNCTION tpi_sel(internal, oid, internal, integer) RETURNS float8"
                + " AS 'eqsel' LANGUAGE internal STRICT;\n"
                + "REVOKE EXECUTE ON FUNCTION tpi_sel(internal, oid, internal, integer)"
                + " FROM PUBLIC;\n"),
        EXT_DIR + "tpi--1.0.sql");
    // A test-only update script to a pgstattuple version no manifest lists (R5v).
    pg.copyFileToContainer(Transferable.of("SELECT 1;\n"), EXT_DIR + "pgstattuple--1.5--1.9.sql");
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
    for (String role : roles.reversed()) {
      exec(admin, "DROP ROLE IF EXISTS " + role);
    }
    roles.clear();
    // Memberships are cluster-wide: give the runtime role back exactly what install() gave it.
    var granted = new ArrayList<String>();
    try (var c = admin.getConnection();
        var st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT m.roleid::pg_catalog.regrole::pg_catalog.text FROM pg_catalog.pg_auth_members m"
                    + " WHERE m.member = '"
                    + APP
                    + "'::pg_catalog.regrole")) {
      while (rs.next()) {
        granted.add(rs.getString(1));
      }
    }
    for (String role : granted) {
      exec(admin, "REVOKE " + role + " FROM " + APP);
    }
  }

  // ------------------------------------------------------------------ helpers

  int major() {
    return major;
  }

  Db db() throws SQLException {
    String name = "fg" + major + "_" + (counter++);
    TwoRoleCluster.install(pg, name);
    databases.add(name);
    var su = keep(TwoRoleCluster.superuser(pg, name));
    var app = keep(TwoRoleCluster.app(pg, name));
    return new Db(name, su, app);
  }

  HikariDataSource keep(HikariDataSource ds) {
    pools.add(ds);
    return ds;
  }

  HikariDataSource pool(String user, String database, String initSql) {
    return keep(TwoRoleCluster.pool(pg, user, PASSWORD, database, initSql));
  }

  /** A NOLOGIN group, dropped after the test. */
  String group(String name) throws SQLException {
    exec(admin, "CREATE ROLE " + name + " NOLOGIN");
    roles.add(name);
    return name;
  }

  String login(String name, String attributes) throws SQLException {
    exec(admin, "CREATE ROLE " + name + " LOGIN PASSWORD '" + PASSWORD + "' " + attributes);
    roles.add(name);
    return name;
  }

  PostgreSQLContainer<?> container() {
    return pg;
  }

  static ShreddingException refusal(DataSource app) {
    return refusal(app, List.of());
  }

  static ShreddingException refusal(DataSource app, List<String> accepted) {
    try {
      JdbcSupport.verifySchema(app, false, accepted);
    } catch (ShreddingException e) {
      return e;
    }
    throw new AssertionError("the gate verified; a refusal was expected");
  }

  static void refuses(DataSource app, String... lines) {
    var e = refusal(app);
    assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    for (String line : lines) {
      assertThat(e).hasMessageContaining(line);
    }
  }

  static void unverifiable(DataSource app, String... lines) {
    var e = refusal(app);
    assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE);
    for (String line : lines) {
      assertThat(e).hasMessageContaining(line);
    }
  }

  static void verifies(DataSource app) {
    verifies(app, List.of());
  }

  static void verifies(DataSource app, List<String> accepted) {
    assertThatCode(() -> JdbcSupport.verifySchema(app, false, accepted)).doesNotThrowAnyException();
  }

  static String held(String fn) {
    return "holds EXECUTE on function " + fn;
  }

  static int count(String text, String part) {
    int n = 0;
    for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) {
      n++;
    }
    return n;
  }

  /** A connection of {@code ds} inside a transaction with the gate's pin, for the seams. */
  static Connection pinned(DataSource ds) throws SQLException {
    Connection c = ds.getConnection();
    c.setAutoCommit(false);
    try (var s = c.createStatement()) {
      s.execute(
          "SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true),"
              + " pg_catalog.set_config('jit', 'off', true)");
    }
    return c;
  }

  // ------------------------------------------------------------------ F1 to F5: who holds it

  @Test
  void execute_on_lo_export_granted_to_the_runtime_role_refuses() throws SQLException {
    var db = db();
    exec(db.su(), "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO " + APP);
    refuses(
        db.app(),
        "login role " + APP + " " + held("pg_catalog.lo_export(oid, text)"),
        "REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) FROM " + APP);
  }

  @Test
  void execute_granted_to_the_login_role_behind_set_role_refuses() throws SQLException {
    var db = db();
    String gw = login("fg_gateway" + major, "NOINHERIT");
    exec(
        db.su(),
        "GRANT " + APP + " TO " + gw,
        "GRANT EXECUTE ON FUNCTION pg_catalog.lo_import(text) TO " + gw);
    refuses(
        pool(gw, db.name(), "SET ROLE " + APP),
        "login role " + gw + " " + held("pg_catalog.lo_import(text)"));
  }

  @Test
  void execute_granted_to_a_group_of_a_noinherit_login_refuses() throws SQLException {
    var db = db();
    String grp = group("fg_grp_ni" + major);
    exec(
        db.su(),
        "GRANT " + grp + " TO " + APP + " WITH INHERIT FALSE",
        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO " + grp);
    refuses(
        db.app(),
        "role "
            + grp
            + ", reachable from login role "
            + APP
            + ", "
            + held("pg_catalog.pg_read_file(text)"));
  }

  @Test
  void execute_granted_to_a_group_of_an_inherit_login_refuses() throws SQLException {
    var db = db();
    String grp = group("fg_grp_in" + major);
    exec(
        db.su(),
        "GRANT " + grp + " TO " + APP,
        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO " + grp);
    refuses(db.app(), "role " + grp + ", reachable", held("pg_catalog.pg_read_file(text)"));
  }

  @Test
  void execute_granted_to_public_on_a_withheld_function_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text, bigint, bigint) TO PUBLIC");
    refuses(db.app(), "PUBLIC " + held("pg_catalog.pg_read_binary_file(text, bigint, bigint)"));
  }

  // ------------------------------------------------------------------ F6 to F12: what is held

  @Test
  void every_withheld_function_of_this_server_refuses_when_granted() throws SQLException {
    var db = db();
    var catalogue = PinnedCatalogue.forMajor(major).orElseThrow();
    var live = new ArrayList<String>();
    try (var c = db.su().getConnection();
        var s = c.createStatement();
        var rs =
            s.executeQuery(
                "SELECT objoid::pg_catalog.regprocedure::pg_catalog.text FROM pg_catalog.pg_init_privs"
                    + " WHERE classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass"
                    + " AND privtype = 'i' ORDER BY objoid")) {
      while (rs.next()) {
        live.add(rs.getString(1));
      }
    }
    assertThat(live).hasSize(62).hasSameSizeAs(catalogue.baseline());
    for (String fn : live) {
      exec(db.su(), "GRANT EXECUTE ON FUNCTION " + fn + " TO PUBLIC");
    }
    var e = refusal(db.app());
    for (var w : catalogue.baseline()) {
      assertThat(e).hasMessageContaining("PUBLIC " + held(w.signature()) + ", which the server");
    }
  }

  @Test
  void execute_on_dblink_connect_u_refuses_once_per_overload() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION dblink",
        "GRANT EXECUTE ON FUNCTION public.dblink_connect_u(text) TO " + APP,
        "GRANT EXECUTE ON FUNCTION public.dblink_connect_u(text, text) TO " + APP);
    var e = refusal(db.app());
    assertThat(count(e.getMessage(), "on function public.dblink_connect_u(text)")).isEqualTo(1);
    assertThat(count(e.getMessage(), "on function public.dblink_connect_u(text, text)"))
        .isEqualTo(1);
  }

  @Test
  void default_privileges_laundered_into_an_extension_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE "
            + pg.getUsername()
            + " GRANT EXECUTE ON FUNCTIONS TO "
            + APP,
        "CREATE EXTENSION dblink");
    refuses(db.app(), held("public.dblink_connect_u(text)"));
  }

  @Test
  void default_privileges_on_an_extension_shipped_public_verifies() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE "
            + pg.getUsername()
            + " GRANT EXECUTE ON FUNCTIONS TO "
            + APP,
        "CREATE EXTENSION pg_trgm");
    verifies(db.app());
  }

  @Test
  void shipped_grant_to_pg_stat_scan_tables_in_reach_refuses() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION pgstattuple", "GRANT pg_stat_scan_tables TO " + APP);
    refuses(db.app(), "role pg_stat_scan_tables, reachable", held("public.pgstattuple("));
  }

  @Test
  void shipped_grant_to_pg_monitor_in_reach_refuses() throws SQLException {
    var db = db();
    exec(db.su(), "GRANT pg_monitor TO " + APP);
    refuses(db.app(), "role pg_monitor, reachable", held("pg_catalog.pg_ls_logdir("));
  }

  @Test
  void extra_grant_to_a_predefined_role_not_in_reach_verifies() throws SQLException {
    var db = db();
    exec(db.su(), "GRANT EXECUTE ON FUNCTION pg_catalog.pg_reload_conf() TO pg_monitor");
    verifies(db.app());
  }

  // ------------------------------------------------------------------ F13 to F17: native code

  @Test
  void internal_alias_of_be_lo_export_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.save_blob(oid, text) RETURNS integer LANGUAGE internal STRICT AS 'be_lo_export'");
    refuses(db.app(), "PUBLIC " + held("public.save_blob(oid, text)"), "symbol be_lo_export");
  }

  @Test
  void alias_added_to_an_extension_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_trgm",
        "CREATE FUNCTION public.save_blob(oid, text) RETURNS integer LANGUAGE internal STRICT AS 'be_lo_export'",
        "ALTER EXTENSION pg_trgm ADD FUNCTION public.save_blob(oid, text)");
    refuses(
        db.app(),
        "PUBLIC " + held("public.save_blob(oid, text)"),
        "the same server code (symbol be_lo_export)");
  }

  @Test
  void clean_database_with_every_available_contrib_extension_verifies() throws SQLException {
    var db = db();
    var catalogue = PinnedCatalogue.forMajor(major).orElseThrow();
    for (String ext : catalogue.installableExtensions()) {
      exec(db.su(), "CREATE EXTENSION IF NOT EXISTS \"" + ext + "\" CASCADE");
    }
    long t0 = System.nanoTime();
    verifies(db.app());
    System.out.printf(
        "MEASURE pg%d: gate with %d extensions installed: %.1f ms%n",
        major, catalogue.installableExtensions().size(), (System.nanoTime() - t0) / 1e6);
  }

  @Test
  void security_definer_c_alias_of_dblink_connect_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.conn_u(text) RETURNS text LANGUAGE c STRICT SECURITY DEFINER"
            + " AS '$libdir/dblink', 'dblink_connect'");
    refuses(db.app(), "PUBLIC " + held("public.conn_u(text)"), "runs with the rights of its owner");
  }

  @Test
  void c_alias_with_any_library_spelling_refuses() throws Exception {
    var db = db();
    var r =
        pg.execInContainer("cp", "/usr/local/lib/postgresql/dblink.so", "/tmp/copy-of-dblink.so");
    assertThat(r.getExitCode()).isZero();
    exec(
        db.su(),
        "CREATE FUNCTION public.a1(text) RETURNS text LANGUAGE c STRICT SECURITY DEFINER AS 'dblink', 'dblink_connect'",
        "CREATE FUNCTION public.a2(text) RETURNS text LANGUAGE c STRICT SECURITY DEFINER AS '$libdir/dblink.so', 'dblink_connect'",
        "CREATE FUNCTION public.a3(text) RETURNS text LANGUAGE c STRICT SECURITY DEFINER AS '/usr/local/lib/postgresql/dblink.so', 'dblink_connect'",
        "CREATE FUNCTION public.a4(text) RETURNS text LANGUAGE c STRICT SECURITY DEFINER AS '/tmp/copy-of-dblink.so', 'dblink_connect'",
        "CREATE EXTENSION dblink",
        "CREATE FUNCTION public.b1(text, text) RETURNS text LANGUAGE c STRICT AS '/tmp/copy-of-dblink.so', 'dblink_connect'");
    // b1 is a caller-rights copy of dblink_connect_u's code, outside any extension: R3.
    refuses(
        db.app(),
        held("public.a1(text)"),
        held("public.a2(text)"),
        held("public.a3(text)"),
        held("public.a4(text)"),
        "function public.b1(text, text) is native code made by hand outside any extension");
  }

  @Test
  void security_definer_native_copy_of_get_raw_page_refuses() throws SQLException {
    var db = db();
    var app = db.app();
    exec(
        db.su(),
        "CREATE FUNCTION public.rawpage(text, bigint) RETURNS bytea LANGUAGE c STRICT SECURITY DEFINER"
            + " AS '$libdir/pageinspect', 'get_raw_page_1_9'");
    refuses(app, "PUBLIC " + held("public.rawpage(text, bigint)"), "rights of its owner");
  }

  @Test
  void security_definer_internal_copy_of_pg_import_system_collations_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.imp(regnamespace) RETURNS integer LANGUAGE internal STRICT SECURITY DEFINER"
            + " AS 'pg_import_system_collations'");
    refuses(db.app(), "PUBLIC " + held("public.imp(regnamespace)"), "rights of its owner");
  }

  @Test
  void operator_over_a_withheld_function_is_refused_by_the_server() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE OPERATOR public.>>> (LEFTARG = oid, RIGHTARG = text, FUNCTION = pg_catalog.lo_export)");
    assertThatThrownBy(() -> exec(db.app(), "SELECT 0::oid OPERATOR(public.>>>) '/tmp/x'"))
        .hasMessageContaining("permission denied for function lo_export");
  }

  // ------------------------------------------------------------------ F20, F24, F25, F27, F38

  private void wrapper(Db db, String grantee) throws SQLException {
    exec(
        db.su(),
        "CREATE FUNCTION public.export_blob(o oid, f text) RETURNS integer LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT pg_catalog.lo_export(o, f)'",
        "REVOKE EXECUTE ON FUNCTION public.export_blob(oid, text) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.export_blob(oid, text) TO " + grantee);
  }

  @Test
  void security_definer_sql_wrapper_is_the_stated_limit() throws SQLException {
    // L19 in SECURITY-NOTES: a wrapper with a body passes. If a change closes it, change the notes.
    var db = db();
    wrapper(db, "PUBLIC");
    verifies(db.app());
  }

  @Test
  void published_security_definer_audit_query_lists_a_wrapper_granted_to_a_group()
      throws Exception {
    var db = db();
    String grp = group("fg_wrap" + major);
    exec(db.su(), "GRANT " + grp + " TO " + APP + " WITH INHERIT FALSE");
    wrapper(db, grp);
    String notes = Files.readString(Path.of("../SECURITY-NOTES.md"));
    Matcher m =
        Pattern.compile("<!-- l19-audit-query -->\\s*```sql\\n(.*?)```", Pattern.DOTALL)
            .matcher(notes);
    assertThat(m.find()).describedAs("SECURITY-NOTES carries the L19 audit query").isTrue();
    String query = m.group(1).replace("'app'", "'" + APP + "'");
    var listed = new ArrayList<String>();
    try (var c = db.su().getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery(query)) {
      while (rs.next()) {
        listed.add(rs.getString("function") + " via " + rs.getString("executable_via"));
      }
    }
    assertThat(listed).contains("export_blob(oid,text) via " + grp);
  }

  @Test
  void published_security_definer_audit_query_lists_a_revoked_wrapper_an_aggregate_calls()
      throws Exception {
    // C-PR47-2: the second half of the L19 query lists a wrapper nobody may execute directly.
    var db = db();
    exec(
        db.su(),
        DEFINER_W,
        REVOKE_W,
        "CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text,"
            + " initcond = 'PG_VERSION')");
    String notes = Files.readString(Path.of("../SECURITY-NOTES.md"));
    Matcher m =
        Pattern.compile("<!-- l19-audit-query -->\\s*```sql\\n(.*?)```", Pattern.DOTALL)
            .matcher(notes);
    assertThat(m.find()).isTrue();
    var listed = new ArrayList<String>();
    try (var c = db.su().getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery(m.group(1).replace("'app'", "'" + APP + "'"))) {
      while (rs.next()) {
        listed.add(rs.getString("function") + " via " + rs.getString("executable_via"));
      }
    }
    assertThat(listed).contains("w(text,boolean) via called by aggregate agg_w(boolean)");
  }

  @Test
  void withheld_function_in_a_schema_without_usage_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE SCHEMA hidden",
        "CREATE EXTENSION dblink SCHEMA hidden",
        "REVOKE ALL ON SCHEMA hidden FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION hidden.dblink_connect_u(text) TO " + APP);
    refuses(db.app(), held("hidden.dblink_connect_u(text)"));
  }

  @Test
  void unreadable_pg_init_privs_refuses_with_005() throws SQLException {
    var db = db();
    exec(db.su(), "REVOKE SELECT ON pg_catalog.pg_init_privs FROM PUBLIC");
    unverifiable(db.app());
  }

  @Test
  void allow_privileged_runtime_role_warns_with_the_function_leg() throws SQLException {
    var db = db();
    exec(db.su(), "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO " + APP);
    var verdict = JdbcSupport.verifySchema(db.app(), true);
    assertThat(verdict.privilegeLegs())
        .anySatisfy(l -> assertThat(l).contains(held("pg_catalog.lo_export(oid, text)")));
  }

  // ------------------------------------------------------------------ F31 to F37: the record

  @Test
  void extension_drop_function_then_grant_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION dblink",
        "ALTER EXTENSION dblink DROP FUNCTION public.dblink_connect_u(text)",
        "GRANT EXECUTE ON FUNCTION public.dblink_connect_u(text) TO " + APP);
    refuses(db.app(), held("public.dblink_connect_u(text)"));
  }

  @Test
  void extension_add_of_lo_export_after_public_grant_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_trgm",
        "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO PUBLIC",
        "ALTER EXTENSION pg_trgm ADD FUNCTION pg_catalog.lo_export(oid, text)");
    refuses(
        db.app(),
        "the shipped record of function pg_catalog.lo_export(oid, text) names PUBLIC",
        "the shipped record of function pg_catalog.lo_export(oid, text) was changed after initdb");
  }

  @Test
  void extension_add_then_drop_of_an_initdb_function_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_trgm",
        "ALTER EXTENSION pg_trgm ADD FUNCTION pg_catalog.lo_export(oid, text)",
        "ALTER EXTENSION pg_trgm DROP FUNCTION pg_catalog.lo_export(oid, text)");
    refuses(db.app(), "the shipped record of function pg_catalog.lo_export(oid, text) is missing");
  }

  @Test
  void drop_extension_then_hand_made_c_function_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.w(text) RETURNS text LANGUAGE c STRICT AS '$libdir/dblink', 'dblink_connect'");
    refuses(db.app(), "function public.w(text) is native code made by hand outside any extension");
  }

  @Test
  void default_privileges_to_an_accepted_role_before_create_extension_refuses()
      throws SQLException {
    var db = db();
    exec(
        db.su(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE "
            + pg.getUsername()
            + " GRANT EXECUTE ON FUNCTIONS TO pg_signal_backend",
        "GRANT pg_signal_backend TO " + APP,
        "CREATE EXTENSION dblink");
    refuses(db.app(), "role pg_signal_backend, reachable", held("public.dblink_connect_u(text)"));
  }

  @Test
  void hardened_default_privileges_with_pgcrypto_verifies() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "ALTER DEFAULT PRIVILEGES FOR ROLE "
            + pg.getUsername()
            + " REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
        "CREATE SCHEMA crypto",
        "CREATE EXTENSION pgcrypto SCHEMA crypto",
        "GRANT USAGE ON SCHEMA crypto TO " + APP,
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA crypto TO " + APP);
    verifies(db.app());
  }

  @Test
  void owner_transfer_of_a_withheld_function_refuses() throws SQLException {
    var db = db();
    String grp = group("fg_own" + major);
    exec(
        db.su(),
        "GRANT " + grp + " TO " + APP + " WITH INHERIT FALSE",
        "ALTER FUNCTION pg_catalog.lo_import(text) OWNER TO " + grp);
    refuses(
        db.app(),
        "role "
            + grp
            + ", reachable from login role "
            + APP
            + ", owns function pg_catalog.lo_import(text)");
  }

  // ------------------------------------------------------------------ F41 to F45: R5 and R4

  private static final String WAL = "pg_get_wal_record_info(pg_lsn)";

  private void launderWal(Db db) throws SQLException {
    exec(
        db.su(),
        "CREATE EXTENSION pg_walinspect",
        "ALTER EXTENSION pg_walinspect DROP FUNCTION public." + WAL,
        "DROP FUNCTION public." + WAL);
  }

  @Test
  void recreated_extension_function_added_back_refuses() throws SQLException {
    var db = db();
    launderWal(db);
    exec(
        db.su(),
        "CREATE FUNCTION public."
            + WAL
            + " RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_record_info'",
        "ALTER EXTENSION pg_walinspect ADD FUNCTION public." + WAL,
        // the same code under another name: R5a case 2, by symbol
        "CREATE FUNCTION public.wal_info(pg_lsn) RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_record_info'",
        "ALTER EXTENSION pg_walinspect ADD FUNCTION public.wal_info(pg_lsn)");
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.pg_get_wal_record_info(pg_lsn)")
            + ", which runs code that pg_walinspect 1.1 ships without EXECUTE for PUBLIC",
        "PUBLIC "
            + held("public.wal_info(pg_lsn)")
            + ", which runs code that pg_walinspect 1.1 ships without EXECUTE for PUBLIC (symbol pg_get_wal_record_info");
  }

  @Test
  void recreated_contrib_function_with_another_symbol_refuses() throws SQLException {
    var db = db();
    launderWal(db);
    exec(
        db.su(),
        "CREATE FUNCTION public."
            + WAL
            + " RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_stats'",
        "ALTER EXTENSION pg_walinspect ADD FUNCTION public." + WAL);
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.pg_get_wal_record_info(pg_lsn)")
            + ", which runs the same server code (symbol pg_get_wal_stats)");
  }

  @Test
  void foreign_symbol_added_to_a_contrib_extension_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_walinspect",
        "CREATE FUNCTION public.fw(text, text) RETURNS real LANGUAGE c STRICT AS '$libdir/pg_trgm', 'similarity'",
        "ALTER EXTENSION pg_walinspect ADD FUNCTION public.fw(text, text)");
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.fw(text, text)")
            + ", a member of extension pg_walinspect 1.1 that the PostgreSQL "
            + major
            + " manifest does not list");
  }

  @Test
  void recreated_extension_function_added_to_another_extension_refuses() throws SQLException {
    var db = db();
    launderWal(db);
    exec(
        db.su(),
        "CREATE FUNCTION public."
            + WAL
            + " RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_record_info'",
        "ALTER EXTENSION plpgsql ADD FUNCTION public." + WAL);
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.pg_get_wal_record_info(pg_lsn)")
            + ", a member of extension plpgsql 1.0");
  }

  @Test
  void drop_extension_then_hand_made_function_added_to_an_extension_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_walinspect",
        "DROP EXTENSION pg_walinspect",
        "CREATE EXTENSION pg_trgm",
        "CREATE FUNCTION public."
            + WAL
            + " RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_record_info'",
        "ALTER EXTENSION pg_trgm ADD FUNCTION public." + WAL);
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.pg_get_wal_record_info(pg_lsn)")
            + ", a member of extension pg_trgm");
  }

  @Test
  void extension_drop_grant_public_add_back_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION dblink",
        "ALTER EXTENSION dblink DROP FUNCTION public.dblink_connect_u(text)",
        "GRANT EXECUTE ON FUNCTION public.dblink_connect_u(text) TO PUBLIC",
        "ALTER EXTENSION dblink ADD FUNCTION public.dblink_connect_u(text)");
    refuses(
        db.app(),
        "the extension record of function public.dblink_connect_u(text) grants EXECUTE to PUBLIC explicitly");
  }

  @Test
  void third_party_extension_native_function_refuses_by_default() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION tp");
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.tp_similarity(text, text)")
            + ", native code of third-party extension tp");
  }

  @Test
  void accepted_third_party_extension_verifies_and_warns() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION tp");
    verifies(db.app(), List.of(" tp "));
  }

  @Test
  void accepted_third_party_member_with_a_withheld_symbol_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION tp",
        "CREATE FUNCTION public.tpw(pg_lsn) RETURNS text LANGUAGE c STRICT AS '$libdir/pg_walinspect', 'pg_get_wal_record_info'",
        "ALTER EXTENSION tp ADD FUNCTION public.tpw(pg_lsn)");
    var e = refusal(db.app(), List.of("tp"));
    assertThat(e)
        .hasMessageContaining(
            "PUBLIC "
                + held("public.tpw(pg_lsn)")
                + ", a member of extension tp that the manifest has no record of")
        .hasMessageContaining("revoke EXECUTE on it from PUBLIC and from every role in reach");
  }

  @Test
  void accepted_list_naming_a_manifest_extension_refuses_to_start() throws SQLException {
    var db = db();
    assertThatThrownBy(() -> JdbcSupport.verifySchema(db.app(), false, List.of("DbLink")))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG))
        .hasMessageContaining("an extension the PostgreSQL " + major + " image ships");
  }

  // ------------------------------------------------------------------ F46 to F51, R0, R5v

  @Test
  void older_extension_version_shipped_public_verifies() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION pgstattuple VERSION '1.4'");
    verifies(db.app());
  }

  @Test
  void older_version_re_created_with_the_newer_symbol_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pgstattuple VERSION '1.4'",
        "ALTER EXTENSION pgstattuple DROP FUNCTION public.pgstattuple(text)",
        "DROP FUNCTION public.pgstattuple(text)",
        "CREATE FUNCTION public.pgstattuple(text) RETURNS text LANGUAGE c STRICT AS '$libdir/pgstattuple', 'pgstattuple_v1_5'",
        "ALTER EXTENSION pgstattuple ADD FUNCTION public.pgstattuple(text)");
    refuses(
        db.app(),
        "PUBLIC "
            + held("public.pgstattuple(text)")
            + ", a member of extension pgstattuple 1.4 that the PostgreSQL "
            + major
            + " manifest does not list for that version");
  }

  @Test
  void extension_in_another_schema_verifies() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE SCHEMA s",
        "CREATE EXTENSION dblink SCHEMA s",
        "CREATE EXTENSION pg_walinspect SCHEMA s");
    verifies(db.app());
  }

  @Test
  void r0_is_independent_of_the_session_search_path() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE SCHEMA s",
        "CREATE DOMAIN s.text AS pg_catalog.varchar",
        "CREATE FUNCTION s.pg_read_file(s.text) RETURNS pg_catalog.text LANGUAGE sql AS 'SELECT ''x''::pg_catalog.text'",
        "ALTER ROLE "
            + APP
            + " IN DATABASE "
            + db.name()
            + " SET search_path = public, s, pg_catalog",
        "GRANT USAGE ON SCHEMA s TO " + APP);
    var app = keep(TwoRoleCluster.app(pg, db.name()));
    // The hostile path is live for the runtime role: outside the pinned window the signature of
    // lo_export reads pg_catalog.text, so the baseline would not match (mutation 23).
    assertThat(
            TwoRoleCluster.scalar(
                app, "SELECT pg_catalog.pg_get_function_identity_arguments(765::pg_catalog.oid)"))
        .isEqualTo("oid, pg_catalog.text");
    verifies(app);
  }

  @Test
  void baseline_signature_differing_from_the_live_oid_refuses_with_005() throws SQLException {
    var db = db();
    var real = PinnedCatalogue.forMajor(major).orElseThrow();
    var baseline = new ArrayList<>(real.baseline());
    var first = baseline.get(0);
    baseline.set(
        0,
        new PinnedCatalogue.Withheld(
            first.oid(),
            "pg_catalog.foo(text)",
            first.key(),
            first.symbol(),
            first.securityDefiner(),
            first.acl()));
    var doctored =
        PinnedCatalogue.of(major, baseline, real.manifest(), real.versions(), real.core());
    try (Connection c = pinned(db.app())) {
      var rows = FunctionGrants.judgeRecords(FunctionGrants.records(c, doctored), doctored);
      assertThat(rows)
          .singleElement()
          .satisfies(
              r -> {
                assertThat(r.rule()).isEqualTo("R0");
                assertThat(FunctionGrantMessages.signature(r, major))
                    .contains("baseline expects pg_catalog.foo(text)");
              });
      c.rollback();
    }
  }

  @Test
  void server_major_without_a_baseline_refuses_with_005() throws SQLException {
    var db = db();
    long oid =
        Long.parseLong(
            TwoRoleCluster.scalar(
                db.app(), "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user"));
    var reach =
        new SchemaVerification.Reach(
            oid,
            APP,
            APP,
            List.of(new SchemaVerification.ReachRole(oid, APP, false, false, false)));
    try (Connection c = pinned(db.app())) {
      assertThatThrownBy(
              () ->
                  FunctionGrants.check(
                      c, reach, List.of(), new ArrayList<>(), m -> Optional.empty()))
          .isInstanceOfSatisfying(
              ShreddingException.class,
              e -> assertThat(e.code()).isEqualTo(ErrorCodes.SCHEMA_UNVERIFIABLE))
          .hasMessageContaining(
              "no pinned initdb baseline and extension manifest for PostgreSQL " + major);
      c.rollback();
    }
  }

  @Test
  void extension_version_not_in_the_manifest_refuses_with_005() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION pgstattuple", "ALTER EXTENSION pgstattuple UPDATE TO '1.9'");
    unverifiable(
        db.app(),
        "extension pgstattuple is installed at version 1.9",
        "A module release with that version");
  }

  @Test
  void extension_left_at_an_update_source_version_refuses_with_the_update_remedy()
      throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION pg_stat_statements VERSION '1.4'",
        "UPDATE pg_catalog.pg_extension SET extversion = '1.3' WHERE extname = 'pg_stat_statements'");
    unverifiable(
        db.app(),
        "extension pg_stat_statements is installed at version 1.3",
        "update it with ALTER EXTENSION pg_stat_statements UPDATE");
    exec(db.su(), "ALTER EXTENSION pg_stat_statements UPDATE");
    verifies(db.app());
  }

  // ------------------------------------------------------------------ JIT (C-PR45-3-18)

  @Test
  void statement_two_gives_the_same_rows_with_jit_on_and_off() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO " + APP,
        "CREATE FUNCTION public.save_blob(oid, text) RETURNS integer LANGUAGE internal STRICT AS 'be_lo_export'");
    var catalogue = PinnedCatalogue.forMajor(major).orElseThrow();
    long[] none = new long[0];
    long[] baseline = FunctionGrants.baselineOids(catalogue);
    List<FunctionGrantsSql.ExecuteFact> off;
    List<FunctionGrantsSql.ExecuteFact> on;
    long t0 = System.nanoTime();
    try (Connection c = pinned(db.app())) {
      off = FunctionGrantsSql.executes(c, none, baseline);
      c.rollback();
    }
    long t1 = System.nanoTime();
    try (Connection c = pinned(db.app());
        var s = c.createStatement()) {
      s.execute(
          "SELECT pg_catalog.set_config('jit', 'on', true), pg_catalog.set_config('jit_above_cost', '0', true)");
      on = FunctionGrantsSql.executes(c, none, baseline);
      c.rollback();
    }
    long t2 = System.nanoTime();
    assertThat(on).isEqualTo(off).isNotEmpty();
    System.out.printf(
        "MEASURE pg%d: statement 2 jit off %.1f ms, jit on %.1f ms%n",
        major, (t1 - t0) / 1e6, (t2 - t1) / 1e6);
  }

  @Test
  void gate_leaves_jit_and_search_path_as_they_were() throws SQLException {
    var db = db();
    var one = pool(APP, db.name(), "SET search_path = public, pg_catalog");
    String jit = TwoRoleCluster.scalar(one, "SELECT pg_catalog.current_setting('jit')");
    String path = TwoRoleCluster.scalar(one, "SELECT pg_catalog.current_setting('search_path')");
    JdbcSupport.verifySchema(one);
    assertThat(TwoRoleCluster.scalar(one, "SELECT pg_catalog.current_setting('jit')"))
        .isEqualTo(jit);
    assertThat(TwoRoleCluster.scalar(one, "SELECT pg_catalog.current_setting('search_path')"))
        .isEqualTo(path);
  }

  // ------------------------------------- R6, caller objects (design revision 5, C-PR45-3-15)

  private static final String READ2 = "pg_catalog.pg_read_file(text, boolean)";
  private static final String READ1 = "pg_catalog.pg_read_file(text)";

  /** The first column of the first row, as the given pool. */
  static String scalar(DataSource ds, String sql) throws SQLException {
    try (var c = ds.getConnection();
        var st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getString(1) : "";
    }
  }

  /**
   * A hand-made copy of core function {@code fn} in language internal, as {@code public.r6_copy},
   * with EXECUTE revoked from PUBLIC: no other leg sees it, only R6 through the object naming it.
   */
  static String handMadeCopy(Db db, String fn) throws SQLException {
    exec(
        db.su(),
        "DO $$ DECLARE p pg_catalog.oid := '"
            + fn
            + "'::pg_catalog.regprocedure; BEGIN"
            + " EXECUTE pg_catalog.format('CREATE FUNCTION public.r6_copy(%s) RETURNS %s"
            + " LANGUAGE internal%s AS %L', pg_catalog.pg_get_function_identity_arguments(p),"
            + " pg_catalog.pg_get_function_result(p),"
            + " (SELECT CASE WHEN x.proisstrict THEN ' STRICT' ELSE '' END"
            + " FROM pg_catalog.pg_proc x WHERE x.oid = p),"
            + " (SELECT x.prosrc FROM pg_catalog.pg_proc x WHERE x.oid = p));"
            + " EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION public.r6_copy(%s) FROM"
            + " PUBLIC', pg_catalog.pg_get_function_identity_arguments(p)); END $$");
    return scalar(
        db.su(),
        "SELECT pg_catalog.concat('public.r6_copy(',"
            + " pg_catalog.pg_get_function_identity_arguments('public.r6_copy'::pg_catalog.regproc),"
            + " ')')");
  }

  @Test
  void aggregate_with_sfunc_pg_read_file_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_s(boolean) (sfunc = pg_catalog.pg_read_file,"
            + " stype = text, initcond = 'PG_VERSION')");
    // The path itself (A1): the runtime role reads a file it may not read directly.
    assertThat(scalar(db.app(), "SELECT public.agg_s(true)")).startsWith(Integer.toString(major));
    assertThatThrownBy(() -> scalar(db.app(), "SELECT pg_catalog.pg_read_file('PG_VERSION')"))
        .hasMessageContaining("permission denied for function pg_read_file");
    refuses(
        db.app(),
        "PUBLIC or a role in reach may use aggregate public.agg_s(boolean), owned by",
        "outside reach, whose transfn is function " + READ2,
        "a function the server ships without EXECUTE for PUBLIC");
  }

  @Test
  void aggregate_with_finalfunc_pg_read_file_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_f(text) (sfunc = pg_catalog.textcat, stype = text,"
            + " initcond = '', finalfunc = pg_catalog.pg_read_file)");
    assertThat(scalar(db.app(), "SELECT public.agg_f('PG_VERSION')"))
        .startsWith(Integer.toString(major));
    refuses(db.app(), "aggregate public.agg_f(text)", "whose finalfn is function " + READ1);
  }

  @Test
  void moving_aggregate_with_mfinalfunc_pg_read_file_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_m(text) (sfunc = pg_catalog.textcat, stype = text,"
            + " initcond = '', msfunc = pg_catalog.textcat, minvfunc = pg_catalog.textcat,"
            + " mstype = text, minitcond = '', mfinalfunc = pg_catalog.pg_read_file)");
    // The moving path (A4): the window frame runs mfinalfunc with no check for the caller.
    assertThat(
            scalar(
                db.app(),
                "SELECT pg_catalog.max(m) FROM (SELECT public.agg_m(x) OVER (ROWS BETWEEN"
                    + " CURRENT ROW AND CURRENT ROW) AS m FROM (VALUES ('PG_VERSION')) AS v(x)) AS w"))
        .startsWith(Integer.toString(major));
    refuses(db.app(), "aggregate public.agg_m(text)", "whose mfinalfn is function " + READ1);
  }

  /** Slot k of the R6 aggregate list, with the core function each template puts there. */
  private static final String[] SLOT_FUNCTIONS = {
    "pg_catalog.string_agg_transfn(internal, text, text)",
    "pg_catalog.string_agg_finalfn(internal)",
    "pg_catalog.string_agg_combine(internal, internal)",
    "pg_catalog.string_agg_serialize(internal)",
    "pg_catalog.string_agg_deserialize(bytea, internal)",
    "pg_catalog.textcat(text, text)",
    "pg_catalog.textcat(text, text)",
    "pg_catalog.lower(text)"
  };

  /**
   * Each of the eight aggregate slots is judged: the slot's function is replaced by a hand-made
   * internal copy that PUBLIC may not execute (R3 code), and only R6 can see it.
   */
  @ParameterizedTest
  @ValueSource(ints = {1, 2, 3, 4, 5, 6, 7, 8})
  void each_aggregate_slot_running_hand_made_native_code_refuses(int slot) throws SQLException {
    var db = db();
    String copy = handMadeCopy(db, SLOT_FUNCTIONS[slot - 1]);
    var f = new String[8];
    for (int i = 0; i < 8; i++) {
      String fn = i == slot - 1 ? copy : SLOT_FUNCTIONS[i];
      f[i] = fn.substring(0, fn.indexOf('('));
    }
    String sql =
        slot <= 5
            ? "CREATE AGGREGATE public.agg_t(text, text) (sfunc = "
                + f[0]
                + ", stype = internal, finalfunc = "
                + f[1]
                + ", combinefunc = "
                + f[2]
                + ", serialfunc = "
                + f[3]
                + ", deserialfunc = "
                + f[4]
                + ")"
            : "CREATE AGGREGATE public.agg_t(text) (sfunc = pg_catalog.textcat, stype = text,"
                + " initcond = '', msfunc = "
                + f[5]
                + ", minvfunc = "
                + f[6]
                + ", mstype = text, minitcond = '', mfinalfunc = "
                + f[7]
                + ")";
    exec(db.su(), sql);
    String name = FunctionGrants.SLOTS.get("agg").get(slot - 1);
    refuses(
        db.app(),
        "whose " + name + " is function " + copy,
        "native code created outside any extension");
  }

  @Test
  void aggregate_over_a_withheld_function_owned_by_the_runtime_role_is_skipped_by_r6()
      throws SQLException {
    // Its owner checks run as the runtime role, which may not execute pg_read_file: the call
    // fails at run time, and legs 1 to 3 judge what reach holds.
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_s(boolean) (sfunc = pg_catalog.pg_read_file,"
            + " stype = text, initcond = 'PG_VERSION')",
        "ALTER AGGREGATE public.agg_s(boolean) OWNER TO " + APP);
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.agg_s(true)"))
        .hasMessageContaining("permission denied for function pg_read_file");
    verifies(db.app());
  }

  @Test
  void hand_made_aggregate_over_core_functions_owned_outside_reach_verifies() throws SQLException {
    // The interim rule refused it by R3, by accident: an aggregate runs no code of its own.
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.my_sum(integer) (sfunc = pg_catalog.int4pl, stype = integer)");
    verifies(db.app());
  }

  @Test
  void aggregate_over_a_withheld_function_nobody_in_reach_may_use_verifies() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE AGGREGATE public.agg_s(boolean) (sfunc = pg_catalog.pg_read_file,"
            + " stype = text, initcond = 'PG_VERSION')",
        "REVOKE EXECUTE ON FUNCTION public.agg_s(boolean) FROM PUBLIC");
    verifies(db.app());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "pg_stat_reset_single_table_counters",
        "pg_stat_reset_single_function_counters",
        "pg_stat_reset_subscription_stats",
        "pg_ls_tmpdir"
      })
  void trusted_language_with_a_withheld_validator_refuses(String validator) throws SQLException {
    // L1: the validator fires on CREATE FUNCTION with no EXECUTE check (round 5 review). The
    // fourth fit, pg_ls_tmpdir(oid), was measured at build time: no return-type check either.
    var db = db();
    exec(
        db.su(),
        "CREATE TRUSTED LANGUAGE r6lang HANDLER pg_catalog.plpgsql_call_handler"
            + " VALIDATOR pg_catalog."
            + validator);
    refuses(
        db.app(),
        "may create functions in language r6lang, owned by",
        "whose validator is function pg_catalog." + validator + "(",
        "a function the server ships without EXECUTE for PUBLIC");
  }

  @Test
  void untrusted_language_with_a_withheld_validator_verifies() throws SQLException {
    // Only a superuser may create functions in an untrusted language.
    var db = db();
    exec(
        db.su(),
        "CREATE LANGUAGE r6lang HANDLER pg_catalog.plpgsql_call_handler"
            + " VALIDATOR pg_catalog.pg_stat_reset_single_table_counters");
    verifies(db.app());
  }

  @Test
  void language_owned_by_the_runtime_role_with_a_withheld_validator_refuses() throws SQLException {
    // C-PR47-1: a validator runs with no EXECUTE check, so the owner's place plays no part.
    var db = db();
    exec(
        db.su(),
        "CREATE TRUSTED LANGUAGE r6lang HANDLER pg_catalog.plpgsql_call_handler"
            + " VALIDATOR pg_catalog.pg_ls_tmpdir",
        "ALTER LANGUAGE r6lang OWNER TO " + APP);
    var e = refusal(db.app());
    assertThat(e)
        .hasMessageContaining(
            "may create functions in language r6lang, owned by " + APP + ", whose")
        .hasMessageContaining("whose validator is function pg_catalog.pg_ls_tmpdir(")
        .hasMessageNotContaining(APP + " outside reach");
  }

  @Test
  void operator_owned_by_the_runtime_role_with_a_hand_made_estimator_refuses() throws SQLException {
    // C-PR47-1: the planner calls an estimator with no EXECUTE check, whoever owns the operator.
    var db = db();
    String rest = handMadeCopy(db, "pg_catalog.eqsel(internal, oid, internal, integer)");
    exec(
        db.su(),
        "CREATE OPERATOR public.=== (LEFTARG = text, RIGHTARG = text,"
            + " FUNCTION = pg_catalog.texteq, RESTRICT = public.r6_copy)",
        "ALTER OPERATOR public.=== (text, text) OWNER TO " + APP);
    refuses(
        db.app(),
        "operator public.===(text,text), owned by " + APP + ", whose oprrest is function " + rest,
        "native code created outside any extension");
  }

  // ------------------------------------------- C-PR47-2: revoked SECURITY DEFINER wrappers

  private static final String DEFINER_W =
      "CREATE FUNCTION public.w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
          + " AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)'";
  private static final String REVOKE_W =
      "REVOKE EXECUTE ON FUNCTION public.w(text, boolean) FROM PUBLIC";
  private static final String W_REASON =
      "a SECURITY DEFINER function that neither PUBLIC nor a role whose rights the login may"
          + " use may execute";

  @Test
  void aggregate_over_a_revoked_security_definer_wrapper_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        DEFINER_W,
        REVOKE_W,
        "CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text,"
            + " initcond = 'PG_VERSION')");
    assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));
    refuses(
        db.app(),
        "aggregate public.agg_w(boolean)",
        "whose transfn is function public.w(text, boolean)",
        W_REASON);
  }

  @Test
  void core_aggregate_rewritten_over_a_revoked_wrapper_refuses() throws SQLException {
    // Oid 2518 and the symbol aggregate_dummy stay, so R7 is silent; R6 sees the wrapper.
    var db = db();
    exec(
        db.su(),
        DEFINER_W,
        REVOKE_W,
        "CREATE FUNCTION public.tobool(text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "CREATE OR REPLACE AGGREGATE pg_catalog.bool_or(boolean) (sfunc = public.w,"
            + " stype = text, initcond = 'PG_VERSION', finalfunc = public.tobool)");
    refuses(
        db.app(),
        "aggregate pg_catalog.bool_or(boolean)",
        "whose transfn is function public.w(text, boolean)",
        W_REASON);
  }

  @Test
  void contrib_aggregate_over_a_same_key_wrapper_in_another_schema_refuses() throws SQLException {
    // The manifest key citext_larger(citext,citext) has no schema, so R5b sees the shipped
    // support set; statement 3's schema-qualified name and rights mode tell the wrapper apart.
    var db = db();
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
    refuses(
        db.app(),
        "aggregate public.max(public.citext)",
        "whose transfn is function evil.citext_larger(",
        "whose combinefn is function evil.citext_larger(",
        W_REASON);
  }

  @Test
  void trusted_language_with_a_revoked_security_definer_validator_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.v(pg_catalog.oid) RETURNS void LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT 1'",
        "REVOKE EXECUTE ON FUNCTION public.v(pg_catalog.oid) FROM PUBLIC",
        "CREATE TRUSTED LANGUAGE r6lang HANDLER pg_catalog.plpgsql_call_handler"
            + " VALIDATOR public.v");
    refuses(
        db.app(),
        "may create functions in language r6lang",
        "whose validator is function public.v(oid)",
        W_REASON);
  }

  @Test
  void aggregate_over_a_public_security_definer_wrapper_is_the_stated_limit() throws SQLException {
    // L19: reach may call the wrapper directly, so the aggregate gives nothing more.
    var db = db();
    exec(
        db.su(),
        DEFINER_W,
        "CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text,"
            + " initcond = 'PG_VERSION')");
    verifies(db.app());
  }

  // ------------------------------- C-PR47-4: reach may run it only with rights the login may use

  private static final String AGG_W =
      "CREATE AGGREGATE public.agg_w(boolean) (sfunc = public.w, stype = text,"
          + " initcond = 'PG_VERSION')";

  @Test
  void aggregate_over_a_wrapper_granted_to_a_no_inherit_no_set_member_refuses()
      throws SQLException {
    // A grant WITH INHERIT FALSE, SET FALSE gives the login none of g's rights: a direct call is
    // denied, so the aggregate gives more than a direct call and R6 refuses it.
    var db = db();
    String g = group("fg_nis" + major);
    exec(
        db.su(),
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET FALSE",
        DEFINER_W,
        REVOKE_W,
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        AGG_W);
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
        .hasMessageContaining("permission denied for function w");
    refuses(
        db.app(),
        "aggregate public.agg_w(boolean)",
        "whose transfn is function public.w(text, boolean)",
        W_REASON);
  }

  @Test
  void aggregate_over_a_wrapper_owned_by_a_no_inherit_no_set_member_refuses() throws SQLException {
    // The owner side: w1 runs as g, which the login cannot use, and calls w, granted to g only.
    var db = db();
    String g = group("fg_nio" + major);
    exec(
        db.su(),
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET FALSE",
        DEFINER_W,
        REVOKE_W,
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        "CREATE FUNCTION public.w1(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT public.w($1, $2)'",
        "REVOKE EXECUTE ON FUNCTION public.w1(text, boolean) FROM PUBLIC",
        "ALTER FUNCTION public.w1(text, boolean) OWNER TO " + g,
        "CREATE AGGREGATE public.agg_w1(boolean) (sfunc = public.w1, stype = text,"
            + " initcond = 'PG_VERSION')");
    refuses(
        db.app(),
        "aggregate public.agg_w1(boolean)",
        "whose transfn is function public.w1(text, boolean)",
        W_REASON);
  }

  @Test
  void aggregate_over_a_wrapper_granted_to_an_inherited_group_is_the_stated_limit()
      throws SQLException {
    // L19: the login inherits g's rights and may call w directly, so the aggregate gives nothing
    // more.
    var db = db();
    String g = group("fg_inh" + major);
    exec(
        db.su(),
        "GRANT " + g + " TO " + APP + " WITH INHERIT TRUE, SET FALSE",
        DEFINER_W,
        REVOKE_W,
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        AGG_W);
    assertThat(scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
        .startsWith(Integer.toString(major));
    verifies(db.app());
  }

  @Test
  void aggregate_over_a_wrapper_granted_to_a_set_only_group_is_the_stated_limit()
      throws SQLException {
    // L19 through SET ROLE: the login may become g and call w directly.
    var db = db();
    String g = group("fg_set" + major);
    exec(
        db.su(),
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET TRUE",
        DEFINER_W,
        REVOKE_W,
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        AGG_W);
    verifies(db.app());
  }

  @Test
  void refusal_quotes_a_schema_and_object_name_that_is_not_plain_lowercase() throws SQLException {
    // C-PR47-5: labels go through quote_ident, so "Evil" and "Agg" show as regprocedure prints
    // them, and a look-alike of public.w cannot read as public.w.
    var db = db();
    exec(
        db.su(),
        "CREATE SCHEMA \"Evil\"",
        "CREATE FUNCTION \"Evil\".w(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)'",
        "REVOKE EXECUTE ON FUNCTION \"Evil\".w(text, boolean) FROM PUBLIC",
        "CREATE AGGREGATE public.\"Agg\"(boolean) (sfunc = \"Evil\".w, stype = text,"
            + " initcond = 'PG_VERSION')");
    refuses(
        db.app(),
        "aggregate public.\"Agg\"(boolean)",
        "whose transfn is function \"Evil\".w(text, boolean)",
        W_REASON);
  }

  @Test
  void operator_code_is_checked_as_the_caller_and_its_estimator_is_judged() throws SQLException {
    var db = db();
    String code = handMadeCopy(db, "pg_catalog.texteq(text, text)");
    exec(
        db.su(),
        "CREATE OPERATOR public.=== (LEFTARG = text, RIGHTARG = text, FUNCTION = public.r6_copy)");
    // O1: oprcode runs with the caller's EXECUTE checked, so R6 leaves it to the server.
    assertThatThrownBy(() -> scalar(db.app(), "SELECT 'a'::text OPERATOR(public.===) 'a'"))
        .hasMessageContaining("permission denied for function r6_copy");
    // C-RC021-2: the copy is native code made by hand, refused whatever its grants (leg 4);
    // the operator itself still gives no R6 line, because oprcode is checked as the caller.
    assertThat(refusal(db.app()))
        .hasMessageContaining(
            "function public.r6_copy(text, text) is native code made by hand outside any extension")
        .hasMessageNotContaining("operator public.===");
    var other = db();
    String rest = handMadeCopy(other, "pg_catalog.eqsel(internal, oid, internal, integer)");
    exec(
        other.su(),
        "CREATE OPERATOR public.=== (LEFTARG = text, RIGHTARG = text,"
            + " FUNCTION = pg_catalog.texteq, RESTRICT = public.r6_copy)");
    // The planner calls an estimator with no EXECUTE check at all.
    refuses(other.app(), "operator public.===(text,text)", "whose oprrest is function " + rest);
    assertThat(code).isEqualTo("public.r6_copy(text, text)");
  }

  @Test
  void contrib_aggregate_re_created_over_another_support_function_refuses() throws SQLException {
    // Revision 5, manifest column 7: the key min(citext) and the symbol aggregate_dummy stay,
    // so only the recorded support functions tell it from the shipped one.
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION citext",
        "ALTER EXTENSION citext DROP AGGREGATE public.min(public.citext)",
        "DROP AGGREGATE public.min(public.citext)",
        "CREATE AGGREGATE public.min(public.citext) (sfunc = public.citext_larger,"
            + " stype = public.citext, combinefunc = public.citext_larger)",
        "ALTER EXTENSION citext ADD AGGREGATE public.min(public.citext)");
    refuses(
        db.app(),
        "PUBLIC " + held("public.min(public.citext)"),
        "manifest does not list for that version");
  }

  // ------------------------------------ R7, core functions rewritten in place (C-PR45-3-17)

  @Test
  void core_function_rewritten_in_place_with_a_symbol_w_does_not_hold_refuses_with_005()
      throws SQLException {
    // K1: CREATE OR REPLACE keeps the oid; pg_trgm's similarity is in no part of W, so no other
    // leg sees it. Before R7 this verified.
    var db = db();
    exec(
        db.su(),
        "CREATE OR REPLACE FUNCTION pg_catalog.lower(text) RETURNS text LANGUAGE c"
            + " AS '$libdir/pg_trgm', 'similarity'");
    unverifiable(
        db.app(),
        "core function pg_catalog.lower(text) is language c, symbol similarity, library"
            + " $libdir/pg_trgm on this server",
        "ships it as language internal, symbol lower",
        "rewritten in place");
  }

  @Test
  void core_function_rewritten_to_another_internal_symbol_or_to_sql_refuses_with_005()
      throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE OR REPLACE FUNCTION pg_catalog.lower(text) RETURNS text LANGUAGE internal"
            + " IMMUTABLE STRICT AS 'upper'");
    unverifiable(
        db.app(), "core function pg_catalog.lower(text) is language internal, symbol upper");
    var other = db();
    exec(
        other.su(),
        "CREATE OR REPLACE FUNCTION pg_catalog.lower(text) RETURNS text LANGUAGE sql"
            + " IMMUTABLE STRICT AS 'SELECT $1'");
    unverifiable(other.app(), "core function pg_catalog.lower(text) is language sql");
  }

  @Test
  void core_function_rewritten_as_security_definer_refuses_with_005() throws SQLException {
    var db = db();
    exec(db.su(), "ALTER FUNCTION pg_catalog.lower(text) SECURITY DEFINER");
    unverifiable(
        db.app(), "pg_catalog.lower(text) is language internal, symbol lower, SECURITY DEFINER");
  }

  // --------------------------------- the paths the server refuses by signature (revision 5)

  /**
   * Every other slot that names a function takes or returns {@code cstring} or {@code internal}, or
   * has a shape no withheld built-in fits, so the server refuses a withheld function there at
   * CREATE. One statement per path group; statements of one case are split on {@code |}.
   */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "CREATE CAST (boolean AS text) WITH FUNCTION pg_catalog.pg_read_file(text)",
        "CREATE OPERATOR public.<=> (LEFTARG = text, RIGHTARG = text,"
            + " FUNCTION = pg_catalog.texteq, JOIN = pg_catalog.pg_read_file)",
        "CREATE TYPE public.r6t|CREATE TYPE public.r6t (INPUT = pg_catalog.pg_read_file,"
            + " OUTPUT = pg_catalog.textout)",
        "CREATE TYPE public.r6r AS RANGE (SUBTYPE = text, SUBTYPE_DIFF = pg_catalog.pg_read_file)",
        "CREATE OPERATOR CLASS public.r6oc FOR TYPE text USING btree AS OPERATOR 1 <,"
            + " FUNCTION 1 pg_catalog.pg_read_file(text, boolean)",
        "CREATE CONVERSION public.r6c FOR 'UTF8' TO 'LATIN1' FROM pg_catalog.pg_read_file",
        "CREATE TEXT SEARCH TEMPLATE public.r6tt (LEXIZE = pg_catalog.pg_read_file)",
        "CREATE TEXT SEARCH PARSER public.r6p (START = pg_catalog.pg_read_file,"
            + " GETTOKEN = pg_catalog.prsd_nexttoken, END = pg_catalog.prsd_end,"
            + " LEXTYPES = pg_catalog.prsd_lextype)",
        "CREATE LANGUAGE r6h HANDLER pg_catalog.pg_read_file",
        "CREATE FOREIGN DATA WRAPPER r6f HANDLER pg_catalog.pg_read_file",
        "CREATE FOREIGN DATA WRAPPER r6f VALIDATOR pg_catalog.pg_stat_reset_single_table_counters",
        "CREATE TRANSFORM FOR text LANGUAGE plpgsql"
            + " (FROM SQL WITH FUNCTION pg_catalog.pg_read_file(text))",
        "CREATE TABLE public.r6tab (x integer)|CREATE TRIGGER r6tg BEFORE INSERT ON public.r6tab"
            + " FOR EACH ROW EXECUTE FUNCTION pg_catalog.pg_read_file()",
        "CREATE EVENT TRIGGER r6e ON ddl_command_start EXECUTE FUNCTION pg_catalog.pg_read_file()"
      })
  void server_refuses_a_withheld_function_in_a_slot_it_cannot_fit(String statements)
      throws SQLException {
    var db = db();
    String[] parts = statements.split("\\|");
    for (int i = 0; i < parts.length - 1; i++) {
      exec(db.su(), parts[i]);
    }
    assertThatThrownBy(() -> exec(db.su(), parts[parts.length - 1]))
        .isInstanceOf(SQLException.class);
    verifies(db.app());
  }

  /**
   * W as the count tests read it: every function the server or a shipped extension records without
   * PUBLIC EXECUTE in pg_init_privs (privtype 'i' or 'e'), C-PR47-3.
   */
  private static final String W =
      "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_init_privs i ON i.objoid = p.oid"
          + " AND i.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass"
          + " AND i.privtype IN ('i', 'e')"
          + " WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(i.initprivs) y"
          + " WHERE y.grantee = 0)";

  /**
   * The shapes of every slot statement 3 does not read: cstring or internal in or out (type I/O,
   * analyze, subscript, access method, conversion, text search, FDW handler), a cstring[] argument
   * (typmod input), trigger and event_trigger, a btree compare {@code (T, T) -> int4/bool/float8},
   * an FDW validator {@code (text[], oid)}, a hash {@code (T) -> int4}, an extended hash {@code (T,
   * int8) -> int8} and a btree equal-image {@code (oid) -> bool}.
   */
  private static final String UNREAD_SHAPES =
      "SELECT pg_catalog.count(*) "
          + W
          + " AND (p.prorettype IN ('cstring'::pg_catalog.regtype, 'internal'::pg_catalog.regtype,"
          + " 'trigger'::pg_catalog.regtype, 'event_trigger'::pg_catalog.regtype)"
          + " OR p.proargtypes::pg_catalog.oid[] && '{2275,2281,1263}'::pg_catalog.oid[]"
          + " OR (p.pronargs = 2 AND p.proargtypes[0] = p.proargtypes[1]"
          + " AND p.prorettype IN ('int4'::pg_catalog.regtype, 'bool'::pg_catalog.regtype,"
          + " 'float8'::pg_catalog.regtype))"
          + " OR (p.pronargs = 2 AND p.proargtypes[0] = 'text[]'::pg_catalog.regtype)"
          + " OR (p.pronargs = 1 AND p.prorettype = 'int4'::pg_catalog.regtype)"
          + " OR (p.pronargs = 2 AND p.proargtypes[1] = 'int8'::pg_catalog.regtype"
          + " AND p.prorettype = 'int8'::pg_catalog.regtype)"
          + " OR (p.pronargs = 1 AND p.proargtypes[0] = 'oid'::pg_catalog.regtype"
          + " AND p.prorettype = 'bool'::pg_catalog.regtype))";

  private static String fits(String shape) {
    return "SELECT pg_catalog.string_agg(p.oid::pg_catalog.regprocedure::pg_catalog.text, ';'"
        + " ORDER BY p.proname) "
        + W
        + " AND "
        + shape;
  }

  /**
   * The count behind "refused by signature", kept live on each pin with every manifest extension
   * created: no withheld function, built-in or shipped by an extension, fits a slot statement 3
   * does not read. Two read slots have fits, asserted by name: the validator {@code (oid)} fits
   * four built-ins, and the aggregate combine {@code (s, s) -> s} fits {@code dblink_connect_u}. R6
   * judges both. A pin bump that adds a fit turns this red.
   */
  @Test
  void withheld_functions_fit_no_unread_slot_shape() throws SQLException {
    var db = db();
    for (String ext : PinnedCatalogue.forMajor(major).orElseThrow().installableExtensions()) {
      exec(db.su(), "CREATE EXTENSION IF NOT EXISTS \"" + ext + "\" CASCADE");
    }
    assertThat(scalar(db.su(), UNREAD_SHAPES)).isEqualTo("0");
    assertThat(
            scalar(
                db.su(), fits("p.pronargs = 1 AND p.proargtypes[0] = 'oid'::pg_catalog.regtype")))
        .isEqualTo(
            "pg_ls_tmpdir(oid);pg_stat_reset_single_function_counters(oid);"
                + "pg_stat_reset_single_table_counters(oid);pg_stat_reset_subscription_stats(oid)");
    assertThat(
            scalar(
                db.su(),
                fits(
                    "p.pronargs = 2 AND p.proargtypes[0] = p.proargtypes[1]"
                        + " AND p.prorettype = p.proargtypes[0]")))
        .isEqualTo("dblink_connect_u(text,text)");
  }

  @Test
  void count_test_sees_an_extension_withheld_function_with_an_internal_argument()
      throws SQLException {
    // C-PR47-3: the count reads the extension part of W too, so a pin bump that ships such a
    // function in a contrib extension turns the guard red.
    var db = db();
    assertThat(scalar(db.su(), UNREAD_SHAPES)).isEqualTo("0");
    exec(db.su(), "CREATE EXTENSION tpi");
    assertThat(scalar(db.su(), UNREAD_SHAPES)).isEqualTo("1");
  }

  // ------------------------------------------------- C-RC021-2: no-check slots (addendum Rev 2)

  /** A hand-made native trigger function, EXECUTE revoked: only leg 4 and R6 can see it. */
  private static final String H_TRG =
      "CREATE FUNCTION public.h_trg() RETURNS trigger LANGUAGE internal"
          + " AS 'suppress_redundant_updates_trigger'|REVOKE EXECUTE ON FUNCTION public.h_trg()"
          + " FROM PUBLIC";

  private static final String H_TRG_LABEL = "public.h_trg()";

  private static String leg4(String fn) {
    return "function " + fn + " is native code made by hand outside any extension";
  }

  private static String slotLine(String slot, String what, String fn) {
    return "function " + fn + " as the " + slot + " of " + what;
  }

  private static void plant(Db db, String statements) throws SQLException {
    exec(db.su(), statements.split("\\|"));
  }

  @Test
  void revoked_hand_made_native_attached_nowhere_refuses_leg_4() throws SQLException {
    var db = db();
    plant(db, H_TRG);
    refuses(db.app(), leg4(H_TRG_LABEL));
  }

  /**
   * T1 to T12 and the reach rule: every trigger of the database is judged, whatever its kind, its
   * table, its state or the table's owner. Each case plants the path, then the trigger.
   */
  @ParameterizedTest(name = "{0}")
  @org.junit.jupiter.params.provider.CsvSource(
      delimiter = ';',
      value = {
        "T1 row trigger; CREATE TABLE public.t (id int)|GRANT INSERT, UPDATE ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t",
        "T2 statement trigger; CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE TRIGGER x AFTER INSERT ON public.t FOR EACH STATEMENT EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t",
        "T3 truncate trigger; CREATE TABLE public.t (id int)|GRANT TRUNCATE ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE TRUNCATE ON public.t FOR EACH STATEMENT EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t",
        "T4 constraint trigger; CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE CONSTRAINT TRIGGER x AFTER INSERT ON public.t DEFERRABLE INITIALLY DEFERRED"
            + " FOR EACH ROW EXECUTE FUNCTION public.h_trg(); x on public.t",
        "T5 column update grant; CREATE TABLE public.t (id int, c int)|GRANT UPDATE (c) ON public.t"
            + " TO "
            + APP
            + "|CREATE TRIGGER x BEFORE UPDATE OF c ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t",
        "T6 partition through parent; CREATE TABLE public.p (id int) PARTITION BY RANGE (id)"
            + "|CREATE TABLE public.p1 PARTITION OF public.p FOR VALUES FROM (0) TO (10)"
            + "|GRANT INSERT ON public.p TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.p1 FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.p1",
        "T7 inheritance child; CREATE TABLE public.h (id int)|CREATE TABLE public.hc ()"
            + " INHERITS (public.h)|GRANT SELECT, UPDATE ON public.h TO "
            + APP
            + "|CREATE TRIGGER x BEFORE UPDATE ON public.hc FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.hc",
        "T8 rule target; CREATE TABLE public.r2 (id int)|CREATE TABLE public.r1 (id int)"
            + "|CREATE RULE rr AS ON INSERT TO public.r1 DO INSTEAD INSERT INTO public.r2"
            + " VALUES (NEW.id)|GRANT INSERT ON public.r1 TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.r2 FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.r2",
        "T9 view base table; CREATE TABLE public.b1 (id int)|CREATE VIEW public.v1 AS SELECT id"
            + " FROM public.b1|GRANT INSERT ON public.v1 TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.b1 FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.b1",
        "T10 instead of on a view; CREATE VIEW public.v2 AS SELECT 1 AS id|GRANT INSERT ON"
            + " public.v2 TO "
            + APP
            + "|CREATE TRIGGER x INSTEAD OF INSERT ON public.v2 FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.v2",
        "T11a before on fk cascade target; CREATE TABLE public.fp (id int PRIMARY KEY)"
            + "|CREATE TABLE public.fc (id int REFERENCES public.fp ON DELETE CASCADE)"
            + "|GRANT SELECT, DELETE ON public.fp TO "
            + APP
            + "|CREATE TRIGGER x BEFORE DELETE ON public.fc FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.fc",
        "T11b after on fk cascade target; CREATE TABLE public.fp (id int PRIMARY KEY)"
            + "|CREATE TABLE public.fc (id int REFERENCES public.fp ON DELETE CASCADE)"
            + "|GRANT SELECT, DELETE ON public.fp TO "
            + APP
            + "|CREATE TRIGGER x AFTER DELETE ON public.fc FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.fc",
        "T12a disabled trigger; CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg()|ALTER TABLE public.t DISABLE TRIGGER x; x on public.t",
        "T12b replica trigger; CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg()|ALTER TABLE public.t ENABLE REPLICA TRIGGER x; x on public.t",
        "T12c always trigger; CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg()|ALTER TABLE public.t ENABLE ALWAYS TRIGGER x; x on public.t",
        "rule 2 table the runtime role cannot reach; CREATE TABLE public.t (id int)"
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t",
        "rule 2 table owned by the runtime role; CREATE TABLE public.t (id int)|ALTER TABLE"
            + " public.t OWNER TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.h_trg(); x on public.t"
      })
  void trigger_over_hand_made_native_refuses(String path, String setup, String trigger)
      throws SQLException {
    var db = db();
    plant(db, H_TRG);
    plant(db, setup);
    refuses(db.app(), leg4(H_TRG_LABEL), slotLine("function", "trigger " + trigger, H_TRG_LABEL));
  }

  @Test
  void trigger_reached_through_noinherit_group_grant_refuses() throws SQLException {
    var db = db();
    String grp = group("rc021_grp");
    plant(db, H_TRG);
    exec(
        db.su(),
        "CREATE TABLE public.t (id int)",
        "GRANT INSERT ON public.t TO " + grp,
        "CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION public.h_trg()");
    exec(db.su(), "GRANT " + grp + " TO " + APP);
    refuses(db.app(), slotLine("function", "trigger x on public.t", H_TRG_LABEL));
  }

  @Test
  void after_trigger_on_fk_cascade_target_runs_as_caller() throws SQLException {
    // Control (T11b, review M2): the AFTER trigger function of a cascade runs as the caller.
    var db = db();
    exec(
        db.su(),
        "CREATE TABLE public.who (u text)",
        "CREATE FUNCTION public.mark() RETURNS trigger LANGUAGE plpgsql AS"
            + " $$BEGIN INSERT INTO public.who VALUES (current_user); RETURN OLD; END$$",
        "CREATE TABLE public.fp (id int PRIMARY KEY)",
        "CREATE TABLE public.fc (id int REFERENCES public.fp ON DELETE CASCADE)",
        "INSERT INTO public.fp VALUES (1)",
        "INSERT INTO public.fc VALUES (1)",
        "GRANT SELECT, DELETE ON public.fp TO " + APP,
        "GRANT INSERT ON public.who TO " + APP,
        "CREATE TRIGGER x AFTER DELETE ON public.fc FOR EACH ROW EXECUTE FUNCTION public.mark()");
    exec(db.app(), "DELETE FROM public.fp");
    assertThat(scalar(db.su(), "SELECT u FROM public.who")).isEqualTo(APP);
  }

  @Test
  void revoked_and_public_sql_definer_trigger_get_the_same_verdict() throws SQLException {
    // Ruling 4: the trg verdict never reads the function's ACL. A non-native definer trigger
    // function is judged on the owner-context page, not here.
    String definer =
        "CREATE FUNCTION public.aud() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS"
            + " $$BEGIN RETURN NEW; END$$";
    String trigger =
        "CREATE TABLE public.t (id int)|GRANT INSERT ON public.t TO "
            + APP
            + "|CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.aud()";
    var revoked = db();
    plant(revoked, definer + "|REVOKE EXECUTE ON FUNCTION public.aud() FROM PUBLIC|" + trigger);
    verifies(revoked.app());
    var open = db();
    plant(open, definer + "|" + trigger);
    verifies(open.app());
  }

  @Test
  void plpgsql_invoker_trigger_verifies() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.inv() RETURNS trigger LANGUAGE plpgsql AS"
            + " $$BEGIN RETURN NEW; END$$",
        "REVOKE EXECUTE ON FUNCTION public.inv() FROM PUBLIC",
        "CREATE TABLE public.t (id int)",
        "GRANT INSERT ON public.t TO " + APP,
        "CREATE TRIGGER x BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION public.inv()");
    verifies(db.app());
  }

  @Test
  void trigger_attached_by_runtime_role_to_its_temp_table_over_public_hand_made_native_refuses()
      throws SQLException {
    // P1 (review M4): the runtime role attaches the trigger itself. The gate refuses TEMP too;
    // the lines asserted here are the ones this mechanism adds.
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.h_trg() RETURNS trigger LANGUAGE internal"
            + " AS 'suppress_redundant_updates_trigger'",
        "GRANT TEMP ON DATABASE " + db.name() + " TO " + APP);
    try (var c = db.app().getConnection();
        var st = c.createStatement()) {
      st.execute("CREATE TEMP TABLE tt (id int)");
      st.execute(
          "CREATE TRIGGER x BEFORE INSERT ON tt FOR EACH ROW EXECUTE FUNCTION public.h_trg()");
      refuses(db.app(), leg4(H_TRG_LABEL), "as the function of trigger x on pg_temp_");
    }
  }

  @Test
  void shipped_contrib_triggers_attached_verify() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION moddatetime",
        "CREATE EXTENSION insert_username",
        "CREATE EXTENSION autoinc",
        "CREATE EXTENSION refint",
        "CREATE EXTENSION tcn",
        "CREATE EXTENSION lo",
        "CREATE TABLE public.t (id int, m timestamp, u text, n int, l public.lo)",
        "GRANT INSERT, UPDATE ON public.t TO " + APP,
        "CREATE SEQUENCE public.s",
        "CREATE TRIGGER a BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.moddatetime(m)",
        "CREATE TRIGGER b BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.insert_username(u)",
        "CREATE TRIGGER c BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.autoinc(n, 's')",
        "CREATE TRIGGER d BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.check_primary_key('id', 't', 'id')",
        "CREATE TRIGGER e AFTER INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.triggered_change_notification()",
        "CREATE TRIGGER f BEFORE UPDATE OR DELETE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.lo_manage(l)",
        "CREATE TRIGGER g BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " pg_catalog.suppress_redundant_updates_trigger()");
    verifies(db.app());
  }

  @Test
  void foreign_key_internal_triggers_verify() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE TABLE public.fp (id int PRIMARY KEY)",
        "CREATE TABLE public.fc (id int REFERENCES public.fp ON DELETE CASCADE ON UPDATE SET NULL)",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON public.fp, public.fc TO " + APP);
    verifies(db.app());
  }

  /** E1, one per event, and the disabled state. */
  @ParameterizedTest
  @ValueSource(strings = {"ddl_command_start", "ddl_command_end", "sql_drop", "table_rewrite"})
  void event_trigger_over_hand_made_native_refuses(String event) throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.h_evt() RETURNS event_trigger LANGUAGE internal"
            + " AS 'pg_backend_pid'",
        "REVOKE EXECUTE ON FUNCTION public.h_evt() FROM PUBLIC",
        "CREATE EVENT TRIGGER x ON " + event + " EXECUTE FUNCTION public.h_evt()");
    refuses(
        db.app(),
        leg4("public.h_evt()"),
        slotLine("function", "event trigger x on " + event, "public.h_evt()"));
  }

  @Test
  void disabled_event_trigger_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.h_evt() RETURNS event_trigger LANGUAGE internal"
            + " AS 'pg_backend_pid'",
        "REVOKE EXECUTE ON FUNCTION public.h_evt() FROM PUBLIC",
        "CREATE EVENT TRIGGER x ON ddl_command_start EXECUTE FUNCTION public.h_evt()",
        "ALTER EVENT TRIGGER x DISABLE");
    refuses(
        db.app(), slotLine("function", "event trigger x on ddl_command_start", "public.h_evt()"));
  }

  @Test
  void event_trigger_fires_for_role_with_no_create_or_temp() throws SQLException {
    // E2: a PL/pgSQL spy, EXECUTE revoked, raises with the current user. The runtime role has
    // neither CREATE nor TEMP; the spy's error comes first, so it ran before the refusal.
    var db = db();
    exec(
        db.su(),
        "REVOKE TEMP ON DATABASE " + db.name() + " FROM PUBLIC",
        "CREATE FUNCTION public.spy_evt() RETURNS event_trigger LANGUAGE plpgsql AS"
            + " $$BEGIN RAISE EXCEPTION 'spy ran as %', current_user; END$$",
        "REVOKE EXECUTE ON FUNCTION public.spy_evt() FROM PUBLIC",
        "CREATE EVENT TRIGGER x ON ddl_command_start EXECUTE FUNCTION public.spy_evt()");
    assertThatThrownBy(() -> exec(db.app(), "CREATE TABLE public.zz (i int)"))
        .hasMessageContaining("spy ran as " + APP);
    assertThatThrownBy(() -> exec(db.app(), "CREATE TEMP TABLE zz (i int)"))
        .hasMessageContaining("spy ran as " + APP);
  }

  /** N1: operator class support functions are called with no EXECUTE check. */
  @Test
  void opclass_support_function_hand_made_refuses() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.h_cmp(int, int) RETURNS int LANGUAGE internal IMMUTABLE STRICT"
            + " AS 'btint4cmp'",
        "REVOKE EXECUTE ON FUNCTION public.h_cmp(int, int) FROM PUBLIC",
        "CREATE OPERATOR CLASS public.h_ops FOR TYPE int USING btree AS OPERATOR 1 <,"
            + " OPERATOR 2 <=, OPERATOR 3 =, OPERATOR 4 >=, OPERATOR 5 >,"
            + " FUNCTION 1 public.h_cmp(int, int)");
    refuses(
        db.app(),
        leg4("public.h_cmp(integer, integer)"),
        "function public.h_cmp(integer, integer) as the support of operator family public.h_ops");
  }

  @Test
  void revoked_sql_definer_btree_comparator_refuses_leg_7() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.s_cmp(int, int) RETURNS int LANGUAGE sql IMMUTABLE STRICT"
            + " SECURITY DEFINER AS 'SELECT pg_catalog.btint4cmp($1, $2)'",
        "REVOKE EXECUTE ON FUNCTION public.s_cmp(int, int) FROM PUBLIC",
        "CREATE OPERATOR CLASS public.s_ops FOR TYPE int USING btree AS OPERATOR 1 <,"
            + " OPERATOR 2 <=, OPERATOR 3 =, OPERATOR 4 >=, OPERATOR 5 >,"
            + " FUNCTION 1 public.s_cmp(int, int)");
    refuses(
        db.app(),
        "function public.s_cmp(integer, integer) as the support of operator family public.s_ops",
        "a SECURITY DEFINER function");
  }

  /** N2: the eight function columns of a base type, all hand-made. */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "input:public.h_in(cstring)",
        "output:public.h_out(public.h_t)",
        "receive:public.h_recv(internal)",
        "send:public.h_send(public.h_t)",
        "typmod_in:public.h_tmi(cstring[])",
        "typmod_out:public.h_tmo(integer)",
        "analyze:public.h_an(internal)",
        "subscript:public.h_sub(internal)"
      })
  void type_function_hand_made_refuses(String slotAndFunction) throws SQLException {
    var db = db();
    String[] parts = {
      "CREATE TYPE public.h_t",
      "CREATE FUNCTION public.h_in(cstring) RETURNS public.h_t LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'int4in'",
      "CREATE FUNCTION public.h_out(public.h_t) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'int4out'",
      "CREATE FUNCTION public.h_recv(internal) RETURNS public.h_t LANGUAGE internal IMMUTABLE"
          + " STRICT AS 'int4recv'",
      "CREATE FUNCTION public.h_send(public.h_t) RETURNS bytea LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'int4send'",
      "CREATE FUNCTION public.h_tmi(cstring[]) RETURNS int LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'varchartypmodin'",
      "CREATE FUNCTION public.h_tmo(int) RETURNS cstring LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'varchartypmodout'",
      "CREATE FUNCTION public.h_an(internal) RETURNS boolean LANGUAGE internal STRICT"
          + " AS 'array_typanalyze'",
      "CREATE FUNCTION public.h_sub(internal) RETURNS internal LANGUAGE internal IMMUTABLE STRICT"
          + " AS 'raw_array_subscript_handler'",
      "CREATE TYPE public.h_t (INPUT = public.h_in, OUTPUT = public.h_out, RECEIVE = public.h_recv,"
          + " SEND = public.h_send, TYPMOD_IN = public.h_tmi, TYPMOD_OUT = public.h_tmo,"
          + " ANALYZE = public.h_an, SUBSCRIPT = public.h_sub, ELEMENT = int4,"
          + " INTERNALLENGTH = 4, PASSEDBYVALUE, ALIGNMENT = int4)"
    };
    exec(db.su(), parts);
    exec(db.su(), "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC");
    String slot = slotAndFunction.substring(0, slotAndFunction.indexOf(':'));
    String fn = slotAndFunction.substring(slotAndFunction.indexOf(':') + 1);
    refuses(db.app(), slotLine(slot, "type public.h_t", fn));
  }

  /** N3a, N3b: range canonical and subdiff. */
  @ParameterizedTest
  @ValueSource(
      strings = {
        "canonical:public.h_canon(public.h_rc)",
        "subdiff:public.h_diff(integer, integer)"
      })
  void range_function_hand_made_refuses(String slotAndFunction) throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE TYPE public.h_rc",
        "CREATE FUNCTION public.h_canon(public.h_rc) RETURNS public.h_rc LANGUAGE internal"
            + " IMMUTABLE STRICT AS 'int4range_canonical'",
        "CREATE FUNCTION public.h_diff(int, int) RETURNS float8 LANGUAGE internal IMMUTABLE STRICT"
            + " AS 'int4range_subdiff'",
        "CREATE TYPE public.h_rc AS RANGE (SUBTYPE = int4, CANONICAL = public.h_canon,"
            + " SUBTYPE_DIFF = public.h_diff)",
        "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC");
    String slot = slotAndFunction.substring(0, slotAndFunction.indexOf(':'));
    String fn = slotAndFunction.substring(slotAndFunction.indexOf(':') + 1);
    refuses(db.app(), slotLine(slot, "range type public.h_rc", fn));
  }

  /** N3c, N3d: the remaining no-check slots, one hand-made native function each. */
  @ParameterizedTest(name = "{0}")
  @org.junit.jupiter.params.provider.CsvSource(
      delimiter = ';',
      value = {
        "fdw handler; CREATE FUNCTION public.h_fh() RETURNS fdw_handler LANGUAGE c"
            + " AS '$libdir/file_fdw', 'file_fdw_handler'|CREATE FOREIGN DATA WRAPPER h_w HANDLER"
            + " public.h_fh; handler; foreign-data wrapper h_w; public.h_fh()",
        "fdw validator; CREATE FUNCTION public.h_fv(text[], oid) RETURNS boolean LANGUAGE internal"
            + " AS 'postgresql_fdw_validator'|CREATE FOREIGN DATA WRAPPER h_w VALIDATOR"
            + " public.h_fv; validator; foreign-data wrapper h_w; public.h_fv(text[], oid)",
        "am handler; CREATE FUNCTION public.h_amh(internal) RETURNS index_am_handler"
            + " LANGUAGE internal AS 'bthandler'|CREATE ACCESS METHOD h_am TYPE INDEX HANDLER"
            + " public.h_amh; handler; access method h_am; public.h_amh(internal)",
        "ts parser start; CREATE FUNCTION public.h_ps(internal, int) RETURNS internal"
            + " LANGUAGE internal STRICT AS 'prsd_start'|CREATE TEXT SEARCH PARSER public.h_p"
            + " (START = public.h_ps, GETTOKEN = pg_catalog.prsd_nexttoken, END = pg_catalog.prsd_end,"
            + " LEXTYPES = pg_catalog.prsd_lextype); start; text search parser public.h_p;"
            + " public.h_ps(internal, integer)",
        "ts template lexize; CREATE FUNCTION public.h_lx(internal, internal, internal, internal)"
            + " RETURNS internal LANGUAGE internal STRICT AS 'dsimple_lexize'|CREATE TEXT SEARCH"
            + " TEMPLATE public.h_tt (LEXIZE = public.h_lx); lexize; text search template"
            + " public.h_tt; public.h_lx(internal, internal, internal, internal)",
        "conversion; CREATE FUNCTION public.h_cv(int, int, cstring, internal, int, boolean)"
            + " RETURNS int LANGUAGE c STRICT AS '$libdir/utf8_and_iso8859_1', 'utf8_to_iso8859_1'"
            + "|CREATE CONVERSION public.h_c FOR 'UTF8' TO 'LATIN1' FROM public.h_cv; function;"
            + " conversion public.h_c; public.h_cv(integer, integer, cstring, internal, integer,"
            + " boolean)",
        "transform; CREATE FUNCTION public.h_fs(internal) RETURNS internal LANGUAGE internal"
            + " IMMUTABLE STRICT AS 'prsd_lextype'|CREATE TRANSFORM FOR int LANGUAGE plpgsql (FROM SQL WITH"
            + " FUNCTION public.h_fs(internal)); fromsql; transform integer for language plpgsql;"
            + " public.h_fs(internal)",
        "planner support; CREATE FUNCTION public.h_su(internal) RETURNS internal LANGUAGE internal"
            + " AS 'textlike_support'|CREATE FUNCTION public.f(text) RETURNS boolean LANGUAGE sql"
            + " SUPPORT public.h_su AS 'SELECT true'; support; function public.f(text);"
            + " public.h_su(internal)"
      })
  void other_no_check_slot_hand_made_refuses(
      String path, String setup, String slot, String what, String fn) throws SQLException {
    var db = db();
    plant(db, setup + "|REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC");
    refuses(db.app(), leg4(fn), slotLine(slot, what, fn));
  }

  /** T13, X1 to X7: the server checks EXECUTE as the runtime role for its own statement. */
  @ParameterizedTest(name = "{0}")
  @org.junit.jupiter.params.provider.CsvSource(
      delimiter = ';',
      value = {
        "X1 default; CREATE TABLE public.t (id int, d int DEFAULT public.spyx(1)); INSERT INTO"
            + " public.t (id) VALUES (1)",
        "X2 generated column; CREATE TABLE public.t (id int, g int GENERATED ALWAYS AS"
            + " (public.spyx(id)) STORED); INSERT INTO public.t (id) VALUES (1)",
        "X3 check; CREATE TABLE public.t (id int CHECK (public.spyx(id) > -1)); INSERT INTO"
            + " public.t VALUES (1)",
        "X4 domain check; CREATE DOMAIN public.dd AS int CHECK (public.spyx(VALUE) > -1)"
            + "|CREATE TABLE public.t (id public.dd); INSERT INTO public.t VALUES (1)",
        "X5a index expression; CREATE TABLE public.t (id int)|CREATE INDEX ON public.t"
            + " (public.spyx(id)); INSERT INTO public.t VALUES (1)",
        "X5b partial index predicate; CREATE TABLE public.t (id int)|CREATE INDEX ON public.t (id)"
            + " WHERE public.spyx(id) > 0; INSERT INTO public.t VALUES (1)",
        "X6 policy; CREATE TABLE public.t (id int)|INSERT INTO public.t VALUES (1)|ALTER TABLE"
            + " public.t ENABLE ROW LEVEL SECURITY|CREATE POLICY p ON public.t USING"
            + " (public.spyx(id) > -1); SELECT count(*) FROM public.t",
        "X7a view; CREATE TABLE public.t (id int)|CREATE VIEW public.v AS SELECT public.spyx(1) AS"
            + " x; SELECT * FROM public.v",
        "X7b rule action; CREATE TABLE public.t (id int)|CREATE RULE r AS ON INSERT TO public.t DO"
            + " ALSO SELECT public.spyx(NEW.id); INSERT INTO public.t VALUES (1)",
        "T13 trigger when; CREATE TABLE public.t (id int)|CREATE TRIGGER x BEFORE INSERT ON"
            + " public.t FOR EACH ROW WHEN (public.spyx(NEW.id) > -1) EXECUTE FUNCTION"
            + " pg_catalog.suppress_redundant_updates_trigger(); INSERT INTO public.t VALUES (1)"
      })
  void path_is_checked_as_caller_for_the_runtime_roles_own_statement(
      String path, String setup, String statement) throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.spyx(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
            + " $$BEGIN RETURN $1; END$$",
        "REVOKE EXECUTE ON FUNCTION public.spyx(int) FROM PUBLIC");
    plant(db, setup);
    exec(db.su(), "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO " + APP);
    assertThatThrownBy(() -> exec(db.app(), statement))
        .hasMessageContaining("permission denied for function spyx");
  }

  /** Ruling 8: statement 3 keeps only rows the verdict can refuse. */
  @Test
  void statement_3_filter_drops_only_rows_the_verdict_passes() throws SQLException {
    var db = db();
    plant(db, H_TRG);
    exec(
        db.su(),
        "CREATE EXTENSION moddatetime",
        "CREATE FUNCTION public.inv() RETURNS trigger LANGUAGE plpgsql AS"
            + " $$BEGIN RETURN NEW; END$$",
        "CREATE FUNCTION public.def() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS"
            + " $$BEGIN RETURN NEW; END$$",
        "CREATE TABLE public.t (id int, m timestamp)",
        "CREATE TRIGGER a BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION public.inv()",
        "CREATE TRIGGER b BEFORE INSERT ON public.t FOR EACH ROW EXECUTE FUNCTION public.def()",
        "CREATE TRIGGER c BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " public.moddatetime(m)",
        "CREATE TRIGGER d BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION"
            + " pg_catalog.suppress_redundant_updates_trigger()",
        "CREATE TRIGGER e BEFORE UPDATE ON public.t FOR EACH ROW EXECUTE FUNCTION public.h_trg()");
    long login =
        Long.parseLong(
            scalar(db.su(), "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '" + APP + "'"));
    List<String> kept;
    try (Connection c = pinned(db.app())) {
      kept =
          FunctionGrantsSql.callers(c, new long[] {login}, login).stream()
              .filter(f -> f.kind().equals("trg"))
              .map(FunctionGrantsSql.CallerFact::fnLabel)
              .filter(l -> !l.startsWith("pg_catalog.\"RI_FKey"))
              .sorted()
              .toList();
      c.rollback();
    }
    assertThat(kept)
        .containsExactly(
            "pg_catalog.suppress_redundant_updates_trigger()",
            "public.def()",
            "public.h_trg()",
            "public.moddatetime()");
  }

  /**
   * Addendum ruling 12: statement 3's time is recorded, with no threshold. Every installable
   * contrib extension and the module schema installed; first call, then the median of five.
   */
  @Test
  void statement_3_time_with_every_contrib_extension_is_recorded() throws SQLException {
    var db = db();
    var catalogue = PinnedCatalogue.forMajor(major).orElseThrow();
    for (String ext : catalogue.installableExtensions()) {
      exec(db.su(), "CREATE EXTENSION IF NOT EXISTS \"" + ext + "\" CASCADE");
    }
    long login =
        Long.parseLong(
            scalar(db.su(), "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '" + APP + "'"));
    var times = new ArrayList<Double>();
    int rows = 0;
    try (Connection c = pinned(db.app())) {
      for (int i = 0; i < 6; i++) {
        long t0 = System.nanoTime();
        rows = FunctionGrantsSql.callers(c, new long[] {login}, login).size();
        times.add((System.nanoTime() - t0) / 1e6);
      }
      c.rollback();
    }
    double first = times.get(0);
    var rest = new ArrayList<>(times.subList(1, times.size()));
    rest.sort(null);
    System.out.printf(
        "MEASURE pg%d: statement 3 with %d extensions, %d rows: first %.1f ms, median %.1f ms%n",
        major, catalogue.installableExtensions().size(), rows, first, rest.get(rest.size() / 2));
    assertThat(rows).isPositive();
  }
}
