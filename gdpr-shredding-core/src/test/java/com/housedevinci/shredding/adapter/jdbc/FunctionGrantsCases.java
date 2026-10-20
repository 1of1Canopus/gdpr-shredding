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
        held("public.b1(text, text)"));
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
    refuses(
        db.app(),
        "PUBLIC " + held("public.w(text)") + ", native code created outside any extension");
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
    verifies(db.app());
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
   * The count behind "refused by signature", kept live on each pin: no withheld initdb function
   * takes or returns cstring or internal, returns trigger or event_trigger, or fits a combine,
   * btree compare, range subdiff or FDW validator shape. The validator shape (oid) fits four: R6
   * judges that slot. A pin bump that adds a fit turns this red.
   */
  @Test
  void withheld_built_ins_fit_no_refused_slot_shape_and_four_fit_the_validator()
      throws SQLException {
    var db = db();
    String w =
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_init_privs i ON i.objoid = p.oid"
            + " AND i.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND i.privtype = 'i'"
            + " WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(i.initprivs) y"
            + " WHERE y.grantee = 0)";
    String refusedShapes =
        "SELECT pg_catalog.count(*) "
            + w
            + " AND (p.prorettype IN ('cstring'::pg_catalog.regtype, 'internal'::pg_catalog.regtype,"
            + " 'trigger'::pg_catalog.regtype, 'event_trigger'::pg_catalog.regtype)"
            + " OR p.proargtypes::pg_catalog.oid[] && '{2275,2281}'::pg_catalog.oid[]"
            + " OR (p.pronargs = 2 AND p.proargtypes[0] = p.proargtypes[1]"
            + " AND (p.prorettype IN ('int4'::pg_catalog.regtype, 'bool'::pg_catalog.regtype,"
            + " 'float8'::pg_catalog.regtype) OR p.prorettype = p.proargtypes[0]))"
            + " OR (p.pronargs = 2 AND p.proargtypes[0] = 'text[]'::pg_catalog.regtype))";
    assertThat(scalar(db.su(), refusedShapes)).isEqualTo("0");
    String validators =
        "SELECT pg_catalog.string_agg(p.proname::text, ',' ORDER BY p.proname) "
            + w
            + " AND p.pronargs = 1 AND p.proargtypes[0] = 'oid'::pg_catalog.regtype";
    assertThat(scalar(db.su(), validators))
        .isEqualTo(
            "pg_ls_tmpdir,pg_stat_reset_single_function_counters,"
                + "pg_stat_reset_single_table_counters,pg_stat_reset_subscription_stats");
  }
}
