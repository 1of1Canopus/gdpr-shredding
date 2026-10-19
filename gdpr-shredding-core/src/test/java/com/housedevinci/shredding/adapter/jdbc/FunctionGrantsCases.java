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
            + " SET search_path = public, s, pg_catalog");
    verifies(keep(TwoRoleCluster.app(pg, db.name())));
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
    var doctored = PinnedCatalogue.of(major, baseline, real.manifest(), real.versions());
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
}
