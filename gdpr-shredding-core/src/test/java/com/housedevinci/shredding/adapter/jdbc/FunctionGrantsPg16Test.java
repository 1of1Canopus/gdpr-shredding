package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;

import java.sql.SQLException;
import org.junit.jupiter.api.Test;

/**
 * The function-grants paths on the PostgreSQL 16 pin (C-PR45-3), plus the ones that need {@code
 * adminpack}, which 17 no longer ships.
 */
class FunctionGrantsPg16Test extends FunctionGrantsCases {

  FunctionGrantsPg16Test() {
    super(16);
  }

  private static final String PFW = "pg_catalog.pg_file_write(text, text, boolean)";

  @Test
  void execute_on_adminpack_pg_file_write_refuses_on_16() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION adminpack", "GRANT EXECUTE ON FUNCTION " + PFW + " TO " + APP);
    refuses(db.app(), "login role " + APP + " " + held(PFW));
  }

  @Test
  void c_alias_of_an_extension_symbol_refuses_on_16() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION adminpack",
        "CREATE FUNCTION public.w_abs(text, text, boolean) RETURNS bigint LANGUAGE c STRICT"
            + " AS '/usr/local/lib/postgresql/adminpack.so', 'pg_file_write_v1_1'");
    refuses(
        db.app(),
        "PUBLIC " + held("public.w_abs(text, text, boolean)"),
        "symbol pg_file_write_v1_1");
  }

  @Test
  void extension_drop_function_then_grant_is_r3_on_16() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION adminpack",
        "ALTER EXTENSION adminpack DROP FUNCTION " + PFW,
        "GRANT EXECUTE ON FUNCTION " + PFW + " TO " + APP);
    refuses(db.app(), held(PFW) + ", native code created outside any extension");
  }

  @Test
  void four_step_launder_of_pg_file_write_refuses_on_16() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION adminpack",
        "ALTER EXTENSION adminpack DROP FUNCTION " + PFW,
        "DROP FUNCTION " + PFW,
        "CREATE FUNCTION "
            + PFW
            + " RETURNS bigint LANGUAGE c STRICT AS '$libdir/adminpack', 'pg_file_write_v1_1'",
        "ALTER EXTENSION adminpack ADD FUNCTION " + PFW);
    refuses(
        db.app(),
        "PUBLIC "
            + held(PFW)
            + ", which runs code that adminpack 2.1 ships without EXECUTE for PUBLIC");
  }

  @Test
  void older_adminpack_versions_shipped_public_verify_on_16() throws SQLException {
    var db = db();
    exec(db.su(), "CREATE EXTENSION adminpack VERSION '1.0'");
    verifies(db.app());
    var other = db();
    exec(other.su(), "CREATE EXTENSION adminpack VERSION '1.1'");
    verifies(other.app());
  }

  @Test
  void core_function_sharing_a_withheld_extension_symbol_verifies() throws SQLException {
    // F47 through leg 2 and R5a: pg_rotate_logfile_old() (core, internal) shares its symbol with
    // adminpack 1.1 pg_logfile_rotate(), which 1.1 withholds.
    var db = db();
    verifies(db.app());
    exec(db.su(), "CREATE EXTENSION adminpack VERSION '1.1'");
    verifies(db.app());
  }

  @Test
  void core_function_rewritten_to_language_c_with_a_withheld_symbol_refuses() throws SQLException {
    // C-PR45-3-16: CREATE OR REPLACE keeps oid 4099 and makes it run pg_file_write's code.
    // R7 refuses first (005); leg 2 still names the withheld code, as "also seen" (mutation 27).
    var db = db();
    exec(
        db.su(),
        "CREATE EXTENSION adminpack",
        "CREATE OR REPLACE FUNCTION pg_catalog.pg_rotate_logfile_old() RETURNS boolean"
            + " LANGUAGE c AS '$libdir/adminpack', 'pg_file_write_v1_1'");
    unverifiable(
        db.app(),
        "core function pg_catalog.pg_rotate_logfile_old() is language c, symbol"
            + " pg_file_write_v1_1",
        "also seen: PUBLIC " + held("pg_catalog.pg_rotate_logfile_old()"),
        "symbol pg_file_write_v1_1");
  }
}
