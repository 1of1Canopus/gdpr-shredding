package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review, pass 3 of PR 47 (2026-10-20), head 43dfc2c. Every method is named {@code
 * confirms_*}: an attack on the fixes of C-PR47-4 and C-PR47-5 that the build handles correctly,
 * kept as evidence. Every case runs on both pins, each in its own database.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CipherProbePr47Pass3Test {

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

  private record Db(DataSource su, DataSource app, String tag) {}

  private Db db(int major) throws SQLException {
    var pg = pins.get(major);
    String tag = major + "_" + (counter++);
    String name = "p47c_" + tag;
    TwoRoleCluster.install(pg, name);
    return new Db(TwoRoleCluster.superuser(pg, name), TwoRoleCluster.app(pg, name), tag);
  }

  private static String wrapper(String schema, String name) {
    return "CREATE FUNCTION "
        + schema
        + "."
        + name
        + "(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
        + " AS 'SELECT pg_catalog.pg_read_file($1, 0, 200, $2)'";
  }

  private static String revoke(String schema, String name) {
    return "REVOKE EXECUTE ON FUNCTION " + schema + "." + name + "(text, boolean) FROM PUBLIC";
  }

  private static String aggregate(String name, String fn) {
    return "CREATE AGGREGATE public."
        + name
        + "(boolean) (sfunc = "
        + fn
        + ", stype = text, initcond = 'PG_VERSION')";
  }

  /** Same setup for each option set: w revoked from PUBLIC, EXECUTE granted to role g only. */
  private Db granted(int major, String options, boolean ownerSide) throws SQLException {
    var db = db(major);
    String g = "p47m_" + db.tag();
    exec(
        db.su(),
        "CREATE ROLE " + g + " NOLOGIN",
        "GRANT " + g + " TO " + APP + " WITH " + options,
        wrapper("public", "w"),
        revoke("public", "w"));
    if (ownerSide) {
      exec(
          db.su(),
          "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text, bigint, bigint, boolean) TO "
              + g,
          "ALTER FUNCTION public.w(text, boolean) OWNER TO " + g);
    } else {
      exec(db.su(), "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g);
    }
    exec(db.su(), aggregate("agg_w", "public.w"));
    return db;
  }

  private static String outcome(DataSource app) {
    try {
      JdbcSupport.verifySchema(app, false, List.of());
      return "";
    } catch (ShreddingException e) {
      return e.getMessage();
    }
  }

  /**
   * INHERIT TRUE, SET FALSE: the login holds USAGE on g, so it may call w directly. The aggregate
   * gives nothing a direct call does not (limit L19): leg 7 must not name it.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_inherit_true_set_false_grantee_counts_as_may_run(int major) throws Exception {
    for (boolean ownerSide : new boolean[] {false, true}) {
      var db = granted(major, "INHERIT TRUE, SET FALSE", ownerSide);
      assertThat(scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
          .startsWith(Integer.toString(major));
      assertThat(outcome(db.app())).doesNotContain("agg_w");
    }
  }

  /**
   * INHERIT FALSE, SET TRUE: no inherited rights, but the login may SET ROLE g and then call w.
   * Counts as may-run: leg 7 must not name the aggregate.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_inherit_false_set_true_grantee_counts_as_may_run(int major) throws Exception {
    for (boolean ownerSide : new boolean[] {false, true}) {
      var db = granted(major, "INHERIT FALSE, SET TRUE", ownerSide);
      String g = "p47m_" + db.tag();
      assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
          .hasMessageContaining("permission denied for function w");
      try (var c = db.app().getConnection();
          var s = c.createStatement()) {
        s.execute("SET ROLE " + g);
        try (var rs = s.executeQuery("SELECT public.w('PG_VERSION', true)")) {
          assertThat(rs.next()).isTrue();
          assertThat(rs.getString(1)).startsWith(Integer.toString(major));
        }
        s.execute("RESET ROLE");
      }
      assertThat(outcome(db.app())).doesNotContain("agg_w");
    }
  }

  /**
   * ADMIN TRUE, INHERIT FALSE, SET FALSE: on 16 and 17 ADMIN gives the right to grant g, not g's
   * rights, and not SET ROLE g. The login cannot call w, the aggregate can: leg 7 must refuse.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_admin_only_grantee_does_not_count_and_refuses(int major) throws Exception {
    for (boolean ownerSide : new boolean[] {false, true}) {
      var db = granted(major, "ADMIN TRUE, INHERIT FALSE, SET FALSE", ownerSide);
      String g = "p47m_" + db.tag();
      assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
          .hasMessageContaining("permission denied for function w");
      assertThatThrownBy(() -> exec(db.app(), "SET ROLE " + g))
          .hasMessageContaining("permission denied to set role");
      assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));
      assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
          .contains("aggregate public.agg_w(boolean)")
          .contains("whose transfn is function public.w(text, boolean)");
    }
  }

  /**
   * Two hops: the login may SET ROLE a (no inherit), and a inherits b, which alone holds EXECUTE on
   * w. pg_has_role(login, b, ...) is false for USAGE and SET, so R6 refuses. Fail-closed: the login
   * could reach w by SET ROLE a, so this refusal is stricter than needed, never weaker.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_two_hop_set_then_inherit_refuses_fail_closed(int major) throws Exception {
    var db = db(major);
    String a = "p47a_" + db.tag();
    String b = "p47b_" + db.tag();
    exec(
        db.su(),
        "CREATE ROLE " + a + " NOLOGIN",
        "CREATE ROLE " + b + " NOLOGIN",
        "GRANT " + b + " TO " + a + " WITH INHERIT TRUE, SET FALSE",
        "GRANT " + a + " TO " + APP + " WITH INHERIT FALSE, SET TRUE",
        wrapper("public", "w"),
        revoke("public", "w"),
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + b,
        aggregate("agg_w", "public.w"));
    assertThat(outcome(db.app())).contains("aggregate public.agg_w(boolean)");
  }

  /**
   * A schema name holding a double quote prints quoted and doubled, as regprocedure prints it, so
   * {@code ev"il.w} cannot pass for a different name.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_schema_with_a_quote_prints_quoted(int major) throws Exception {
    var db = db(major);
    String schema = "\"ev\"\"il\"";
    exec(
        db.su(),
        "CREATE SCHEMA " + schema,
        wrapper(schema, "w"),
        revoke(schema, "w"),
        aggregate("agg_w", schema + ".w"));
    assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
        .contains("aggregate public.agg_w(boolean)")
        .contains("whose transfn is function \"ev\"\"il\".w(text, boolean)");
  }

  /**
   * A 63-byte schema name (the limit) of two-byte characters and capitals, and a 63-byte function
   * name: the label is text, not name, so quoting does not truncate it.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_63_byte_names_print_whole(int major) throws Exception {
    var db = db(major);
    String schemaName = "X" + "é".repeat(31); // 1 + 62 bytes
    String fn = "f".repeat(63);
    String schema = "\"" + schemaName + "\"";
    exec(
        db.su(),
        "CREATE SCHEMA " + schema,
        wrapper(schema, fn),
        revoke(schema, fn),
        aggregate("agg_w", schema + "." + fn));
    assertThat(
            scalar(
                db.su(),
                "SELECT octet_length(nspname) FROM pg_namespace WHERE nspname = '"
                    + schemaName
                    + "'"))
        .isEqualTo("63");
    assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
        .contains("whose transfn is function " + schema + "." + fn + "(text, boolean)");
  }
}
