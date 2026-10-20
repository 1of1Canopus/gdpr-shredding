package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.scalar;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review, pass 2 of PR 47 (2026-10-20), head 13afe8f. Methods named {@code confirms_*} are
 * GREEN on 13afe8f: attacks on the fixes of C-PR47-1 to C-PR47-3 that the build refuses or lists,
 * kept as evidence. Methods named {@code probe_*} are RED on 13afe8f. Every case runs on both pins,
 * each in its own database.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CipherProbePr47Pass2Test {

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
    String name = "p47b_" + tag;
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

  private static List<String> l19(DataSource su) throws Exception {
    String notes = Files.readString(Path.of("../SECURITY-NOTES.md"));
    var m =
        Pattern.compile("<!-- l19-audit-query -->\\s*```sql\\n(.*?)```", Pattern.DOTALL)
            .matcher(notes);
    assertThat(m.find()).isTrue();
    var listed = new ArrayList<String>();
    try (var c = su.getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery(m.group(1).replace("'app'", "'" + APP + "'"))) {
      while (rs.next()) {
        listed.add(rs.getString("function") + " via " + rs.getString("executable_via"));
      }
    }
    return listed;
  }

  /**
   * The L19 audit query and R6 follow the wrapper by oid: renamed and moved to another schema after
   * the aggregate was made, it is still listed and still refused, under its new name.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_renamed_and_moved_wrapper_is_listed_by_l19_and_refused(int major) throws Exception {
    var db = db(major);
    exec(
        db.su(),
        wrapper("public", "w"),
        revoke("public", "w"),
        aggregate("agg_w", "public.w"),
        "CREATE SCHEMA evil",
        "ALTER FUNCTION public.w(text, boolean) RENAME TO w2",
        "ALTER FUNCTION public.w2(text, boolean) SET SCHEMA evil");
    assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));
    assertThat(l19(db.su()))
        .contains("evil.w2(text,boolean) via called by aggregate agg_w(boolean)");
    assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
        .contains("aggregate public.agg_w(boolean)")
        .contains("whose transfn is function evil.w2(text, boolean)");
  }

  /**
   * Two wrappers with the same schema-less key, one granted to PUBLIC (limit L19), one revoked.
   * Each slot carries its own facts, so the granted one never clears the revoked one, in either
   * creation order.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_same_key_wrappers_in_two_schemas_are_judged_apart(int major) throws Exception {
    for (boolean revokedFirst : new boolean[] {true, false}) {
      var db = db(major);
      exec(db.su(), "CREATE SCHEMA evil");
      if (revokedFirst) {
        exec(db.su(), wrapper("evil", "w"), revoke("evil", "w"), wrapper("public", "w"));
      } else {
        exec(db.su(), wrapper("public", "w"), wrapper("evil", "w"), revoke("evil", "w"));
      }
      exec(db.su(), aggregate("agg_a", "evil.w"), aggregate("agg_b", "public.w"));
      String message = FunctionGrantsCases.refusal(db.app()).getMessage();
      assertThat(message)
          .contains("aggregate public.agg_a(boolean)")
          .contains("whose transfn is function evil.w(text, boolean)")
          .doesNotContain("agg_b")
          .doesNotContain("function public.w(");
    }
  }

  /**
   * "Owner in reach counts as may-run", attacked with the weakest membership: the wrapper's owner
   * is granted to the runtime role WITH INHERIT FALSE, SET FALSE, and holds EXECUTE on
   * pg_read_file. The runtime role cannot become that owner, yet the aggregate reads the file as
   * it. The gate must refuse, whichever leg sees it.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_wrapper_owned_by_a_no_inherit_no_set_member_refuses(int major) throws Exception {
    var db = db(major);
    String g = "p47g_" + db.tag();
    exec(
        db.su(),
        "CREATE ROLE " + g + " NOLOGIN",
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET FALSE",
        "GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text, bigint, bigint, boolean) TO " + g,
        wrapper("public", "w"),
        revoke("public", "w"),
        "ALTER FUNCTION public.w(text, boolean) OWNER TO " + g,
        aggregate("agg_w", "public.w"));
    assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));
    assertThat(FunctionGrantsCases.refusal(db.app())).isNotNull();
  }

  /**
   * "PUBLIC or a role in reach holds EXECUTE" reads reach as every role the login is a MEMBER of,
   * also through a grant WITH INHERIT FALSE, SET FALSE, which gives the login none of that role's
   * rights. A wrapper revoked from PUBLIC and granted only to such a role cannot be called
   * directly, yet the aggregate runs it, and the gate treats it as limit L19.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_wrapper_granted_only_to_a_no_inherit_no_set_member_passes_and_reads_a_file(int major)
      throws Exception {
    var db = db(major);
    String g = "p47h_" + db.tag();
    exec(
        db.su(),
        "CREATE ROLE " + g + " NOLOGIN",
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET FALSE",
        wrapper("public", "w"),
        revoke("public", "w"),
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        aggregate("agg_w", "public.w"));
    // Impact, shown first: the direct call is refused, the aggregate reads the file.
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
        .hasMessageContaining("permission denied for function w");
    assertThat(scalar(db.app(), "SELECT public.agg_w(true)")).startsWith(Integer.toString(major));
    // Red today: the gate verifies. Green once fn_reach counts only roles whose rights the login
    // may use (USAGE or SET), so R6 refuses with leg 7.
    assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
        .contains("aggregate public.agg_w(boolean)")
        .contains("whose transfn is function public.w(text, boolean)");
  }

  /**
   * The owner side of "reach may run it as itself", with the same membership: wrapper w1 is owned
   * by a role the login is a MEMBER of WITH INHERIT FALSE, SET FALSE, so R6 counts it as run by
   * reach. Its body runs as that role and calls wrapper w, granted only to that role, whose body
   * runs as the superuser. Neither wrapper can be called directly; the aggregate reads the file.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_wrapper_owned_by_a_no_inherit_no_set_member_chains_to_a_file_read(int major)
      throws Exception {
    var db = db(major);
    String g = "p47k_" + db.tag();
    exec(
        db.su(),
        "CREATE ROLE " + g + " NOLOGIN",
        "GRANT " + g + " TO " + APP + " WITH INHERIT FALSE, SET FALSE",
        wrapper("public", "w"),
        revoke("public", "w"),
        "GRANT EXECUTE ON FUNCTION public.w(text, boolean) TO " + g,
        "CREATE FUNCTION public.w1(text, boolean) RETURNS text LANGUAGE sql SECURITY DEFINER"
            + " AS 'SELECT public.w($1, $2)'",
        "REVOKE EXECUTE ON FUNCTION public.w1(text, boolean) FROM PUBLIC",
        "ALTER FUNCTION public.w1(text, boolean) OWNER TO " + g,
        aggregate("agg_w1", "public.w1"));
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w1('PG_VERSION', true)"))
        .hasMessageContaining("permission denied for function w1");
    assertThatThrownBy(() -> scalar(db.app(), "SELECT public.w('PG_VERSION', true)"))
        .hasMessageContaining("permission denied for function w");
    assertThat(scalar(db.app(), "SELECT public.agg_w1(true)")).startsWith(Integer.toString(major));
    assertThat(FunctionGrantsCases.refusal(db.app()).getMessage())
        .contains("aggregate public.agg_w1(boolean)")
        .contains("whose transfn is function public.w1(text, boolean)");
  }

  /**
   * SECURITY-NOTES says the second half of the L19 query lists "every wrapper an aggregate,
   * operator or language calls". It reads an operator's estimators only, not its function. Green
   * today: kept as evidence for the wording fix (an operator's function is checked as the caller,
   * so the omission itself opens nothing).
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void confirms_l19_second_half_omits_an_operator_function(int major) throws Exception {
    var db = db(major);
    exec(
        db.su(),
        wrapper("public", "w"),
        revoke("public", "w"),
        "CREATE OPERATOR public.### (LEFTARG = text, RIGHTARG = boolean, FUNCTION = public.w)");
    assertThat(l19(db.su())).noneMatch(line -> line.contains("called by operator"));
  }

  /**
   * The refusal names the slot function by schema so the operator can tell evil.f from public.f. A
   * schema named public followed by U+200B (zero width space) prints as "public.w": the label is
   * not quoted, and the message escape leaves format characters as they are.
   */
  @ParameterizedTest
  @ValueSource(ints = {16, 17})
  void probe_refusal_label_hides_a_zero_width_character_in_the_schema_name(int major)
      throws Exception {
    var db = db(major);
    String schema = "U&\"public\\200B\"";
    exec(
        db.su(),
        "CREATE SCHEMA " + schema,
        wrapper(schema, "w"),
        revoke(schema, "w"),
        aggregate("agg_w", schema + ".w"));
    String message = FunctionGrantsCases.refusal(db.app()).getMessage();
    assertThat(message).contains("aggregate public.agg_w(boolean)");
    assertThat(message).doesNotContain(String.valueOf((char) 0x200B));
  }
}
