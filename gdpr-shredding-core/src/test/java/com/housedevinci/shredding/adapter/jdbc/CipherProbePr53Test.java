package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.FunctionGrantsCases.refusal;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.domain.ErrorCodes;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of PR 53 (owner-context control, design page Rev 2), pass 1, head 308cc5f. Each
 * probe_ test fails on that head. Internal file; the fix pass adds it to the suite before touching
 * production code. Every probe runs on both pins. The superuser plants the shape; the runtime role
 * shows the path where a path is shown; the gate's verdict is asserted.
 */
class CipherProbePr53Test {

  private static final PostgreSQLContainer<?> PG16 = TwoRoleCluster.container(16);
  private static final PostgreSQLContainer<?> PG17 = TwoRoleCluster.container(17);
  private static int counter;

  @BeforeAll
  static void start() throws SQLException {
    PG16.start();
    PG17.start();
    TwoRoleCluster.roles(PG16);
    TwoRoleCluster.roles(PG17);
  }

  @AfterAll
  static void stop() {
    PG16.stop();
    PG17.stop();
  }

  private static final String SU = OwnerContextCases.SU;

  /** A revoked plpgsql IMMUTABLE function that names the role it runs as. */
  private static final String SPY =
      "CREATE FUNCTION public.spy(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
          + " 'BEGIN RAISE NOTICE ''SPY as %'', current_user; RETURN $1; END'"
          + "|REVOKE EXECUTE ON FUNCTION public.spy(int) FROM PUBLIC";

  private static final String PARENT =
      "CREATE TABLE public.par (id int PRIMARY KEY)|INSERT INTO public.par VALUES (1), (2), (3)"
          + "|GRANT SELECT, UPDATE, DELETE ON public.par TO "
          + APP;

  interface Body {
    void run(int major, OwnerContextCases.Db db) throws SQLException;
  }

  private static void onBoth(Body body) throws SQLException {
    for (var pg : List.of(PG16, PG17)) {
      int major = pg == PG16 ? 16 : 17;
      String name = "p53_" + major + "_" + (counter++);
      TwoRoleCluster.install(pg, name);
      try (var su = TwoRoleCluster.superuser(pg, name);
          var app = TwoRoleCluster.app(pg, name)) {
        body.run(major, new OwnerContextCases.Db(name, su, app));
      }
    }
  }

  private static void plant(OwnerContextCases.Db db, String statements) throws SQLException {
    exec(db.su(), statements.split("\\|"));
  }

  private static List<String> notices(OwnerContextCases.Db db, String... sql) throws SQLException {
    var out = new ArrayList<String>();
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      for (String each : sql) {
        s.execute(each);
        for (SQLWarning w = s.getWarnings(); w != null; w = w.getNextWarning()) {
          out.add(w.getMessage());
        }
        s.clearWarnings();
      }
    }
    return out;
  }

  private static void refusesNaming(OwnerContextCases.Db db, String why, String... parts) {
    var e = refusal(db.app());
    assertThat(e.code()).describedAs(e.getMessage()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED);
    for (String part : parts) {
      assertThat(e).describedAs(why).hasMessageContaining(part);
    }
  }

  /**
   * C-PR53-1 (MEDIUM). TRIGGER privilege on a table owned outside reach is a control over code the
   * owner runs, like ownership (R3), but no leg reads it: O2 reads ownership and CREATE, O3 reads
   * MAINTAIN, and object grants are read on the module's tables only. The gate starts; then the
   * runtime role attaches a BEFORE trigger whose WHEN calls a function it may not call, and its own
   * DELETE on the parent runs that WHEN as the target's owner through the cascade.
   */
  @Test
  void probe_trigger_grant_on_fk_action_target_owned_outside_reach_is_not_refused()
      throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|"
                  + PARENT
                  + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
                  + "|INSERT INTO public.ch VALUES (1)"
                  + "|GRANT TRIGGER ON public.ch TO "
                  + APP);
          var e = refusal(db.app());
          assertThat(e.getMessage())
              .describedAs("pg %d: the gate must name the TRIGGER grant", major)
              .contains("TRIGGER")
              .contains("public.ch");
        });
  }

  /** C-PR53-1, the path itself (a control for the probe above; green on the head). */
  @Test
  void control_trigger_grant_lets_the_runtime_role_run_code_as_the_target_owner()
      throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|"
                  + PARENT
                  + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
                  + "|INSERT INTO public.ch VALUES (1)"
                  + "|GRANT TRIGGER ON public.ch TO "
                  + APP);
          // The WHEN is false, so the trigger function is never called; the WHEN still runs.
          var seen =
              notices(
                  db,
                  "CREATE TRIGGER t BEFORE DELETE ON public.ch FOR EACH ROW"
                      + " WHEN (public.spy(1) = 2) EXECUTE FUNCTION"
                      + " pg_catalog.suppress_redundant_updates_trigger()",
                  "DELETE FROM public.par WHERE id = 1");
          assertThat(seen).contains("SPY as " + SU);
        });
  }

  /**
   * C-PR53-2 (MEDIUM). Extended statistics expressions are a planner source. The planner reads them
   * and folds their constant immutable calls when it plans a query on the table, so the foreign-key
   * check (and the cascade write) runs them as the table's owner. Statement 4 reads index, key and
   * constraint trees but not pg_statistic_ext.stxexprs. Same class as C-RC021-2i. The path is shown
   * with spy; the gate is asserted on sdi, the function the builder's index test uses, so the probe
   * turns green on the same leg that judges an index expression.
   */
  @Test
  void probe_statistics_expression_on_fk_check_table_over_withheld_function_is_not_judged()
      throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|"
                  + PARENT
                  + "|CREATE TABLE public.rc (pid int REFERENCES public.par ON DELETE RESTRICT)"
                  + "|CREATE STATISTICS public.rcs ON (public.spy(1) + pid) FROM public.rc"
                  + "|"
                  + OwnerContextCases.SDI
                  + "|CREATE STATISTICS public.rcd ON (public.sdi(1) + pid) FROM public.rc");
          assertThat(notices(db, "DELETE FROM public.par WHERE id = 3"))
              .describedAs("pg %d: the check query ran the statistics expression", major)
              .contains("SPY as " + SU);
          refusesNaming(
              db,
              "statement 4 must judge statistics expressions",
              OwnerContextCases.SDI_LABEL,
              "rcd");
        });
  }

  /** C-PR53-2 on an FK-action target (cascade). */
  @Test
  void probe_statistics_expression_on_fk_action_target_over_withheld_function_is_not_judged()
      throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|"
                  + PARENT
                  + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
                  + "|INSERT INTO public.ch VALUES (1)"
                  + "|CREATE STATISTICS public.chs ON (public.spy(2) + pid) FROM public.ch"
                  + "|"
                  + OwnerContextCases.SDI
                  + "|CREATE STATISTICS public.chd ON (public.sdi(2) + pid) FROM public.ch");
          assertThat(notices(db, "DELETE FROM public.par WHERE id = 1")).contains("SPY as " + SU);
          refusesNaming(
              db,
              "statement 4 must judge statistics expressions",
              OwnerContextCases.SDI_LABEL,
              "chd");
        });
  }

  /**
   * C-PR53-3 (MEDIUM). O3 reads MAINTAIN grants only. A runtime role that owns a partitioned table
   * whose partition is owned outside reach runs REINDEX TABLE on the parent, and the server
   * rebuilds the partition's index as the partition's owner, running its index expression. VACUUM
   * and ANALYZE skip the partition with "permission denied"; REINDEX does not. No foreign key, no
   * definer function: O2 has no entry point and passes.
   */
  @Test
  void probe_reindex_through_owned_partitioned_parent_is_not_refused() throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|CREATE TABLE public.pp (i int) PARTITION BY RANGE (i)"
                  + "|CREATE TABLE public.pp1 (i int)|INSERT INTO public.pp1 VALUES (1)"
                  + "|CREATE INDEX pp1x ON public.pp1 ((public.spy(i)))"
                  + "|ALTER TABLE public.pp ATTACH PARTITION public.pp1 FOR VALUES FROM (0) TO (10)"
                  + "|ALTER TABLE public.pp OWNER TO "
                  + APP);
          assertThat(notices(db, "REINDEX TABLE public.pp"))
              .describedAs(
                  "pg %d: REINDEX on the parent ran the partition's index as its owner", major)
              .contains("SPY as " + SU);
          var e = refusal(db.app());
          assertThat(e.getMessage()).contains("public.pp1");
        });
  }

  /**
   * C-PR53-4 (LOW, QUESTIONS #C-61). A rule action on an FK-action target that writes a second
   * table runs that table's defaults as the owner; O1 does not follow the write. Ruled a stated
   * limit for 0.2.1. This probe pins the documentation: SECURITY-NOTES must state the limit with
   * this example. It reads the shipped file.
   */
  @Test
  void probe_second_hop_write_limit_is_not_documented() throws Exception {
    var notes =
        java.nio.file.Files.readString(
            java.nio.file.Path.of(System.getProperty("user.dir"))
                .getParent()
                .resolve("SECURITY-NOTES.md"));
    assertThat(notes).describedAs("the second-hop limit (C-PR53-4) is stated").contains("C-PR53-4");
  }

  /**
   * C-PR53-5 (MEDIUM, PostgreSQL 17 only). On 17, JSON_VALUE ... RETURNING a domain stores the
   * domain only as the typid of its JsonReturning node: no CoerceToDomain, no resulttype. Statement
   * 4 reads resulttype, not typid, so the domain is never followed and its CHECK is never judged,
   * yet the server checks the domain when the default is evaluated: as the owner under SET DEFAULT
   * (measured: the CHECK's function ran as the bootstrap superuser). On 16, JSON_OBJECT ...
   * RETURNING a domain stores a CoerceToDomain and is followed (control, measured).
   */
  @Test
  void probe_json_value_returning_domain_check_is_not_followed_on_17() throws SQLException {
    String name = "p53_17_" + (counter++);
    TwoRoleCluster.install(PG17, name);
    try (var su = TwoRoleCluster.superuser(PG17, name);
        var app = TwoRoleCluster.app(PG17, name)) {
      var db = new OwnerContextCases.Db(name, su, app);
      plant(
          db,
          PARENT
              + "|"
              + OwnerContextCases.SDI
              + "|CREATE DOMAIN public.dj AS int CHECK (public.sdi(VALUE) = VALUE)"
              + "|CREATE TABLE public.ch (pid int DEFAULT"
              + " (JSON_VALUE(jsonb '1', '$' RETURNING public.dj))::int"
              + " REFERENCES public.par ON DELETE SET DEFAULT)");
      refusesNaming(
          db,
          "the domain named by RETURNING is followed",
          OwnerContextCases.SDI_LABEL,
          "public.dj");
    }
  }
}
