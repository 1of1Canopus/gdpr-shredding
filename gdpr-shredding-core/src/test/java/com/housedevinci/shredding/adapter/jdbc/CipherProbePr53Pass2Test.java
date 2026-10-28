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
 * Security review of PR 53, pass 2, head 6a0f003. One adversarial variant per pass 1 finding. Tests
 * named probe_ fail on that head; tests named control_ pin a variant that holds. Every test runs on
 * both pins unless its name says 17. Internal file; the fix pass adds it to the suite before
 * touching production code.
 */
class CipherProbePr53Pass2Test {

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

  /** A revoked plpgsql IMMUTABLE function that names the role it runs as. Not a definer. */
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
      String name = "p53b_" + major + "_" + (counter++);
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
   * C-PR53-6 (MEDIUM). REINDEX SCHEMA by the schema's owner rebuilds every index in the schema,
   * also on tables owned outside reach, and each build runs as the table's owner. Measured on 16.14
   * and 17.11: REINDEX TABLE on the same table is refused ("must be owner" on 16, "permission
   * denied" on 17), REINDEX SCHEMA is not. Owning a schema is read only by O2, which applies only
   * with an entry point; here there is none (no foreign key, no definer function), as in C-PR53-3.
   * Same class as C-PR53-3: a parent object reach owns makes the server rebuild a child it does not
   * own.
   */
  @Test
  void probe_reindex_schema_by_schema_owner_over_table_owned_outside_reach_is_not_refused()
      throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              SPY
                  + "|CREATE SCHEMA s2 AUTHORIZATION "
                  + APP
                  + "|CREATE TABLE s2.t (i int)|INSERT INTO s2.t VALUES (1)"
                  + "|CREATE INDEX tx ON s2.t ((public.spy(i)))");
          assertThat(notices(db, "REINDEX SCHEMA s2"))
              .describedAs("pg %d: REINDEX SCHEMA rebuilt the index as the table owner", major)
              .contains("SPY as " + SU);
          refusesNaming(db, "a schema reach owns holds a table owned outside reach", "s2");
        });
  }

  /** C-PR53-1 variant: TRIGGER granted to a role the runtime role can only SET to (no INHERIT). */
  @Test
  void control_trigger_grant_to_a_set_only_role_refuses() throws SQLException {
    onBoth(
        (major, db) -> {
          String x = "p2x_" + db.name();
          plant(
              db,
              PARENT
                  + "|CREATE TABLE public.ch (pid int REFERENCES public.par ON DELETE CASCADE)"
                  + "|CREATE ROLE "
                  + x
                  + "|GRANT "
                  + x
                  + " TO "
                  + APP
                  + " WITH INHERIT FALSE, SET TRUE"
                  + "|GRANT TRIGGER ON public.ch TO "
                  + x);
          refusesNaming(db, "TRIGGER held by a SET-only role", "TRIGGER", "public.ch");
        });
  }

  /** C-PR53-2 variant: the statistics object sits on a partition of the FK table. */
  @Test
  void control_statistics_on_a_partition_of_the_fk_table_refuses() throws SQLException {
    onBoth(
        (major, db) -> {
          plant(
              db,
              PARENT
                  + "|"
                  + OwnerContextCases.SDI
                  + "|CREATE TABLE public.rcp (pid int REFERENCES public.par ON DELETE RESTRICT)"
                  + " PARTITION BY RANGE (pid)"
                  + "|CREATE TABLE public.rcp1 PARTITION OF public.rcp FOR VALUES FROM (0) TO (100)"
                  + "|CREATE STATISTICS public.rcps ON (public.sdi(1) + pid) FROM public.rcp1");
          refusesNaming(db, "statistics on a partition", OwnerContextCases.SDI_LABEL, "rcps");
        });
  }

  /**
   * C-PR53-3 variant: the parent is owned by a role reach holds by membership, and the partition
   * owned outside reach sits two levels down.
   */
  @Test
  void control_partition_two_levels_under_a_parent_owned_by_a_member_role_refuses()
      throws SQLException {
    onBoth(
        (major, db) -> {
          String x = "p2y_" + db.name();
          plant(
              db,
              SPY
                  + "|CREATE ROLE "
                  + x
                  + "|GRANT "
                  + x
                  + " TO "
                  + APP
                  + "|CREATE TABLE public.pp (i int) PARTITION BY RANGE (i)"
                  + "|CREATE TABLE public.ppm PARTITION OF public.pp FOR VALUES FROM (0) TO (10)"
                  + " PARTITION BY RANGE (i)"
                  + "|CREATE TABLE public.pp2 PARTITION OF public.ppm FOR VALUES FROM (0) TO (5)"
                  + "|INSERT INTO public.pp VALUES (1)"
                  + "|CREATE INDEX pp2x ON public.pp2 ((public.spy(i)))"
                  + "|ALTER TABLE public.pp OWNER TO "
                  + x
                  + "|ALTER TABLE public.ppm OWNER TO "
                  + x);
          assertThat(notices(db, "SET ROLE " + x, "REINDEX TABLE public.pp", "RESET ROLE"))
              .contains("SPY as " + SU);
          refusesNaming(db, "partition two levels down", "public.pp2");
        });
  }

  /** C-PR53-5 variant on 17: RETURNING a domain over a domain; the CHECK sits on the inner one. */
  @Test
  void control_json_value_returning_nested_domain_refuses_on_17() throws SQLException {
    String name = "p53b_17_" + (counter++);
    TwoRoleCluster.install(PG17, name);
    try (var su = TwoRoleCluster.superuser(PG17, name);
        var app = TwoRoleCluster.app(PG17, name)) {
      var db = new OwnerContextCases.Db(name, su, app);
      plant(
          db,
          PARENT
              + "|"
              + OwnerContextCases.SDI
              + "|CREATE DOMAIN public.dj1 AS int CHECK (public.sdi(VALUE) = VALUE)"
              + "|CREATE DOMAIN public.dj2 AS public.dj1"
              + "|CREATE TABLE public.ch (pid int DEFAULT"
              + " (JSON_VALUE(jsonb '1', '$' RETURNING public.dj2))::int"
              + " REFERENCES public.par ON DELETE SET DEFAULT)");
      refusesNaming(db, "the inner domain is followed", OwnerContextCases.SDI_LABEL, "public.dj1");
    }
  }

  /**
   * C-PR53-7 (INFO), wording of C-PR53-4. Measured on 16 and 17: a rule on the target writes rlog,
   * rlog's CHECK runs as the owner, and a rule on rlog writes r3, whose default runs as the owner
   * too. The shipped paragraph says only "that table's defaults and triggers", and does not say the
   * chain goes on. The paragraph must name every expression of the written table and the further
   * hops.
   */
  @Test
  void probe_second_hop_wording_omits_checks_and_further_hops() throws Exception {
    var notes =
        java.nio.file.Files.readString(
            java.nio.file.Path.of(System.getProperty("user.dir"))
                .getParent()
                .resolve("SECURITY-NOTES.md"));
    int at = notes.indexOf("Second-hop writes are a stated limit");
    assertThat(at).isNotNegative();
    String para = notes.substring(at, notes.indexOf("\n\n", at));
    assertThat(para).contains("CHECK").contains("third table");
  }
}
