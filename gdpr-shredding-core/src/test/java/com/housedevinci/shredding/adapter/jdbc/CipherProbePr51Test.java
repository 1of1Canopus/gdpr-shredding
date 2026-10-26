package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.housedevinci.shredding.domain.ShreddingException;
import java.sql.SQLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Security review of PR 51 (C-RC021-2, trigger-slots addendum Rev 2), pass 1, head b868da2. Each
 * probe fails on that head. Internal file; the fix pass adds it to the suite before touching
 * production code.
 */
class CipherProbePr51Test {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container(16);
  private static final PostgreSQLContainer<?> PG17 = TwoRoleCluster.container(17);

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    PG17.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.roles(PG17);
  }

  @AfterAll
  static void stop() {
    PG.stop();
    PG17.stop();
  }

  /**
   * C-PR51-1. {@code CREATE TYPE ... AS RANGE} makes its constructor functions (and on 14 and later
   * the multirange constructors) itself: LANGUAGE internal, oid 16384 or above, in no extension,
   * symbols {@code range_constructor2/3} and {@code multirange_constructor0/1/2}. The leg 4 closure
   * now refuses them whatever their grants. On main a REVOKE from PUBLIC let the schema start; on
   * this branch nothing does: the remedy line says "Drop it, or install it as an extension", and a
   * range constructor cannot be dropped apart from its type. A schema with one user range type can
   * no longer use the library.
   */
  @Test
  void probe_user_range_type_with_revoked_constructors_refuses_with_no_remedy()
      throws SQLException {
    for (var pg : new PostgreSQLContainer<?>[] {PG, PG17}) {
      String db = "rng_revoked";
      TwoRoleCluster.install(pg, db);
      try (var su = TwoRoleCluster.superuser(pg, db);
          var app = TwoRoleCluster.app(pg, db)) {
        exec(
            su,
            "CREATE TYPE public.floatrange AS RANGE (subtype = float8)",
            "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC");
        assertThatCode(() -> JdbcSupport.verifySchema(app))
            .describedAs("a user range type with its constructors revoked starts (main did)")
            .doesNotThrowAnyException();
      }
    }
  }

  /**
   * C-PR51-1, the default case. Same type, default grants. Already refused on main through leg 4
   * for PUBLIC; the closure keeps it refused. The constructors are server-made code over five fixed
   * symbols that only build a range value; they reach nothing a revoke would protect.
   */
  @Test
  void probe_user_range_type_with_default_grants_refuses() throws SQLException {
    String db = "rng_default";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(su, "CREATE TYPE public.floatrange AS RANGE (subtype = float8)");
      assertThatCode(() -> JdbcSupport.verifySchema(app))
          .describedAs("a user range type with default grants starts")
          .doesNotThrowAnyException();
    }
  }

  /**
   * Reclassified, not a finding (green on b868da2: R7 reports every core function as rewritten,
   * "cannot be judged"). Statements 2 and 3 decide "native" by language NAME ({@code lanname IN
   * (internal, c)}). A superuser may rename both languages. The hand-made native trigger function
   * of the addendum then is neither native nor core nor in an extension: statement 2 does not list
   * it (no leg 4), and the statement 3 filter drops its trigger row. The probe judges only whether
   * the gate refuses; any code is accepted.
   */
  @Test
  void control_renamed_internal_language_does_not_hide_hand_made_native_trigger()
      throws SQLException {
    String db = "lang_renamed";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "ALTER LANGUAGE internal RENAME TO builtin",
          "CREATE TABLE public.lr_mark (id int)",
          "GRANT SELECT, INSERT, UPDATE ON public.lr_mark TO " + APP,
          "CREATE FUNCTION public.lr_t() RETURNS trigger LANGUAGE builtin"
              + " AS 'suppress_redundant_updates_trigger'",
          "REVOKE EXECUTE ON FUNCTION public.lr_t() FROM PUBLIC",
          "CREATE TRIGGER lr BEFORE UPDATE ON public.lr_mark"
              + " FOR EACH ROW EXECUTE FUNCTION public.lr_t()");
      exec(app, "INSERT INTO public.lr_mark VALUES (1)");
      long updated;
      try (var c = app.getConnection();
          var s = c.createStatement()) {
        updated = s.executeUpdate("UPDATE public.lr_mark SET id = id");
      }
      assertThat(updated).describedAs("the native trigger fired for the runtime role").isZero();
      var e = catchThrowableOfType(ShreddingException.class, () -> JdbcSupport.verifySchema(app));
      assertThat(e)
          .describedAs("renaming the language hides hand-made native code from the gate")
          .isNotNull();
    }
  }

  /**
   * Control for the extension door of the leg 4 closure. A hand-made native trigger function added
   * to plpgsql (installed everywhere) is an extension member, so leg 4 skips it; R5 must refuse it
   * as an unshipped member. Expected green; it pins the door.
   */
  @Test
  void control_hand_made_native_added_to_plpgsql_and_attached_revoked_refuses()
      throws SQLException {
    String db = "ext_door";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "CREATE TABLE public.ed_mark (id int)",
          "GRANT SELECT, INSERT, UPDATE ON public.ed_mark TO " + APP,
          "CREATE FUNCTION public.ed_t() RETURNS trigger LANGUAGE internal"
              + " AS 'suppress_redundant_updates_trigger'",
          "REVOKE EXECUTE ON FUNCTION public.ed_t() FROM PUBLIC",
          "ALTER EXTENSION plpgsql ADD FUNCTION public.ed_t()",
          "CREATE TRIGGER ed BEFORE UPDATE ON public.ed_mark"
              + " FOR EACH ROW EXECUTE FUNCTION public.ed_t()");
      var e = catchThrowableOfType(ShreddingException.class, () -> JdbcSupport.verifySchema(app));
      assertThat(e).describedAs("an unshipped member of plpgsql refuses").isNotNull();
      assertThat(e.getMessage()).contains("ed_t");
    }
  }

  /**
   * Control, green on b868da2. Section 5 of the addendum lists {@code
   * re_created_moddatetime_trigger_refuses_r5}; the PR drops it as covered by leg 4, but leg 4
   * skips extension members. A native re-creation refuses through R5b on the slot line; this pins
   * it.
   */
  @Test
  void control_re_created_moddatetime_native_trigger_is_named_by_its_slot() throws SQLException {
    String db = "moddt";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "CREATE EXTENSION moddatetime",
          "CREATE OR REPLACE FUNCTION public.moddatetime() RETURNS trigger LANGUAGE internal AS"
              + " 'suppress_redundant_updates_trigger'",
          "REVOKE EXECUTE ON FUNCTION public.moddatetime() FROM PUBLIC",
          "CREATE TABLE public.md (id int, m timestamp)",
          "GRANT SELECT, INSERT, UPDATE ON public.md TO " + APP,
          "CREATE TRIGGER md BEFORE UPDATE ON public.md FOR EACH ROW EXECUTE FUNCTION"
              + " public.moddatetime(m)");
      var e = catchThrowableOfType(ShreddingException.class, () -> JdbcSupport.verifySchema(app));
      assertThat(e).describedAs("a rewritten contrib trigger function refuses").isNotNull();
      assertThat(e.getMessage())
          .contains("function public.moddatetime() as the function of trigger md on public.md");
    }
  }

  /** Cost record, not a probe: the whole gate on a schema of 5000 tables, each with one FK. */
  @Test
  void measure_gate_with_5000_tables_and_foreign_keys() throws SQLException {
    String db = "scale";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "DROP EVENT TRIGGER IF EXISTS shredding_test_statistics_off",
          "CREATE TABLE public.root (id int PRIMARY KEY)",
          "DO $$BEGIN FOR i IN 1..5000 LOOP EXECUTE pg_catalog.format("
              + "'CREATE TABLE public.s%s (id int PRIMARY KEY, r int REFERENCES public.root)', i);"
              + " END LOOP; END$$");
      long t0 = System.nanoTime();
      var e = catchThrowableOfType(ShreddingException.class, () -> JdbcSupport.verifySchema(app));
      System.out.printf(
          "MEASURE cipher pg16: gate with 5000 tables and FKs: %.1f ms, refused=%s%n",
          (System.nanoTime() - t0) / 1e6, e == null ? "no" : e.code());
    }
  }
}
