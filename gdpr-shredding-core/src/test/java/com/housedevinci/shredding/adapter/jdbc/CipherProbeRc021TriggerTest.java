package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

/** Whole-module pass for 0.2.1, finding C-RC021-2. Fails on main at d6f88a6. */
class CipherProbeRc021TriggerTest {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
  }

  @AfterAll
  static void stop() {
    PG.stop();
  }

  /**
   * RC021-2. Leg 4 refuses a hand-made native function that reach or PUBLIC may execute. A trigger
   * calls its function with no EXECUTE check, so revoking EXECUTE and attaching the same function
   * as a trigger on a table the runtime role writes keeps it reachable, and the gate passes. R6
   * judges agg, opr and lang slots only. The symbol is a harmless built-in; the probe judges the
   * gate verdict, not a payload.
   */
  @Test
  void probe_hand_made_native_function_reachable_as_a_trigger_passes_the_gate()
      throws SQLException {
    String db = "trig";
    TwoRoleCluster.install(PG, db);
    try (var su = TwoRoleCluster.superuser(PG, db);
        var app = TwoRoleCluster.app(PG, db)) {
      exec(
          su,
          "CREATE TABLE public.trig_mark (id int)",
          "GRANT SELECT, INSERT, UPDATE ON public.trig_mark TO " + APP,
          "CREATE FUNCTION public.rc021_t() RETURNS trigger LANGUAGE internal"
              + " AS 'suppress_redundant_updates_trigger'");
      var control =
          org.assertj.core.api.Assertions.catchThrowableOfType(
              com.housedevinci.shredding.domain.ShreddingException.class,
              () -> JdbcSupport.verifySchema(app));
      assertThat(control)
          .describedAs("control: leg 4 refuses the function while PUBLIC may run it")
          .isNotNull();
      assertThat(control.code()).isEqualTo("SHRED-SCHEMA-004");

      exec(
          su,
          "REVOKE EXECUTE ON FUNCTION public.rc021_t() FROM PUBLIC",
          "CREATE TRIGGER rc021 BEFORE UPDATE ON public.trig_mark"
              + " FOR EACH ROW EXECUTE FUNCTION public.rc021_t()");
      exec(app, "INSERT INTO public.trig_mark VALUES (1)");
      long updated;
      try (var c = app.getConnection();
          var s = c.createStatement()) {
        updated = s.executeUpdate("UPDATE public.trig_mark SET id = id");
      }
      assertThat(updated)
          .describedAs("the trigger fired for the runtime role: no-op update suppressed")
          .isZero();

      var reached =
          org.assertj.core.api.Assertions.catchThrowableOfType(
              com.housedevinci.shredding.domain.ShreddingException.class,
              () -> JdbcSupport.verifySchema(app));
      assertThat(reached)
          .describedAs("the runtime role still runs the hand-made native code, through a trigger")
          .isNotNull();
    }
  }
}
