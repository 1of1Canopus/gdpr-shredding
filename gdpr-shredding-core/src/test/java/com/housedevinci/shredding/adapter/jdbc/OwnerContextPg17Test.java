package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.FunctionGrantsCases.refuses;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.APP;
import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;
import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;
import org.junit.jupiter.api.Test;

/** The owner-context paths on the PostgreSQL 17 pin, plus MAINTAIN, which only 17 has. */
class OwnerContextPg17Test extends OwnerContextCases {

  OwnerContextPg17Test() {
    super(17);
  }

  /** O3, Q5 (C-RC021-2f): MAINTAIN runs the table's index expressions as its owner. */
  @Test
  void maintain_on_a_table_owned_outside_reach_refuses_on_17() throws SQLException {
    var db = db();
    plant(
        db,
        "CREATE FUNCTION public.spy(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS"
            + " 'BEGIN RAISE NOTICE ''EXPR as %'', current_user; RETURN $1; END'"
            + "|REVOKE EXECUTE ON FUNCTION public.spy(int) FROM PUBLIC"
            + "|CREATE TABLE public.tm (i int)|INSERT INTO public.tm VALUES (1)"
            + "|CREATE INDEX tmx ON public.tm ((public.spy(i)))"
            + "|GRANT MAINTAIN ON public.tm TO "
            + APP);
    try (var c = db.app().getConnection();
        var s = c.createStatement()) {
      s.execute("REINDEX TABLE public.tm");
      var w = s.getWarnings();
      assertThat(w == null ? "no notice" : w.getMessage()).isEqualTo("EXPR as " + SU);
    }
    refuses(
        db.app(),
        "login role " + APP + " holds MAINTAIN on relation public.tm, owned by " + SU,
        "(O3, C-RC021-2f)");
  }

  @Test
  void maintain_granted_to_public_refuses_on_17() throws SQLException {
    var db = db();
    plant(db, "CREATE TABLE public.tm (i int)|GRANT MAINTAIN ON public.tm TO PUBLIC");
    refuses(db.app(), "PUBLIC holds MAINTAIN on relation public.tm");
  }

  @Test
  void o3_is_not_relaxed_by_allow_privileged_runtime_role_on_17() throws SQLException {
    var db = db();
    plant(db, "CREATE TABLE public.tm (i int)|GRANT MAINTAIN ON public.tm TO " + APP);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> JdbcSupport.verifySchema(db.app(), true, java.util.List.of()))
        .hasMessageContaining("(O3, C-RC021-2f)");
  }

  @Test
  void pg_maintain_in_reach_refuses_on_17() throws SQLException {
    var db = db();
    exec(db.su(), "GRANT pg_maintain TO " + APP);
    refuses(db.app(), "role pg_maintain, reachable from login role " + APP);
  }
}
