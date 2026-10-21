package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.TwoRoleCluster.exec;

import java.sql.SQLException;
import org.junit.jupiter.api.Test;

/** The function-grants paths on the PostgreSQL 17 pin (C-PR45-3), plus the ones only 17 has. */
class FunctionGrantsPg17Test extends FunctionGrantsCases {

  FunctionGrantsPg17Test() {
    super(17);
  }

  /** E3 (C-RC021-2): a login event trigger fires on every connection, with no EXECUTE check. */
  @Test
  void login_event_trigger_over_hand_made_native_refuses_on_17() throws SQLException {
    var db = db();
    exec(
        db.su(),
        "CREATE FUNCTION public.h_evt() RETURNS event_trigger LANGUAGE internal"
            + " AS 'pg_backend_pid'",
        "REVOKE EXECUTE ON FUNCTION public.h_evt() FROM PUBLIC",
        "CREATE EVENT TRIGGER x ON login EXECUTE FUNCTION public.h_evt()");
    refuses(
        db.app(),
        "function public.h_evt() is native code made by hand outside any extension",
        "function public.h_evt() as the function of event trigger x on login");
  }
}
