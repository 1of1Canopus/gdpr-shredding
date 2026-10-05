package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes, PR 13, <b>second pass</b>: the surfaces the round-1 fixes introduced.
 *
 * <p>Round 1 closed C-13-1 (tgqual/tgattr), C-13-2 (pg_inherits), C-13-3 (VerifiedSchema) and
 * C-13-4 (read-only transaction). This file attacks the new legs themselves - a WHEN that is always
 * true rather than false, a full column list rather than one column, inheritance in the other
 * direction, a partition, a decoy relation in a schema earlier on the search_path - and enumerates,
 * statement by statement, what the runtime role can still do to the four tables, the sequence, the
 * three functions and the seven triggers when it holds exactly the grant block of SECURITY-NOTES.md
 * "Database roles".
 */
@Testcontainers
class CipherProbeNoDdlPr13bTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "probe_owner";
  private static final String APP = "probe_app";

  private static final List<String> GRANT_BLOCK =
      List.of(
          "GRANT USAGE ON SCHEMA public TO " + APP,
          "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
          "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
          "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
          "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
          "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
          "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
          "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP);

  private static HikariDataSource superuserDs;
  private static HikariDataSource ownerDs;
  private static HikariDataSource appDs;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword(), null);
    su(
        "DROP ROLE IF EXISTS " + APP,
        "DROP ROLE IF EXISTS " + OWNER,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER");
    ownerDs = pool(OWNER, "pw", null);
    appDs = pool(APP, "pw", null);
  }

  @AfterAll
  static void stop() {
    close(appDs);
    close(ownerDs);
    close(superuserDs);
    POSTGRES.stop();
  }

  @BeforeEach
  void freshTwoRoleSchema() {
    su(
        "DROP SCHEMA IF EXISTS decoy CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    JdbcSupport.initializeSchema(ownerDs);
    owner(GRANT_BLOCK.toArray(String[]::new));
    JdbcSupport.verifySchema(appDs, false);
  }

  // ------------------------------------------------------------ the new tgqual leg

  /**
   * C-13-1 leg 1, the other predicate. Round 1's message is written about {@code WHEN (false)}. A
   * {@code WHEN} that is <em>always true</em> keeps the guard firing, so it is not an attack by
   * itself - but a predicate the check tolerates is a predicate that can be swapped for a false one
   * later with no catalogue column moving. The leg must refuse any {@code tgqual}, not a false one.
   */
  @Test
  void probe_a_guard_with_an_always_true_when_clause_is_refused() {
    owner(
        "DROP TRIGGER shredding_erasure_append_only ON shredding_erasure",
        "CREATE TRIGGER shredding_erasure_append_only"
            + " BEFORE UPDATE OR DELETE ON shredding_erasure"
            + " FOR EACH ROW WHEN (OLD.seq IS NOT NULL OR OLD.seq IS NULL)"
            + " EXECUTE FUNCTION shredding_erasure_append_only()",
        "ALTER TABLE shredding_erasure ENABLE ALWAYS TRIGGER shredding_erasure_append_only");

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("WHEN clause")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  /**
   * C-13-1 leg 2, the widest column list. {@code UPDATE OF <every column>} fires for every UPDATE
   * that names a column, so the guard looks intact - and an UPDATE that names no column at all
   * ({@code UPDATE t SET x = x} does name one, but a statement-level path or a later narrowing does
   * not) is one ALTER away. The leg must refuse any non-empty {@code tgattr}.
   */
  @Test
  void probe_a_guard_narrowed_to_the_full_column_list_is_refused() {
    owner(
        "DROP TRIGGER shredding_erasure_anchor_monotonic ON shredding_erasure_anchor",
        "CREATE TRIGGER shredding_erasure_anchor_monotonic"
            + " BEFORE UPDATE OF id, head_hash, row_count, updated_at, keyed"
            + " ON shredding_erasure_anchor"
            + " FOR EACH ROW EXECUTE FUNCTION shredding_erasure_anchor_monotonic()",
        "ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER"
            + " shredding_erasure_anchor_monotonic");

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("column list")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ------------------------------------------------------------ inheritance, both directions

  /** C-13-2 mirror: one of ours is the child, an attacker relation is the parent. */
  @Test
  void probe_one_of_our_tables_made_a_child_of_a_foreign_parent_is_refused() {
    owner(
        "CREATE TABLE decoy_parent (tenant varchar(255) NOT NULL)",
        "ALTER TABLE shredding_erasure INHERIT decoy_parent");

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("inherits from")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  /**
   * A partition is an inheritance edge with a different {@code inhparent} relkind. Attaching the
   * erasure log as a partition of a foreign partitioned table makes every read and every write
   * through the parent's name reach our rows, and the parent carries no guard.
   */
  @Test
  void probe_the_erasure_log_attached_as_a_partition_is_refused() {
    owner(
        "CREATE TABLE decoy_partitioned (LIKE shredding_erasure) PARTITION BY RANGE (seq)",
        "ALTER TABLE shredding_erasure ADD CONSTRAINT decoy_ck CHECK (seq >= 0)");
    // ATTACH needs matching constraints; the point is the pg_inherits row, which ATTACH creates.
    try {
      owner(
          "ALTER TABLE decoy_partitioned ATTACH PARTITION shredding_erasure"
              + " FOR VALUES FROM (0) TO (9223372036854775807)");
    } catch (RuntimeException notAttachable) {
      // Some shapes refuse ATTACH; the inheritance edge is then unreachable, which is a pass.
      owner("ALTER TABLE shredding_erasure DROP CONSTRAINT decoy_ck");
      return;
    }
    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ------------------------------------------------------------ a decoy earlier on the path

  /**
   * A view carrying the erasure log's name in a schema earlier on the runtime role's {@code
   * search_path}. {@code current_schema()} is the first schema on that path, so verification looks
   * at the decoy, not at the real schema. It must refuse rather than verify, and it must not verify
   * the real schema while the session would resolve the name to the decoy.
   */
  @Test
  void probe_a_decoy_relation_earlier_on_the_search_path_is_refused() {
    su("CREATE SCHEMA decoy AUTHORIZATION " + OWNER);
    owner(
        "CREATE VIEW decoy.shredding_erasure AS SELECT * FROM public.shredding_erasure",
        "CREATE TABLE decoy.shredding_erasure_anchor (LIKE public.shredding_erasure_anchor)",
        "CREATE TABLE decoy.shredding_erased_subject (LIKE public.shredding_erased_subject)",
        "CREATE TABLE decoy.shredding_data_key (LIKE public.shredding_data_key)",
        "GRANT USAGE ON SCHEMA decoy TO " + APP,
        "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA decoy TO " + APP);
    try (HikariDataSource decoyFirst = pool(APP, "pw", "decoy,public")) {
      assertThatThrownBy(() -> JdbcSupport.verifySchema(decoyFirst, false))
          .describedAs("the first schema on the path is what current_schema() resolves to")
          .isInstanceOf(ShreddingException.class);
    }
  }

  // ------------------------------------------------------------ the constrained runtime role

  /**
   * The builder's pointer: three times on this mechanism the attack came from the constrained
   * runtime role. With exactly the documented grant block, every statement below must be refused by
   * the server. Each is a way to change a verified property - a trigger, a guard body, a rule, a
   * policy, an inheritance edge, a column default, a table option, a statistics target, an owner,
   * the sequence's position - and none of them is reachable.
   */
  @Test
  void probe_the_runtime_role_can_change_no_verified_property() {
    var allowed = new ArrayList<String>();
    for (var attack : runtimeRoleAttacks().entrySet()) {
      try (Connection c = appDs.getConnection();
          Statement st = c.createStatement()) {
        st.execute(attack.getValue());
        allowed.add(attack.getKey() + "  ->  " + attack.getValue());
      } catch (SQLException refused) {
        // expected
      }
    }
    assertThat(allowed)
        .describedAs("statements the constrained runtime role was allowed to run")
        .isEmpty();
  }

  private static Map<String, String> runtimeRoleAttacks() {
    var m = new java.util.LinkedHashMap<String, String>();
    m.put("disable a guard", "ALTER TABLE shredding_erasure DISABLE TRIGGER ALL");
    m.put(
        "disable one guard",
        "ALTER TABLE shredding_erasure DISABLE TRIGGER shredding_erasure_append_only");
    m.put("re-enable as origin", "ALTER TABLE shredding_erasure ENABLE TRIGGER ALL");
    m.put(
        "add a trigger",
        "CREATE TRIGGER x BEFORE INSERT ON shredding_erasure FOR EACH ROW"
            + " EXECUTE FUNCTION shredding_erasure_append_only()");
    m.put(
        "replace a guard body",
        "CREATE OR REPLACE FUNCTION shredding_erasure_append_only()"
            + " RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql");
    m.put("add a rule", "CREATE RULE r AS ON DELETE TO shredding_erasure DO INSTEAD NOTHING");
    m.put("enable rls", "ALTER TABLE shredding_erasure ENABLE ROW LEVEL SECURITY");
    m.put("add a policy", "CREATE POLICY p ON shredding_erased_subject USING (false)");
    m.put("add an inheritance child", "CREATE TABLE child () INHERITS (shredding_erasure)");
    m.put("make ours a child", "ALTER TABLE shredding_erasure INHERIT shredding_erased_subject");
    m.put(
        "change a column default",
        "ALTER TABLE shredding_erasure ALTER COLUMN reason SET DEFAULT 'x'");
    m.put("drop the seq default", "ALTER TABLE shredding_erasure ALTER COLUMN seq DROP DEFAULT");
    m.put("add a column", "ALTER TABLE shredding_erasure ADD COLUMN extra text");
    m.put(
        "add a generated column",
        "ALTER TABLE shredding_erasure ADD COLUMN g text GENERATED ALWAYS AS (reason) STORED");
    m.put("drop not null", "ALTER TABLE shredding_erasure ALTER COLUMN hash DROP NOT NULL");
    m.put("add a constraint", "ALTER TABLE shredding_erasure ADD CONSTRAINT ck CHECK (seq > 0)");
    m.put(
        "drop a constraint",
        "ALTER TABLE shredding_erasure DROP CONSTRAINT shredding_erasure_hash_key");
    m.put(
        "statistics target",
        "ALTER TABLE shredding_erasure ALTER COLUMN reason SET STATISTICS 100");
    m.put("table options", "ALTER TABLE shredding_erasure SET (fillfactor = 50)");
    m.put("unlogged", "ALTER TABLE shredding_erasure SET UNLOGGED");
    m.put("take ownership", "ALTER TABLE shredding_erasure OWNER TO " + APP);
    m.put("rename", "ALTER TABLE shredding_erasure RENAME TO shredding_erasure_old");
    m.put("move schema", "ALTER TABLE shredding_erasure SET SCHEMA pg_temp");
    m.put("reindex", "REINDEX TABLE shredding_erasure");
    m.put("cluster", "CLUSTER shredding_erasure USING shredding_erasure_pkey");
    m.put("lock out", "LOCK TABLE shredding_erasure IN ACCESS EXCLUSIVE MODE");
    m.put("truncate", "TRUNCATE shredding_erasure");
    m.put("delete a row", "DELETE FROM shredding_erasure");
    m.put("update a row", "UPDATE shredding_erasure SET reason = 'x'");
    m.put("delete a tombstone", "DELETE FROM shredding_erased_subject");
    m.put("rewrite a tombstone", "UPDATE shredding_erased_subject SET tenant = 'x'");
    m.put("delete the anchor", "DELETE FROM shredding_erasure_anchor");
    m.put("truncate the anchor", "TRUNCATE shredding_erasure_anchor");
    m.put("rewind the sequence", "SELECT setval('shredding_erasure_seq_seq', 1)");
    m.put("restart the sequence", "ALTER SEQUENCE shredding_erasure_seq_seq RESTART WITH 1");
    m.put("read the sequence", "SELECT last_value FROM shredding_erasure_seq_seq");
    m.put("a temp decoy", "CREATE TEMP TABLE shredding_erasure (x int)");
    m.put("a new schema", "CREATE SCHEMA mine");
    m.put("a table in the schema", "CREATE TABLE mine_t (x int)");
    m.put(
        "an event trigger",
        "CREATE EVENT TRIGGER et ON ddl_command_start"
            + " EXECUTE FUNCTION shredding_erasure_append_only()");
    m.put("an extension", "CREATE EXTENSION IF NOT EXISTS pg_trgm");
    m.put("drop an index", "DROP INDEX shredding_erasure_subject");
    m.put("drop a guard function", "DROP FUNCTION shredding_erasure_append_only() CASCADE");
    m.put("drop a table", "DROP TABLE shredding_erasure");
    return m;
  }

  /**
   * The one write the runtime role does hold on a guarded table: table-wide {@code UPDATE} on the
   * anchor. The monotonic guard must be the only thing standing there, and it must refuse every
   * direction except "advance by exactly one row with a different head hash".
   */
  @Test
  void probe_the_anchor_guard_bounds_the_runtime_roles_update() {
    owner("INSERT INTO shredding_erasure_anchor VALUES (1, " + repeat('a') + ", 5, now(), true)");

    List<String> refusedExpected =
        List.of(
            "UPDATE shredding_erasure_anchor SET row_count = row_count - 1",
            "UPDATE shredding_erasure_anchor SET row_count = 0, head_hash = " + repeat('9'),
            "UPDATE shredding_erasure_anchor SET updated_at = now()",
            "UPDATE shredding_erasure_anchor SET keyed = false",
            "UPDATE shredding_erasure_anchor SET row_count = row_count + 1",
            "UPDATE shredding_erasure_anchor SET id = 2",
            "UPDATE shredding_erasure_anchor SET row_count = row_count + 2,"
                + " head_hash = "
                + repeat('9'));
    var allowed = new ArrayList<String>();
    for (String sql : refusedExpected) {
      try (Connection c = appDs.getConnection();
          Statement st = c.createStatement()) {
        st.execute(sql);
        allowed.add(sql);
      } catch (SQLException refused) {
        // expected
      }
    }
    assertThat(allowed).describedAs("anchor updates the guard let through").isEmpty();
    assertThat(scalar("SELECT row_count FROM shredding_erasure_anchor")).isEqualTo(5);
  }

  // ------------------------------------------------------------ the read-only transaction

  /**
   * C-13-4's real claim, tested on the server rather than on the driver's own flag: while
   * verification is running, a write issued on the very same connection must be refused by
   * PostgreSQL with SQLState 25006, and the connection must be usable for writes again afterwards.
   */
  @Test
  void probe_the_verification_transaction_is_read_only_on_the_server() throws SQLException {
    var writeFailure = new AtomicReference<String>("no write was attempted");
    try (Connection real = appDs.getConnection()) {
      var attempted = new java.util.concurrent.atomic.AtomicBoolean(false);
      InvocationHandler handler =
          (proxy, method, args) -> {
            if ("prepareStatement".equals(method.getName())
                && attempted.compareAndSet(false, true)) {
              try (Statement st = real.createStatement()) {
                st.execute(insertOneErasureRow());
                writeFailure.set(null);
              } catch (SQLException refusedByServer) {
                writeFailure.set(refusedByServer.getSQLState());
              }
            }
            try {
              return method.invoke(real, args);
            } catch (java.lang.reflect.InvocationTargetException e) {
              throw e.getCause();
            }
          };
      Connection spy =
          (Connection)
              Proxy.newProxyInstance(
                  Connection.class.getClassLoader(), new Class<?>[] {Connection.class}, handler);
      try {
        SchemaVerification.verify(spy, false);
      } catch (RuntimeException ignoredBecauseTheWriteAbortedTheTransaction) {
        // The refusal itself aborts the transaction; the SQLState is what this probe asserts.
      }
      assertThat(writeFailure.get())
          .describedAs("a write on the verification connection must be refused by the server")
          .isEqualTo("25006");
    }
    // And the pool hands back a connection that can write.
    app(insertOneErasureRow());
    assertThat(scalar("SELECT count(*) FROM shredding_erasure")).isEqualTo(1);
  }

  /** The settings the verification changed must be back, whatever the verdict was. */
  @Test
  void probe_the_verification_restores_the_connection_settings_after_a_refusal() throws Exception {
    owner("DROP TRIGGER shredding_erasure_no_truncate ON shredding_erasure");
    try (Connection c = appDs.getConnection()) {
      boolean autoCommit = c.getAutoCommit();
      boolean readOnly = c.isReadOnly();
      int isolation = c.getTransactionIsolation();
      assertThatThrownBy(() -> SchemaVerification.verify(c, false))
          .isInstanceOf(ShreddingException.class);
      assertThat(c.getAutoCommit()).isEqualTo(autoCommit);
      assertThat(c.isReadOnly()).isEqualTo(readOnly);
      assertThat(c.getTransactionIsolation()).isEqualTo(isolation);
      try (Statement st = c.createStatement()) {
        st.execute(insertOneErasureRow());
      }
    }
  }

  // ------------------------------------------------------------ the sequence's default

  /**
   * The sequence leg's own Javadoc says it catches "a hand-made table with no bigserial default".
   * The auto dependency edge it reads survives {@code DROP DEFAULT}, so it does not. Recorded as
   * INFO: only the owner can reach it and an append then fails loudly on the NOT NULL, so nothing
   * verified becomes untrue silently - but the leg does not do what it says.
   */
  @Test
  void probe_the_sequence_leg_catches_a_dropped_bigserial_default() {
    owner("ALTER TABLE shredding_erasure ALTER COLUMN seq DROP DEFAULT");
    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .describedAs("the leg claims to catch a table with no bigserial default")
        .isInstanceOf(ShreddingException.class);
  }

  // ------------------------------------------------------------ fixture

  private static String repeat(char c) {
    return "'" + String.valueOf(c).repeat(64) + "'";
  }

  private static String insertOneErasureRow() {
    return "INSERT INTO shredding_erasure (ts, tenant, subject_pseudonym, outcome,"
        + " backup_clear_at, chain_version, key_id, prev_hash, hash)"
        + " VALUES (now(), 'tenant', "
        + repeat('x')
        + ", 'COMPLETE', now(), 'v2', 'k', "
        + repeat('0')
        + ", "
        + repeat('1')
        + ")";
  }

  private static HikariDataSource pool(String user, String password, String searchPath) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    if (searchPath != null) {
      config.addDataSourceProperty("options", "-c search_path=" + searchPath);
      config.setConnectionInitSql("SET search_path TO " + searchPath);
    }
    return new HikariDataSource(config);
  }

  private static void close(HikariDataSource ds) {
    if (ds != null) {
      ds.close();
    }
  }

  private static void su(String... sql) {
    exec(superuserDs, sql);
  }

  private static void owner(String... sql) {
    exec(ownerDs, sql);
  }

  private static void app(String... sql) {
    exec(appDs, sql);
  }

  private static void exec(DataSource ds, String... sql) {
    try (Connection c = ds.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long scalar(String sql) {
    try (Connection c = superuserDs.getConnection();
        Statement st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getLong(1);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
