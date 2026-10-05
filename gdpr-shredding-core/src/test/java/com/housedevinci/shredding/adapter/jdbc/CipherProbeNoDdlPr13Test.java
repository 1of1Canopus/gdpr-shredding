package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probes for the "no DDL at runtime" mechanism, PR 13, first pass.
 *
 * <p>Each test here fails against the branch as submitted and states one property the mechanism
 * claims but does not hold. The fixture is the documented two-role posture, the same one {@code
 * SchemaVerificationTest} uses: the owner applies the bundled script and holds the objects, the
 * runtime role holds exactly the grant block of SECURITY-NOTES.md "Database roles".
 */
@Testcontainers
class CipherProbeNoDdlPr13Test {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
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
    superuserDs = pool(POSTGRES.getUsername(), POSTGRES.getPassword());
    su(
        "DROP ROLE IF EXISTS " + APP,
        "DROP ROLE IF EXISTS " + OWNER,
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER");
    ownerDs = pool(OWNER, "pw");
    appDs = pool(APP, "pw");
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
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
    JdbcSupport.initializeSchema(ownerDs);
    owner(GRANT_BLOCK.toArray(String[]::new));
    // Sanity: the fixture itself verifies clean, so every refusal below is the probe's doing.
    JdbcSupport.verifySchema(appDs, false);
  }

  // ---------------------------------------------------------------- C-13-1

  /**
   * C-13-1, HIGH, leg 1. A trigger carries a {@code WHEN} predicate in {@code pg_trigger.tgqual},
   * which verification never reads. Recreated with {@code WHEN (false)}, the guard is present,
   * points at the right function through {@code tgfoid}, has the expected {@code tgtype} and is at
   * {@code ENABLE ALWAYS} - every column the check compares is byte-identical to the clean schema -
   * and it never fires. The erasure log is an ordinary table while the gate logs "schema verified
   * ... 7 triggers ENABLE ALWAYS".
   */
  @Test
  void probe_a_guard_recreated_with_a_when_clause_is_still_reported_verified() {
    owner(
        "DROP TRIGGER shredding_erasure_append_only ON shredding_erasure",
        "CREATE TRIGGER shredding_erasure_append_only"
            + " BEFORE UPDATE OR DELETE ON shredding_erasure"
            + " FOR EACH ROW WHEN (false)"
            + " EXECUTE FUNCTION shredding_erasure_append_only()",
        "ALTER TABLE shredding_erasure ENABLE ALWAYS TRIGGER shredding_erasure_append_only");

    // The guard is off: a row appended to the log can now be deleted from it.
    owner(insertOneErasureRow());
    assertThat(scalar("SELECT count(*) FROM shredding_erasure")).isEqualTo(1);
    owner("DELETE FROM shredding_erasure");
    assertThat(scalar("SELECT count(*) FROM shredding_erasure"))
        .describedAs("the append-only guard did not fire, so control 8 does not hold")
        .isZero();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("shredding_erasure_append_only")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  /**
   * C-13-1, HIGH, leg 2. The same hole through {@code pg_trigger.tgattr}: a trigger narrowed to
   * {@code BEFORE UPDATE OF updated_at} keeps {@code tgtype = 19}. The runtime role holds table
   * {@code UPDATE} on the anchor by the documented grant block, so with the monotonic guard
   * narrowed this way <em>the runtime role itself</em>, owning nothing, rewinds the chain anchor to
   * an arbitrary head hash and a row count of zero - and verification reports the schema clean.
   */
  @Test
  void probe_a_guard_narrowed_to_update_of_one_column_is_still_reported_verified() {
    owner(
        "DROP TRIGGER shredding_erasure_anchor_monotonic ON shredding_erasure_anchor",
        "CREATE TRIGGER shredding_erasure_anchor_monotonic"
            + " BEFORE UPDATE OF updated_at ON shredding_erasure_anchor"
            + " FOR EACH ROW EXECUTE FUNCTION shredding_erasure_anchor_monotonic()",
        "ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER"
            + " shredding_erasure_anchor_monotonic",
        "INSERT INTO shredding_erasure_anchor VALUES (1, " + repeat('a') + ", 5, now(), true)");

    app("UPDATE shredding_erasure_anchor SET head_hash = " + repeat('9') + ", row_count = 0");
    assertThat(scalar("SELECT row_count FROM shredding_erasure_anchor"))
        .describedAs("the monotonic guard did not fire for the runtime role's own UPDATE")
        .isZero();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("shredding_erasure_anchor_monotonic")
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ---------------------------------------------------------------- C-13-2

  /**
   * C-13-2, MEDIUM. An inheritance child of the erasure log is one {@code CREATE TABLE ...
   * INHERITS} away and carries none of the parent's triggers. Rows written into the child are
   * returned by every read of the verified parent relation - the module's own {@code read()} and
   * the chain verifier included - and a {@code DELETE} against the parent name removes them with no
   * guard anywhere near it. {@code pg_class.relhassubclass} is one column, exactly like the {@code
   * relhasrules} leg this check already has, and it is not read.
   */
  @Test
  void probe_an_inheritance_child_of_the_erasure_log_is_still_reported_verified() {
    owner(
        "CREATE TABLE shredding_erasure_child () INHERITS (shredding_erasure)",
        "INSERT INTO shredding_erasure_child (seq, ts, tenant, subject_pseudonym, outcome,"
            + " backup_clear_at, chain_version, key_id, prev_hash, hash)"
            + " VALUES (999, now(), 'tenant', "
            + repeat('x')
            + ", 'COMPLETE', now(), 'v2', 'k', "
            + repeat('0')
            + ", "
            + repeat('2')
            + ")");

    assertThat(scalar("SELECT count(*) FROM shredding_erasure"))
        .describedAs("a row nobody appended is visible through the verified relation")
        .isEqualTo(1);
    owner("DELETE FROM shredding_erasure WHERE seq = 999");
    assertThat(scalar("SELECT count(*) FROM shredding_erasure"))
        .describedAs("and it is deletable through the verified relation with no guard firing")
        .isZero();

    assertThatThrownBy(() -> JdbcSupport.verifySchema(appDs, false))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.SCHEMA_UNGUARDED);
  }

  // ---------------------------------------------------------------- C-13-3

  /**
   * C-13-3, LOW. Design §6b row 12 closes the "a caller-supplied DataSource handed to core
   * directly" path with: the adapters "will not construct without a {@code VerifiedSchema}, which
   * only {@code JdbcSupport.verifySchema} produces". {@code VerifiedSchema} is a record, so its
   * canonical constructor is public and anyone can produce one. The row-12 control is the type, and
   * the type is forgeable, so the enumerated integration surface has one path that is neither
   * verified nor refused by design.
   */
  @Test
  void probe_a_verified_schema_can_be_produced_without_any_verification() throws Exception {
    var canonical = VerifiedSchema.class.getDeclaredConstructor(String.class);
    assertThat(Modifier.isPublic(canonical.getModifiers()))
        .describedAs(
            "VerifiedSchema is the capability that stands for \"this schema was verified\";"
                + " a public constructor makes it a naming convention instead")
        .isFalse();
  }

  // ---------------------------------------------------------------- C-13-4

  /**
   * C-13-4, LOW. Design §4 and {@code SchemaVerification}'s own Javadoc say "one connection, one
   * read-only transaction, catalogue reads only". The connection is left in autocommit and is never
   * set read-only, so the eleven catalogue reads take eleven snapshots: the INFO line "schema
   * verified" is a claim about no single instant of the database, and nothing on the server side
   * refuses a statement that writes.
   */
  @Test
  void probe_verification_does_not_run_in_one_read_only_transaction() throws SQLException {
    var autoCommit = new AtomicBoolean(true);
    var readOnly = new AtomicBoolean(false);
    var seen = new AtomicBoolean(false);
    try (Connection real = appDs.getConnection()) {
      InvocationHandler handler =
          (proxy, method, args) -> {
            if ("prepareStatement".equals(method.getName()) && seen.compareAndSet(false, true)) {
              autoCommit.set(real.getAutoCommit());
              readOnly.set(real.isReadOnly());
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
      SchemaVerification.verify(spy, false);
    }
    assertThat(seen).isTrue();
    assertThat(autoCommit.get())
        .describedAs("verification must hold one snapshot, not one per catalogue read")
        .isFalse();
    assertThat(readOnly.get())
        .describedAs("a verification connection must be refused a write by the server, not by hope")
        .isTrue();
  }

  // ---------------------------------------------------------------- fixture

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

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
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
