package com.housedevinci.shredding.adapter.jdbc;

import static com.housedevinci.shredding.adapter.jdbc.DatabaseIdentityCheckTest.record;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * C-PR-1b, the three connection entry points of {@link JdbcSupport} seen statement by statement:
 * every store call runs the fingerprint exactly once, before its work and inside its own
 * transaction (M12); in {@code inReadCommittedTransaction} after the isolation pin and read-back
 * (round 2, item 1); read-only by SQL, never by {@code setReadOnly}; and a fingerprint that fails
 * or returns the wrong number of rows refuses. A recording proxy over the real pool shows the
 * order; nothing here changes what reaches the server.
 */
class DatabaseIdentityEntryPointTest {

  private static final PostgreSQLContainer<?> PG = TwoRoleCluster.container();
  private static final byte[] SECRET =
      "erasure-log-secret-that-is-32-bytes-or-more"
          .getBytes(java.nio.charset.StandardCharsets.UTF_8);

  private static HikariDataSource appDs;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    TwoRoleCluster.roles(PG);
    TwoRoleCluster.install(PG, PG.getDatabaseName());
    appDs = TwoRoleCluster.app(PG, PG.getDatabaseName());
  }

  @AfterAll
  static void stop() {
    if (appDs != null) {
      appDs.close();
    }
    PG.stop();
  }

  // ------------------------------------------------------------------ store calls

  @FunctionalInterface
  interface Call {
    void run(Stores s) throws Exception;
  }

  record Stores(VerifiedSchema schema, JdbcKeyProvider keys, JdbcErasureStore store) {}

  enum Path {
    WRITE,
    ERASURE,
    READ
  }

  static Stream<Arguments> storeCalls() {
    TenantId t = TenantId.of("t");
    return Stream.of(
        Arguments.of(
            "JdbcKeyProvider.currentForWrite",
            Path.WRITE,
            (Call) s -> s.keys().currentForWrite(t, SubjectId.of("w-" + System.nanoTime()))),
        Arguments.of(
            "JdbcKeyProvider.recordEncryptions",
            Path.WRITE,
            (Call) s -> s.keys().recordEncryptions(t, SubjectId.of("e1"), 1, 1)),
        Arguments.of(
            "JdbcKeyProvider.rotate",
            Path.WRITE,
            (Call) s -> s.keys().rotate(t, SubjectId.of("r-" + System.nanoTime()))),
        Arguments.of(
            "JdbcKeyProvider.forRead",
            Path.READ,
            (Call) s -> s.keys().forRead(t, SubjectId.of("e1"), 1)),
        Arguments.of("JdbcKeyProvider.healthy", Path.READ, (Call) s -> s.keys().healthy()),
        Arguments.of(
            "JdbcErasureStore.erase",
            Path.ERASURE,
            (Call)
                s -> {
                  String n = "erase-" + System.nanoTime();
                  s.store().erase(t, SubjectId.of(n), (destroyed, cleared) -> record(n));
                }),
        Arguments.of(
            "JdbcErasureStore.append",
            Path.ERASURE,
            (Call) s -> s.store().append(record("append-" + System.nanoTime()))),
        Arguments.of(
            "JdbcErasureStore.latestForSubject",
            Path.READ,
            (Call) s -> s.store().latestForSubject(t, DatabaseIdentityCheckTest.pseudonym("x"))),
        Arguments.of("JdbcErasureStore.anchor", Path.READ, (Call) s -> s.store().anchor()),
        Arguments.of(
            "JdbcErasureStore.readAfter", Path.READ, (Call) s -> s.store().readAfter(0, 5)),
        Arguments.of(
            "JdbcErasureStore.<init> trail check",
            Path.READ,
            (Call)
                s -> new JdbcErasureStore(s.schema(), chain(), List.of(), (c, col, tn, sb) -> 0L)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("storeCalls")
  void each_entry_point_runs_the_check_before_the_work(String name, Path path, Call call)
      throws Exception {
    var recorded = run(call);
    List<String> sql = recorded.sql;
    int at = indexOfFingerprint(sql);
    assertThat(at).describedAs("%s ran no fingerprint: %s", name, sql).isGreaterThanOrEqualTo(0);
    if (path == Path.ERASURE) {
      assertThat(sql.subList(0, at))
          .describedAs("an erasure pins READ COMMITTED first, then checks")
          .containsExactly(JdbcSupport.PIN_SQL, JdbcSupport.ISOLATION_SQL);
    } else {
      assertThat(at)
          .describedAs("%s: the fingerprint is the first statement: %s", name, sql)
          .isZero();
    }
    assertThat(sql.get(at))
        .isEqualTo(
            path == Path.READ
                ? DatabaseIdentity.FINGERPRINT_READ_ONLY_SQL
                : DatabaseIdentity.FINGERPRINT_SQL);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("storeCalls")
  void each_store_call_adds_one_fingerprint_statement(String name, Path path, Call call)
      throws Exception {
    var recorded = run(call);
    assertThat(recorded.sql.stream().filter(DatabaseIdentityEntryPointTest::isFingerprint).count())
        .describedAs("%s: %s", name, recorded.sql)
        .isEqualTo(1);
    assertThat(recorded.sql)
        .describedAs("read-only is part of the fingerprint, never a statement of its own")
        .noneMatch(s -> s.toUpperCase(java.util.Locale.ROOT).startsWith("SET TRANSACTION READ"));
    assertThat(recorded.commits.get())
        .describedAs("%s: one commit; on the read path it is the new transaction's end", name)
        .isEqualTo(1);
  }

  @Test
  void no_entry_point_calls_set_read_only() throws Exception {
    var counting = new Recording(appDs);
    JdbcSupport.verifySchema(counting);
    var stores = stores(counting);
    stores.keys().currentForWrite(TenantId.of("t"), SubjectId.of("e1"));
    for (Arguments each : storeCalls().toList()) {
      try {
        ((Call) each.get()[2]).run(stores);
      } catch (ShreddingException e) {
        // A domain refusal after the check still went through the entry point.
      }
    }
    assertThat(counting.forbidden).describedAs("setReadOnly, setCatalog, setSchema").isEmpty();
  }

  @Test
  void read_entry_point_transaction_is_read_only_on_the_server() throws SQLException {
    VerifiedSchema schema = JdbcSupport.verifySchema(appDs).schema();
    String readOnly =
        JdbcSupport.withConnection(
            schema,
            c -> {
              try (var s = c.createStatement();
                  var rs = s.executeQuery("SHOW transaction_read_only")) {
                rs.next();
                return rs.getString(1);
              }
            });
    assertThat(readOnly).isEqualTo("on");
    Throwable write =
        catchThrowable(
            () ->
                JdbcSupport.withConnection(
                    schema,
                    c -> {
                      try (var s = c.createStatement()) {
                        s.execute("SELECT pg_catalog.nextval('public.shredding_erasure_seq_seq')");
                      }
                      return null;
                    }));
    assertThat(write.getCause()).isInstanceOf(SQLException.class);
    assertThat(((SQLException) write.getCause()).getSQLState()).isEqualTo("25006");
    // And it ended with the call: the pooled connection is not left read-only.
    try (var c = appDs.getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery("SHOW transaction_read_only")) {
      rs.next();
      assertThat(rs.getString(1)).isEqualTo("off");
    }
  }

  // ------------------------------------------------------------------ M12

  @FunctionalInterface
  interface EntryPoint {
    String[] run(VerifiedSchema schema, JdbcSupport.SqlWork<String[]> work);
  }

  static Stream<Arguments> entryPoints() {
    return Stream.of(
        Arguments.of("inTransaction", (EntryPoint) JdbcSupport::inTransaction),
        Arguments.of(
            "inReadCommittedTransaction", (EntryPoint) JdbcSupport::inReadCommittedTransaction),
        Arguments.of("withConnection", (EntryPoint) JdbcSupport::withConnection));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("entryPoints")
  void check_and_work_share_one_transaction_on_every_entry_point(String name, EntryPoint entry)
      throws SQLException {
    var recording = new Recording(appDs);
    VerifiedSchema schema = JdbcSupport.verifySchema(recording).schema();
    recording.probeAtFingerprint.set(true);

    String[] atWork = entry.run(schema, Recording::session);

    assertThat(recording.atFingerprint).describedAs("the check ran").isNotEmpty();
    String[] atCheck = recording.atFingerprint.get(0);
    assertThat(atWork[0]).describedAs("same backend").isEqualTo(atCheck[0]);
    assertThat(atWork[1])
        .describedAs("same transaction: its start time is the same for the check and the work")
        .isEqualTo(atCheck[1]);
  }

  // ------------------------------------------------------------------ failures

  @Test
  void a_failed_fingerprint_query_refuses_with_012_and_keeps_only_the_sqlstate()
      throws SQLException {
    var recording = new Recording(appDs);
    var keys =
        new JdbcKeyProvider(
            JdbcSupport.verifySchema(recording).schema(),
            master(),
            RandomSource.secure(),
            Clock.systemUTC());
    recording.failFingerprint.set(true);
    long before = TwoRoleCluster.rows(appDs, "shredding_data_key");

    for (Throwable thrown :
        List.of(
            catchThrowable(() -> keys.currentForWrite(TenantId.of("t"), SubjectId.of("f1"))),
            catchThrowable(() -> keys.forRead(TenantId.of("t"), SubjectId.of("f1"), 1)))) {
      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-SCHEMA-012");
      assertThat(thrown.getMessage())
          .contains("could not be checked (SQLState 57P01)")
          .doesNotContain("secret-host")
          .doesNotContain("jdbc:");
    }
    assertThat(TwoRoleCluster.rows(appDs, "shredding_data_key")).isEqualTo(before);
  }

  @Test
  void fingerprint_with_two_rows_refuses() throws SQLException {
    VerifiedSchema schema = JdbcSupport.verifySchema(appDs).schema();
    DatabaseIdentity id = schema.identity();
    for (int rows : new int[] {0, 2}) {
      Connection fake = fakeConnection(id, rows);
      Throwable thrown = catchThrowable(() -> DatabaseIdentity.require(fake, schema, false));
      assertThat(thrown).isInstanceOf(ShreddingException.class);
      assertThat(((ShreddingException) thrown).code()).isEqualTo("SHRED-SCHEMA-012");
      assertThat(thrown.getMessage()).contains("returned " + rows + " rows");
    }
    // The same fake with one row passes: the refusals above are about the count.
    DatabaseIdentity.require(fakeConnection(id, 1), schema, false);
  }

  // ------------------------------------------------------------------ helpers

  private static Recording run(Call call) throws Exception {
    var recording = new Recording(appDs);
    var stores = stores(recording);
    // Precondition rows for recordEncryptions and forRead.
    stores.keys().currentForWrite(TenantId.of("t"), SubjectId.of("e1"));
    recording.reset();
    try {
      call.run(stores);
    } catch (ShreddingException e) {
      // A domain refusal after the check (an erased subject, say) still shows the order.
    }
    return recording;
  }

  private static Stores stores(Recording recording) {
    VerifiedSchema schema = JdbcSupport.verifySchema(recording).schema();
    return new Stores(
        schema,
        new JdbcKeyProvider(schema, master(), RandomSource.secure(), Clock.systemUTC()),
        new JdbcErasureStore(schema, chain(), List.of(), (c, col, tn, sb) -> 0L));
  }

  private static ErasureChain chain() {
    return ErasureChain.keyed(SECRET, "k1");
  }

  private static MasterKey master() {
    return MasterKey.fromBytes(new byte[32]);
  }

  private static boolean isFingerprint(String sql) {
    return sql.contains("pg_control_system");
  }

  private static int indexOfFingerprint(List<String> sql) {
    for (int i = 0; i < sql.size(); i++) {
      if (isFingerprint(sql.get(i))) {
        return i;
      }
    }
    return -1;
  }

  /** Records every statement and transaction call of the connections it hands out. */
  static final class Recording extends org.springframework.jdbc.datasource.DelegatingDataSource {
    final List<String> sql = Collections.synchronizedList(new ArrayList<>());
    final List<String> forbidden = Collections.synchronizedList(new ArrayList<>());
    final List<String[]> atFingerprint = Collections.synchronizedList(new ArrayList<>());
    final AtomicInteger commits = new AtomicInteger();
    final AtomicBoolean failFingerprint = new AtomicBoolean();
    final AtomicBoolean probeAtFingerprint = new AtomicBoolean();

    Recording(DataSource target) {
      super(target);
    }

    void reset() {
      sql.clear();
      commits.set(0);
    }

    static String[] session(Connection c) throws SQLException {
      try (var s = c.createStatement();
          var rs =
              s.executeQuery("SELECT pg_catalog.pg_backend_pid()::text, pg_catalog.now()::text")) {
        rs.next();
        return new String[] {rs.getString(1), rs.getString(2)};
      }
    }

    @Override
    public Connection getConnection() throws SQLException {
      Connection real = super.getConnection();
      InvocationHandler h =
          (proxy, method, args) -> {
            switch (method.getName()) {
              case "setReadOnly", "setCatalog", "setSchema" -> forbidden.add(method.getName());
              case "commit" -> commits.incrementAndGet();
              case "prepareStatement" -> {
                String text = (String) args[0];
                sql.add(text);
                if (isFingerprint(text) && failFingerprint.get()) {
                  throw new SQLException("terminating connection to secret-host jdbc:x", "57P01");
                }
                PreparedStatement ps = (PreparedStatement) invoke(method, real, args);
                if (isFingerprint(text) && probeAtFingerprint.get()) {
                  return probing(ps, real);
                }
                return ps;
              }
              case "createStatement" -> {
                return recordingStatement((Statement) invoke(method, real, args));
              }
              default -> {}
            }
            return invoke(method, real, args);
          };
      return (Connection)
          Proxy.newProxyInstance(
              Connection.class.getClassLoader(), new Class<?>[] {Connection.class}, h);
    }

    private PreparedStatement probing(PreparedStatement ps, Connection real) {
      return (PreparedStatement)
          Proxy.newProxyInstance(
              PreparedStatement.class.getClassLoader(),
              new Class<?>[] {PreparedStatement.class},
              (p, m, a) -> {
                Object out = invoke(m, ps, a);
                if ("executeQuery".equals(m.getName())) {
                  atFingerprint.add(session(real));
                }
                return out;
              });
    }

    private Statement recordingStatement(Statement st) {
      return (Statement)
          Proxy.newProxyInstance(
              Statement.class.getClassLoader(),
              new Class<?>[] {Statement.class},
              (p, m, a) -> {
                if (m.getName().startsWith("execute")
                    && a != null
                    && a.length > 0
                    && a[0] instanceof String text) {
                  sql.add(text);
                }
                return invoke(m, st, a);
              });
    }

    private static Object invoke(Method m, Object target, Object[] args) throws Throwable {
      try {
        return m.invoke(target, args);
      } catch (InvocationTargetException e) {
        throw e.getCause();
      }
    }
  }

  /** A connection whose fingerprint returns {@code rows} copies of {@code id}, not in recovery. */
  private static Connection fakeConnection(DatabaseIdentity id, int rows) {
    var left = new AtomicInteger(rows);
    Object[] columns = {
      false,
      id.systemIdentifier(),
      id.databaseOid(),
      id.databaseName(),
      id.schemaOid(),
      id.sessionUser(),
      id.currentUser()
    };
    ResultSet rs =
        (ResultSet)
            Proxy.newProxyInstance(
                ResultSet.class.getClassLoader(),
                new Class<?>[] {ResultSet.class},
                (p, m, a) ->
                    switch (m.getName()) {
                      case "next" -> left.getAndDecrement() > 0;
                      case "getBoolean" -> (Boolean) columns[(Integer) a[0] - 1];
                      case "getLong" -> ((Number) columns[(Integer) a[0] - 1]).longValue();
                      case "getString" -> String.valueOf(columns[(Integer) a[0] - 1]);
                      default -> null;
                    });
    PreparedStatement ps =
        (PreparedStatement)
            Proxy.newProxyInstance(
                PreparedStatement.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                (p, m, a) -> "executeQuery".equals(m.getName()) ? rs : null);
    return (Connection)
        Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (p, m, a) -> "prepareStatement".equals(m.getName()) ? ps : null);
  }
}
