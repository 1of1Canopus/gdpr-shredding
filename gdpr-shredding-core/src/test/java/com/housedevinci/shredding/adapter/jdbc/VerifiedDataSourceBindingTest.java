package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ErasureRecord;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1: a {@link VerifiedSchema} is bound to the {@code DataSource} it was verified on, and a
 * JDBC store writes through that one only. One test per path of the design page (section 2) that
 * core can reach without Spring. A refusal asserts three things: code {@code SHRED-SCHEMA-011}, no
 * connection taken from the foreign pool, and no URL, user or password in the message.
 *
 * <p>Two databases in one container: {@code guarded} (the container default, verified) and {@code
 * other} (initialised, verified only where a test says so). The container role owns both, so
 * verification runs in the privileged mode; the two-role posture has its own classes.
 *
 * <p>The deprecated constructors are called on purpose: they are the ones that still take a {@code
 * DataSource}, and their refusal is the control under test.
 */
@SuppressWarnings("removal")
class VerifiedDataSourceBindingTest {

  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final byte[] SECRET =
      "erasure-log-secret-that-is-32-bytes-or-more".getBytes(StandardCharsets.UTF_8);
  private static final MasterKey MASTER = MasterKey.fromBytes(new byte[32]);
  private static final BlindIndexResidual NO_RESIDUE = (c, column, tenant, subject) -> 0L;

  private static HikariDataSource guarded;
  private static HikariDataSource other;
  private static VerifiedSchema schema;

  @BeforeAll
  static void start() throws SQLException {
    POSTGRES.start();
    guarded = pool(POSTGRES.getDatabaseName());
    try (Connection c = guarded.getConnection();
        var s = c.createStatement()) {
      s.execute("CREATE DATABASE other");
    }
    other = pool("other");
    JdbcSupport.initializeSchema(guarded);
    JdbcSupport.initializeSchema(other);
    schema = JdbcSupport.verifySchema(guarded, true).schema();
  }

  @AfterAll
  static void stop() {
    for (var ds : new HikariDataSource[] {other, guarded}) {
      if (ds != null) {
        ds.close();
      }
    }
    POSTGRES.stop();
  }

  // ------------------------------------------------------------------ P2

  @Test
  void key_provider_refuses_a_datasource_that_is_not_the_verified_one() {
    var foreign = new Counting(other);
    assertRefused(
        () -> new JdbcKeyProvider(foreign, schema, MASTER, RandomSource.secure(), clock()),
        "JdbcKeyProvider",
        foreign);
  }

  @Test
  void erasure_store_refuses_a_datasource_that_is_not_the_verified_one() {
    var foreign = new Counting(other);
    assertRefused(
        () ->
            new JdbcErasureStore(
                foreign, schema, ErasureChain.keyed(SECRET, "k1"), List.of(), NO_RESIDUE),
        "JdbcErasureStore",
        foreign);
  }

  // ------------------------------------------------------------------ P3

  @Test
  void a_second_pool_to_the_same_database_is_refused() {
    try (HikariDataSource twin = pool(POSTGRES.getDatabaseName())) {
      var foreign = new Counting(twin);
      assertRefused(
          () -> new JdbcKeyProvider(foreign, schema, MASTER, RandomSource.secure(), clock()),
          "JdbcKeyProvider",
          foreign);
    }
  }

  // ------------------------------------------------------------------ P4

  @Test
  void schema_verified_on_pool_b_refuses_pool_a() {
    VerifiedSchema onB = JdbcSupport.verifySchema(other, true).schema();
    var poolA = new Counting(guarded);
    assertRefused(
        () ->
            new JdbcErasureStore(
                poolA, onB, ErasureChain.keyed(SECRET, "k1"), List.of(), NO_RESIDUE),
        "JdbcErasureStore",
        poolA);
  }

  // ------------------------------------------------------------------ P15 (R7)

  static Stream<Arguments> wrappers() {
    return Stream.of(
        Arguments.of(
            "Spring LazyConnectionDataSourceProxy",
            (Function<DataSource, DataSource>) LazyConnectionDataSourceProxy::new),
        Arguments.of(
            "Spring TransactionAwareDataSourceProxy",
            (Function<DataSource, DataSource>) TransactionAwareDataSourceProxy::new),
        Arguments.of(
            "plain application delegate", (Function<DataSource, DataSource>) Delegate::new),
        // Mutation 5 guard: a delegate that claims to equal every object. A check written with
        // equals instead of != would accept it.
        Arguments.of(
            "delegate whose equals answers true",
            (Function<DataSource, DataSource>) ClaimsEquality::new));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("wrappers")
  void a_wrapper_around_the_verified_pool_is_refused(
      String what, Function<DataSource, DataSource> wrap) {
    // The counter sits under the wrapper, so the wrapper is what the store is handed, and a check
    // that a wrapper fooled would show up as connections taken through it.
    var underneath = new Counting(guarded);
    DataSource wrapped = wrap.apply(underneath);
    assertRefused(
        () -> new JdbcKeyProvider(wrapped, schema, MASTER, RandomSource.secure(), clock()),
        "JdbcKeyProvider",
        underneath);
    assertRefused(
        () ->
            new JdbcErasureStore(
                wrapped, schema, ErasureChain.keyed(SECRET, "k1"), List.of(), NO_RESIDUE),
        "JdbcErasureStore",
        underneath);
  }

  // ------------------------------------------------------------------ R1

  @Test
  void initialize_and_verify_binds_the_schema_to_its_pool() throws SQLException {
    VerifiedSchema initialised = JdbcSupport.initializeAndVerifySchema(other, true).schema();

    assertThat(initialised.dataSource()).isSameAs(other);
    // The deprecated form accepts the very object it was initialised and verified on ...
    new JdbcKeyProvider(other, initialised, MASTER, RandomSource.secure(), clock());
    // ... and refuses the other pool, which proves the bound object is the argument, not a default.
    var foreign = new Counting(guarded);
    assertRefused(
        () -> new JdbcKeyProvider(foreign, initialised, MASTER, RandomSource.secure(), clock()),
        "JdbcKeyProvider",
        foreign);
    // And the new form writes where it was initialised.
    long before = rows(other, "shredding_data_key");
    new JdbcKeyProvider(initialised, MASTER, RandomSource.secure(), clock())
        .currentForWrite(TenantId.of("r1"), SubjectId.of("init-" + System.nanoTime()));
    assertThat(rows(other, "shredding_data_key")).isEqualTo(before + 1);
  }

  // ------------------------------------------------------------------ R2

  /**
   * One case per deprecated constructor. Each must refuse on its own, not only the terminal one.
   */
  @FunctionalInterface
  interface DeprecatedForm {
    Object build(DataSource ds, VerifiedSchema schema);
  }

  static Stream<Arguments> deprecatedConstructors() {
    ErasureChain chain = ErasureChain.keyed(SECRET, "k1");
    return Stream.of(
        Arguments.of(
            "JdbcKeyProvider(DataSource, VerifiedSchema, MasterKey, RandomSource, Clock)",
            (DeprecatedForm)
                (ds, s) -> new JdbcKeyProvider(ds, s, MASTER, RandomSource.secure(), clock())),
        Arguments.of(
            "JdbcErasureStore(DataSource, VerifiedSchema, ErasureChain, List, BlindIndexResidual)",
            (DeprecatedForm) (ds, s) -> new JdbcErasureStore(ds, s, chain, List.of(), NO_RESIDUE)),
        Arguments.of(
            "JdbcErasureStore(..., BlindIndexResidual, CopySignatures)",
            (DeprecatedForm)
                (ds, s) ->
                    new JdbcErasureStore(
                        ds, s, chain, List.of(), NO_RESIDUE, CopySignatures.defaults())),
        Arguments.of(
            "JdbcErasureStore(..., CopySignatures, List<AcknowledgedCopy>)",
            (DeprecatedForm)
                (ds, s) ->
                    new JdbcErasureStore(
                        ds,
                        s,
                        chain,
                        List.of(),
                        NO_RESIDUE,
                        CopySignatures.defaults(),
                        List.of())));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("deprecatedConstructors")
  void each_deprecated_constructor_refuses_a_foreign_pool(String form, DeprecatedForm build) {
    var foreign = new Counting(other);
    String store = form.substring(0, form.indexOf('('));
    assertRefused(() -> build.build(foreign, schema), store, foreign);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("deprecatedConstructors")
  void deprecated_constructor_with_the_verified_pool_still_works(
      String form, DeprecatedForm build) {
    assertThat(build.build(guarded, schema)).isNotNull();
  }

  // ------------------------------------------------------------------ P12

  @Test
  void a_schema_verified_on_another_pool_binds_to_that_pool_and_writes_there() throws SQLException {
    VerifiedSchema onOther = JdbcSupport.verifySchema(other, true).schema();
    long guardedBefore = rows(guarded, "shredding_data_key");
    long otherBefore = rows(other, "shredding_data_key");

    new JdbcKeyProvider(onOther, MASTER, RandomSource.secure(), clock())
        .currentForWrite(TenantId.of("p12"), SubjectId.of("s-" + System.nanoTime()));

    assertThat(rows(other, "shredding_data_key"))
        .describedAs("the row lands in the database that was verified for this schema")
        .isEqualTo(otherBefore + 1);
    assertThat(rows(guarded, "shredding_data_key")).isEqualTo(guardedBefore);
  }

  // ------------------------------------------------------------------ P13 / P14

  /** Stands for a store built after startup, inside some other object, never exposed as a bean. */
  private static final class RequestScopedService {
    Object handle(DataSource ds, VerifiedSchema verified) {
      return new JdbcKeyProvider(ds, verified, MASTER, RandomSource.secure(), clock());
    }
  }

  @Test
  void a_store_built_with_new_outside_any_container_is_refused() {
    var foreign = new Counting(other);
    assertRefused(
        () -> new RequestScopedService().handle(foreign, schema), "JdbcKeyProvider", foreign);
  }

  // ------------------------------------------------------------------ new constructors

  @Test
  void new_constructor_writes_to_the_verified_pool() throws SQLException {
    long keysBefore = rows(guarded, "shredding_data_key");
    long otherKeys = rows(other, "shredding_data_key");
    new JdbcKeyProvider(schema, MASTER, RandomSource.secure(), clock())
        .currentForWrite(TenantId.of("n1"), SubjectId.of("s-" + System.nanoTime()));
    assertThat(rows(guarded, "shredding_data_key")).isEqualTo(keysBefore + 1);

    // The erasure store's chain is keyed in this database by whichever test appended first, so
    // this is the only append in the class and it uses the one key id.
    long logBefore = rows(guarded, "shredding_erasure");
    long otherLog = rows(other, "shredding_erasure");
    new JdbcErasureStore(schema, ErasureChain.keyed(SECRET, "k1"), List.of(), NO_RESIDUE)
        .append(record("new-constructor"));
    assertThat(rows(guarded, "shredding_erasure")).isEqualTo(logBefore + 1);
    assertThat(rows(other, "shredding_data_key")).isEqualTo(otherKeys);
    assertThat(rows(other, "shredding_erasure")).isEqualTo(otherLog);
  }

  // ------------------------------------------------------------------ helpers

  private static void assertRefused(Runnable build, String store, Counting foreign) {
    int before = foreign.connections.get();
    Throwable thrown = catchThrowable(build::run);
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    var refusal = (ShreddingException) thrown;
    assertThat(refusal.code()).isEqualTo(ErrorCodes.STORE_DATASOURCE_UNVERIFIED);
    assertThat(refusal.getMessage())
        .startsWith("shredding: " + store + " was given a DataSource")
        .contains("(SHRED-SCHEMA-011)")
        .doesNotContain("jdbc:")
        .doesNotContain(POSTGRES.getHost() + ":")
        .doesNotContain(POSTGRES.getUsername())
        .doesNotContain(POSTGRES.getPassword());
    assertThat(foreign.connections.get())
        .describedAs("the refusal comes before any connection is taken from the foreign pool")
        .isEqualTo(before);
  }

  private static Clock clock() {
    return Clock.systemUTC();
  }

  private static ErasureRecord record(String pseudonym) {
    return ErasureRecord.of(
        Instant.now(),
        TenantId.of("t1"),
        String.format("%-64s", pseudonym).replace(' ', '0'),
        "tester",
        "test",
        1,
        1,
        1,
        0,
        ErasureOutcome.COMPLETE,
        List.of(),
        Instant.now().plusSeconds(60));
  }

  private static long rows(DataSource ds, String table) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery("SELECT count(*) FROM public." + table)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static HikariDataSource pool(String database) {
    var config = new HikariConfig();
    config.setJdbcUrl(
        "jdbc:postgresql://"
            + POSTGRES.getHost()
            + ":"
            + POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
            + "/"
            + database);
    config.setUsername(POSTGRES.getUsername());
    config.setPassword(POSTGRES.getPassword());
    config.setMaximumPoolSize(2);
    return new HikariDataSource(config);
  }

  /** A plain delegate any application can write. */
  static class Delegate implements DataSource {
    final DataSource target;

    Delegate(DataSource target) {
      this.target = target;
    }

    @Override
    public Connection getConnection() throws SQLException {
      return target.getConnection();
    }

    @Override
    public Connection getConnection(String u, String p) throws SQLException {
      return target.getConnection(u, p);
    }

    @Override
    public PrintWriter getLogWriter() throws SQLException {
      return target.getLogWriter();
    }

    @Override
    public void setLogWriter(PrintWriter out) throws SQLException {
      target.setLogWriter(out);
    }

    @Override
    public void setLoginTimeout(int seconds) throws SQLException {
      target.setLoginTimeout(seconds);
    }

    @Override
    public int getLoginTimeout() throws SQLException {
      return target.getLoginTimeout();
    }

    @Override
    public Logger getParentLogger() {
      return Logger.getGlobal();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
      return target.unwrap(iface);
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
      return target.isWrapperFor(iface);
    }
  }

  /** Counts every connection asked of it, so a refusal can prove it asked for none. */
  static final class Counting extends Delegate {
    final AtomicInteger connections = new AtomicInteger();

    Counting(DataSource target) {
      super(target);
    }

    @Override
    public Connection getConnection() throws SQLException {
      connections.incrementAndGet();
      return super.getConnection();
    }

    @Override
    public Connection getConnection(String u, String p) throws SQLException {
      connections.incrementAndGet();
      return super.getConnection(u, p);
    }
  }

  /** Answers {@code equals} true for anything: what an identity check must not be fooled by. */
  static final class ClaimsEquality extends Delegate {
    ClaimsEquality(DataSource target) {
      super(target);
    }

    @Override
    public boolean equals(Object other) {
      return true;
    }

    @Override
    public int hashCode() {
      return target.hashCode();
    }
  }
}
