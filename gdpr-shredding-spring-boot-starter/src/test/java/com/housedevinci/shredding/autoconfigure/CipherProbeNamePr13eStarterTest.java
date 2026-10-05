package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.batch.BatchIdentity;
import com.housedevinci.shredding.autoconfigure.batch.BatchIdentityRepository;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * P2b of the name-resolution design (section 3.4, finding N-3): the three statements this module
 * builds on the <b>application's own</b> Hibernate connection, inside the application's
 * transaction. No session mechanism is available there - a transaction-local {@code set_config}
 * would re-point every later statement of that transaction, including statements of entities this
 * module knows nothing about (T15b) - so these three get Property B only: every name qualified.
 *
 * <p><b>The hostile path, and why it has to be spelled out.</b> {@code pg_catalog} is implicitly
 * <em>first</em> on a {@code search_path} that does not name it, so the stock {@code "$user",
 * public} is not hostile at all: an {@code =(bigint, bigint)} created in {@code public} loses to
 * {@code pg_catalog.int8eq} and {@code WHERE id = $1} answers truthfully (measured: 1 row of 5).
 * The attack needs {@code pg_catalog} demoted by being named late, which is exactly the posture
 * SECURITY-NOTES warns about and the one an estate reaches by writing its own {@code search_path}.
 * Here every pooled connection is initialised with {@code SET search_path = public, pg_catalog} - a
 * connection-init SQL rather than an {@code ALTER ROLE}, so no pool has to be rebuilt for the role
 * setting to be resolved - and the same three ids then answer 5 of 5 through {@code IN} and 3 of 5
 * through the qualified {@code OR} chain.
 *
 * <p>The sharp consequence, measured as T4d: the {@code IDENTITY} rebind is {@code UPDATE
 * &lt;table&gt; SET &lt;col&gt; = ? WHERE &lt;id&gt; = ?}. With the shadow answering true for every
 * pair, it rewrites <em>every</em> row of the table with this subject's ciphertext bound to this
 * subject's row id - cross-row corruption that the existing {@code executeUpdate() != 1} check then
 * reports as a configuration problem, with the wrong reason. Qualified, it updates one row.
 */
@SpringBootTest(classes = CipherProbeNamePr13eStarterTest.ShadowApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeNamePr13eStarterTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add("shredding.jdbc.initialize-schema", () -> "true");
    registry.add("shredding.jdbc.allow-privileged-runtime-role", () -> "true");
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add("spring.jpa.properties.hibernate.default_schema", () -> "public");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
    // The hostile path, on every connection of the pool from the moment it is handed out:
    // pg_catalog named last is what puts the role's own schema ahead of it for operator
    // resolution. Named explicitly rather than set with ALTER ROLE so no pool needs rebuilding.
    registry.add(
        "spring.datasource.hikari.connection-init-sql",
        () -> "SET search_path = public, pg_catalog");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = BatchIdentity.class)
  @EnableJpaRepositories(basePackageClasses = BatchIdentityRepository.class)
  static class ShadowApp {

    @Bean
    static StatementRecorder statementRecorder() {
      return new StatementRecorder();
    }
  }

  @Autowired BatchIdentityRepository identities;
  @Autowired TransactionTemplate transactions;
  @Autowired DataSource dataSource;

  /**
   * N12 and N13. Two rows are written, their stored bytes are read raw, the shadow goes in, and a
   * third {@code IDENTITY} insert must touch its own row and no other. The re-read that the
   * subject-immutability check uses runs on the same statement shape against the same column, so
   * the same assertion covers it: a re-read that returned another row's bytes would refuse the
   * write with {@code SHRED-WRITE-002} instead of committing.
   *
   * <p>No assertion is made about the table being empty when the test starts: the context and the
   * container are shared with the other case, and the property under test is about the rows this
   * test wrote, not about the table's size.
   */
  @Test
  void probe_a_shadowed_bigint_equality_cannot_widen_the_identity_rebind() {
    transactions.executeWithoutResult(
        s ->
            identities.saveAll(
                List.of(new BatchIdentity("o-1", "first"), new BatchIdentity("o-2", "second"))));
    Map<String, String> before = storedByOwner();
    assertThat(before).containsKeys("o-1", "o-2");

    shadowBigintEquality();

    transactions.executeWithoutResult(s -> identities.save(new BatchIdentity("o-3", "third")));

    Map<String, String> after = storedByOwner();
    assertThat(after)
        .describedAs(
            "the rebind of the third row must not have rewritten any row that was already there:"
                + " with a bare `WHERE id = ?` and public.=(bigint,bigint) answering true it"
                + " reports UPDATE <every row> and binds this subject's ciphertext to every one")
        .containsAllEntriesOf(before)
        .containsKey("o-3");

    List<String> names =
        transactions.execute(
            s ->
                identities.findAll().stream()
                    .filter(i -> i.getOwnerId().startsWith("o-"))
                    .map(BatchIdentity::getName)
                    .toList());
    assertThat(names)
        .describedAs("and every row still decrypts to its own value")
        .containsExactlyInAnyOrder("first", "second", "third");
  }

  /**
   * N11, the write-verification ledger's own statement. It reads every row it is about to let
   * commit, through {@code SELECT <id>, <cols> FROM <table> WHERE (<id> OPERATOR(pg_catalog.=) ? OR
   * ...)}. {@code IN (?, ...)} cannot be operator-qualified at all, which is why it is an {@code
   * OR} chain of qualified comparisons.
   *
   * <p>What the shadow does to the unqualified form is measured on the statement the module
   * actually issued, not on a copy of it written here: the recorder captures the ledger's own text,
   * and that text is re-executed with the same ids bound. The table holds more rows than the chunk
   * asks for, so the honest answer is the chunk's size. With {@code IN (?, ?, ?)} and {@code
   * public.=(bigint,bigint) -> true} the server returns every row of the table - T4a, rows read
   * that were never asked for, on a plan that degrades to a sequential scan because the shadow is
   * not indexable.
   */
  @Test
  void probe_the_ledger_reads_back_only_the_rows_it_asked_for_under_the_shadow() {
    transactions.executeWithoutResult(
        s ->
            identities.saveAll(
                List.of(new BatchIdentity("p-1", "pre-one"), new BatchIdentity("p-2", "pre-two"))));

    shadowBigintEquality();

    StatementRecorder.SQL.clear();
    StatementRecorder.RECORDING = true;
    List<Long> batchIds;
    try {
      batchIds =
          transactions.execute(
              s ->
                  identities
                      .saveAll(
                          List.of(
                              new BatchIdentity("b-1", "one"),
                              new BatchIdentity("b-2", "two"),
                              new BatchIdentity("b-3", "three")))
                      .stream()
                      .map(BatchIdentity::getId)
                      .toList());
    } finally {
      StatementRecorder.RECORDING = false;
    }

    List<String> names =
        transactions.execute(
            s ->
                identities.findAll().stream()
                    .filter(i -> i.getOwnerId().startsWith("b-"))
                    .map(BatchIdentity::getName)
                    .toList());
    assertThat(names)
        .describedAs("the ledger verified three rows and let them commit, each bound to its own id")
        .containsExactlyInAnyOrder("one", "two", "three");

    String settlement =
        StatementRecorder.SQL.stream()
            .filter(sql -> sql.startsWith("SELECT ") && sql.contains("batch_identity"))
            .filter(sql -> sql.contains("?"))
            .reduce((a, b) -> b)
            .orElseThrow(
                () ->
                    new AssertionError("the ledger issued no read-back: " + StatementRecorder.SQL));

    assertThat(rowsReturnedBy(settlement, batchIds))
        .describedAs(
            "the ledger's own statement, re-executed with the same ids bound against a table that"
                + " holds more rows than the chunk: the chunk's size, not the whole table. The"
                + " `IN (?, ?, ?)` form answers with every row (T4a). Statement: "
                + settlement)
        .isEqualTo(batchIds.size());
  }

  /** How many rows the module's own captured statement returns for these ids, bound in order. */
  private int rowsReturnedBy(String sql, List<Long> ids) {
    try (Connection c = dataSource.getConnection();
        var ps = c.prepareStatement(sql)) {
      for (int i = 0; i < ids.size(); i++) {
        ps.setObject(i + 1, ids.get(i));
      }
      try (var rs = ps.executeQuery()) {
        int n = 0;
        while (rs.next()) {
          n++;
        }
        return n;
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * An {@code =(bigint, bigint)} in {@code public}, which the connection-init {@code search_path}
   * puts ahead of {@code pg_catalog}. Created once and reused: the two cases share the container,
   * and an operator that is already there is not an error worth failing on.
   */
  private void shadowBigintEquality() {
    exec(
        "CREATE OR REPLACE FUNCTION public.always(pg_catalog.int8, pg_catalog.int8)"
            + " RETURNS boolean AS $$ SELECT true $$ LANGUAGE sql",
        "DROP OPERATOR IF EXISTS public.= (pg_catalog.int8, pg_catalog.int8)",
        "CREATE OPERATOR public.= (LEFTARG = pg_catalog.int8,"
            + " RIGHTARG = pg_catalog.int8, FUNCTION = public.always)");
  }

  /** The raw stored ciphertext of every row, keyed by its owner, read with nothing in the way. */
  private Map<String, String> storedByOwner() {
    try (Connection c = dataSource.getConnection();
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT owner_id, pg_catalog.encode(name, 'base64')"
                    + " FROM public.batch_identity ORDER BY id")) {
      var out = new LinkedHashMap<String, String>();
      while (rs.next()) {
        out.put(rs.getString(1), rs.getString(2));
      }
      return Map.copyOf(out);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private void exec(String... sql) {
    try (Connection c = dataSource.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Records the SQL text of every {@code prepareStatement} on the application's own connections, so
   * an assertion can be made about the statement the module issued rather than about a copy of it
   * written in the test.
   */
  static final class StatementRecorder
      implements org.springframework.beans.factory.config.BeanPostProcessor {
    static final List<String> SQL = new java.util.concurrent.CopyOnWriteArrayList<>();
    static volatile boolean RECORDING = false;

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
      if (!(bean instanceof DataSource ds)) {
        return bean;
      }
      return (DataSource)
          java.lang.reflect.Proxy.newProxyInstance(
              getClass().getClassLoader(),
              new Class<?>[] {DataSource.class},
              (proxy, method, args) -> {
                Object result = call(method, ds, args);
                return result instanceof Connection c ? wrap(c) : result;
              });
    }

    private static Connection wrap(Connection connection) {
      return (Connection)
          java.lang.reflect.Proxy.newProxyInstance(
              StatementRecorder.class.getClassLoader(),
              new Class<?>[] {Connection.class},
              (proxy, method, args) -> {
                if (RECORDING
                    && method.getName().equals("prepareStatement")
                    && args != null
                    && args.length > 0
                    && args[0] instanceof String sql) {
                  SQL.add(sql);
                }
                return call(method, connection, args);
              });
    }

    private static Object call(java.lang.reflect.Method method, Object target, Object[] args)
        throws Throwable {
      try {
        return method.invoke(target, args);
      } catch (java.lang.reflect.InvocationTargetException e) {
        throw e.getCause() != null ? e.getCause() : e;
      }
    }
  }
}
