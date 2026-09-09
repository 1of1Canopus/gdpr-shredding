package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher fifth pass: attacks on the C-26/C-27 re-keying and per-row re-read landed at 733ada4. */
@SpringBootTest(classes = CipherProbeFifthPassTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeFifthPassTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class TestApp {
    @org.springframework.context.annotation.Bean
    static StatementCounter statementCounter() {
      return new StatementCounter();
    }
  }

  @Autowired WidgetRepository widgets;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  // -- P1: a transaction that completes inside an open read bracket -----------------------------

  /**
   * C-33. {@code ShreddingEventListener.registerTransactionBoundaryClear} registers {@code
   * ShreddingContext.clearAll()} as an after-completion callback on every write to a shredded
   * entity, and {@code clearAll()} does {@code READ_FRAMES.remove()} - it drops the whole
   * read-bracket frame stack for the thread, including frames belonging to brackets that are still
   * open. {@code ShreddingReadBracketCustomizer} is a {@code BeanPostProcessor} at {@code
   * LOWEST_PRECEDENCE}, so its proxy wraps the transactional proxy: the transaction begins and
   * commits <em>inside</em> the bracket. Any transaction that writes a shredded entity and commits
   * while a bracket is open therefore erases that bracket's debt, and {@code popReadBracket()}
   * finds an empty stack and passes.
   *
   * <p>This is exactly {@code CipherProbeFrameTest} F3's shape - an unverified projection decode
   * inside {@code withReadBracket} that nothing drains, which F3 asserts must be refused with
   * {@code SHRED-READ-UNVERIFIED} - with one addition: a write inside the same transaction, and
   * the transaction committing inside the bracket rather than outside it.
   */
  @Test
  void probe_a_transaction_committing_inside_a_read_bracket_does_not_erase_its_debt() {
    String owner = "p1-clearall-" + System.nanoTime();
    transactions.executeWithoutResult(s -> widgets.save(new Widget(owner, "P1-CLEARALL-SECRET")));

    String outcome;
    try {
      outcome =
          "RETURNED "
              + ShreddingContext.withReadBracket(
                  () ->
                      transactions.execute(
                          s -> {
                            entityManager.clear();
                            // A write to a shredded entity: this is what registers clearAll() as
                            // an after-completion callback on this transaction.
                            widgets.save(new Widget("p1-innocuous-" + System.nanoTime(), "x"));
                            // An unverified projection decode, recorded into the OUTER frame that
                            // withReadBracket opened. Nothing drains it: onPostLoad never runs for
                            // a scalar projection. F3 proves this alone is refused.
                            return entityManager
                                .createQuery(
                                    "select w.name from Widget w where w.ownerId = :o",
                                    String.class)
                                .setParameter("o", owner)
                                .getResultList();
                          }));
    } catch (RuntimeException e) {
      outcome = "REFUSED " + code(e);
    }
    System.out.println("P1 clearAll vs open bracket -> " + outcome);
    assertThat(outcome).doesNotContain("P1-CLEARALL-SECRET");
  }

  // -- P2: two rows of ONE subject, one carrying the other's ciphertext -------------------------

  /**
   * C-34. The AAD and the stored header bind (tenant, subject, entity, field) and no row identity,
   * and {@code onPostLoad}'s per-row re-read compares the row's stored header against the row's
   * resolved subject and tenant only. Two rows of the <em>same</em> subject therefore have
   * interchangeable ciphertexts: copying row A's {@code name} column into row B leaves both headers
   * naming the same subject, both re-reads match, and the multiset drains a count of two cleanly.
   * Row B then displays row A's value as its own, with no error anywhere.
   *
   * <p>{@code SECURITY-NOTES.md}'s threat table claims "a ciphertext moved between rows, subjects
   * or tenants" is stopped by "the row's stored header is checked against the row". It is stopped
   * between subjects and between tenants. It is not stopped between rows.
   */
  @Test
  void probe_a_ciphertext_swapped_between_two_rows_of_one_subject_is_detected() throws Exception {
    String owner = "p2-onesubject-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(owner, "ROW-A-VALUE"));
          widgets.save(new Widget(owner, "ROW-B-VALUE"));
        });
    List<Long> ids = idsOf("widget", owner);
    copyColumnBetweenRows("widget", "name", ids.get(0), ids.get(1));

    String outcome;
    try {
      List<String> names =
          transactions.execute(
              s -> {
                entityManager.clear();
                return widgets.findByOwnerId(owner).stream().map(Widget::getName).sorted().toList();
              });
      outcome = "RETURNED " + names;
    } catch (RuntimeException e) {
      outcome = "REFUSED " + code(e);
    }
    System.out.println("P2 same-subject row swap -> " + outcome);
    // Either the swap is refused, or the two rows still hold their own two distinct values.
    // Returning ROW-A-VALUE twice means row B is displaying row A's value as its own.
    assertThat(outcome).doesNotContain("ROW-A-VALUE, ROW-A-VALUE");
  }

  // -- P3: the per-row re-read is one extra SELECT per loaded row -------------------------------

  /**
   * C-35. {@code onPostLoad} calls {@code readStoredShreddedColumns}, a fresh {@code SELECT ...
   * WHERE id = ?} through {@code session.doReturningWork}, once for every loaded row of every
   * shredded entity. A page of N shredded rows costs N+1 round trips instead of 1. This is an
   * unbounded, caller-influenceable amplification on the read path of every shredded entity: a
   * caller that controls the page size controls the multiplier.
   *
   * <p>Counted deterministically by proxying {@code Connection.prepareStatement} on the
   * application's own {@code DataSource}, not inferred from timings or from Postgres' asynchronous
   * statistics collector.
   */
  @Test
  void probe_a_multi_row_read_does_not_issue_one_extra_query_per_row() {
    String owner = "p3-cost-" + System.nanoTime();
    int rows = 200;
    transactions.executeWithoutResult(
        s -> {
          for (int i = 0; i < rows; i++) {
            widgets.save(new Widget(owner, "value-" + i));
          }
        });

    StatementCounter.BY_ID.set(0);
    StatementCounter.ALL.set(0);
    StatementCounter.COUNTING = true;
    List<String> names;
    try {
      names =
          transactions.execute(
              s -> {
                entityManager.clear();
                return widgets.findByOwnerId(owner).stream().map(Widget::getName).toList();
              });
    } finally {
      StatementCounter.COUNTING = false;
    }
    int byId = StatementCounter.BY_ID.get();
    System.out.println(
        "P3 per-row re-read cost -> "
            + names.size()
            + " rows, "
            + StatementCounter.ALL.get()
            + " statements prepared, "
            + byId
            + " of them a per-row shredded-column re-read");
    assertThat(names).hasSize(rows);
    // One query for the list is the honest cost. N extra by-id lookups is not.
    assertThat(byId).isLessThan(rows / 2);
  }

  /**
   * Counts {@code prepareStatement} calls on the application's real {@code DataSource}. Registered
   * as a {@code BeanPostProcessor} so it wraps the auto-configured, Testcontainers-backed
   * {@code DataSource} rather than replacing it - {@code session.doReturningWork}, which is how
   * {@code readStoredShreddedColumns} issues its query, goes through the very same connection.
   */
  static final class StatementCounter implements org.springframework.beans.factory.config.BeanPostProcessor {
    static final java.util.concurrent.atomic.AtomicInteger ALL =
        new java.util.concurrent.atomic.AtomicInteger();
    static final java.util.concurrent.atomic.AtomicInteger BY_ID =
        new java.util.concurrent.atomic.AtomicInteger();
    static volatile boolean COUNTING = false;

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
      if (!(bean instanceof javax.sql.DataSource ds)) {
        return bean;
      }
      return (javax.sql.DataSource)
          java.lang.reflect.Proxy.newProxyInstance(
              getClass().getClassLoader(),
              new Class<?>[] {javax.sql.DataSource.class},
              (proxy, method, args) -> {
                Object result = invoke(method, ds, args);
                if (result instanceof java.sql.Connection connection) {
                  return wrap(connection);
                }
                return result;
              });
    }

    private static java.sql.Connection wrap(java.sql.Connection connection) {
      return (java.sql.Connection)
          java.lang.reflect.Proxy.newProxyInstance(
              StatementCounter.class.getClassLoader(),
              new Class<?>[] {java.sql.Connection.class},
              (proxy, method, args) -> {
                if (COUNTING
                    && method.getName().equals("prepareStatement")
                    && args != null
                    && args.length > 0
                    && args[0] instanceof String sql) {
                  ALL.incrementAndGet();
                  // readStoredShreddedColumns' shape: SELECT "name" FROM "widget" WHERE "id" = ?
                  if (sql.contains("\"widget\"") && sql.contains("\"id\" = ?")) {
                    BY_ID.incrementAndGet();
                  }
                }
                return invoke(method, connection, args);
              });
    }

    private static Object invoke(java.lang.reflect.Method method, Object target, Object[] args)
        throws Throwable {
      try {
        return method.invoke(target, args);
      } catch (java.lang.reflect.InvocationTargetException e) {
        throw e.getCause() != null ? e.getCause() : e;
      }
    }
  }

  private List<Long> idsOf(String table, String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("SELECT id FROM " + table + " WHERE owner_id = ? ORDER BY id")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        var ids = new java.util.ArrayList<Long>();
        while (rs.next()) {
          ids.add(rs.getLong(1));
        }
        return ids;
      }
    }
  }

  private void copyColumnBetweenRows(String table, String column, long fromId, long toId)
      throws Exception {
    byte[] value;
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT " + column + " FROM " + table + " WHERE id = ?")) {
      ps.setLong(1, fromId);
      try (var rs = ps.executeQuery()) {
        rs.next();
        value = rs.getBytes(1);
      }
    }
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("UPDATE " + table + " SET " + column + " = ? WHERE id = ?")) {
      ps.setBytes(1, value);
      ps.setLong(2, toId);
      ps.executeUpdate();
    }
  }

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof com.housedevinci.shredding.domain.ShreddingException s) {
        return s.code();
      }
    }
    return thrown.getClass().getSimpleName();
  }
}
