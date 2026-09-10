package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.batch.BatchAssigned;
import com.housedevinci.shredding.autoconfigure.batch.BatchAssignedRepository;
import com.housedevinci.shredding.autoconfigure.batch.BatchChild;
import com.housedevinci.shredding.autoconfigure.batch.BatchIdentity;
import com.housedevinci.shredding.autoconfigure.batch.BatchIdentityRepository;
import com.housedevinci.shredding.autoconfigure.batch.BatchParent;
import com.housedevinci.shredding.autoconfigure.batch.BatchParentRepository;
import com.housedevinci.shredding.autoconfigure.batch.BatchUuid;
import com.housedevinci.shredding.autoconfigure.batch.BatchUuidRepository;
import com.housedevinci.shredding.autoconfigure.batch.BatchWidget;
import com.housedevinci.shredding.autoconfigure.batch.BatchWidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.sql.DataSource;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * S-1, and the design addendum "insert-side binding under batching" (2026-09-10).
 *
 * <p>The property: <em>no row of a {@code @Shredded} entity commits whose stored header is not
 * bound to that row's own id, subject and tenant - at any {@code hibernate.jdbc.batch_size}.</em>
 * The whole class runs with {@code batch_size=10} and ordered inserts and updates, which is the
 * configuration in which the per-row post-hoc check of design item 14 silently did nothing.
 *
 * <p>Per the framework-integration rule, one test per path Hibernate offers to write a row, written
 * before the hook and each either verified or refused: batched {@code saveAll}, {@code persist} in
 * a loop, a batched {@code UPDATE}, {@code merge} of a new entity, a cascade insert, a
 * {@code @BatchSize} collection loaded and then flushed, {@code IDENTITY}, an assigned identifier,
 * two entities in one flush, {@code StatelessSession.insertMultiple}, a write with no transaction
 * at all, an insert-then-delete inside one transaction, a flush then a rollback, and a bulk JPQL
 * update.
 *
 * <p>"Verified" is measured, not assumed: {@link SettlementRecorder} records every SQL string
 * prepared on the application's own {@code DataSource}, and the settlement statement has a shape no
 * other statement in this module has - {@code SELECT "id", ... FROM "table" WHERE "id" IN (...)}. A
 * path is covered when a settlement statement naming that table ran before the commit.
 *
 * <p><strong>S-12 (Cipher seventh pass).</strong> S-1's original probe, {@code
 * CipherProbeBatchedInsertCheckTest}, was rewritten per QUESTIONS #25 into what is now {@code
 * CipherProbePropertyAccessSequenceTest} - a startup-refusal assertion, once S-5 made its
 * property-access fixture unstartable - and no longer exercises batching or the insert check by
 * name. This class is what carries S-1's property in the default build.
 */
@SpringBootTest(classes = BatchedWriteVerificationTest.BatchApp.class)
@Testcontainers
@DirtiesContext
class BatchedWriteVerificationTest {

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
    registry.add("spring.jpa.properties.hibernate.jdbc.batch_size", () -> "10");
    registry.add("spring.jpa.properties.hibernate.order_inserts", () -> "true");
    registry.add("spring.jpa.properties.hibernate.order_updates", () -> "true");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = BatchWidget.class)
  @EnableJpaRepositories(basePackageClasses = BatchWidgetRepository.class)
  static class BatchApp {
    @org.springframework.context.annotation.Bean
    static SettlementRecorder settlementRecorder() {
      return new SettlementRecorder();
    }
  }

  @Autowired BatchWidgetRepository widgets;
  @Autowired BatchIdentityRepository identities;
  @Autowired BatchAssignedRepository assigned;
  @Autowired BatchParentRepository parents;
  @Autowired BatchUuidRepository uuids;
  @Autowired EntityManager entityManager;
  @Autowired EntityManagerFactory entityManagerFactory;
  @Autowired TransactionTemplate transactions;
  @Autowired DataSource dataSource;

  // -- inserts ----------------------------------------------------------------------------------

  /**
   * The S-1 configuration itself. Three rows go into one JDBC batch, so at {@code onPostInsert}
   * time none of them is readable: before this change the per-row check read nothing, found nothing
   * to disagree with, and returned. The debt is settled once the batch has executed.
   */
  @Test
  void a_batched_save_all_is_settled_before_the_commit() {
    String owner = owner("saveAll");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s ->
                    widgets.saveAll(
                        List.of(
                            new BatchWidget(owner, "batched-1"),
                            new BatchWidget(owner, "batched-2"),
                            new BatchWidget(owner, "batched-3")))));

    assertThat(settlementsFor("batch_widget")).isNotEmpty();
    assertThat(placeholdersInSettlementFor("batch_widget")).isEqualTo(3);
    assertThat(readNames(owner)).containsExactlyInAnyOrder("batched-1", "batched-2", "batched-3");
  }

  /** {@code persist} in a loop: the same batch, reached without Spring Data in the way. */
  @Test
  void a_persist_loop_is_settled_before_the_commit() {
    String owner = owner("persist");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s -> {
                  for (int i = 0; i < 5; i++) {
                    entityManager.persist(new BatchWidget(owner, "persisted-" + i));
                  }
                }));

    assertThat(placeholdersInSettlementFor("batch_widget")).isEqualTo(5);
    assertThat(readNames(owner)).hasSize(5);
  }

  /** {@code merge} of a transient instance: a different action, the same insert. */
  @Test
  void a_merge_of_a_new_entity_is_settled_before_the_commit() {
    String owner = owner("merge");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s -> entityManager.merge(new BatchWidget(owner, "merged"))));

    assertThat(settlementsFor("batch_widget")).isNotEmpty();
    assertThat(readNames(owner)).containsExactly("merged");
  }

  /**
   * A cascade: nothing in the application saves a {@code BatchChild}, so a control hung off the
   * repository call would miss every one of them. The children are also mapped {@code @BatchSize},
   * which is the collection-loading row of the matrix.
   */
  @Test
  void a_cascade_insert_of_shredded_children_is_settled_before_the_commit() {
    String owner = owner("cascade");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s ->
                    parents.save(
                        new BatchParent(owner)
                            .with(new BatchChild(owner, "child-1"))
                            .with(new BatchChild(owner, "child-2")))));

    assertThat(placeholdersInSettlementFor("batch_child")).isEqualTo(2);
    // The collection is lazy, so it has to be initialised inside a read region: matrix row 7 -
    // initialising it after the repository call returned is SHRED-READ-UNSCOPED, by design.
    List<String> notes =
        transactions.execute(
            s -> {
              entityManager.clear();
              return com.housedevinci.shredding.jpa.ShreddingContext.withReadBracket(
                  () ->
                      parents.findByOwnerId(owner).get(0).getChildren().stream()
                          .map(BatchChild::getNote)
                          .toList());
            });
    assertThat(notes).containsExactlyInAnyOrder("child-1", "child-2");
  }

  /**
   * {@code IDENTITY} cannot batch its inserts, which is why S-1's probe needed a sequence - but
   * "cannot today" is an assumption, so it is asserted rather than relied on: the row is readable
   * inside {@code onPostInsert}, the design 3.1 rebind therefore updates exactly one row, and the
   * settlement finds the rebound header.
   */
  @Test
  void an_identity_insert_is_rebound_and_settled_even_with_a_batch_size_set() {
    String owner = owner("identity");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s ->
                    identities.saveAll(
                        List.of(
                            new BatchIdentity(owner, "identity-1"),
                            new BatchIdentity(owner, "identity-2")))));

    assertThat(settlementsFor("batch_identity")).isNotEmpty();
    List<String> names =
        transactions.execute(
            s -> {
              entityManager.clear();
              return identities.findByOwnerId(owner).stream().map(BatchIdentity::getName).toList();
            });
    assertThat(names).containsExactlyInAnyOrder("identity-1", "identity-2");
  }

  /** An assigned identifier: RowId tag 0x03, no generator, still batched and still settled. */
  @Test
  void an_assigned_identifier_insert_is_settled_before_the_commit() {
    String owner = owner("assigned");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s ->
                    assigned.saveAll(
                        List.of(
                            new BatchAssigned(owner + "-a", owner, "assigned-a"),
                            new BatchAssigned(owner + "-b", owner, "assigned-b")))));

    assertThat(placeholdersInSettlementFor("batch_assigned")).isEqualTo(2);
    String stored =
        transactions.execute(
            s -> {
              entityManager.clear();
              return assigned.findById(owner + "-a").orElseThrow().getName();
            });
    assertThat(stored).isEqualTo("assigned-a");
  }

  /**
   * A UUID primary key: generated before the insert, so Hibernate batches it, and returned by the
   * driver as a {@code UUID} rather than as a number - which the settlement query has to match rows
   * on. The commonest shape in which a real application meets S-1.
   */
  @Test
  void a_uuid_identified_insert_is_settled_before_the_commit() {
    String owner = owner("uuid");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s ->
                    uuids.saveAll(
                        List.of(new BatchUuid(owner, "uuid-1"), new BatchUuid(owner, "uuid-2")))));

    assertThat(placeholdersInSettlementFor("batch_uuid")).isEqualTo(2);
    List<String> names =
        transactions.execute(
            s -> {
              entityManager.clear();
              return uuids.findByOwnerId(owner).stream().map(BatchUuid::getName).toList();
            });
    assertThat(names).containsExactlyInAnyOrder("uuid-1", "uuid-2");
  }

  /** Two entities in one flush: one settlement statement per table, not one per row. */
  @Test
  void two_entities_written_in_one_flush_are_both_settled() {
    String owner = owner("two");
    recorded(
        () ->
            transactions.executeWithoutResult(
                s -> {
                  widgets.saveAll(
                      List.of(new BatchWidget(owner, "w-1"), new BatchWidget(owner, "w-2")));
                  assigned.save(new BatchAssigned(owner + "-x", owner, "a-1"));
                }));

    assertThat(settlementsFor("batch_widget")).hasSize(1);
    assertThat(settlementsFor("batch_assigned")).hasSize(1);
  }

  // -- updates ----------------------------------------------------------------------------------

  /**
   * The update half of S-1, which Cipher reasoned about but did not reproduce: with the UPDATE
   * still in the batch, the per-row check read the pre-update row and passed vacuously.
   */
  @Test
  void a_batched_update_is_settled_before_the_commit() {
    String owner = owner("update");
    transactions.executeWithoutResult(
        s ->
            widgets.saveAll(
                List.of(new BatchWidget(owner, "before-1"), new BatchWidget(owner, "before-2"))));

    recorded(
        () ->
            transactions.executeWithoutResult(
                s -> {
                  entityManager.clear();
                  for (var widget : widgets.findByOwnerId(owner)) {
                    widget.setName(widget.getName().replace("before", "after"));
                  }
                }));

    assertThat(placeholdersInSettlementFor("batch_widget")).isEqualTo(2);
    assertThat(readNames(owner)).containsExactlyInAnyOrder("after-1", "after-2");
  }

  /** An explicit flush settles there and then, so the ledger never carries a whole import. */
  @Test
  void an_explicit_flush_settles_immediately_and_leaves_nothing_owed() {
    String owner = owner("flush");
    transactions.executeWithoutResult(
        s -> {
          widgets.saveAll(List.of(new BatchWidget(owner, "f-1"), new BatchWidget(owner, "f-2")));
          entityManager.flush();
          var session =
              entityManager.unwrap(org.hibernate.engine.spi.SharedSessionContractImplementor.class);
          assertThat(WriteVerification.outstanding(session)).isZero();
        });
    assertThat(readNames(owner)).hasSize(2);
  }

  // -- paths that must not refuse ---------------------------------------------------------------

  /**
   * Inside one flush Hibernate executes insertions before deletions, so an insert and a delete of
   * the same row in one transaction would settle against a row that is legitimately gone. A deleted
   * row discharges its own debt; this is the false-refusal guard for that.
   */
  @Test
  void an_insert_and_a_delete_of_one_row_in_one_transaction_is_not_refused() {
    String owner = owner("delete");
    transactions.executeWithoutResult(
        s -> {
          var saved = widgets.save(new BatchWidget(owner, "doomed"));
          widgets.delete(saved);
        });
    assertThat(readNames(owner)).isEmpty();
  }

  /** A flush and then a rollback commits nothing, and settlement has nothing to complain about. */
  @Test
  void a_flush_then_a_rollback_commits_nothing_and_refuses_nothing() {
    String owner = owner("rollback");
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new BatchWidget(owner, "rolled-back"));
          entityManager.flush();
          s.setRollbackOnly();
        });
    assertThat(readNames(owner)).isEmpty();
  }

  // -- paths that must refuse -------------------------------------------------------------------

  /**
   * {@code StatelessSession.insertMultiple} sets the batch size to the size of the list and fires
   * {@code PostInsert} inside the loop, before its own {@code executeBatch()} - S-1's shape again,
   * on a session that fires no flush event at all. The transaction is the settlement anchor, so
   * this path is covered by the before-completion pass.
   */
  @Test
  void a_stateless_session_insert_multiple_is_settled_before_the_commit() {
    String owner = owner("stateless");
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    recorded(
        () -> {
          try (var stateless = sessionFactory.openStatelessSession()) {
            var tx = stateless.beginTransaction();
            stateless.insertMultiple(
                List.of(
                    new BatchWidget(owner, "stateless-1"), new BatchWidget(owner, "stateless-2")));
            tx.commit();
          }
        });

    assertThat(placeholdersInSettlementFor("batch_widget")).isEqualTo(2);
    assertThat(readNames(owner)).containsExactlyInAnyOrder("stateless-1", "stateless-2");
  }

  /**
   * A write with no transaction has no point at which what reached the database can be compared
   * against the scope it was written under, so it is refused at bind time rather than performed and
   * never checked. {@code StatelessSession} is the one way to reach this from JPA.
   */
  @Test
  void a_stateless_write_with_no_transaction_is_refused() {
    String owner = owner("no-tx");
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    String outcome;
    try (var stateless = sessionFactory.openStatelessSession()) {
      stateless.insert(new BatchWidget(owner, "unanchored"));
      outcome = "WRITTEN";
    } catch (RuntimeException e) {
      outcome = "REFUSED " + codeOf(e);
    }

    assertThat(outcome).isEqualTo("REFUSED " + ErrorCodes.UNVERIFIED_WRITE);
    assertThat(readNames(owner)).isEmpty();
  }

  /**
   * The refusal S-1 asked for, in the form the built code got wrong: a debt that <em>cannot</em> be
   * settled. The row is inserted inside the transaction and then removed on the session's own
   * connection, so at settlement time it is simply not there - which is byte for byte the state
   * {@code readStoredShreddedColumns} returned {@code null} for, and which the old check read as
   * "nothing is wrong" and passed. A check that could not run is now a refusal.
   *
   * <p>Reached through {@code StatelessSession}, the one session that fires no flush event, so the
   * debt is still outstanding when the transaction tries to commit.
   */
  @Test
  void a_written_row_that_cannot_be_read_back_refuses_the_commit() {
    String owner = owner("vanished");
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    String outcome;
    try (var stateless = sessionFactory.openStatelessSession()) {
      var tx = stateless.beginTransaction();
      try {
        stateless.insert(new BatchWidget(owner, "vanishing"));
        stateless.doWork(
            connection -> {
              try (var ps =
                  connection.prepareStatement("delete from batch_widget where owner_id = ?")) {
                ps.setString(1, owner);
                ps.executeUpdate();
              }
            });
        tx.commit();
        outcome = "COMMITTED";
      } catch (RuntimeException e) {
        outcome = "REFUSED " + codeOf(e);
      }
    }

    assertThat(outcome).isEqualTo("REFUSED " + ErrorCodes.UNVERIFIED_WRITE);
  }

  /**
   * #27 (Cipher seventh pass). {@code settle} used to clear its whole ledger before it verified any
   * of it, on the reasoning that a refusal aborts the transaction anyway - which made {@code
   * beforeCompletion}'s own "still outstanding" refusal permanently unreachable and meant a caught
   * settlement refusal (the shape {@link SwallowedWriteRefusalTest} exercises) discharged debts it
   * had never actually checked. A debt is now removed only once the check that discharges it has
   * passed: two rows in one chunk, one left alone and one deleted out from under its own debt
   * (S-1's "vanished row" shape, the same as {@link
   * #a_written_row_that_cannot_be_read_back_refuses_the_commit}), called directly so the still-open
   * transaction can be inspected before it unwinds - {@code settle} throws for the vanished row,
   * and the row that verified is discharged regardless of where in the chunk it fell: one debt
   * remains outstanding, not two and not zero.
   */
  @Test
  void a_settlement_refusal_discharges_only_the_debt_that_actually_passed() {
    String owner = owner("partial-settle");
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    try (var stateless = sessionFactory.openStatelessSession()) {
      var tx = stateless.beginTransaction();
      var session = (org.hibernate.engine.spi.SharedSessionContractImplementor) stateless;
      try {
        stateless.insertMultiple(
            List.of(new BatchWidget(owner, "keeps-its-row"), new BatchWidget(owner, "vanishes")));
        // The second-inserted row vanishes, so the chunk's loop reaches (and discharges) the first
        // row's debt before it ever reaches the one that throws.
        stateless.doWork(
            connection -> {
              try (var ps =
                  connection.prepareStatement(
                      "delete from batch_widget where id = (select max(id) from batch_widget"
                          + " where owner_id = ?)")) {
                ps.setString(1, owner);
                ps.executeUpdate();
              }
            });

        assertThat(WriteVerification.outstanding(session)).isEqualTo(2);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> WriteVerification.settle(session))
            .isInstanceOf(ShreddingException.class)
            .satisfies(e -> assertThat(codeOf(e)).isEqualTo(ErrorCodes.UNVERIFIED_WRITE));
        assertThat(WriteVerification.outstanding(session)).isEqualTo(1);
      } finally {
        tx.rollback();
      }
    }
  }

  /**
   * C-34's row swap, performed inside the writing transaction and under a batch size: two rows of
   * one subject exchange their stored ciphertexts, so each row's header names the other's id. The
   * per-row check cannot see this - at {@code onPostInsert} time neither row exists yet - and
   * settlement refuses it before the commit.
   */
  @Test
  void a_row_whose_stored_header_names_another_row_refuses_the_commit() {
    String owner = owner("swapped");
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    String outcome;
    try (var stateless = sessionFactory.openStatelessSession()) {
      var tx = stateless.beginTransaction();
      try {
        stateless.insertMultiple(
            List.of(new BatchWidget(owner, "swap-1"), new BatchWidget(owner, "swap-2")));
        stateless.doWork(
            connection -> {
              try (var ps =
                  connection.prepareStatement(
                      "update batch_widget a set name = b.name from batch_widget b"
                          + " where a.owner_id = ? and b.owner_id = ? and a.id <> b.id")) {
                ps.setString(1, owner);
                ps.setString(2, owner);
                ps.executeUpdate();
              }
            });
        tx.commit();
        outcome = "COMMITTED";
      } catch (RuntimeException e) {
        outcome = "REFUSED " + codeOf(e);
      }
    }

    assertThat(outcome).isEqualTo("REFUSED " + ErrorCodes.SUBJECT_IMMUTABLE);
    assertThat(readNames(owner)).isEmpty();
  }

  /** Matrix row 15 is unchanged by this design: a bulk JPQL update has no scope and is refused. */
  @Test
  void a_bulk_jpql_update_is_still_refused_with_no_write_context() {
    String owner = owner("bulk");
    transactions.executeWithoutResult(s -> widgets.save(new BatchWidget(owner, "bulk-before")));

    String outcome;
    try {
      transactions.executeWithoutResult(
          s ->
              entityManager
                  .createQuery("update BatchWidget w set w.name = :n where w.ownerId = :o")
                  .setParameter("n", "bulk-after")
                  .setParameter("o", owner)
                  .executeUpdate());
      outcome = "UPDATED";
    } catch (RuntimeException e) {
      outcome = "REFUSED " + codeOf(e);
    }

    assertThat(outcome).isEqualTo("REFUSED " + ErrorCodes.NO_CONTEXT);
    assertThat(readNames(owner)).containsExactly("bulk-before");
  }

  // -- helpers ----------------------------------------------------------------------------------

  private static String owner(String tag) {
    return "batch-" + tag + "-" + System.nanoTime();
  }

  private List<String> readNames(String ownerId) {
    return transactions.execute(
        s -> {
          entityManager.clear();
          return widgets.findByOwnerId(ownerId).stream().map(BatchWidget::getName).toList();
        });
  }

  private static String codeOf(Throwable t) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      if (c instanceof ShreddingException e) {
        return e.code();
      }
    }
    return t.getClass().getSimpleName();
  }

  private static void recorded(Runnable body) {
    SettlementRecorder.SQL.clear();
    SettlementRecorder.RECORDING = true;
    try {
      body.run();
    } finally {
      SettlementRecorder.RECORDING = false;
    }
  }

  /** Every settlement statement issued against one table while recording was on. */
  private static List<String> settlementsFor(String table) {
    return SettlementRecorder.SQL.stream()
        .filter(sql -> sql.contains("\"" + table + "\"") && sql.contains(" IN ("))
        .toList();
  }

  /** How many rows the settlement statements covered: one bind placeholder per row. */
  private static int placeholdersInSettlementFor(String table) {
    int total = 0;
    for (String sql : settlementsFor(table)) {
      String in = sql.substring(sql.indexOf(" IN ("));
      total += in.length() - in.replace("?", "").length();
    }
    return total;
  }

  /**
   * Records the SQL of every {@code prepareStatement} on the application's real {@code DataSource}.
   * Registered as a {@code BeanPostProcessor} so it wraps the auto-configured,
   * Testcontainers-backed {@code DataSource} rather than replacing it - settlement goes through
   * {@code doReturningWork}, which borrows that very connection.
   */
  static final class SettlementRecorder
      implements org.springframework.beans.factory.config.BeanPostProcessor {
    static final List<String> SQL = new CopyOnWriteArrayList<>();
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
                Object result = invoke(method, ds, args);
                return result instanceof java.sql.Connection c ? wrap(c) : result;
              });
    }

    private static java.sql.Connection wrap(java.sql.Connection connection) {
      return (java.sql.Connection)
          java.lang.reflect.Proxy.newProxyInstance(
              SettlementRecorder.class.getClassLoader(),
              new Class<?>[] {java.sql.Connection.class},
              (proxy, method, args) -> {
                if (RECORDING
                    && method.getName().equals("prepareStatement")
                    && args != null
                    && args.length > 0
                    && args[0] instanceof String sql) {
                  SQL.add(sql);
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
}
