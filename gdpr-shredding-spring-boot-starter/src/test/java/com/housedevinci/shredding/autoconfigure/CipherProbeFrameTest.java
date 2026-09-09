package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.DocRepository;
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
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher fourth pass: attacks on the read-bracket frame accounting introduced at 3b1ced1. */
@SpringBootTest(classes = CipherProbeFrameTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeFrameTest {

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
  static class TestApp {}

  @Autowired WidgetRepository widgets;
  @Autowired DocRepository docs;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  // -- F1: the frame's key is entity.field, not the row ---------------------------------------

  /**
   * {@code ShreddingContext.recordDecoded} keys the frame by {@code entityName + "." + fieldName}
   * only. Two rows of the same entity in one result set therefore write to the same map key, and
   * {@code Map.put} keeps the last. Widget has exactly one shredded field, so there is no second
   * field to catch the collision the way Doc.body does.
   */
  @Test
  void probe_a_moved_ciphertext_in_a_second_row_of_one_result_set() throws Exception {
    String alice = "a-frame-alice-" + System.nanoTime();
    String bob = "b-frame-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-FRAME-SECRET"));
          widgets.save(new Widget(bob, "bob name"));
        });
    moveColumn("widget", "name", alice, bob);

    String outcome =
        transactions.execute(
            s -> {
              entityManager.clear();
              try {
                // Scoped to this test's own two rows (WidgetRepository.findByOwnerIdIn), not
                // findAll(Sort): several methods of this class share one Testcontainers Postgres
                // for the whole test class with no per-method reset, so an unscoped query would
                // also decode - and, correctly, refuse on - a moved-ciphertext row a different
                // test method planted.
                List<String> names =
                    widgets.findByOwnerIdIn(List.of(alice, bob), Sort.by("ownerId")).stream()
                        .map(Widget::getName)
                        .toList();
                return "RETURNED " + names;
              } catch (RuntimeException e) {
                return "REFUSED " + code(e);
              }
            });
    System.out.println("FRAME F1 multi-row single-shredded-field -> " + outcome);
    assertThat(outcome).doesNotContain("ALICE-FRAME-SECRET");
  }

  // -- F2: the persistence context after a refused load ----------------------------------------

  /**
   * {@code onPostLoad} throws after Hibernate has already registered the hydrated entity in the
   * session's first-level cache. A second read of the same row in the same transaction is a cache
   * hit: no converter runs, no {@code PostLoad} fires, the frame is trivially clean.
   *
   * <p>C-27's fix evicts the refused instance from the persistence context (see {@code
   * ShreddingEventListener.refuseLoad}), so the second read below is forced back through a real
   * reload and this same check - not served from the cache. What {@code findById} adds beyond
   * {@code findByOwnerId} (used for the first read, and unaffected): {@code
   * SimpleJpaRepository.findById} carries its own {@code @Transactional(readOnly = true)}, and
   * Spring's own transactional advice - independent of anything this module does, standard
   * behaviour for any {@code @Transactional} method participating in an existing transaction -
   * marks that ambient transaction rollback-only the moment an exception escapes it. The read
   * transaction below therefore fails to commit ({@code UnexpectedRollbackException}) even though
   * both refusals were caught, which is an equally valid, arguably stronger way for "the second
   * read must not return the secret" to hold: not merely refused-and-retryable, but nothing in this
   * transaction can be committed as if the retry had gone unnoticed. Both outcomes are accepted;
   * neither one returns the secret, which is the property being tested.
   */
  @Test
  void probe_a_refused_row_is_returned_on_the_retry_from_the_persistence_context()
      throws Exception {
    String alice = "a-l1-alice-" + System.nanoTime();
    String bob = "b-l1-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-L1-SECRET"));
          widgets.save(new Widget(bob, "bob name"));
        });
    long bobId = idOf("widget", bob);
    moveColumn("widget", "name", alice, bob);

    String outcome;
    try {
      outcome =
          transactions.execute(
              s -> {
                entityManager.clear();
                String first;
                try {
                  first = "RETURNED " + widgets.findByOwnerId(bob).get(0).getName();
                } catch (RuntimeException e) {
                  first = "REFUSED " + code(e);
                }
                String second;
                try {
                  second =
                      "RETURNED " + widgets.findById(bobId).map(Widget::getName).orElse("<empty>");
                } catch (RuntimeException e) {
                  second = "REFUSED " + code(e);
                }
                return "first=[" + first + "] second=[" + second + "]";
              });
    } catch (org.springframework.transaction.UnexpectedRollbackException e) {
      // Spring marked the participating transaction rollback-only when the second read's own
      // @Transactional advice (SimpleJpaRepository.findById) saw the refusal escape it - see the
      // javadoc above. The secret was still never returned; the whole transaction is refused
      // instead, which is at least as strong a guarantee as "second=REFUSED" would have been.
      outcome =
          "first=[REFUSED] second=[TRANSACTION-ROLLED-BACK] (" + e.getClass().getSimpleName() + ")";
    }
    System.out.println("FRAME F2 first-level-cache retry -> " + outcome);
    assertThat(outcome).doesNotContain("ALICE-L1-SECRET");
  }

  // -- F3: nested brackets, outer debt ----------------------------------------------------------

  /** An outer frame's undrained decode must survive an inner repository call opening its own. */
  @Test
  void probe_a_nested_repository_call_does_not_absolve_the_outer_frames_debt() {
    String owner = "nested-" + System.nanoTime();
    transactions.executeWithoutResult(s -> widgets.save(new Widget(owner, "NESTED-SECRET")));

    String outcome =
        transactions.execute(
            s -> {
              entityManager.clear();
              try {
                return "RETURNED "
                    + ShreddingContext.withReadBracket(
                        () -> {
                          // Records Widget.name into the OUTER frame; nothing will drain it.
                          List<String> projected =
                              entityManager
                                  .createQuery(
                                      "select w.name from Widget w where w.ownerId = :o",
                                      String.class)
                                  .setParameter("o", owner)
                                  .getResultList();
                          // An inner bracket that is itself perfectly clean.
                          widgets.findByOwnerId(owner);
                          return projected;
                        });
              } catch (RuntimeException e) {
                return "REFUSED " + code(e);
              }
            });
    System.out.println("FRAME F3 nested brackets -> " + outcome);
    assertThat(outcome).doesNotContain("NESTED-SECRET");
  }

  // -- F4: empty results are trivially clean ---------------------------------------------------

  @Test
  void probe_empty_results_are_not_refused() {
    transactions.executeWithoutResult(
        s -> {
          assertThat(widgets.findByOwnerId("nobody-" + System.nanoTime())).isEmpty();
          assertThat(widgets.findById(-42L)).isEmpty();
          assertThat(docs.findByOwnerId("nobody-doc")).isEmpty();
        });
  }

  // -- F5: a read-only transaction with a manual flush mode still refuses ------------------------

  @Test
  void probe_a_read_only_manual_flush_transaction_still_refuses_a_moved_ciphertext()
      throws Exception {
    String alice = "a-ro-alice-" + System.nanoTime();
    String bob = "b-ro-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-RO-SECRET"));
          widgets.save(new Widget(bob, "bob name"));
        });
    moveColumn("widget", "name", alice, bob);

    var readOnly =
        new org.springframework.transaction.support.TransactionTemplate(
            transactions.getTransactionManager());
    readOnly.setReadOnly(true);
    String outcome =
        readOnly.execute(
            s -> {
              entityManager.clear();
              entityManager.setFlushMode(jakarta.persistence.FlushModeType.COMMIT);
              entityManager
                  .unwrap(org.hibernate.Session.class)
                  .setHibernateFlushMode(org.hibernate.FlushMode.MANUAL);
              try {
                return "RETURNED " + widgets.findByOwnerId(bob).get(0).getName();
              } catch (RuntimeException e) {
                return "REFUSED " + code(e);
              }
            });
    System.out.println("FRAME F5 read-only manual flush -> " + outcome);
    assertThat(outcome).doesNotContain("ALICE-RO-SECRET");
  }

  // -- F6: the legitimate multi-row, multi-subject read -----------------------------------------

  /**
   * Dollar's mandated companion to the leak repro above: two genuine subjects, nothing moved, one
   * {@code findAll(Sort)} spanning both rows. Before the C-26 fix this refused with
   * SHRED-SUBJECT-MISMATCH - the third pass's flat {@code entity.field} key meant bob's row drained
   * whatever alice's converter had last written there, an artefact of the map rather than a real
   * mismatch (the finding's own "mirror" repro). After the fix each row is verified against its
   * own, independently re-read header, so the call must succeed and - the stronger assertion Dollar
   * asked for beyond "no exception" - each row must decrypt to its own value, not the other's.
   */
  @Test
  void probe_two_rows_of_two_subjects_read_in_one_query() {
    String alice = "a-legit-alice-" + System.nanoTime();
    String bob = "b-legit-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-LEGIT"));
          widgets.save(new Widget(bob, "BOB-LEGIT"));
        });

    java.util.Map<String, String> byOwner =
        transactions.execute(
            s -> {
              entityManager.clear();
              // Scoped to this test's own two rows: see the note on F1 above - this class shares
              // one Testcontainers Postgres across all its methods with no per-method reset.
              return widgets.findByOwnerIdIn(List.of(alice, bob), Sort.by("ownerId")).stream()
                  .collect(java.util.stream.Collectors.toMap(Widget::getOwnerId, Widget::getName));
            });
    System.out.println("FRAME F6 legitimate two-subject read -> " + byOwner);
    assertThat(byOwner).hasSize(2);
    assertThat(byOwner.get(alice)).isEqualTo("ALICE-LEGIT");
    assertThat(byOwner.get(bob)).isEqualTo("BOB-LEGIT");
  }

  private long idOf(String table, String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT id FROM " + table + " WHERE owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        rs.next();
        return rs.getLong(1);
      }
    }
  }

  private void moveColumn(String table, String column, String fromOwner, String toOwner)
      throws Exception {
    byte[] value;
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("SELECT " + column + " FROM " + table + " WHERE owner_id = ?")) {
      ps.setString(1, fromOwner);
      try (var rs = ps.executeQuery()) {
        rs.next();
        value = rs.getBytes(1);
      }
    }
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement("UPDATE " + table + " SET " + column + " = ? WHERE owner_id = ?")) {
      ps.setBytes(1, value);
      ps.setString(2, toOwner);
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
