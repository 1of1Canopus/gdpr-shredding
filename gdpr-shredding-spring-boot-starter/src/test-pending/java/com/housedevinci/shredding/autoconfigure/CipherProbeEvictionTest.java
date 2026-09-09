package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.assoc.Holder;
import com.housedevinci.shredding.autoconfigure.assoc.HolderRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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

/**
 * Cipher fifth pass, C-36: {@code refuseLoad}'s eviction versus an instance the session has already
 * handed to another managed entity.
 */
@SpringBootTest(classes = CipherProbeEvictionTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeEvictionTest {

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
  @EntityScan(basePackageClasses = {Widget.class, Holder.class})
  @EnableJpaRepositories(basePackageClasses = {WidgetRepository.class, HolderRepository.class})
  static class TestApp {}

  @Autowired WidgetRepository widgets;
  @Autowired HolderRepository holders;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  /**
   * The refused {@code Widget} is evicted from the persistence context, but the {@code Holder} that
   * was hydrated in the same query - and which holds a plain Java reference to that same, fully
   * decrypted {@code Widget} instance - is not. A caller that catches the refusal and reaches the
   * {@code Holder} again in the same session gets the moved plaintext through the association.
   */
  @Test
  void probe_a_refused_row_is_unreachable_through_an_association_that_survived_the_eviction()
      throws Exception {
    String alice = "e-alice-" + System.nanoTime();
    String bob = "e-bob-" + System.nanoTime();
    String label = "holder-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-EVICT-SECRET"));
          Widget bobWidget = widgets.save(new Widget(bob, "bob name"));
          holders.save(new Holder(label, bobWidget));
        });
    long holderId = idOf("holder", label);
    moveColumn("widget", "name", alice, bob);

    // The outcome is captured from inside the transaction, not returned from it: Spring's own
    // read-only advice on the repository method marks the participating transaction rollback-only
    // when the refusal escapes it, so the commit throws UnexpectedRollbackException regardless of
    // what happened inside. The security question is whether application code inside the
    // transaction was ever handed the moved plaintext - by then it can already have been logged,
    // written to a response buffer or sent to another service.
    var captured = new java.util.concurrent.atomic.AtomicReference<String>("NOT-REACHED");
    String outcome;
    try {
      transactions.executeWithoutResult(
          s -> {
            entityManager.clear();
            String first;
            try {
              first = "RETURNED " + holders.findByLabel(label).get(0).getWidget().getName();
            } catch (RuntimeException e) {
              first = "REFUSED " + code(e);
            }
            String second;
            try {
              Holder again = entityManager.find(Holder.class, holderId);
              second =
                  again == null
                      ? "NO-HOLDER"
                      : "RETURNED " + String.valueOf(again.getWidget().getName());
            } catch (RuntimeException e) {
              second = "REFUSED " + code(e);
            }
            String third;
            try {
              // The same second read, but through a bracketed repository call rather than a bare
              // EntityManager.find: if the Holder is still in the first-level cache this is a
              // cache hit with no SQL, no PostLoad and no converter, and getWidget() hands back the
              // very instance refuseLoad evicted - still fully decrypted.
              third =
                  holders
                      .findById(holderId)
                      .map(h -> "RETURNED " + String.valueOf(h.getWidget().getName()))
                      .orElse("NO-HOLDER");
            } catch (RuntimeException e) {
              third = "REFUSED " + code(e);
            }
            captured.set(
                "first=[" + first + "] second=[" + second + "] third=[" + third + "]");
          });
      outcome = captured.get();
    } catch (RuntimeException e) {
      outcome = captured.get() + " commit=[" + e.getClass().getSimpleName() + "]";
    }
    System.out.println("C-36 eviction vs association -> " + outcome);
    assertThat(outcome).doesNotContain("ALICE-EVICT-SECRET");
  }

  private long idOf(String table, String label) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT id FROM " + table + " WHERE label = ?")) {
      ps.setString(1, label);
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
