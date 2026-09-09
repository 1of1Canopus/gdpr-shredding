package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.composite.Ticket;
import com.housedevinci.shredding.autoconfigure.composite.TicketRepository;
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

/** Cipher fifth pass, QUESTIONS #20: the composite-identifier residual, demonstrated. */
@SpringBootTest(classes = CipherProbeCompositeIdTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeCompositeIdTest {

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
  @EntityScan(basePackageClasses = Ticket.class)
  @EnableJpaRepositories(basePackageClasses = TicketRepository.class)
  static class TestApp {}

  @Autowired TicketRepository tickets;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  /**
   * A composite-id shredded entity: {@code onPostLoad} returns before it can verify anything, and
   * before it can drain the frame. Either the read is refused (the frame's undrained decode is what
   * catches it) or a moved ciphertext is displayed. This probe asserts the latter never happens.
   */
  @Test
  void probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed() throws Exception {
    String alice = "c-alice-" + System.nanoTime();
    String bob = "c-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          tickets.save(new Ticket(alice, 1L, "ALICE-COMPOSITE-SECRET"));
          tickets.save(new Ticket(bob, 1L, "bob note"));
        });
    moveColumn("ticket", "note", alice, bob);

    String outcome;
    try {
      outcome =
          transactions.execute(
              s -> {
                entityManager.clear();
                try {
                  return "RETURNED " + tickets.findByOwnerId(bob).get(0).getNote();
                } catch (RuntimeException e) {
                  return "REFUSED " + code(e);
                }
              });
    } catch (RuntimeException e) {
      outcome = "TRANSACTION-REFUSED " + e.getClass().getSimpleName();
    }
    System.out.println("COMPOSITE read -> " + outcome);
    assertThat(outcome).doesNotContain("ALICE-COMPOSITE-SECRET");
  }

  /**
   * C-38. The read above is refused - but by the frame's undrained decode, not by any check that
   * knows what a composite id means. The consequence is that a {@code @Shredded} entity with a
   * composite identifier does not work at all: every read of a row that carries a stored shredded
   * value is refused with {@code SHRED-READ-UNVERIFIED}, because {@code onPostLoad} returns before
   * it can drain, and every write is refused with it because {@code save}'s merge has to read
   * first. That is fail-closed, and it is also a mapping this module cannot support - which is
   * exactly what the startup scan already refuses for a {@code @SecondaryTable} split. It must
   * refuse this at boot, naming the entity, not at the first read in production.
   *
   * <p>The same {@code idColumns.length != 1} early return also disables {@code
   * refuseIfSubjectMoved} (control 14) on the write path for these entities, which QUESTIONS #20
   * records as undemonstrated; it stays undemonstrable only for as long as the read refusal above
   * keeps the row unreachable, which is an accident of two unrelated checks, not a control.
   */
  @Test
  void probe_a_composite_id_shredded_entity_is_refused_at_startup() {
    String owner = "cs-alice-" + System.nanoTime();
    // The context is already up (@SpringBootTest above): nothing refused this mapping at startup.
    // Prove the consequence instead - a plain, untampered read of a row this application can
    // legitimately write is refused - and assert that the application should never have started.
    transactions.executeWithoutResult(s -> tickets.save(new Ticket(owner, 1L, "CS-VALUE")));
    String outcome;
    try {
      outcome =
          transactions.execute(
              s -> {
                entityManager.clear();
                try {
                  return "RETURNED " + tickets.findByOwnerId(owner).get(0).getNote();
                } catch (RuntimeException e) {
                  return "REFUSED " + code(e);
                }
              });
    } catch (RuntimeException e) {
      outcome = "TRANSACTION-REFUSED " + e.getClass().getSimpleName();
    }
    System.out.println("COMPOSITE untampered read -> " + outcome);
    // A composite-id shredded entity is unusable. The startup scan must say so at boot; if it did,
    // this context would not have come up and this test would never have run.
    assertThat(outcome).isEqualTo("RETURNED CS-VALUE");
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
