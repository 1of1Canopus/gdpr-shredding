package com.housedevinci.shredding.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The acceptance check from the spec, end to end: create a customer, prove the column is unreadable
 * in raw SQL, erase, prove the row is still there, the field reads as the sentinel, the audit row
 * is untouched and the erasure record is chained.
 */
@SpringBootTest
@Testcontainers
@DirtiesContext
class SampleEndToEndTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          // Pinned by digest, the same image module B uses. The tag is dropped here because
          // Testcontainers' service-connection support re-parses the name and rejects tag+digest.
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add(
        "shredding.master-key",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "integration-test master key, 32b".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.erasure-log.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "integration-test chain secret 32".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.blind-index.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "integration-test index secret 32".getBytes(StandardCharsets.UTF_8)));
  }

  @Autowired CustomerService service;
  @Autowired CustomerRepository customers;
  @Autowired AuditRepository audit;
  @Autowired ErasureChainVerifier verifier;
  @Autowired DataSource dataSource;
  @Autowired TransactionTemplate transactions;
  @Autowired EntityManager entityManager;

  @Test
  void the_row_survives_the_erasure_and_the_field_does_not() throws Exception {
    String customerId = "cust-" + System.nanoTime();
    service.create("acme", customerId, "alice@example.com", "+33100000000");

    // 1. the column is unreadable in raw SQL
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT email, phone FROM customer WHERE customer_id = ?")) {
      ps.setString(1, customerId);
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        byte[] stored = rs.getBytes(1);
        assertThat(new String(stored, StandardCharsets.UTF_8)).doesNotContain("alice@example.com");
        assertThat(new String(stored, StandardCharsets.ISO_8859_1)).startsWith("SH1");
      }
    }

    // 2. the application still reads it
    assertThat(service.byCustomerId(customerId).get(0).getEmail()).isEqualTo("alice@example.com");
    assertThat(service.findByEmail("acme", "  ALICE@Example.com ")).hasSize(1);

    // 3. erase
    var result = service.erase("acme", customerId, "dpo", "art 17 request");
    assertThat(result.complete()).isTrue();
    assertThat(result.keysDestroyed()).isEqualTo(1);
    assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);

    // 4. the row is still there and the field reads as the sentinel
    var after = service.byCustomerId(customerId);
    assertThat(after).hasSize(1);
    assertThat(after.get(0).getEmail()).isEqualTo(ErasedValue.MARKER);
    assertThat(after.get(0).getPhone()).isEqualTo(ErasedValue.MARKER);
    assertThat(after.get(0).getCustomerId()).isEqualTo(customerId);
    assertThat(after.get(0).getEmailBidx()).isNull();

    // 5. the audit rows are untouched and still name the customer
    assertThat(audit.findByCustomerId(customerId))
        .extracting(CustomerAuditEvent::getAction)
        .containsExactly("created", "erased");

    // 6. the erasure log verifies
    var report = verifier.verify();
    assertThat(report.status()).isEqualTo(ErasureChainVerifier.Status.INTACT);
    assertThat(report.intact()).isTrue();

    // 7. the blind index no longer finds them
    assertThat(service.findByEmail("acme", "alice@example.com")).isEmpty();
  }

  /**
   * Cipher probe: Hibernate's dirty checking must not decide the sentinel is a change and write a
   * fresh ciphertext over the shredded column. That would give the erased subject a brand new
   * encrypted value of the string "[erased]" and, worse, need a key to do it.
   */
  @Test
  void probe_reading_an_erased_entity_rewrites_the_column_on_flush() throws Exception {
    String customerId = "cust-flush-" + System.nanoTime();
    service.create("acme", customerId, "bob@example.com", "+33200000000");
    service.erase("acme", customerId, "dpo", "art 17");

    byte[] before = rawEmail(customerId);

    // load the erased row inside a transaction and flush, exactly as a request would
    transactions.executeWithoutResult(
        status -> {
          Customer loaded = customers.findByCustomerId(customerId).get(0);
          assertThat(loaded.getEmail()).isEqualTo(ErasedValue.MARKER);
          entityManager.flush();
        });

    assertThat(rawEmail(customerId))
        .as("the shredded column must be byte-identical after a read and a flush")
        .isEqualTo(before);
  }

  /**
   * The other half of control 11. Dirty checking is the reason the flush above writes nothing; this
   * is the refusal that catches anything which gets past it, asserted where it can be reached
   * directly.
   */
  @Test
  void writing_the_sentinel_back_is_refused() {
    assertThatThrownBy(
            () -> new CustomerEmailConverter().convertToDatabaseColumn(ErasedValue.MARKER))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.ERASED);
  }

  /**
   * Cipher probe: a generated toString over every field is the commonest way a decrypted value
   * lands in a log. The sample greps its own entity rendering for the fixture.
   */
  @Test
  void probe_entity_tostring_leaks_the_decrypted_value() {
    String customerId = "cust-tostring-" + System.nanoTime();
    Customer created = service.create("acme", customerId, "dave@example.com", "+33400000000");

    assertThat(created.toString()).doesNotContain("dave@example.com", "+33400000000");
    assertThat(created.toString()).contains(customerId);
    assertThat(new CustomerEmailConverter().toString()).doesNotContain("dave@example.com");
  }

  /**
   * Cipher probe: changing the subject expression's source on a persisted row would re-encrypt it
   * under someone else's key, so the first subject's erasure would leave it readable.
   */
  @Test
  void probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope() {
    String customerId = "cust-move-" + System.nanoTime();
    service.create("acme", customerId, "erin@example.com", "+33500000000");

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status -> {
                      Customer loaded = customers.findByCustomerId(customerId).get(0);
                      loaded.setCustomerId("someone-else");
                      loaded.setEmail("erin+moved@example.com");
                      entityManager.flush();
                    }))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE));
  }

  @Test
  void erasing_twice_is_a_no_op() {
    String customerId = "cust-twice-" + System.nanoTime();
    service.create("acme", customerId, "frank@example.com", "+33600000000");

    var first = service.erase("acme", customerId, "dpo", "art 17");
    var second = service.erase("acme", customerId, "dpo", "art 17");

    assertThat(first.alreadyErased()).isFalse();
    assertThat(second.alreadyErased()).isTrue();
  }

  @Test
  void a_new_write_for_an_erased_subject_is_refused() {
    String customerId = "cust-rewrite-" + System.nanoTime();
    service.create("acme", customerId, "grace@example.com", "+33700000000");
    service.erase("acme", customerId, "dpo", "art 17");

    assertThatThrownBy(
            () -> service.create("acme", customerId, "grace@example.com", "+33700000000"))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.ERASED));
  }

  /** Hibernate wraps some of these and rethrows others; the module's code is what matters. */
  private static String shreddingCode(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }

  private byte[] rawEmail(String customerId) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT email FROM customer WHERE customer_id = ?")) {
      ps.setString(1, customerId);
      try (var rs = ps.executeQuery()) {
        rs.next();
        return rs.getBytes(1);
      }
    }
  }
}
