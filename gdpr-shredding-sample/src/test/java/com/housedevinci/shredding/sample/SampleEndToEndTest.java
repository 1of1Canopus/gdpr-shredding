package com.housedevinci.shredding.sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.ShreddingContext;
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
              // Testcontainers' service-connection support re-parses the name and rejects
              // tag+digest.
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    // S-25: pinned rather than resolved from the container's bootstrap connection, the same
    // reason the startup timeout above exists - resolution failing under load is
    // "Unable to determine Dialect", not a Hibernate bug.
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
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

    // 3. erase
    var result = service.erase("acme", customerId, "dpo", "art 17 request");
    assertThat(result.complete()).isTrue();
    assertThat(result.keysDestroyed()).isEqualTo(1);
    // S-7 (the seventh pass): Customer carries no @BlindIndex - the tenant every @Shredded
    // field here has to declare (there is no ambient TenantSupplier in this sample) rules one out.
    assertThat(result.blindIndexColumnsCleared()).isEqualTo(0);

    // 4. the row is still there and the field reads as the sentinel
    var after = service.byCustomerId(customerId);
    assertThat(after).hasSize(1);
    assertThat(after.get(0).getEmail()).isEqualTo(ErasedValue.MARKER);
    assertThat(after.get(0).getPhone()).isEqualTo(ErasedValue.MARKER);
    assertThat(after.get(0).getCustomerId()).isEqualTo(customerId);

    // 5. the audit rows are untouched and still name the customer
    assertThat(audit.findByCustomerId(customerId))
        .extracting(CustomerAuditEvent::getAction)
        .containsExactly("created", "erased");

    // 6. the erasure log verifies
    var report = verifier.verify();
    assertThat(report.status()).isEqualTo(ErasureChainVerifier.Status.INTACT);
    assertThat(report.intact()).isTrue();
  }

  /**
   * The security review's probe: Hibernate's dirty checking must not decide the sentinel is a
   * change and write a fresh ciphertext over the shredded column. That would give the erased
   * subject a brand new encrypted value of the string "[erased]" and, worse, need a key to do it.
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
   * The security review's probe: a generated toString over every field is the commonest way a
   * decrypted value lands in a log. The sample greps its own entity rendering for the fixture.
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
   * The security review's probe: changing the subject expression's source on a persisted row would
   * re-encrypt it under someone else's key, so the first subject's erasure would leave it readable.
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

  /**
   * CIPHER-01. A blob that authenticated under one subject is copied verbatim into another
   * subject's row. Before the fix, {@code FieldCipher.decrypt} trusted the header inside the blob
   * as the row's own identity, so the copy decrypted and displayed alice's email under bob's row.
   * The fix - {@code ShreddedConverter} records the decoded header, {@code onPostLoad} compares it
   * against the row's true, resolved subject - refuses the whole load instead.
   */
  @Test
  void probe_a_blob_moved_into_another_subjects_row_still_decrypts() throws Exception {
    String aliceId = "cust-alice-" + System.nanoTime();
    String bobId = "cust-bob-" + System.nanoTime();
    service.create("acme", aliceId, "alice@example.com", "+33100000001");
    service.create("acme", bobId, "bob@example.com", "+33100000002");

    byte[] aliceEmail = rawEmail(aliceId);
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("UPDATE customer SET email = ? WHERE customer_id = ?")) {
      ps.setBytes(1, aliceEmail);
      ps.setString(2, bobId);
      ps.executeUpdate();
    }

    assertThatThrownBy(() -> customers.findByCustomerId(bobId))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_MISMATCH));
  }

  /**
   * CIPHER-01's other half: the same blob, moved to a row in a different tenant. Control 15 makes
   * tenant isolation mandatory; before the fix a tenant-A blob sitting in a tenant-B row read back
   * as tenant A's plaintext.
   */
  @Test
  void probe_a_blob_moved_into_another_tenants_row_still_decrypts() throws Exception {
    String subjectId = "cust-tenant-" + System.nanoTime();
    service.create("acme", subjectId, "carla@example.com", "+33100000003");
    // Same subject id, a different tenant - a distinct (tenant, subject) pair and a distinct key.
    service.create("other-tenant", subjectId, "placeholder@example.com", "+33100000004");

    byte[] acmeEmail = rawEmail(subjectId, "acme");
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "UPDATE customer SET email = ? WHERE customer_id = ? AND tenant_id = ?")) {
      ps.setBytes(1, acmeEmail);
      ps.setString(2, subjectId);
      ps.setString(3, "other-tenant");
      ps.executeUpdate();
    }

    assertThatThrownBy(() -> customers.findByCustomerId(subjectId))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_MISMATCH));
  }

  /**
   * Decision (c): the case the old per-thread map could not catch. The row is loaded and detached
   * in one transaction/thread, its subject changed, then merged in a brand new session that never
   * loaded it - so a cache of "what this process loaded" has nothing on it. The second-query check
   * in {@code onPreUpdate} still catches it, because it reads the row's current header from the
   * database rather than from anything this process remembered.
   *
   * <p>CIPHER-11: {@code EntityManager.merge} re-loads the row's current persisted state internally
   * to reconcile it against the detached instance, which reaches a shredded converter exactly like
   * any other load - so it needs the read bracket open, the same as a Spring Data repository call
   * gets automatically. {@code ShreddingContext.withReadBracket(...)} is the documented way for a
   * raw {@code EntityManager} entity operation to get it explicitly.
   */
  @Test
  void probe_changing_the_subject_expression_moves_a_row_out_of_erasure_scope_on_a_detached_merge()
      throws Exception {
    String customerId = "cust-detached-" + System.nanoTime();
    service.create("acme", customerId, "hana@example.com", "+33800000000");

    Customer detached =
        transactions.execute(status -> customers.findByCustomerId(customerId).get(0));
    entityManager.clear(); // simulates a brand new session/thread that never loaded this row
    detached.setCustomerId("someone-else-detached");

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        ShreddingContext.withReadBracket(
                            () -> {
                              entityManager.merge(detached);
                              entityManager.flush();
                              return null;
                            })))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE));
  }

  /**
   * CIPHER-08. A write that never reaches {@code PostInsert} - here, the converter refusing with
   * {@code SHRED-ERASED-001} <em>during flush, after {@code onPreInsert} already returned</em> -
   * used to leave the scope on the thread. On a pooled request thread the next, unrelated write
   * would then find a scope nobody meant to leave there and encrypt under the previous request's
   * subject instead of failing closed with {@code SHRED-CONTEXT-001}. The fix is a transaction-
   * boundary clear registered before the scope is ever pushed, not only the {@code Post} listeners,
   * which by construction do not run on this failure path.
   */
  @Test
  void probe_a_failed_insert_leaves_a_stale_shredding_scope() {
    String customerId = "cust-leak-" + System.nanoTime();
    service.create("acme", customerId, "ivy@example.com", "+33900000000");
    service.erase("acme", customerId, "dpo", "art 17");

    assertThatThrownBy(() -> service.create("acme", customerId, "ivy@example.com", "+33900000000"))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.ERASED));

    assertThat(com.housedevinci.shredding.jpa.ShreddingContext.current())
        .as("the failed insert must not leave a scope on this thread for the next write")
        .isEmpty();

    // the next write, on the same thread, must resolve its own subject rather than inherit
    // anything: if the scope had leaked, this would either encrypt under the wrong subject or
    // throw a different, unrelated error before ever reaching the tenant/customerId it was given.
    String nextCustomerId = "cust-after-leak-" + System.nanoTime();
    Customer created = service.create("acme", nextCustomerId, "jack@example.com", "+33900000001");
    assertThat(created.getEmail()).isEqualTo("jack@example.com");
    assertThat(service.byCustomerId(nextCustomerId).get(0).getEmail())
        .isEqualTo("jack@example.com");
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

  private byte[] rawEmail(String customerId, String tenantId) throws Exception {
    try (var c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "SELECT email FROM customer WHERE customer_id = ? AND tenant_id = ?")) {
      ps.setString(1, customerId);
      ps.setString(2, tenantId);
      try (var rs = ps.executeQuery()) {
        rs.next();
        return rs.getBytes(1);
      }
    }
  }
}
