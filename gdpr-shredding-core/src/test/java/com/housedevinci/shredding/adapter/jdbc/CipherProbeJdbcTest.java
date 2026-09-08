package com.housedevinci.shredding.adapter.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.DataKeyCache;
import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.application.FieldCipher;
import com.housedevinci.shredding.domain.BlindIndexColumn;
import com.housedevinci.shredding.domain.ErasedValuePolicy;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/** Cipher probes that need a real PostgreSQL: the erasure transaction, the race, the index. */
@Testcontainers
class CipherProbeJdbcTest {

  // Pinned by digest, the same image module B uses.
  private static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static final byte[] SECRET =
      "erasure-log-secret-that-is-32-bytes-or-more".getBytes(StandardCharsets.UTF_8);
  private static final TenantId TENANT = TenantId.of("acme");

  private static HikariDataSource dataSource;

  private JdbcKeyProvider keys;
  private DataKeyCache cache;
  private FieldCipher cipher;

  @BeforeAll
  static void startDatabase() {
    POSTGRES.start();
    var config = new HikariConfig();
    config.setJdbcUrl(POSTGRES.getJdbcUrl());
    config.setUsername(POSTGRES.getUsername());
    config.setPassword(POSTGRES.getPassword());
    config.setMaximumPoolSize(8);
    dataSource = new HikariDataSource(config);
  }

  @AfterAll
  static void stopDatabase() {
    if (dataSource != null) {
      dataSource.close();
    }
    POSTGRES.stop();
  }

  @BeforeEach
  void setUp() throws Exception {
    // The erasure log is append-only by design, so it cannot be emptied between tests: the whole
    // set of tables is dropped and re-created instead, which is also a check that the schema step
    // is idempotent and runs from nothing.
    try (Connection c = dataSource.getConnection();
        var st = c.createStatement()) {
      st.execute(
          "DROP TABLE IF EXISTS shredding_erasure, shredding_erasure_anchor,"
              + " shredding_data_key, shredding_erased_subject, customer CASCADE");
    }
    JdbcSupport.initializeSchema(dataSource);
    try (Connection c = dataSource.getConnection();
        var st = c.createStatement()) {
      st.execute(
          "CREATE TABLE customer ("
              + " id bigserial PRIMARY KEY,"
              + " tenant_id varchar(255) NOT NULL,"
              + " customer_id varchar(255) NOT NULL,"
              + " email bytea,"
              + " email_bidx bytea)");
    }
    keys =
        new JdbcKeyProvider(
            dataSource,
            MasterKey.fromBytes(new byte[32]),
            RandomSource.secure(),
            Clock.systemUTC());
    cache = new DataKeyCache(Duration.ofSeconds(60), 100, Clock.systemUTC());
    cipher =
        new FieldCipher(
            keys, cache, RandomSource.secure(), FieldCipher.DEFAULT_MAX_ENCRYPTIONS_PER_KEY);
  }

  private JdbcErasureStore store(List<BlindIndexColumn> columns) {
    return new JdbcErasureStore(dataSource, ErasureChain.keyed(SECRET, "k1"), columns);
  }

  private ErasureService service(JdbcErasureStore store) {
    return new ErasureService(
        store,
        cache,
        new Pseudonymiser(SECRET),
        List.of(),
        Duration.ofDays(30),
        Clock.systemUTC(),
        1,
        2);
  }

  /**
   * An erasure that destroys the key but does not write the record leaves an erasure nobody can
   * prove; a record without the destruction is a false proof. Both must be impossible, which means
   * one transaction, not two calls.
   */
  @Test
  void probe_crash_between_key_destruction_and_the_erasure_record() {
    SubjectId subject = SubjectId.of("s-crash");
    cipher.encrypt(TENANT, subject, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    var store = store(List.of());

    assertThatThrownBy(
            () ->
                store.erase(
                    TENANT,
                    subject,
                    (destroyed, cleared) -> {
                      throw new IllegalStateException("crash after the key rows were deleted");
                    }))
        .isInstanceOf(IllegalStateException.class);

    // The key row survived: the whole transaction rolled back.
    assertThat(keys.forRead(TENANT, subject, 1)).isPresent();
    assertThat(store.readAfter(0, 10)).isEmpty();
    assertThat(store.anchor()).isEmpty();
  }

  /**
   * A write that is in flight when an erasure starts must not slip a fresh value in under a key
   * that is on its way out, and must not resurrect the key either.
   */
  @Test
  void probe_concurrent_write_encrypts_under_a_destroying_key() throws Exception {
    SubjectId subject = SubjectId.of("s-race");
    cipher.encrypt(TENANT, subject, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    var store = store(List.of());
    var erasureHolds = new CountDownLatch(1);
    var writerTried = new CountDownLatch(1);
    var writerFailure = new AtomicReference<Throwable>();

    Thread writer =
        new Thread(
            () -> {
              try {
                erasureHolds.await(10, TimeUnit.SECONDS);
                cipher.encrypt(
                    TENANT,
                    subject,
                    "Customer",
                    "email",
                    "later@b.c".getBytes(StandardCharsets.UTF_8));
              } catch (Throwable t) {
                writerFailure.set(t);
              } finally {
                writerTried.countDown();
              }
            });

    Thread eraser =
        new Thread(
            () ->
                store.erase(
                    TENANT,
                    subject,
                    (destroyed, cleared) -> {
                      erasureHolds.countDown();
                      // hold the FOR UPDATE lock while the writer tries
                      try {
                        Thread.sleep(300);
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                      return com.housedevinci.shredding.domain.ErasureRecord.of(
                          java.time.Instant.now(),
                          TENANT,
                          new Pseudonymiser(SECRET).pseudonym(TENANT, subject),
                          "dpo",
                          "art 17",
                          destroyed,
                          1,
                          1,
                          cleared,
                          com.housedevinci.shredding.domain.ErasureOutcome.COMPLETE,
                          List.of(),
                          java.time.Instant.now().plus(Duration.ofDays(30)));
                    }));

    eraser.start();
    writer.start();
    eraser.join(30_000);
    writerTried.await(30, TimeUnit.SECONDS);
    writer.join(30_000);

    assertThat(writerFailure.get())
        .as("the racing write must fail, not create a new key for an erased subject")
        .isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) writerFailure.get()).code()).isEqualTo(ErrorCodes.ERASED);
    assertThat(keys.forRead(TENANT, subject, 1)).isEmpty();
  }

  /**
   * An index that survives the erasure keeps the erased subject searchable and linkable for ever.
   * The value is unreadable and the row still answers "is this alice@example.com?" with yes.
   */
  @Test
  void probe_blind_index_still_matches_the_erased_subject() throws Exception {
    SubjectId subject = SubjectId.of("s-index");
    byte[] blob =
        cipher.encrypt(
            TENANT, subject, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    byte[] index =
        new com.housedevinci.shredding.domain.BlindIndex(SECRET, 64)
            .compute(TENANT, "Customer", "email", "a@b.c");
    try (Connection c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "INSERT INTO customer (tenant_id, customer_id, email, email_bidx) VALUES (?,?,?,?)")) {
      ps.setString(1, TENANT.value());
      ps.setString(2, subject.value());
      ps.setBytes(3, blob);
      ps.setBytes(4, index);
      ps.executeUpdate();
    }

    var store =
        store(List.of(new BlindIndexColumn("customer", "email_bidx", "customer_id", "tenant_id")));
    var result = service(store).erase(new ErasureRequest(TENANT, subject, "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
    try (Connection c = dataSource.getConnection();
        var ps =
            c.prepareStatement("SELECT email_bidx, email FROM customer WHERE customer_id = ?")) {
      ps.setString(1, subject.value());
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getBytes(1)).as("the blind index must be gone").isNull();
        assertThat(rs.getBytes(2)).as("the row and its ciphertext stay").isNotNull();
      }
    }
    cache.evictSubject(TENANT, subject);
    assertThat(cipher.decrypt("Customer", "email", blob, ErasedValuePolicy.SENTINEL)).isEmpty();
  }

  @Test
  void the_erasure_record_chain_verifies_end_to_end() {
    var store = store(List.of());
    var service = service(store);
    for (int i = 1; i <= 3; i++) {
      SubjectId s = SubjectId.of("s-chain-" + i);
      cipher.encrypt(TENANT, s, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
      service.erase(new ErasureRequest(TENANT, s, "dpo", "art 17"));
    }

    var report = new ErasureChainVerifier(store, store, Map.of("k1", SECRET)).verify();

    assertThat(report.status()).isEqualTo(ErasureChainVerifier.Status.INTACT);
    assertThat(report.verified()).isEqualTo(3);
    assertThat(store.readAfter(0, 10).get(0).hookOutcomes()).isEmpty();
  }

  @Test
  void the_erasure_log_refuses_update_delete_and_truncate() throws Exception {
    var store = store(List.of());
    SubjectId s = SubjectId.of("s-append-only");
    cipher.encrypt(TENANT, s, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    service(store).erase(new ErasureRequest(TENANT, s, "dpo", "art 17"));

    try (Connection c = dataSource.getConnection();
        var st = c.createStatement()) {
      assertThatThrownBy(() -> st.execute("UPDATE shredding_erasure SET reason = 'x'"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(() -> st.execute("DELETE FROM shredding_erasure"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(() -> st.execute("TRUNCATE shredding_erasure"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(() -> st.execute("DELETE FROM shredding_erasure_anchor"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(
              () ->
                  st.execute(
                      "UPDATE shredding_erasure_anchor SET keyed = NOT keyed,"
                          + " row_count = row_count + 1, head_hash = repeat('a', 64)"))
          .hasMessageContaining("immutable");
    }
  }

  @Test
  void an_unkeyed_instance_is_refused_against_a_keyed_trail() {
    var store = store(List.of());
    SubjectId s = SubjectId.of("s-mode");
    cipher.encrypt(TENANT, s, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    service(store).erase(new ErasureRequest(TENANT, s, "dpo", "art 17"));

    assertThatThrownBy(() -> new JdbcErasureStore(dataSource, ErasureChain.unkeyed(), List.of()))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.ERASURE_KEY_MISMATCH);
  }

  @Test
  void a_wrapped_key_row_cannot_be_swapped_between_subjects() throws Exception {
    SubjectId a = SubjectId.of("s-swap-a");
    SubjectId b = SubjectId.of("s-swap-b");
    cipher.encrypt(TENANT, a, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    cipher.encrypt(TENANT, b, "Customer", "email", "b@b.c".getBytes(StandardCharsets.UTF_8));

    try (Connection c = dataSource.getConnection();
        var ps =
            c.prepareStatement(
                "UPDATE shredding_data_key SET wrapped_key ="
                    + " (SELECT wrapped_key FROM shredding_data_key WHERE subject = ?)"
                    + " WHERE subject = ?")) {
      ps.setString(1, a.value());
      ps.setString(2, b.value());
      ps.executeUpdate();
    }
    cache.evictSubject(TENANT, b);

    assertThatThrownBy(() -> keys.forRead(TENANT, b, 1))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.DECRYPT);
  }
}
