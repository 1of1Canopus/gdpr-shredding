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
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
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

  /** Design §3: every stored value is bound to a row; these probes use one fixed row. */
  private static final RowId ROW = RowId.ofIdentifier(1L);

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
    return new JdbcErasureStore(dataSource, ErasureChain.keyed(SECRET, "k1"), columns, RESIDUAL);
  }

  /**
   * These tests have no Hibernate at all - they drive the JDBC adapter against a hand-made table -
   * so the independent read-back the starter supplies (a residual Hibernate renders from the entity
   * mapping, design addendum 4 §4.5) has no counterpart here. This one counts the same rows with
   * plain SQL on the erasure's own connection, which is what the contract requires of it: one
   * connection, no transaction of its own, no way to write. It is deliberately explicit at every
   * construction site: {@code JdbcErasureStore} has no default residual, because an erasure whose
   * own statements are the only thing that ever checks them is the shape S-22 shipped.
   */
  private static final com.housedevinci.shredding.adapter.jdbc.BlindIndexResidual RESIDUAL =
      (connection, column, tenant, subject) -> {
        String sql =
            "SELECT count(*) FROM "
                + column.table().sql()
                + " WHERE "
                + column.tenantColumn().sql()
                + " = ? AND "
                + column.subjectColumn().sql()
                + " = ? AND "
                + column.column().sql()
                + " IS NOT NULL";
        try (var ps = connection.prepareStatement(sql)) {
          ps.setString(1, tenant.value());
          ps.setString(2, subject.value());
          try (var rs = ps.executeQuery()) {
            return rs.next() ? rs.getLong(1) : 0L;
          }
        } catch (java.sql.SQLException e) {
          throw new IllegalStateException(e);
        }
      };

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
   * CIPHER-15: {@code latestForSubject} used to order by {@code ts DESC, seq DESC}. {@code ts} is
   * {@code clock.instant()} from the application; {@code seq} is the log's own monotonic {@code
   * bigserial}. A backwards clock step between two appends - NTP, a container resume, two nodes
   * disagreeing - could return an older {@code COMPLETE} ahead of a later {@code PARTIAL} and hide
   * an outstanding erasure from the DPO who asked. Two records are appended directly (bypassing
   * {@code ErasureService}'s own clock, which this test does not control) with a {@code PARTIAL}
   * whose {@code ts} is earlier than the {@code COMPLETE} already in the log but whose {@code seq}
   * is later, exactly what a backwards clock step produces.
   */
  @Test
  void probe_a_backwards_clock_hides_an_outstanding_partial() {
    JdbcErasureStore store = store(List.of());
    SubjectId subject = SubjectId.of("s-clockback");
    String pseudonym = new Pseudonymiser(SECRET).pseudonym(TENANT, subject);
    Instant later = Instant.now();
    Instant earlier = later.minus(Duration.ofHours(1));

    store.append(
        com.housedevinci.shredding.domain.ErasureRecord.of(
            later,
            TENANT,
            pseudonym,
            "dpo",
            "art 17",
            3,
            1,
            2,
            0,
            com.housedevinci.shredding.domain.ErasureOutcome.COMPLETE,
            List.of(),
            later.plus(Duration.ofDays(30))));
    var partial =
        store.append(
            com.housedevinci.shredding.domain.ErasureRecord.of(
                earlier,
                TENANT,
                pseudonym,
                "dpo",
                "art 17",
                0,
                1,
                2,
                0,
                com.housedevinci.shredding.domain.ErasureOutcome.PARTIAL,
                List.of(),
                earlier.plus(Duration.ofDays(30))));

    var latest = store.latestForSubject(TENANT, pseudonym);
    assertThat(latest).isPresent();
    assertThat(latest.get().sequence())
        .as("the later-appended PARTIAL, not the earlier-ts COMPLETE, must be reported latest")
        .isEqualTo(partial.sequence());
    assertThat(latest.get().outcome())
        .isEqualTo(com.housedevinci.shredding.domain.ErasureOutcome.PARTIAL);
  }

  /**
   * An erasure that destroys the key but does not write the record leaves an erasure nobody can
   * prove; a record without the destruction is a false proof. Both must be impossible, which means
   * one transaction, not two calls.
   */
  @Test
  void probe_crash_between_key_destruction_and_the_erasure_record() {
    SubjectId subject = SubjectId.of("s-crash");
    cipher.encrypt(
        TENANT, subject, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
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
    cipher.encrypt(
        TENANT, subject, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
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
                    ROW,
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
   * CIPHER-03. The tombstone in {@code probe_concurrent_write_encrypts_under_a_destroying_key} only
   * defends a subject that already had a key row when the erasure started - the {@code FOR UPDATE}
   * it takes locks nothing for a subject whose first write is still in flight. This probe is that
   * earlier case: the subject has <em>never</em> been written, so there is no key row and no
   * tombstone row for either side to block on until {@code JdbcSupport.lockSubject}'s advisory lock
   * gives them one. The eraser takes it first and holds its transaction open (inside the record
   * factory, exactly like the sibling probe above) so the writer's {@code currentForWrite} blocks
   * on the same lock instead of racing ahead with nothing to observe.
   */
  @Test
  void probe_a_write_racing_the_first_key_mint_survives_the_tombstone() throws Exception {
    SubjectId subject = SubjectId.of("s-first-mint-race");
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
                    ROW,
                    "Customer",
                    "email",
                    "first@b.c".getBytes(StandardCharsets.UTF_8));
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
                      // hold the advisory lock while the writer's mint tries to take it too
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
                          "art 17, subject never wrote anything",
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
        .as(
            "a first write racing the erasure of a subject that never had a key must fail, not"
                + " mint a live key for a subject the erasure log already says is erased")
        .isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) writerFailure.get()).code()).isEqualTo(ErrorCodes.ERASED);
    assertThat(keys.forRead(TENANT, subject, 1))
        .as("no key was ever minted for this subject")
        .isEmpty();
    var record = store.readAfter(0, 10).get(0);
    assertThat(record.keysDestroyed())
        .as("nothing existed to destroy; the erasure is honestly recorded as such")
        .isZero();
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
            TENANT, subject, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
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
        store(
            List.of(
                new BlindIndexColumn(
                    com.housedevinci.shredding.domain.TableRef.of("customer"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("email_bidx"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("customer_id"),
                    com.housedevinci.shredding.domain.ColumnRef.unquoted("tenant_id"),
                    java.util.Optional.of("tenantId"),
                    java.util.Optional.of("customerId"))));
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

  /**
   * The chain has to survive the round trip through the column type, not only through memory.
   *
   * <p>PostgreSQL's {@code timestamptz} holds microseconds and rounds anything finer, so a
   * nanosecond timestamp comes back as a different instant and the recomputed hash no longer
   * matches. The clock is nanosecond-precision here on purpose: macOS's {@code Clock.systemUTC()}
   * is only microsecond-precision, so with the system clock this passes on a developer's machine
   * and fails on Linux CI, which is exactly what happened.
   */
  @Test
  void the_chain_survives_a_nanosecond_precision_clock() {
    Instant nanos = Instant.parse("2026-09-08T10:00:00.123456789Z");
    Clock nanoClock =
        new Clock() {
          @Override
          public ZoneId getZone() {
            return ZoneOffset.UTC;
          }

          @Override
          public Clock withZone(ZoneId zone) {
            return this;
          }

          @Override
          public Instant instant() {
            return nanos;
          }
        };
    var store = store(List.of());
    var service =
        new ErasureService(
            store,
            cache,
            new Pseudonymiser(SECRET),
            List.of(),
            Duration.ofDays(30),
            nanoClock,
            1,
            2);
    SubjectId subject = SubjectId.of("s-nanos");
    cipher.encrypt(
        TENANT, subject, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));

    var written =
        service.erase(new ErasureRequest(TENANT, subject, "dpo", "art 17")).records().get(0);
    var readBack = store.readAfter(written.sequence() - 1, 1).get(0);

    assertThat(readBack)
        .as("what comes back out of the column must be what went in, field for field")
        .isEqualTo(written);
    assertThat(new ErasureChainVerifier(store, store, Map.of("k1", SECRET)).verify().status())
        .isEqualTo(ErasureChainVerifier.Status.INTACT);
  }

  @Test
  void the_erasure_record_chain_verifies_end_to_end() {
    var store = store(List.of());
    var service = service(store);
    for (int i = 1; i <= 3; i++) {
      SubjectId s = SubjectId.of("s-chain-" + i);
      cipher.encrypt(TENANT, s, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
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
    cipher.encrypt(TENANT, s, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
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

  /**
   * CIPHER-04. The runtime role needs INSERT on {@code shredding_erased_subject} so {@code mint}
   * and {@code erase} can write the tombstone; before this fix the same grant let it DELETE too.
   * Deleting the tombstone is exactly as dangerous as deleting an erasure row: {@code mint} trusts
   * its absence to mean "never erased" and mints again.
   */
  @Test
  void probe_the_runtime_role_can_delete_the_tombstone_and_mint_again() throws Exception {
    var store = store(List.of());
    SubjectId subject = SubjectId.of("s-tombstone-delete");
    store.erase(
        TENANT,
        subject,
        (destroyed, cleared) ->
            com.housedevinci.shredding.domain.ErasureRecord.of(
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
                java.time.Instant.now().plus(Duration.ofDays(30))));

    try (Connection c = dataSource.getConnection();
        var st = c.createStatement()) {
      assertThatThrownBy(
              () ->
                  st.execute(
                      "DELETE FROM shredding_erased_subject WHERE tenant = 'acme' AND subject ="
                          + " 's-tombstone-delete'"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(() -> st.execute("UPDATE shredding_erased_subject SET erased_at = now()"))
          .hasMessageContaining("append-only");
      assertThatThrownBy(() -> st.execute("TRUNCATE shredding_erased_subject"))
          .hasMessageContaining("append-only");
    }
  }

  /**
   * CIPHER-05. {@code pg_trigger} is database-wide and trigger names are per-table, so a bare
   * {@code tgname} guard with no {@code tgrelid} predicate is satisfied by the same-named trigger
   * on a different schema's copy of the same table - once one schema on the database has run the
   * schema step, every later schema silently skips every trigger it creates. This runs the schema
   * step again in a second, freshly created schema and proves its own append-only triggers exist
   * there too.
   */
  @Test
  void probe_the_append_only_triggers_are_skipped_in_a_second_schema() throws Exception {
    // The default schema (public, from setUp) already has the triggers; this is "a second schema
    // on the same database", the exact condition the finding names.
    try (Connection c = dataSource.getConnection();
        var st = c.createStatement()) {
      st.execute("DROP SCHEMA IF EXISTS other CASCADE");
      st.execute("CREATE SCHEMA other");
      st.execute("SET search_path TO other");
      st.execute(
          new String(
              CipherProbeJdbcTest.class
                  .getResourceAsStream("/com/housedevinci/shredding/schema-postgresql.sql")
                  .readAllBytes(),
              StandardCharsets.UTF_8));
      st.execute(
          "INSERT INTO other.shredding_erasure_anchor (id, head_hash, row_count,"
              + " updated_at, keyed) VALUES (1, repeat('0', 64), 0, now(), true)");
      assertThatThrownBy(() -> st.execute("DELETE FROM other.shredding_erasure_anchor"))
          .as("the anchor's own guard must fire in the second schema too")
          .hasMessageContaining("append-only");
      st.execute(
          "INSERT INTO other.shredding_erased_subject (tenant, subject, erased_at)"
              + " VALUES ('acme', 's-other-schema', now())");
      assertThatThrownBy(() -> st.execute("DELETE FROM other.shredding_erased_subject"))
          .as("the tombstone's guard must fire in the second schema too, not only in the first")
          .hasMessageContaining("append-only");
    } finally {
      try (Connection c = dataSource.getConnection();
          var st = c.createStatement()) {
        st.execute("SET search_path TO public");
        st.execute("DROP SCHEMA IF EXISTS other CASCADE");
      }
    }
  }

  @Test
  void an_unkeyed_instance_is_refused_against_a_keyed_trail() {
    var store = store(List.of());
    SubjectId s = SubjectId.of("s-mode");
    cipher.encrypt(TENANT, s, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    service(store).erase(new ErasureRequest(TENANT, s, "dpo", "art 17"));

    assertThatThrownBy(
            () -> new JdbcErasureStore(dataSource, ErasureChain.unkeyed(), List.of(), RESIDUAL))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.ERASURE_KEY_MISMATCH);
  }

  @Test
  void a_wrapped_key_row_cannot_be_swapped_between_subjects() throws Exception {
    SubjectId a = SubjectId.of("s-swap-a");
    SubjectId b = SubjectId.of("s-swap-b");
    cipher.encrypt(TENANT, a, ROW, "Customer", "email", "a@b.c".getBytes(StandardCharsets.UTF_8));
    cipher.encrypt(TENANT, b, ROW, "Customer", "email", "b@b.c".getBytes(StandardCharsets.UTF_8));

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
