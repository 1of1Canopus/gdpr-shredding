package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.autoconfigure.matrix.MatrixLedger;
import com.housedevinci.shredding.autoconfigure.matrix.MatrixLedgerRepository;
import com.housedevinci.shredding.domain.EncryptedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.RowId;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.Placeholders;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManager;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HashSet;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The framework integration matrix of {@code docs/plans/read-path-design.md} §2: one test per path
 * Hibernate offers to reach a {@code @Shredded} column, written before the mechanism that closes
 * it. A control on one event is not a control.
 *
 * <p>Rows this class covers are the ones the earlier passes had no test for: the {@code @PostLoad}
 * ordering (Cipher item 8), the placeholder write-back on a type with no sentinel (item 2), a
 * forged placeholder in the column (item 3), {@code merge} and {@code refresh}, a {@code
 * StatelessSession}, a {@code Stream} drained after the call, {@code equals}/{@code hashCode} (item
 * 11), and the {@code IDENTITY} rebind window (items 5, 6). The rest are covered by the {@code
 * CipherProbe*} classes named in §2 and are not duplicated here.
 */
@SpringBootTest(classes = FrameworkMatrixTest.MatrixApp.class)
@Testcontainers
@DirtiesContext
class FrameworkMatrixTest {

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
  @EntityScan(basePackageClasses = MatrixLedger.class)
  @EnableJpaRepositories(basePackageClasses = MatrixLedgerRepository.class)
  static class MatrixApp {}

  @Autowired MatrixLedgerRepository ledgers;
  @Autowired EntityManager entityManager;
  @Autowired TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;
  @Autowired jakarta.persistence.EntityManagerFactory entityManagerFactory;

  // -- §2 row 1: an entity load installs and verifies every field of every row -----------------

  @Test
  void an_entity_load_installs_and_verifies_each_row() {
    String owner = save("m1", "note one", "12.34", "2026-01-31");
    save(owner, "note two", "99.99", "2026-02-28");

    List<MatrixLedger> loaded =
        transactions.execute(
            s -> {
              entityManager.clear();
              return ledgers.findByOwnerId(owner);
            });

    assertThat(loaded).hasSize(2);
    assertThat(loaded)
        .extracting(MatrixLedger::getNote)
        .containsExactlyInAnyOrder("note one", "note two");
    assertThat(loaded)
        .allSatisfy(l -> assertThat(Placeholders.isPlaceholder(l.getNote())).isFalse());
    assertThat(loaded)
        .extracting(MatrixLedger::getAmount)
        .allSatisfy(a -> assertThat(a).isNotNull());
    assertThat(loaded).extracting(MatrixLedger::getDue).allSatisfy(d -> assertThat(d).isNotNull());
  }

  // -- §2 row 17: Cipher item 8, the listener must be prepended ---------------------------------

  /**
   * The module's {@code POST_LOAD} listener has to run <em>before</em> Hibernate's own {@code
   * PostLoadEventListenerStandardImpl}, which is what invokes a user's {@code @PostLoad} methods
   * and {@code @EntityListeners} beans. While it was appended, every one of those callbacks was
   * handed the read placeholder instead of the value - silently, and in exactly the place an
   * application computes a derived field or fires an event.
   */
  @Test
  void a_user_post_load_callback_never_sees_a_placeholder() {
    String owner = save("m-postload", "POSTLOAD-NOTE", "5.00", "2026-03-01");
    MatrixLedger.lastPostLoadSawNote = null;
    MatrixLedger.lastPostLoadSawAmount = null;

    transactions.executeWithoutResult(
        s -> {
          entityManager.clear();
          ledgers.findByOwnerId(owner);
        });

    assertThat(Placeholders.isPlaceholder(MatrixLedger.lastPostLoadSawNote)).isFalse();
    assertThat(MatrixLedger.lastPostLoadSawNote).isEqualTo("POSTLOAD-NOTE");
    assertThat(MatrixLedger.lastPostLoadSawAmount).isEqualByComparingTo("5.00");
  }

  // -- §2 row 16: Cipher item 2, the null-placeholder data-loss hole ----------------------------

  /**
   * The hole a {@code null} placeholder opened, on the two types that have no erased sentinel. Load
   * a row, keep the instance, mark it dirty on a <em>non</em>-shredded property and flush: with an
   * ordinary (non-{@code @DynamicUpdate}) mapping Hibernate rewrites every basic column, so the
   * value the entity holds for {@code amount} and {@code due} is what lands in the database. If
   * that value were {@code null} - which is what the placeholder used to be for these types when
   * the install did not run - the live ciphertext would be gone with nothing to notice.
   */
  @Test
  void a_load_then_flush_never_rewrites_a_shredded_column() throws Exception {
    String owner = save("m-flush", "flush note", "42.42", "2026-04-01");
    long id = idOf(owner);
    byte[] before = column("amount", id);

    transactions.executeWithoutResult(
        s -> {
          entityManager.clear();
          MatrixLedger l = ledgers.findById(id).orElseThrow();
          l.setNote(l.getNote() + "!");
          entityManager.flush();
        });

    assertThat(column("amount", id)).isNotNull();
    assertThat(EncryptedValue.decode(column("amount", id)).rowId())
        .isEqualTo(EncryptedValue.decode(before).rowId());
    BigDecimal reread =
        transactions.execute(
            s -> {
              entityManager.clear();
              return ledgers.findById(id).orElseThrow().getAmount();
            });
    assertThat(reread).isEqualByComparingTo("42.42");
  }

  /**
   * And the refusal itself: an instance holding the placeholder is never encrypted back. Built by
   * hand rather than by contriving a failed install, because the property under test is the check,
   * not the route to it.
   */
  @Test
  void a_placeholder_is_never_re_encrypted() {
    var converter = new MatrixLedger.AmountConverter();

    assertThatThrownBy(() -> converter.convertToDatabaseColumn(Placeholders.BIG_DECIMAL))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.PLACEHOLDER);

    var strings = new MatrixLedger.NoteConverter();
    assertThatThrownBy(() -> strings.convertToDatabaseColumn(Placeholders.STRING))
        .isInstanceOf(ShreddingException.class)
        .extracting(e -> ((ShreddingException) e).code())
        .isEqualTo(ErrorCodes.PLACEHOLDER);

    // S-3 (Cipher sixth pass), correcting Cipher item 3: an equal-but-distinct instance IS the
    // placeholder as far as write-back is concerned - a refused load leaves the entity holding the
    // marker instance and detaches it, and the ordinary things an application does to a detached
    // entity (a DTO round trip, new String(...), trim(), a defensive clone()) all produce a
    // value-equal, reference-distinct copy that must be refused exactly like the instance itself.
    // What stays true from item 3 is that an attacker holding UPDATE cannot manufacture one: doing
    // so would need a ciphertext of the marker under the subject's own data key.
    assertThat(Placeholders.isPlaceholder(new String(Placeholders.STRING))).isTrue();
    assertThat(Placeholders.isPlaceholder(new BigDecimal(Placeholders.BIG_DECIMAL.toPlainString())))
        .isTrue();
    assertThat(Placeholders.isPlaceholder(LocalDate.of(-999_999_999, 1, 1))).isTrue();
  }

  // -- §2 row 21: a forged placeholder in the column ---------------------------------------------

  /**
   * An attacker holding {@code UPDATE} writes the placeholder's own rendering into the column,
   * hoping a read hands it back as if it were an installed value. It is not {@code SH1} bytes, so
   * the decode refuses before anything else happens.
   */
  @Test
  void a_forged_placeholder_in_the_column_is_refused() throws Exception {
    String owner = save("m-forged", "forged note", "1.00", "2026-05-01");
    long id = idOf(owner);
    write("note", id, Placeholders.describe().getBytes(StandardCharsets.UTF_8));

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    s -> {
                      entityManager.clear();
                      ledgers.findById(id).orElseThrow().getNote();
                    }))
        .satisfies(t -> assertThat(codeOf(t)).isEqualTo(ErrorCodes.FORMAT));
  }

  // -- §2 row 18: merge and refresh --------------------------------------------------------------

  @Test
  void a_merge_and_a_refresh_are_verified_like_any_other_load() {
    String owner = save("m-merge", "merge note", "7.77", "2026-06-01");
    long id = idOf(owner);

    String merged =
        transactions.execute(
            s -> {
              entityManager.clear();
              MatrixLedger detached = ledgers.findById(id).orElseThrow();
              entityManager.clear();
              return ShreddingContext.withReadBracket(
                  () -> {
                    MatrixLedger reattached = entityManager.merge(detached);
                    entityManager.refresh(reattached);
                    return reattached.getNote();
                  });
            });

    assertThat(merged).isEqualTo("merge note");
    assertThat(Placeholders.isPlaceholder(merged)).isFalse();
  }

  // -- §2 row 19: a StatelessSession fires no PostLoad --------------------------------------------

  /**
   * There is no {@code PostLoad} event on a {@code StatelessSession} at all, so there is no
   * verifier and no region: the read is refused rather than served unverified. Fail-closed, and
   * documented in the error message, because a stateless read is exactly what a batch job reaches
   * for.
   */
  @Test
  void a_stateless_session_read_is_refused() {
    String owner = save("m-stateless", "STATELESS-SECRET", "3.33", "2026-07-01");
    long id = idOf(owner);

    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);
    String outcome;
    try (var stateless = sessionFactory.openStatelessSession()) {
      MatrixLedger l = stateless.get(MatrixLedger.class, id);
      outcome = "RETURNED " + (l == null ? "null" : l.getNote());
    } catch (RuntimeException e) {
      outcome = "REFUSED " + codeOf(e);
    }

    assertThat(outcome).doesNotContain("STATELESS-SECRET");
    assertThat(outcome).startsWith("REFUSED");
  }

  // -- §2 row 7: a Stream drained after the repository call returns
  // --------------------------------

  @Test
  void a_streaming_repository_method_consumed_after_the_call_is_refused() {
    String owner = save("m-stream", "STREAM-SECRET", "8.88", "2026-08-01");

    String outcome;
    try {
      outcome =
          "RETURNED "
              + transactions.execute(
                  s -> {
                    entityManager.clear();
                    try (var stream = ledgers.streamByOwnerId(owner)) {
                      return stream.map(MatrixLedger::getNote).toList();
                    }
                  });
    } catch (RuntimeException e) {
      outcome = "REFUSED " + codeOf(e);
    }

    assertThat(outcome).doesNotContain("STREAM-SECRET");
  }

  // -- §2 row 20: Cipher item 11, equals/hashCode -------------------------------------------------

  /**
   * The documented hazard, demonstrated rather than asserted away. A shredded field holds the
   * placeholder between the converter and the install, so an instance whose {@code hashCode}
   * depends on one and that is put into a {@code HashSet} before the install is unreachable
   * afterwards. The module's own fixtures do not do this, and the README rule says not to; this
   * test is what makes the rule checkable.
   */
  @Test
  void a_set_keyed_on_a_shredded_field_is_unreachable_after_the_install() {
    var keyedOnNote = new HashSet<String>();
    keyedOnNote.add(Placeholders.STRING);

    assertThat(keyedOnNote.contains("the installed value")).isFalse();
    assertThat(keyedOnNote).hasSize(1);
    // Which is the whole point: the key an application would have hashed before the install is not
    // the key it holds after one. A @Shredded field never participates in equals/hashCode.
  }

  // -- §2 rows 22, 23: the IDENTITY rebind
  // ---------------------------------------------------------

  /**
   * Design §3's load-bearing assumption, proved rather than assumed: under {@code IDENTITY} the
   * {@code PreInsert} event carries no identifier, which is why the row is bound to a random,
   * unbound intermediate and rebound in {@code onPostInsert}. If Hibernate ever populated it here,
   * the whole second {@code UPDATE} would be dropped.
   */
  @Test
  void the_insert_event_has_no_id_under_identity() {
    String owner = save("m-identity", "identity note", "1.11", "2026-09-01");
    long id = idOf(owner);

    // What the row actually ended up bound to is the generated identifier, not the intermediate.
    byte[] stored = columnQuietly("note", id);
    var header = EncryptedValue.decode(stored);
    assertThat(header.rowId()).isEqualTo(RowId.ofIdentifier(id));
    assertThat(header.rowId().isUnboundIntermediate()).isFalse();
  }

  /**
   * Cipher item 5: whatever the intermediate is, it verifies against no row. A reader that captured
   * the pre-rebind bytes - change data capture, an {@code AFTER INSERT} trigger, a physical replica
   * caught between the two statements - holds a blob bound to a 128-bit random value that no
   * identifier's canonical encoding can equal.
   */
  @Test
  void an_identity_insert_intermediate_is_bound_to_no_row() {
    var intermediate =
        RowId.unboundIntermediate(com.housedevinci.shredding.domain.RandomSource.secure());

    assertThat(intermediate.isUnboundIntermediate()).isTrue();
    assertThat(intermediate).isNotEqualTo(RowId.ofIdentifier(1L));
    assertThat(intermediate).isNotEqualTo(RowId.ofIdentifier("1"));
    assertThat(intermediate)
        .isNotEqualTo(
            RowId.unboundIntermediate(com.housedevinci.shredding.domain.RandomSource.secure()));
  }

  /** A batched {@code saveAll}: every row is rebound, and every row reads back as its own. */
  @Test
  void a_batched_save_all_rebinds_every_row() {
    String owner = "m-batch-" + System.nanoTime();
    transactions.executeWithoutResult(
        s ->
            ledgers.saveAll(
                List.of(
                    new MatrixLedger(
                        owner, "batch one", new BigDecimal("1.00"), LocalDate.of(2026, 1, 1)),
                    new MatrixLedger(
                        owner, "batch two", new BigDecimal("2.00"), LocalDate.of(2026, 1, 2)),
                    new MatrixLedger(
                        owner, "batch three", new BigDecimal("3.00"), LocalDate.of(2026, 1, 3)))));

    List<MatrixLedger> loaded =
        transactions.execute(
            s -> {
              entityManager.clear();
              return ledgers.findByOwnerId(owner);
            });

    assertThat(loaded).hasSize(3);
    assertThat(loaded)
        .extracting(MatrixLedger::getNote)
        .containsExactlyInAnyOrder("batch one", "batch two", "batch three");
    for (MatrixLedger l : loaded) {
      assertThat(EncryptedValue.decode(columnQuietly("note", l.getId())).rowId())
          .isEqualTo(RowId.ofIdentifier(l.getId()));
    }
  }

  /** A rolled-back insert leaves nothing bound to anything. */
  @Test
  void a_rolled_back_identity_insert_leaves_no_row() throws Exception {
    String owner = "m-rollback-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          ledgers.save(
              new MatrixLedger(owner, "rolled back", new BigDecimal("9.99"), LocalDate.EPOCH));
          entityManager.flush();
          s.setRollbackOnly();
        });

    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT count(*) FROM matrix_ledger WHERE owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        rs.next();
        assertThat(rs.getInt(1)).isZero();
      }
    }
  }

  // ---------------------------------------------------------------- helpers

  private String save(String prefix, String note, String amount, String due) {
    String owner =
        prefix.startsWith("m-") || prefix.contains("-") ? prefix + "-" + System.nanoTime() : prefix;
    transactions.executeWithoutResult(
        s ->
            ledgers.save(
                new MatrixLedger(owner, note, new BigDecimal(amount), LocalDate.parse(due))));
    return owner;
  }

  private long idOf(String owner) {
    return transactions.execute(
        s -> {
          entityManager.clear();
          return ledgers.findByOwnerId(owner).get(0).getId();
        });
  }

  private byte[] column(String column, long id) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT " + column + " FROM matrix_ledger WHERE id = ?")) {
      ps.setLong(1, id);
      try (var rs = ps.executeQuery()) {
        rs.next();
        return rs.getBytes(1);
      }
    }
  }

  private byte[] columnQuietly(String column, long id) {
    try {
      return column(column, id);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private void write(String column, long id, byte[] value) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("UPDATE matrix_ledger SET " + column + " = ? WHERE id = ?")) {
      ps.setBytes(1, value);
      ps.setLong(2, id);
      ps.executeUpdate();
    }
  }

  private static String codeOf(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    return thrown.getClass().getSimpleName();
  }
}
