package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.autoconfigure.fixture.Doc;
import com.housedevinci.shredding.autoconfigure.fixture.DocProjectionRepository;
import com.housedevinci.shredding.autoconfigure.fixture.DocRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
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

/**
 * Cipher third pass (8095d2c): attacks on the read-scope design introduced at 4eb0e98.
 *
 * <p>C-19's repro ({@code Ledger}, a class-level {@code @Convert} column with no field-level
 * {@code @Shredded}) is deliberately not part of this class's shared context: once the C-19 fix is
 * in place, an application whose entity metamodel includes that entity refuses to start entirely,
 * which would take every test below down with it. See {@code CipherProbeReverseScanTest}.
 */
@SpringBootTest(classes = CipherProbeReadScopeTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeReadScopeTest {

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

  @Autowired DocRepository docs;
  @Autowired DocProjectionRepository projections;
  @Autowired WidgetRepository widgets;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  // -- C-17: the CIPHER-11 projection, moved into a repository @Query -------------------------

  /**
   * Before the fix: the bracket let this decrypt through unverified and the moved ciphertext came
   * straight back to the caller. After the fix: the same decrypt is recorded into the bracket's
   * frame, nothing ever drains it (a scalar projection triggers no {@code onPostLoad}), and the
   * frame closes with an undrained entry - the whole call is refused, before any list is returned.
   */
  @Test
  void probe_a_repository_query_projection_returns_a_moved_ciphertext() throws Exception {
    String alice = "a-repo-proj-alice-" + System.nanoTime();
    String bob = "b-repo-proj-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          docs.save(new Doc(alice, "ALICE-SECRET-TITLE", "alice body"));
          docs.save(new Doc(bob, "bob title", "bob body"));
        });
    moveColumn("doc", "title", alice, bob);

    assertThatThrownBy(() -> transactions.execute(s -> projections.titlesOf(bob)))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNVERIFIED));
  }

  @Test
  void probe_a_repository_interface_projection_returns_a_moved_ciphertext() throws Exception {
    String alice = "a-repo-iface-alice-" + System.nanoTime();
    String bob = "b-repo-iface-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          docs.save(new Doc(alice, "ALICE-IFACE-SECRET", "alice body"));
          docs.save(new Doc(bob, "bob title", "bob body"));
        });
    moveColumn("doc", "title", alice, bob);

    assertThatThrownBy(
            () ->
                transactions.execute(
                    s ->
                        projections.findByOwnerId(bob).stream()
                            .map(DocProjectionRepository.TitleView::getTitle)
                            .toList()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNVERIFIED));
  }

  // -- A2 / C-30: two rows in one result set, one of them carrying a moved ciphertext ----------

  /**
   * C-30 (fourth pass): the handed-over version of this probe ran on {@code Doc} (two shredded
   * fields) and asserted only {@code isNotBlank()} - which passed for the wrong reason: {@code
   * Doc.body}'s collision (an artefact of the pre-C-26 flat {@code entity.field} key) threw first,
   * so the moved {@code Doc.title} value was never actually checked at all, and a probe asserting
   * "some error code, whichever it is" cannot tell the difference. Rewritten on {@link Widget}
   * (exactly one shredded field, so nothing else can throw first) and asserting the specific code:
   * with the C-26 fix, bob's own row is independently re-read and compared against its own true
   * subject, and the header it actually holds names alice - a genuine {@code
   * SHRED-SUBJECT-MISMATCH}, not an artefact of which row happened to drain a shared map entry.
   */
  @Test
  void probe_a_second_row_in_the_same_result_set_is_never_verified() throws Exception {
    String alice = "a-multirow-alice-" + System.nanoTime();
    String bob = "b-multirow-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          widgets.save(new Widget(alice, "ALICE-MULTIROW-SECRET"));
          widgets.save(new Widget(bob, "bob name"));
        });
    moveColumn("widget", "name", alice, bob);

    assertThatThrownBy(
            () ->
                transactions.execute(
                    s -> {
                      entityManager.clear();
                      return widgets
                          .findAll(org.springframework.data.domain.Sort.by("ownerId"))
                          .stream()
                          .map(Widget::getName)
                          .toList();
                    }))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_MISMATCH));
  }

  // -- A4: a Stream-returning repository method ------------------------------------------------

  /**
   * C-23: a {@code Stream<Doc>}-returning repository method is a first-class Spring Data return
   * type, and the bracket closes with the repository *method call*, not with the stream - Spring
   * Data hands back a lazy stream backed by an open result set, and rows are actually decoded as
   * the caller drains it, which happens after {@code Bracket.invoke} has already returned. That
   * decrypt therefore has no bracket and no explicit scope open at all: refused, correctly, exactly
   * like any other read with nothing to verify against. What C-23 fixes is the message: before, it
   * told the caller they had written "a scalar, Tuple or constructor-expression projection", which
   * for this repro they had not.
   */
  @Test
  void probe_a_streaming_repository_method_still_decrypts() {
    String owner = "stream-owner-" + System.nanoTime();
    transactions.executeWithoutResult(s -> docs.save(new Doc(owner, "streamed title", "b")));

    assertThatThrownBy(
            () ->
                transactions.execute(
                    s -> {
                      try (var stream = projections.streamByOwner(owner)) {
                        return stream.map(Doc::getTitle).toList();
                      }
                    }))
        .satisfies(
            t -> {
              assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED);
              assertThat(shreddingException(t).getMessage())
                  .contains("Stream")
                  .contains("withReadBracket");
            });
  }

  // -- A5: a decode recorded by a projection is drained by an unrelated later row --------------

  /**
   * Before the fix: {@code projections.titlesOf(alice)} recorded alice's decoded title into a flat,
   * bracket-wide map and returned normally (nothing verified it); later, in the same transaction,
   * bob's row - whose own title column is {@code NULL} - had its {@code onPostLoad} drain that
   * stale entry and wrongly refuse bob's row for a mismatch that was never his. After the fix, each
   * repository call gets its own frame: alice's call is refused on its own terms (C-17, above)
   * before it can return anything, so there is no stale entry left for bob's independent call to
   * inherit. Both halves are asserted: the leaking read is refused, and the unrelated row is not
   * collaterally damaged by it.
   */
  @Test
  void probe_a_projection_decode_contaminates_a_later_rows_check() {
    String alice = "a-stale-alice-" + System.nanoTime();
    String bob = "b-stale-bob-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          docs.save(new Doc(alice, "ALICE-STALE-TITLE", "alice body"));
          docs.save(
              new Doc(bob, null, "bob body")); // bob's title column is NULL: nothing to decode
        });

    String outcome =
        transactions.execute(
            s -> {
              entityManager.clear();
              try {
                projections.titlesOf(alice);
                return "loaded";
              } catch (RuntimeException e) {
                return shreddingCode(e);
              }
            });
    System.out.println("MATRIX stale-decode contamination -> " + outcome);
    assertThat(outcome).isEqualTo(ErrorCodes.READ_UNVERIFIED);

    // bob's row, read in its own, later bracket, is completely unaffected by alice's refused read.
    String bobBody =
        transactions.execute(
            s -> {
              entityManager.clear();
              return docs.findByOwnerId(bob).get(0).getBody();
            });
    assertThat(bobBody).isEqualTo("bob body");
  }

  // -- design addendum 2: the entry epoch, on the real read path -------------------------------

  /**
   * Addendum 2 change 3. The nested case has to keep working, and it is the case an unconditional
   * sweep would have broken: a repository call made from inside another bracketed entry opens its
   * own region, and the outer call's region - same thread, one epoch older - must survive it with
   * its own pending decodes intact.
   *
   * <p>Both values come back in plaintext and neither call refuses. Before the epoch, the two
   * regions were told apart by nothing at all; with an unconditional sweep, the inner call would
   * have destroyed the outer region and the outer close would have raised {@code
   * SHRED-READ-UNVERIFIED} on every nested repository call in the application.
   */
  @Test
  void probe_a_repository_call_nested_inside_a_read_bracket_leaves_the_outer_region_alone() {
    String owner = "nested-outer-" + System.nanoTime();
    String other = "nested-inner-" + System.nanoTime();
    transactions.executeWithoutResult(
        s -> {
          docs.save(new Doc(owner, "OUTER-TITLE", "outer body"));
          docs.save(new Doc(other, "INNER-TITLE", "inner body"));
        });

    var seen =
        transactions.execute(
            s -> {
              entityManager.clear();
              return ShreddingContext.withReadBracket(
                  () -> {
                    Doc outer =
                        entityManager
                            .createQuery("select d from Doc d where d.ownerId = :o", Doc.class)
                            .setParameter("o", owner)
                            .getSingleResult();
                    // a repository call - a second, nested bracketed entry - in the middle of it
                    String innerTitle = docs.findByOwnerId(other).get(0).getTitle();
                    // and the outer region still serves the outer call's own lazy work
                    entityManager.refresh(outer);
                    return List.of(outer.getTitle(), innerTitle, outer.getBody());
                  });
            });
    assertThat(seen).containsExactly("OUTER-TITLE", "INNER-TITLE", "outer body");
  }

  /**
   * Addendum 2 change 2, second case, on the real read path. A region opened directly with {@code
   * ShreddingContext.openRegion()} from inside a call - what a user {@code @PostLoad} method, an
   * {@code @EntityListeners} bean or a hand-written DAO reached from a repository default method
   * can do - sits on top of the deque and would otherwise take every remaining decode of that call
   * and hand it back at drain time with nothing verifying it. It carries no entry epoch, so the
   * decrypt behind it is refused: the call fails closed instead of being served out of a region
   * nobody owns. This is S-4 itself.
   */
  @Test
  void probe_a_raw_region_opened_inside_a_call_refuses_that_calls_later_decodes() {
    String owner = "raw-region-" + System.nanoTime();
    transactions.executeWithoutResult(s -> docs.save(new Doc(owner, "RAW-TITLE", "raw body")));

    assertThatThrownBy(
            () ->
                transactions.execute(
                    s -> {
                      entityManager.clear();
                      return ShreddingContext.withReadBracket(
                          () -> {
                            Doc doc =
                                entityManager
                                    .createQuery(
                                        "select d from Doc d where d.ownerId = :o", Doc.class)
                                    .setParameter("o", owner)
                                    .getSingleResult();
                            assertThat(doc.getTitle()).isEqualTo("RAW-TITLE");
                            // the undisciplined region, opened mid-call and never closed
                            long raw = ShreddingContext.openRegion();
                            assertThat(raw).isPositive();
                            entityManager.clear();
                            return entityManager.find(Doc.class, doc.getId()).getTitle();
                          });
                    }))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));
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

  private static String shreddingCode(Throwable thrown) {
    return shreddingException(thrown).code();
  }

  private static ShreddingException shreddingException(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s;
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }
}
