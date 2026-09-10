package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.fixture.Blob;
import com.housedevinci.shredding.autoconfigure.fixture.BlobRepository;
import com.housedevinci.shredding.autoconfigure.fixture.BlobSeq;
import com.housedevinci.shredding.autoconfigure.fixture.BlobSeqRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Doc;
import com.housedevinci.shredding.autoconfigure.fixture.DocRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Gadget;
import com.housedevinci.shredding.autoconfigure.fixture.GadgetRepository;
import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ErasedValue;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
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
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * L2. The starter's own tests never exercised {@code ShreddingEventListener}, {@code
 * ShreddingContext}, {@code ShreddingRuntime} or the {@code ShreddingAutoConfiguration} bean graph
 * end to end - {@code CipherProbeStartupTest} and {@code CipherProbeSpelTest} call {@code
 * ShreddedModel.scan} and a few beans directly, never through a real Hibernate session. That left
 * exactly the write path, the read path and the startup wiring - controls 5 and 11 to 14 - as the
 * finding says, unmeasured in this module's own coverage report even though the sample module
 * exercises them. This stands up a real Spring Boot context with the auto-configuration, a small
 * local entity ({@code fixture.Widget}, not the sample's {@code Customer} - this module does not
 * depend on the sample), and Testcontainers PostgreSQL, and drives the same shape of end-to-end
 * flow the sample does.
 */
@SpringBootTest(classes = ShreddingIntegrationTest.TestApp.class)
@Testcontainers
@DirtiesContext
class ShreddingIntegrationTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add(
        "shredding.master-key",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "starter-integration-master-key32".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.erasure-log.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "starter-integration-chain-secret".getBytes(StandardCharsets.UTF_8)));
    registry.add(
        "shredding.blind-index.hmac-secret",
        () ->
            Base64.getEncoder()
                .encodeToString(
                    "starter-integration-index-secret".getBytes(StandardCharsets.UTF_8)));
    // No init script for this fixture table; Hibernate creates it from the entity mapping.
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class TestApp {
    // S-7: Gadget.metadata, the field its own @BlindIndex names in of=, no longer declares its own
    // tenant expression (a field a @BlindIndex indexes may not). It falls back to the ambient
    // tenant, and every fixture entity in this file already always resolves to "default" anyway.
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("default");
    }
  }

  @Autowired WidgetRepository widgets;
  @Autowired GadgetRepository gadgets;
  @Autowired DocRepository docs;
  @Autowired BlobRepository blobs;
  @Autowired BlobSeqRepository blobSeqs;
  @Autowired ErasureService erasures;
  @Autowired ErasureChainVerifier verifier;
  @Autowired EntityManager entityManager;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired javax.sql.DataSource dataSource;

  @Test
  @Transactional
  void the_write_path_the_read_path_and_the_erasure_go_through_the_real_listener() {
    String owner = "owner-" + System.nanoTime();
    Widget saved = widgets.save(new Widget(owner, "a widget's real name"));
    entityManager.flush();
    entityManager.clear();

    Widget loaded = widgets.findByOwnerId(owner).get(0);
    assertThat(loaded.getName()).isEqualTo("a widget's real name");
    assertThat(loaded.toString()).doesNotContain("a widget's real name");

    erasures.erase(new ErasureRequest(TenantId.of("default"), SubjectId.of(owner), "dpo", "test"));
    entityManager.clear();

    Widget afterErasure = widgets.findByOwnerId(owner).get(0);
    assertThat(afterErasure.getName()).isEqualTo(ErasedValue.MARKER);

    assertThat(verifier.verify().status()).isEqualTo(ErasureChainVerifier.Status.INTACT);
    assertThat(saved.getId()).isNotNull();
  }

  @Test
  void a_bulk_jpql_update_to_a_shredded_column_is_refused() {
    // A bulk JPQL UPDATE never fires PreUpdateEvent - there is no entity instance, no listener
    // call, so no scope is ever pushed - but the AttributeConverter still runs on the bind
    // parameter. ShreddingContext.require's failure path, exercised through the real converter.
    assertThat(ShreddingContext.current()).isEmpty();
    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery("update Widget w set w.name = :name where w.id = -1")
                            .setParameter("name", "whoever reads this")
                            .executeUpdate()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.NO_CONTEXT));
  }

  @Test
  @Transactional
  void the_subject_cannot_change_on_a_persisted_row() {
    String owner = "owner-immutable-" + System.nanoTime();
    Widget saved = widgets.save(new Widget(owner, "original"));
    entityManager.flush();

    saved.setOwnerId("someone-else");
    assertThatThrownBy(entityManager::flush)
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE));
  }

  @Test
  void the_other_shredded_converter_types_round_trip_and_the_blind_index_clears_on_erasure()
      throws Exception {
    // Not @Transactional: the raw JDBC checks below open their own connection and must see what
    // gadgets.save/erasures.erase actually committed, not an uncommitted change on another
    // connection - each repository call and erasures.erase() commits its own transaction.
    String owner = "owner-gadget-" + System.nanoTime();
    var installed = java.time.LocalDate.of(2020, 1, 15);
    gadgets.save(
        new Gadget(
            owner,
            new java.math.BigDecimal("42.50"),
            installed,
            "{\"model\":\"widgetiser-3000\"}"));

    Gadget loaded = gadgets.findByOwnerId(owner).get(0);
    assertThat(loaded.getBalance()).isEqualByComparingTo("42.50");
    assertThat(loaded.getInstalledOn()).isEqualTo(installed);
    assertThat(loaded.getMetadata()).contains("widgetiser-3000");

    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT metadata_bidx FROM gadget WHERE owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getBytes(1)).as("the blind index was written on insert").isNotNull();
      }
    }

    erasures.erase(new ErasureRequest(TenantId.of("default"), SubjectId.of(owner), "dpo", "test"));
    entityManager.clear();

    Gadget afterErasure = gadgets.findByOwnerId(owner).get(0);
    assertThat(afterErasure.getBalance()).isNull();
    assertThat(afterErasure.getInstalledOn()).isNull();

    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT metadata_bidx FROM gadget WHERE owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getBytes(1)).as("the blind index is nulled on erasure").isNull();
      }
    }
  }

  /**
   * CIPHER-01, exercised through the starter's own integration test rather than only through the
   * sample: a blob copied verbatim into another subject's row must refuse to load.
   */
  @Test
  void probe_a_blob_moved_into_another_subjects_row_is_refused_on_read() throws Exception {
    String aliceId = "owner-alice-" + System.nanoTime();
    String bobId = "owner-bob-" + System.nanoTime();
    widgets.save(new Widget(aliceId, "alice's real name"));
    widgets.save(new Widget(bobId, "bob's real name"));

    byte[] aliceName;
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("SELECT name FROM widget WHERE owner_id = ?")) {
      ps.setString(1, aliceId);
      try (var rs = ps.executeQuery()) {
        rs.next();
        aliceName = rs.getBytes(1);
      }
    }
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("UPDATE widget SET name = ? WHERE owner_id = ?")) {
      ps.setBytes(1, aliceName);
      ps.setString(2, bobId);
      ps.executeUpdate();
    }

    assertThatThrownBy(() -> widgets.findByOwnerId(bobId))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_MISMATCH));
  }

  // -- CIPHER-11: a projection, unwrapped, has no read scope and is refused -----------------

  @Test
  void probe_a_moved_blob_is_returned_by_a_scalar_projection() throws Exception {
    String aliceId = "owner-alice-scalar-" + System.nanoTime();
    String bobId = "owner-bob-scalar-" + System.nanoTime();
    docs.save(new Doc(aliceId, "ALICE-SECRET-TITLE", "alice body"));
    docs.save(new Doc(bobId, "bob title", "bob body"));
    moveColumn("doc", "title", aliceId, bobId);

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery(
                                "select d.title from Doc d where d.ownerId = :id", String.class)
                            .setParameter("id", bobId)
                            .getSingleResult()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));
  }

  @Test
  void probe_a_moved_blob_is_returned_by_a_tuple_projection() throws Exception {
    String aliceId = "owner-alice-tuple-" + System.nanoTime();
    String bobId = "owner-bob-tuple-" + System.nanoTime();
    docs.save(new Doc(aliceId, "ALICE-SECRET-TITLE-2", "alice body 2"));
    docs.save(new Doc(bobId, "bob title 2", "bob body 2"));
    moveColumn("doc", "title", aliceId, bobId);

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery(
                                "select d.title, d.body from Doc d where d.ownerId = :id",
                                Tuple.class)
                            .setParameter("id", bobId)
                            .getSingleResult()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));
  }

  @Test
  void probe_a_moved_blob_is_returned_by_a_constructor_expression_dto() throws Exception {
    String aliceId = "owner-alice-ctor-" + System.nanoTime();
    String bobId = "owner-bob-ctor-" + System.nanoTime();
    docs.save(new Doc(aliceId, "ALICE-SECRET-TITLE-3", "alice body 3"));
    docs.save(new Doc(bobId, "bob title 3", "bob body 3"));
    moveColumn("doc", "title", aliceId, bobId);

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery(
                                "select new "
                                    + DocTitle.class.getName()
                                    + "(d.title) from Doc d where d.ownerId = :id",
                                DocTitle.class)
                            .setParameter("id", bobId)
                            .getSingleResult()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));
  }

  /** CIPHER-11's fix list: an unscoped projection of a row nothing was ever moved into either. */
  @Test
  void an_unscoped_projection_of_a_legitimate_row_is_refused_too() {
    String ownerId = "owner-legit-" + System.nanoTime();
    docs.save(new Doc(ownerId, "a perfectly ordinary title", "a perfectly ordinary body"));

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery(
                                "select d.title from Doc d where d.ownerId = :id", String.class)
                            .setParameter("id", ownerId)
                            .getSingleResult()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));
  }

  /**
   * Design §1, Cipher item 1: {@code withRead} is gone. It vouched for a projection with a
   * caller-supplied subject, which is exactly the "ambient state authorises" shape five review
   * passes kept breaking. A projection inside an open read region now decrypts nothing a caller can
   * see - the converter returns a placeholder - and the region refuses when it closes.
   */
  @Test
  void a_projection_inside_a_read_region_is_refused_when_the_region_closes() {
    String ownerId = "owner-scoped-" + System.nanoTime();
    docs.save(new Doc(ownerId, "SCOPED-TITLE-SECRET", "scoped body"));

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        ShreddingContext.withReadBracket(
                            () ->
                                entityManager
                                    .createQuery(
                                        "select d.title from Doc d where d.ownerId = :id",
                                        String.class)
                                    .setParameter("id", ownerId)
                                    .getSingleResult())))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNVERIFIED))
        .satisfies(t -> assertThat(messagesOf(t)).doesNotContain("SCOPED-TITLE-SECRET"));
  }

  /**
   * And the same projection with no region at all: refused at the decrypt, before anything is
   * returned. Cipher item 1 - a placeholder handed out with nothing that will ever close a region
   * is a value crossing the boundary with no signal.
   */
  @Test
  void a_projection_with_no_read_region_is_refused_at_the_decrypt() {
    String ownerId = "owner-unscoped-" + System.nanoTime();
    docs.save(new Doc(ownerId, "UNSCOPED-TITLE-SECRET", "body"));

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status ->
                        entityManager
                            .createQuery(
                                "select d.title from Doc d where d.ownerId = :id", String.class)
                            .setParameter("id", ownerId)
                            .getSingleResult()))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED))
        .satisfies(t -> assertThat(messagesOf(t)).doesNotContain("UNSCOPED-TITLE-SECRET"));
  }

  private static String messagesOf(Throwable thrown) {
    var sb = new StringBuilder();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      sb.append(String.valueOf(t.getMessage())).append('\n');
    }
    return sb.toString();
  }

  /** A repository call keeps decrypting transparently: the read bracket, not an explicit scope. */
  @Test
  void a_repository_call_reads_transparently_through_the_bracket() {
    String ownerId = "owner-bracket-" + System.nanoTime();
    docs.save(new Doc(ownerId, "bracketed title", "bracketed body"));
    Doc loaded = docs.findByOwnerId(ownerId).get(0);
    assertThat(loaded.getTitle()).isEqualTo("bracketed title");
  }

  // -- CIPHER-12: an unresolvable subject on a row carrying a shredded value is a refusal -----

  @Test
  void probe_a_moved_blob_is_returned_when_the_subject_source_is_null() throws Exception {
    String aliceId = "owner-alice-null-" + System.nanoTime();
    String bobId = "owner-bob-null-" + System.nanoTime();
    docs.save(new Doc(aliceId, "ALICE-SECRET-TITLE-5", "alice body 5"));
    Doc bob = docs.save(new Doc(bobId, "bob title 5", "bob body 5"));
    Long bobId0 = bob.getId();
    moveColumn("doc", "title", aliceId, bobId);
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("UPDATE doc SET owner_id = NULL WHERE id = ?")) {
      ps.setLong(1, bobId0);
      ps.executeUpdate();
    }
    entityManager.clear();

    assertThatThrownBy(() -> docs.findById(bobId0).orElseThrow())
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_UNRESOLVED));
  }

  /** The other half of the ruling: no shredded value on the row, an unresolvable subject loads. */
  @Test
  void a_row_with_no_shredded_value_loads_despite_an_unresolvable_subject() throws Exception {
    Doc row = docs.save(new Doc("owner-empty-" + System.nanoTime(), null, null));
    Long id = row.getId();
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("UPDATE doc SET owner_id = NULL WHERE id = ?")) {
      ps.setLong(1, id);
      ps.executeUpdate();
    }
    entityManager.clear();

    Doc reloaded = docs.findById(id).orElseThrow();
    assertThat(reloaded.getTitle()).isNull();
    assertThat(reloaded.getBody()).isNull();
  }

  // -- CIPHER-13: a refused, unscoped projection leaves nothing behind on the thread ----------

  @Test
  @Transactional
  void probe_a_projection_leaves_a_stale_decoded_entry_that_breaks_a_later_load() {
    String aliceId = "owner-alice-stale-" + System.nanoTime();
    String carolId = "owner-carol-stale-" + System.nanoTime();
    docs.save(new Doc(aliceId, "alice's real title", "alice's real body"));
    docs.save(new Doc(carolId, null, "carol's body, title never set"));

    assertThatThrownBy(
            () ->
                entityManager
                    .createQuery("select d.title from Doc d where d.ownerId = :id", String.class)
                    .setParameter("id", aliceId)
                    .getSingleResult())
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.READ_UNSCOPED));

    // The refused projection above must not corrupt the next, unrelated load in this transaction.
    Doc carol = docs.findByOwnerId(carolId).get(0);
    assertThat(carol.getTitle()).isNull();
    assertThat(carol.getBody()).isEqualTo("carol's body, title never set");
  }

  // -- CIPHER-14: every shredded column is checked, not only the first --------------------------

  @Test
  void probe_the_update_check_is_skipped_when_the_first_shredded_column_is_null() {
    String victim = "owner-victim-" + System.nanoTime();
    String hijacker = "owner-hijacker-" + System.nanoTime();
    Doc saved = docs.save(new Doc(victim, null, "VICTIM-SECRET-BODY"));
    Long id = saved.getId();

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status -> {
                      Doc loaded = docs.findById(id).orElseThrow();
                      loaded.setOwnerId(hijacker);
                      entityManager.flush();
                    }))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE));
  }

  @Test
  void probe_a_row_escapes_its_subjects_erasure_scope_when_the_first_column_is_null() {
    String victim = "owner-victim2-" + System.nanoTime();
    String hijacker = "owner-hijacker2-" + System.nanoTime();
    Doc saved = docs.save(new Doc(victim, null, "VICTIM-SECRET-BODY-2"));
    Long id = saved.getId();

    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status -> {
                      Doc loaded = docs.findById(id).orElseThrow();
                      loaded.setOwnerId(hijacker);
                      entityManager.flush();
                    }))
        .satisfies(t -> assertThat(shreddingCode(t)).isEqualTo(ErrorCodes.SUBJECT_IMMUTABLE));

    erasures.erase(
        new ErasureRequest(TenantId.of("default"), SubjectId.of(victim), "dpo", "art 17"));
    entityManager.clear();

    Doc afterErasure = docs.findByOwnerId(victim).get(0);
    assertThat(afterErasure.getBody()).isEqualTo(ErasedValue.MARKER);
  }

  // -- CIPHER-16 / QUESTIONS #15: byte[] + IDENTITY (and SEQUENCE) round-trips ------------------

  @Test
  void a_shredded_byte_array_field_round_trips_under_identity() {
    String owner = "owner-blob-identity-" + System.nanoTime();
    byte[] payload = {1, 2, 3, 4, 5, 6, 7, 8};
    Blob saved = blobs.save(new Blob(owner, payload));
    entityManager.clear();

    Blob loaded = blobs.findByOwnerId(owner).get(0);
    assertThat(loaded.getPayload()).isEqualTo(payload);

    erasures.erase(new ErasureRequest(TenantId.of("default"), SubjectId.of(owner), "dpo", "test"));
    entityManager.clear();
    Blob afterErasure = blobs.findByOwnerId(owner).get(0);
    assertThat(afterErasure.getPayload()).isEqualTo(ErasedValue.BYTES_MARKER);
    assertThat(saved.getId()).isNotNull();
  }

  @Test
  void a_shredded_byte_array_field_round_trips_under_sequence() {
    String owner = "owner-blob-sequence-" + System.nanoTime();
    byte[] payload = {9, 8, 7, 6, 5, 4, 3, 2, 1};
    blobSeqs.save(new BlobSeq(owner, payload));
    entityManager.clear();

    BlobSeq loaded = blobSeqs.findByOwnerId(owner).get(0);
    assertThat(loaded.getPayload()).isEqualTo(payload);

    erasures.erase(new ErasureRequest(TenantId.of("default"), SubjectId.of(owner), "dpo", "test"));
    entityManager.clear();
    BlobSeq afterErasure = blobSeqs.findByOwnerId(owner).get(0);
    assertThat(afterErasure.getPayload()).isEqualTo(ErasedValue.BYTES_MARKER);
  }

  /** A minimal constructor-expression DTO, for the CIPHER-11 JPQL {@code new ...(...)} variant. */
  public static final class DocTitle {
    private final String title;

    public DocTitle(String title) {
      this.title = title;
    }

    public String title() {
      return title;
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

  private static String shreddingCode(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }
}
