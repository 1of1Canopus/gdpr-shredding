package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
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
              .asCompatibleSubstituteFor("postgres"));

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
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class TestApp {}

  @Autowired WidgetRepository widgets;
  @Autowired GadgetRepository gadgets;
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

  private static String shreddingCode(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }
}
