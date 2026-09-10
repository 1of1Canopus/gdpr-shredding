package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.Note;
import com.housedevinci.shredding.autoconfigure.blindindexambient.NoteRepository;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.sql.DataSource;
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
 * Cipher, eighth pass (fa6f477). S-7b, the general case of S-7, which the seventh pass's startup
 * refusal does not reach.
 *
 * <p>The property design addendum 3 states: <em>every blind index value that exists is reachable
 * and destroyed by the erasure of the subject it was derived for.</em> {@code writeBlindIndexes}
 * derives under {@code Scope.tenantFor(of-field)} - here, no field declaring a tenant, the ambient
 * {@code TenantSupplier} - while {@code JdbcErasureStore.clearBlindIndexes} issues {@code UPDATE
 * ambient_note SET email_idx = NULL WHERE tenant_id = ? AND owner_id = ?}, matching the row's own
 * stored column value. When the two differ - a tenant column holding the owning company while the
 * supplier yields the acting organisation - the erasure destroys the data key, kills the
 * ciphertext, reports success, and leaves {@code HMAC(secret, org-a | Note | email | plaintext)} in
 * the table: a stable cross-row correlator for the erased subject and, for a low-entropy value such
 * as an email address, a confirmation oracle for anyone holding the index secret.
 *
 * <p>No field of {@code Note} declares a tenant expression, so {@code ShreddedModel}'s S-7 check
 * has nothing to refuse and the application boots.
 */
@SpringBootTest(classes = CipherProbeBlindIndexAmbientTenantTest.NoteApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBlindIndexAmbientTenantTest {

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
  @EntityScan(basePackageClasses = Note.class)
  @EnableJpaRepositories(basePackageClasses = NoteRepository.class)
  static class NoteApp {
    /** The acting organisation. The row's own tenant column holds the owning one. */
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @Autowired NoteRepository notes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;
  @Autowired BlindIndex blindIndex;

  @Test
  void probe_a_blind_index_under_the_ambient_tenant_survives_that_subjects_erasure()
      throws Exception {
    String owner = "note-" + System.nanoTime();
    notes.saveAndFlush(new Note(owner, "org-b", "victim@example.test"));

    byte[] before = indexBytes(owner);
    assertThat(before).isNotNull();

    erasures.erase(new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

    byte[] after = indexBytes(owner);
    assertThat(after)
        .describedAs(
            "the blind index of an erased subject's email, still in the table and still equal to"
                + " HMAC(secret, org-a | Note | email | victim@example.test)")
        .isNull();
  }

  /**
   * The surviving bytes are the HMAC of the erased plaintext, not an opaque leftover: recomputing
   * the index under the same secret reproduces them exactly. Green today, and it must stay green
   * before the erasure and become unreachable after it - it is stated here so the fix cannot be
   * "write something else into the column".
   */
  @Test
  void probe_the_index_bytes_are_the_hmac_of_the_plaintext() {
    String owner = "note-" + System.nanoTime();
    notes.saveAndFlush(new Note(owner, "org-b", "victim@example.test"));

    byte[] recomputed =
        blindIndex.compute(TenantId.of("org-a"), "Note", "email", "victim@example.test");
    assertThat(indexBytesQuietly(owner)).isEqualTo(recomputed);
  }

  private byte[] indexBytes(String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("select email_idx from ambient_note where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        return rs.getBytes(1);
      }
    }
  }

  private byte[] indexBytesQuietly(String owner) {
    try {
      return indexBytes(owner);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
