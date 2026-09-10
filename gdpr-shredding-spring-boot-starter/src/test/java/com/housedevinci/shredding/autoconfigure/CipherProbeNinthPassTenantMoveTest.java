package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.domain.ShreddingException;
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
 * Cipher, ninth pass. Addendum 3 change 7's residual, executed rather than argued: a row whose
 * tenant column is moved by native SQL, then read, then erased under the tenant its key belongs to.
 * What must hold is that the read never yields plaintext under the new tenant, and that the erasure
 * does not silently claim to have destroyed an index it cannot reach.
 */
@SpringBootTest(classes = CipherProbeNinthPassTenantMoveTest.MoveApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeNinthPassTenantMoveTest {

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
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class MoveApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @Autowired OwnedNoteRepository notes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;

  /** A row moved between tenants by native SQL must never read back as plaintext. */
  @Test
  void probe_a_row_moved_by_native_sql_does_not_read_back_as_plaintext() throws Exception {
    String owner = "native-" + System.nanoTime();
    OwnedNote saved = notes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    Long id = saved.getId();
    execute("update owned_note set tenant_id = 'org-c' where owner_id = ?", owner);

    ShreddingException refusal = null;
    try {
      var unused = notes.findById(id).map(OwnedNote::getEmail).orElseThrow();
    } catch (RuntimeException thrown) {
      for (Throwable t = thrown; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          refusal = s;
          break;
        }
      }
    }
    assertThat(refusal)
        .describedAs("the stored header says org-b; the row now says org-c, so the read is refused")
        .isNotNull();
    assertThat(refusal.code()).isEqualTo("SHRED-SUBJECT-MISMATCH");
  }

  /**
   * The erasure of the tenant the key belongs to can no longer reach the row's index. It must not
   * report a clearing it did not do; the count is the honest zero, and the WARN of change 5's
   * second half is the only place this is visible.
   */
  @Test
  void probe_an_erasure_after_a_native_tenant_move_does_not_claim_to_have_cleared_the_index()
      throws Exception {
    String owner = "native2-" + System.nanoTime();
    notes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    execute("update owned_note set tenant_id = 'org-c' where owner_id = ?", owner);

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared())
        .describedAs("no row matched, so nothing may be reported as cleared")
        .isZero();
  }

  private void execute(String sql, String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement(sql)) {
      ps.setString(1, owner);
      ps.executeUpdate();
    }
  }
}
