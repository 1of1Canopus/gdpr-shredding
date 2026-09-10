package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.seventhpending.Folder;
import com.housedevinci.shredding.autoconfigure.seventhpending.FolderRepository;
import com.housedevinci.shredding.application.ErasureRequest;
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
 * Cipher, seventh pass (e2c2bdd). A new surface opened by S-2's fix.
 *
 * <p>S-2 made "two {@code @Shredded} fields of one entity declaring different tenants" a supported
 * shape: {@code writeBlindIndexes} now derives an index under {@code scope.tenantFor(of-field)},
 * that field's <em>declared</em> tenant. The erasure that is supposed to destroy that index does
 * not use the field's declared tenant and cannot: {@code JdbcErasureStore.clearBlindIndexes} issues
 * {@code UPDATE t SET idx = NULL WHERE tenant_col = ? AND subject_col = ?}, matching the row's own
 * {@code tenantColumn} value against the tenant the erasure was asked for.
 *
 * <p>So when a field's declared tenant is not the value in the row's tenant column, the index is
 * keyed under a tenant the erasure will never match. Erasing {@code (org-b, subject)} destroys the
 * data key, renders the ciphertext unreadable, and reports success - and leaves in the table an
 * HMAC of the erased plaintext under {@code (org-b, Folder, email)}. That HMAC is a stable
 * correlator across rows and, for a low-entropy plaintext such as an email address, an offline
 * guessing oracle for anyone holding {@code shredding.blind-index.hmac-secret}. Destroying it is
 * the entire reason blind-index columns are erased at all, and the proof of erasure the module
 * emits does not say it was skipped.
 *
 * <p>Before S-2 this could not happen: every field of a row was indexed under the ambient tenant,
 * which is the value an application puts in its tenant column. The fix has to close the gap between
 * "the tenant the index is keyed under" and "the tenant the erasure matches on" - the simplest
 * sound form being a startup refusal ({@code SHRED-CONFIG-001}) of a {@code @BlindIndex} whose
 * {@code of} field declares its own {@code tenant} expression, since the module cannot know a
 * column's runtime value at scan time.
 */
@SpringBootTest(classes = CipherProbeBlindIndexTenantTest.FolderApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBlindIndexTenantTest {

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
  @EntityScan(basePackageClasses = Folder.class)
  @EnableJpaRepositories(basePackageClasses = FolderRepository.class)
  static class FolderApp {}

  @Autowired FolderRepository folders;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;

  @Test
  void probe_a_blind_index_under_a_declared_tenant_survives_that_tenants_erasure() throws Exception {
    String owner = "folder-" + System.nanoTime();
    // The row's tenant column holds org-a, the entity's primary tenant. The email field declares
    // org-b, so its ciphertext and its blind index both belong to org-b's erasure scope.
    folders.saveAndFlush(new Folder(owner, "org-a", "TITLE", "victim@example.test"));
    assertThat(indexBytes(owner)).isNotNull();

    erasures.erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

    assertThat(indexBytes(owner))
        .describedAs("the blind index of an erased subject's email still in the table")
        .isNull();
  }

  private byte[] indexBytes(String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("select email_idx from folder where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        assertThat(rs.next()).isTrue();
        return rs.getBytes(1);
      }
    }
  }
}
