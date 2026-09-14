package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindextenant.Folder;
import com.housedevinci.shredding.autoconfigure.blindindextenant.FolderRepository;
import com.housedevinci.shredding.domain.BlindIndex;
import com.housedevinci.shredding.domain.ErrorCodes;
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
 * The seventh pass (e2c2bdd), S-7 (HIGH) - closed here for good, on the terms design addendum 3
 * change 4 sets ("On relaxing S-7's startup refusal": agreed, and change 4 is what makes it safe).
 *
 * <p>S-7's own fix was a startup refusal: a {@code @BlindIndex(of = ...)} field could not declare
 * its own {@code @Shredded(tenant = ...)}, because the module could not know at scan time whether
 * that expression's runtime value would ever equal the value in {@code tenantColumn} - the value
 * the erasure matches on. That refusal was a guess made at scan time about every future row, and it
 * cost the S-2 shape (one row, two tenants, one of them indexed) entirely.
 *
 * <p>It is no longer guessed. {@code writeBlindIndexes} refuses the write, per row, when the tenant
 * the of-field's data key is derived under is not the value in the row's tenant column - so the
 * declared shape is allowed exactly when it is erasable, and refused exactly when it is not. {@code
 * Folder} - {@code title} under {@code org-a}, {@code email} under {@code org-b}, indexed, {@code
 * tenantColumn = "tenant_id"} - now boots, and each row's own tenant column decides.
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
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
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
  @Autowired BlindIndex blindIndex;

  /**
   * The shape S-7 refused at startup now boots. That is the point of change 4: the module stops
   * guessing at scan time about rows that do not exist yet.
   */
  @Test
  void a_blind_index_on_a_field_with_its_own_tenant_expression_now_starts_up() {
    assertThat(folders).isNotNull();
  }

  /**
   * A row whose tenant column agrees with the indexed field's declared tenant is written, and one
   * erasure request for that tenant destroys the key, the ciphertext and the index together. The
   * other field of the same row keeps its own tenant and its own key - S-2's shape, working.
   */
  @Test
  void a_row_whose_tenant_column_matches_the_indexed_field_is_written_and_erasable()
      throws Exception {
    String owner = "folder-" + System.nanoTime();
    folders.saveAndFlush(new Folder(owner, "org-b", "a title", "victim@example.test"));

    assertThat(indexBytes(owner))
        .isEqualTo(
            blindIndex.compute(TenantId.of("org-b"), "Folder", "email", "victim@example.test"));

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(indexBytes(owner)).isNull();
  }

  /**
   * S-7's actual finding, now caught per row instead of per mapping: a row whose tenant column
   * holds {@code org-a} while the indexed field's key is derived under {@code org-b} would leave an
   * HMAC of the erased plaintext behind after an erasure for either tenant. Refused at the write,
   * naming both.
   */
  @Test
  void a_row_whose_tenant_column_disagrees_with_the_indexed_field_is_refused() throws Exception {
    String owner = "folder-bad-" + System.nanoTime();

    ShreddingException refusal =
        refusalOf(
            () ->
                folders.saveAndFlush(new Folder(owner, "org-a", "a title", "victim@example.test")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.UNVERIFIED_WRITE);
    assertThat(refusal.getMessage()).contains("org-a").contains("org-b").contains("tenant_id");
    assertThat(indexBytes(owner)).isNull();
  }

  private static ShreddingException refusalOf(Runnable write) {
    try {
      write.run();
    } catch (RuntimeException thrown) {
      for (Throwable t = thrown; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          return s;
        }
      }
      throw new AssertionError("the write failed, but not with a ShreddingException", thrown);
    }
    throw new AssertionError("the write was not refused");
  }

  private byte[] indexBytes(String owner) throws Exception {
    try (var c = dataSource.getConnection();
        var ps = c.prepareStatement("select email_idx from folder where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getBytes(1) : null;
      }
    }
  }
}
