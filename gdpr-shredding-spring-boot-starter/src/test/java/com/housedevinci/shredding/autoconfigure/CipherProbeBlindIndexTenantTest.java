package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.blindindextenant.Folder;
import com.housedevinci.shredding.autoconfigure.blindindextenant.FolderRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, seventh pass (e2c2bdd), S-7 (HIGH). A new surface opened by S-2's fix.
 *
 * <p>S-2 made "two {@code @Shredded} fields of one entity declaring different tenants" a supported
 * shape: {@code writeBlindIndexes} derives an index under {@code scope.tenantFor(of-field)}, that
 * field's <em>declared</em> tenant. The erasure that is supposed to destroy that index does not use
 * the field's declared tenant and cannot: {@code JdbcErasureStore.clearBlindIndexes} issues {@code
 * UPDATE t SET idx = NULL WHERE tenant_col = ? AND subject_col = ?}, matching the row's own {@code
 * tenantColumn} value against the tenant the erasure was asked for.
 *
 * <p>So when a field's declared tenant is not the value in the row's tenant column, the index is
 * keyed under a tenant the erasure will never match: a completed erasure would report success and
 * leave in the table an HMAC of the erased plaintext - a stable correlator across rows and, for a
 * low-entropy plaintext such as an email address, an offline guessing oracle for anyone holding
 * {@code shredding.blind-index.hmac-secret}.
 *
 * <p>The fix is a startup refusal: the module cannot know a tenant column's runtime value at scan
 * time, so it cannot prove such an index will ever be reachable by the erasure meant to destroy it,
 * and refuses to write an index it cannot prove erasable. {@code Folder} - {@code title} declaring
 * {@code #{'org-a'}}, {@code email} declaring {@code #{'org-b'}}, {@code @BlindIndex(of = "email",
 * tenantColumn = "tenant_id")} - never gets far enough to save a row; boot itself is refused with
 * {@code SHRED-CONFIG-001}.
 */
@Testcontainers
class CipherProbeBlindIndexTenantTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Folder.class)
  @EnableJpaRepositories(basePackageClasses = FolderRepository.class)
  static class FolderApp {}

  /**
   * A {@code @BlindIndex(of = ...)} field that declares its own tenant must be refused at boot,
   * naming the entity, the index field, the {@code of} field and its tenant expression - not left
   * to write an index a later erasure can silently fail to reach.
   */
  @Test
  void a_blind_index_on_a_field_with_its_own_tenant_expression_fails_startup() {
    String outcome = startup();
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("Folder").contains("email").contains("emailIndex");
  }

  private String startup() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(FolderApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("starter-integration-master-key32"),
                "shredding.erasure-log.hmac-secret=" + b64("starter-integration-chain-secret"),
                "shredding.blind-index.hmac-secret=" + b64("starter-integration-index-secret"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("BLIND-INDEX-TENANT -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println("BLIND-INDEX-TENANT -> " + outcome);
      return outcome;
    }
  }

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code() + ": " + s.getMessage();
      }
    }
    return thrown.getClass().getSimpleName() + ": " + thrown.getMessage();
  }
}
