package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.twotenant.Dossier;
import com.housedevinci.shredding.autoconfigure.twotenant.DossierRepository;
import com.housedevinci.shredding.domain.EncryptedValue;
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
 * Cipher sixth pass. {@code ShreddingEventListener.scopeFor} and {@code onPostLoad} both take the
 * tenant from {@code fields.get(0).tenant()} - the entity's <em>first</em> shredded field - and
 * apply it to every shredded field of the entity. {@code resolveSubject} cross-checks that the
 * fields agree about the subject and refuses when they do not; nothing cross-checks the tenant, at
 * startup or at runtime.
 *
 * <p>The consequence is not cosmetic. A data key is per {@code (tenant, subject)}, so a field whose
 * declared tenant is silently ignored is encrypted into a different tenant's erasure scope: an
 * erasure carried out for {@code (org-b, subject)} destroys a key this field never used, reports
 * success, and leaves the field readable.
 */
@SpringBootTest(classes = CipherProbeTenantExpressionTest.TestApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeTenantExpressionTest {

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
  @EntityScan(basePackageClasses = Dossier.class)
  @EnableJpaRepositories(basePackageClasses = DossierRepository.class)
  static class TestApp {}

  @Autowired DossierRepository dossiers;
  @Autowired DataSource dataSource;

  /**
   * Either the mapping is refused at startup - the same treatment the disagreeing-subject case gets
   * at runtime - or every field is bound to the tenant it declares. Binding {@code memo} to {@code
   * org-a} because {@code note} happens to be declared first is neither.
   */
  @Test
  void probe_a_second_shredded_field_is_bound_to_the_tenant_it_declares() throws Exception {
    String owner = "two-tenant-" + System.nanoTime();
    Dossier saved = dossiers.saveAndFlush(new Dossier(owner, "NOTE-SECRET", "MEMO-SECRET"));

    String memoTenant;
    try (var connection = dataSource.getConnection();
        var ps = connection.prepareStatement("select memo from dossier where id = ?")) {
      ps.setObject(1, saved.getId());
      try (var rs = ps.executeQuery()) {
        rs.next();
        memoTenant = EncryptedValue.decode(rs.getBytes(1)).tenant().value();
      }
    }
    System.out.println("TWO-TENANT memo bound to tenant -> " + memoTenant);
    assertThat(memoTenant).isEqualTo("org-b");
  }
}
