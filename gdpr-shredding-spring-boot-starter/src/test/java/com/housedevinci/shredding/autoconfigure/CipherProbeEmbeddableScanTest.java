package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.embed.Vault;
import com.housedevinci.shredding.autoconfigure.embed.VaultRepository;
import com.housedevinci.shredding.autoconfigure.embedcollection.VaultWithNotes;
import com.housedevinci.shredding.autoconfigure.embedcollection.VaultWithNotesRepository;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher fourth pass: C-19's reverse metamodel scan against a {@code @Shredded} field declared
 * inside an {@code @Embeddable}. Neither the forward field scan (entity class and superclasses) nor
 * the reverse scan (top-level {@code BasicValuedModelPart} attributes only) can see it.
 */
@Testcontainers
class CipherProbeEmbeddableScanTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Vault.class)
  @EnableJpaRepositories(basePackageClasses = VaultRepository.class)
  static class VaultApp {}

  @Test
  void probe_a_shredded_field_inside_an_embeddable() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(VaultApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("embeddable-master-key-32-bytes!!"),
                "shredding.erasure-log.hmac-secret=" + b64("embeddable-chain-secret-32bytes!"),
                "shredding.blind-index.hmac-secret=" + b64("embeddable-index-secret-32bytes!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());

    String startup;
    try (var ctx = builder.run()) {
      startup = "STARTED";
      var vaults = ctx.getBean(VaultRepository.class);
      var tx = ctx.getBean(TransactionTemplate.class);
      String owner = "vault-owner-" + System.nanoTime();
      String write;
      try {
        tx.executeWithoutResult(s -> vaults.save(new Vault(owner, "LABEL", "TOKEN-SECRET")));
        write = "WROTE";
      } catch (RuntimeException e) {
        write = "WRITE-REFUSED " + code(e);
      }
      String read;
      try {
        read =
            "READ "
                + tx.execute(
                    s ->
                        vaults.findByOwnerId(owner).stream()
                            .map(v -> v.getSecrets().getToken())
                            .toList()
                            .toString());
      } catch (RuntimeException e) {
        read = "READ-REFUSED " + code(e);
      }
      System.out.println("EMBED -> " + startup + " / " + write + " / " + read);
    } catch (RuntimeException e) {
      System.out.println("EMBED -> STARTUP-REFUSED " + code(e) + ": " + e.getMessage());
      startup = "STARTUP-REFUSED";
    }
    assertThat(startup).isEqualTo("STARTUP-REFUSED");
  }

  /**
   * Dollar's mandated companion probe: the same defect through an {@code @ElementCollection} of an
   * {@code @Embeddable} instead of a plain {@code @Embedded} singular component - {@code
   * refuseUnmodelledShreddedConverters} has to recurse through a {@code PluralAttributeMapping}
   * whose element descriptor is itself embeddable-valued, not just an {@code
   * EmbeddableValuedModelPart} directly on the entity.
   */
  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = VaultWithNotes.class)
  @EnableJpaRepositories(basePackageClasses = VaultWithNotesRepository.class)
  static class VaultNotesApp {}

  @Test
  void probe_a_shredded_field_inside_an_element_collection_of_embeddables() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(VaultNotesApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("embeddable-master-key-32-bytes!!"),
                "shredding.erasure-log.hmac-secret=" + b64("embeddable-chain-secret-32bytes!"),
                "shredding.blind-index.hmac-secret=" + b64("embeddable-index-secret-32bytes!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());

    String startup;
    try (var ctx = builder.run()) {
      startup = "STARTED";
      System.out.println("EMBED-COLLECTION -> STARTED (should not happen)");
    } catch (RuntimeException e) {
      System.out.println("EMBED-COLLECTION -> STARTUP-REFUSED " + code(e) + ": " + e.getMessage());
      startup = "STARTUP-REFUSED";
    }
    assertThat(startup).isEqualTo("STARTUP-REFUSED");
  }

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    return thrown.getClass().getSimpleName();
  }
}
