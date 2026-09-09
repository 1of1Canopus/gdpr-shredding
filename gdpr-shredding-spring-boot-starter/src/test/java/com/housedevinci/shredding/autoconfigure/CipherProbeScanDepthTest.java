package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.elemcoll.TagBag;
import com.housedevinci.shredding.autoconfigure.elemcoll.TagBagRepository;
import com.housedevinci.shredding.autoconfigure.mapkey.KeyedNotes;
import com.housedevinci.shredding.autoconfigure.mapkey.KeyedNotesRepository;
import com.housedevinci.shredding.autoconfigure.nested.DeepVault;
import com.housedevinci.shredding.autoconfigure.nested.DeepVaultRepository;
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
 * Cipher fifth pass: how deep C-29's reverse metamodel scan actually goes. {@code
 * CipherProbeEmbeddableScanTest} covers one level of {@code @Embedded} and an {@code
 * @ElementCollection} of {@code @Embeddable}s. These three go one step past each of those.
 */
@Testcontainers
class CipherProbeScanDepthTest {

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
  @EntityScan(basePackageClasses = DeepVault.class)
  @EnableJpaRepositories(basePackageClasses = DeepVaultRepository.class)
  static class DeepApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TagBag.class)
  @EnableJpaRepositories(basePackageClasses = TagBagRepository.class)
  static class TagApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = KeyedNotes.class)
  @EnableJpaRepositories(basePackageClasses = KeyedNotesRepository.class)
  static class MapKeyApp {}

  /** Two levels of {@code @Embeddable}. */
  @Test
  void probe_a_shredded_field_two_embeddables_deep_is_refused_at_startup() {
    assertThat(startup(DeepApp.class, "deep")).isEqualTo("STARTUP-REFUSED");
  }

  /** An {@code @ElementCollection} of basic values, converter on the element itself. */
  @Test
  void probe_a_shredded_element_collection_of_basic_values_is_refused_at_startup() {
    assertThat(startup(TagApp.class, "tag")).isEqualTo("STARTUP-REFUSED");
  }

  /**
   * The converter on the map <em>key</em> of an {@code @ElementCollection}. {@code scanAttribute}
   * walks {@code PluralAttributeMapping.getElementDescriptor()} and never {@code
   * getIndexDescriptor()}.
   */
  @Test
  void probe_a_shredded_map_key_in_an_element_collection_is_refused_at_startup() {
    assertThat(startup(MapKeyApp.class, "mapkey")).isEqualTo("STARTUP-REFUSED");
  }

  /** What the unrefused mapping actually does at runtime, once it has been allowed to start. */
  @Test
  void probe_what_an_unrefused_shredded_map_key_does_at_runtime() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(MapKeyApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("scandepth-master-key-32-bytes!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("scandepth-chain-secret-32bytes!!"),
                "shredding.blind-index.hmac-secret=" + b64("scandepth-index-secret-32bytes!!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      var repo = ctx.getBean(KeyedNotesRepository.class);
      var tx = ctx.getBean(org.springframework.transaction.support.TransactionTemplate.class);
      String owner = "mapkey-owner-" + System.nanoTime();
      String write;
      Long id = null;
      try {
        id =
            tx.execute(s -> repo.save(new KeyedNotes(owner, "MAPKEY-SECRET", "value")).getId());
        write = "WROTE";
      } catch (RuntimeException e) {
        write = "WRITE-REFUSED " + code(e);
      }
      String read = "SKIPPED";
      if (id != null) {
        Long theId = id;
        try {
          read =
              "READ "
                  + tx.execute(s -> repo.findById(theId).map(n -> n.getNotes().toString()).orElse("<none>"));
        } catch (RuntimeException e) {
          read = "READ-REFUSED " + code(e);
        }
      }
      System.out.println("SCAN-DEPTH mapkey runtime -> " + write + " / " + read);
    } catch (RuntimeException e) {
      System.out.println("SCAN-DEPTH mapkey runtime -> CONTEXT-FAILED " + code(e));
    }
  }

  private String startup(Class<?> app, String tag) {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(app)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("scandepth-master-key-32-bytes!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("scandepth-chain-secret-32bytes!!"),
                "shredding.blind-index.hmac-secret=" + b64("scandepth-index-secret-32bytes!!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("SCAN-DEPTH " + tag + " -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      System.out.println("SCAN-DEPTH " + tag + " -> STARTUP-REFUSED " + code(e));
      return "STARTUP-REFUSED";
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
