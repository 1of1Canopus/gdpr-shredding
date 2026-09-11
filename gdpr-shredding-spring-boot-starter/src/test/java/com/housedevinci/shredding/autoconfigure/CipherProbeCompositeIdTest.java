package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.composite.Ticket;
import com.housedevinci.shredding.autoconfigure.composite.TicketRepository;
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
 * The fifth pass, C-38: the composite-identifier residual. Before the fix, a {@code @Shredded}
 * entity with a composite id started up and then could never be read - every load returns before
 * {@code onPostLoad} can drain the frame - which is fail-closed but unusable and discovered on the
 * first read in production instead of at boot. The fix refuses this mapping at startup, alongside
 * the existing {@code @SecondaryTable} refusal, so both probes below now build their own context
 * (in the shape of {@code CipherProbeScanDepthTest}) instead of sharing a class-level
 * {@code @SpringBootTest} context, which can no longer come up at all.
 */
@Testcontainers
class CipherProbeCompositeIdTest {

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
  @EntityScan(basePackageClasses = Ticket.class)
  @EnableJpaRepositories(basePackageClasses = TicketRepository.class)
  static class TicketApp {}

  /**
   * C-38, the primary probe. A {@code @Shredded} entity with a composite id ({@code @IdClass}) must
   * be refused at boot, naming the entity, the same as the {@code @SecondaryTable} split - not
   * discovered when the first legitimate, untampered read of a row it wrote itself comes back
   * refused with {@code SHRED-READ-UNVERIFIED}.
   */
  @Test
  void probe_a_composite_id_shredded_entity_is_refused_at_startup() {
    String outcome = startup();
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("Ticket").contains("composite identifier");
  }

  /**
   * The scenario the fourth-pass residual asked about: a ciphertext moved between two rows of a
   * composite-id entity. It is never displayed - not because a per-row check catches it (the
   * composite id disables that check on both the read and the write path), but because the mapping
   * cannot come up at all once C-38's startup refusal is in place, so there is never a row to move
   * a ciphertext into in the first place.
   */
  @Test
  void probe_a_moved_ciphertext_in_a_composite_id_entity_is_never_displayed() {
    String outcome = startup();
    assertThat(outcome).startsWith("STARTUP-REFUSED");
    assertThat(outcome).doesNotContain("ALICE-COMPOSITE-SECRET");
  }

  private String startup() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(TicketApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("compositeid-master-key-32-bytes!"),
                "shredding.erasure-log.hmac-secret=" + b64("compositeid-chain-secret-32byte!"),
                "shredding.blind-index.hmac-secret=" + b64("compositeid-index-secret-32byte!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("COMPOSITE -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println("COMPOSITE -> " + outcome);
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
