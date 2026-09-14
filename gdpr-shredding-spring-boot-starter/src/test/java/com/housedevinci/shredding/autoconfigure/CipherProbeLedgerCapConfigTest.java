package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
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
 * The eighth pass (fa6f477). S-16 (INFO). {@code shredding.write-verification.max-outstanding} is
 * read once at boot into a {@code static volatile int} and never checked.
 *
 * <p>{@code 0} makes {@code ledger.debts.size() >= maxOutstanding} true before the first debt, so
 * every write of a {@code @Shredded} entity in the application is refused with {@code
 * SHRED-UNVERIFIED-WRITE} - at the first write, in production, with a message that reports the cap
 * as {@code 0} and blames a {@code StatelessSession} import. {@code -1} behaves the same. This is
 * the shape the module's own definition of done rules out: "misconfiguration fails fast at startup
 * with a message naming the property".
 */
@Testcontainers
class CipherProbeLedgerCapConfigTest {

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
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class CapApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("default");
    }
  }

  @Test
  void probe_a_ledger_cap_of_zero_is_refused_at_startup() {
    assertThat(startupWith("0")).startsWith("STARTUP-REFUSED");
  }

  @Test
  void probe_a_negative_ledger_cap_is_refused_at_startup() {
    assertThat(startupWith("-1")).startsWith("STARTUP-REFUSED");
  }

  private String startupWith(String cap) {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(CapApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("starter-integration-master-key32"),
                "shredding.erasure-log.hmac-secret=" + b64("starter-integration-chain-secret"),
                "shredding.blind-index.hmac-secret=" + b64("starter-integration-index-secret"),
                "shredding.write-verification.max-outstanding=" + cap,
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      return "STARTED";
    } catch (RuntimeException e) {
      for (Throwable t = e; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          return "STARTUP-REFUSED " + s.code() + ": " + s.getMessage();
        }
      }
      return "STARTUP-REFUSED " + e;
    }
  }
}
