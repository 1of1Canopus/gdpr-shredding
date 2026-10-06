package com.housedevinci.shredding.cipherrc2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.autoconfigure.ShreddingEventListener;
import com.housedevinci.shredding.cipherrc2.order.RcOrderNote;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Release-candidate pass 2 (0.2.0, head 333a4a1), finding RC2-1. The upgrade guide promises a 0.1.x
 * installation with Envers "meets these refusals in this order, one per startup", and puts "a
 * schema-less mapping" under {@code SHRED-SCHEMA-009} at position 4, after the audited blind index
 * at position 2. Executed on the shape a running 0.1.1 install has (ciphertext {@code @NotAudited},
 * Envers composed, blind index audited, no schema), the first refusal is {@code SHRED-CONFIG-001}
 * for the missing schema, ahead of the audited blind index.
 */
@Testcontainers
class CipherProbeRc2UpgradeOrderTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcOrderNote.class)
  static class OrderApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    @Bean
    @org.springframework.core.annotation.Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE)
    org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer enversFirst() {
      return props ->
          props.put(
              org.hibernate.jpa.boot.spi.JpaSettings.INTEGRATOR_PROVIDER,
              (org.hibernate.jpa.boot.spi.IntegratorProvider)
                  () ->
                      java.util.List.of(
                          new com.housedevinci.shredding.cipherrc.aud3.EnversFirstIntegrator()));
    }
  }

  /** Green: what the code does. The schema refusal comes first. */
  @Test
  void rc2_first_refusal_of_a_0_1_1_envers_shape_is_the_missing_schema() {
    Throwable t =
        catchThrowable(
            () ->
                new SpringApplicationBuilder(OrderApp.class)
                    .web(WebApplicationType.NONE)
                    .run(args())
                    .close());
    assertThat(rootMessage(t)).contains("SHRED-CONFIG-001").contains("names no schema");
  }

  /** RED on 333a4a1: the guide's order puts the schema-less mapping at position 4, as -009. */
  @Test
  void probe_upgrade_guide_orders_the_schema_less_mapping_after_the_audited_blind_index()
      throws Exception {
    String order = enversOrderParagraph();
    assertThat(order)
        .as("the schema-less mapping is SHRED-CONFIG-001 and is refused before the mapping's -010")
        .doesNotContain("SHRED-SCHEMA-009` from mapping admission (a schema-less mapping");
  }

  /**
   * RED on 333a4a1: positions 1 and 3 cannot be met by a running 0.1.x install. Repro outside the
   * suite (0.1.1 from Central, PostgreSQL 16, see the pass 2 review): 0.1.1 refuses an audited
   * {@code @Shredded} field ("Patient_AUD.email is mapped by ... but has no field-level
   * {@code @Shredded}") and Envers' auto-registered listener ("this module's listener is registered
   * on post-insert but is not last"), both SHRED-CONFIG-001, so no 0.1.1 install that runs has
   * either shape.
   */
  @Test
  void probe_upgrade_guide_promises_refusals_a_running_0_1_1_install_cannot_meet()
      throws Exception {
    String order = enversOrderParagraph();
    assertThat(order)
        .as("a running 0.1.x install already has @NotAudited ciphertext and manual Envers")
        .doesNotContain("1. `SHRED-CONFIG-001`, Envers audits a `@Shredded` field");
  }

  private static String enversOrderParagraph() throws Exception {
    Path guide = Path.of("..", "docs", "upgrading-0.2.0.md");
    String text = Files.readString(guide, StandardCharsets.UTF_8).replaceAll("\\s+", " ");
    int from = text.indexOf("meets these refusals in this order");
    assertThat(from).as("the ordered paragraph").isNotNegative();
    return text.substring(from, Math.min(text.length(), from + 1500));
  }

  private static String rootMessage(Throwable t) {
    StringBuilder all = new StringBuilder();
    for (Throwable c = t; c != null; c = c.getCause()) {
      all.append(c).append('\n');
    }
    return all.toString();
  }

  private static String[] args() {
    return Stream.of(
            "shredding.master-key=" + b64("rc2-order-probe-master-key-32-by"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("rc2-order-probe-chain-secret-32b"),
            "shredding.blind-index.hmac-secret=" + b64("rc2-order-probe-index-secret-32b"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.properties.hibernate.envers.autoRegisterListeners=false",
            // the sample's application.yml sets default_schema; a 0.1.1 install had none
            "spring.jpa.properties.hibernate.default_schema=",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
            "spring.autoconfigure.exclude="
                + "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration")
        .map(a -> "--" + a)
        .toArray(String[]::new);
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.US_ASCII));
  }
}
