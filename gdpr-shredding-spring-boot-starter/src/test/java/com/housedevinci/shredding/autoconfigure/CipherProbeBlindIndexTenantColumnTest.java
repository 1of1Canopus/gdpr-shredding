package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.blindindexcolumn.camel.CamelTenantNote;
import com.housedevinci.shredding.autoconfigure.blindindexcolumn.embedded.EmbeddedTenantNote;
import com.housedevinci.shredding.autoconfigure.blindindexcolumn.nonstring.NonStringTenantNote;
import com.housedevinci.shredding.autoconfigure.blindindexcolumn.twoproperty.TwoPropertyTenantNote;
import com.housedevinci.shredding.autoconfigure.blindindexcolumn.unmapped.UnmappedTenantNote;
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
 * Design addendum 3, change 1 (applied §3.1): {@code @BlindIndex(tenantColumn = ...)} is a
 * <em>column</em> name, not a property name.
 *
 * <p>The addendum's own recommendation - "refuse at startup when {@code tenantColumn} is not a
 * mapped basic {@code String} property" - read the annotation's value in the wrong namespace: the
 * erasure's {@code UPDATE ... WHERE tenant_id = ?} matches on a column, while the state array the
 * write path reads and {@code EntityPersister.getPropertyNames()} are keyed by property names.
 * Taken literally it would either refuse every correct configuration (first probe) or miss and
 * derive the index under something unstated. The column is therefore resolved to a property through
 * the entity's own column mapping, once, at startup, and the resolution must yield exactly one
 * property that is basic, {@code String}-typed, on the entity's primary table and not inside a
 * component - every other outcome is a startup refusal naming the entity, the index field, {@code
 * tenantColumn} and what was found.
 */
@Testcontainers
class CipherProbeBlindIndexTenantColumnTest {

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
  @EntityScan(basePackageClasses = CamelTenantNote.class)
  @EnableJpaRepositories(basePackageClasses = CamelTenantNote.class)
  static class CamelApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = UnmappedTenantNote.class)
  @EnableJpaRepositories(basePackageClasses = UnmappedTenantNote.class)
  static class UnmappedApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TwoPropertyTenantNote.class)
  @EnableJpaRepositories(basePackageClasses = TwoPropertyTenantNote.class)
  static class TwoPropertyApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = NonStringTenantNote.class)
  @EnableJpaRepositories(basePackageClasses = NonStringTenantNote.class)
  static class NonStringApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = EmbeddedTenantNote.class)
  @EnableJpaRepositories(basePackageClasses = EmbeddedTenantNote.class)
  static class EmbeddedApp {}

  /**
   * The regression change 1 exists to prevent. {@code tenantColumn = "tenant_id"} over a property
   * called {@code tenantId} with no {@code @Column} of its own is the ordinary correct
   * configuration; it must boot.
   */
  @Test
  void probe_a_column_name_over_a_camel_case_property_starts_up() {
    assertThat(startup(CamelApp.class)).isEqualTo("STARTED");
  }

  /** {@code tenantColumn} given the property name instead of the column name. */
  @Test
  void probe_a_tenant_column_naming_a_property_is_refused() {
    String outcome = startup(UnmappedApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("UnmappedTenantNote")
        .contains("emailIndex")
        .contains("tenantid")
        .contains("column name, not a property name");
  }

  /** Two properties over one column: no single value to derive the index under. */
  @Test
  void probe_a_tenant_column_mapped_by_two_properties_is_refused() {
    String outcome = startup(TwoPropertyApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("TwoPropertyTenantNote")
        .contains("tenantId")
        .contains("tenantIdReadOnly");
  }

  /** A tenant column that is not a {@code String} cannot be compared with a {@code TenantId}. */
  @Test
  void probe_a_non_string_tenant_column_is_refused() {
    String outcome = startup(NonStringApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("NonStringTenantNote").contains("java.lang.Long");
  }

  /** A tenant column mapped only inside an {@code @Embeddable} is not in the state array. */
  @Test
  void probe_a_tenant_column_inside_an_embeddable_is_refused() {
    String outcome = startup(EmbeddedApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("EmbeddedTenantNote").contains("@Embeddable");
  }

  private String startup(Class<?> app) {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(app)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("tenantcolumn-master-key-32-byte!"),
                "shredding.erasure-log.hmac-secret=" + b64("tenantcolumn-chain-secret-32byte"),
                "shredding.blind-index.hmac-secret=" + b64("tenantcolumn-index-secret-32byte"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println(app.getSimpleName() + " -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println(app.getSimpleName() + " -> " + outcome);
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
