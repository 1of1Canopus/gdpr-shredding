package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.camel.CamelSubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.embedded.EmbeddedSubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.identifier.IdentifierSubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.nonstring.NonStringSubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.twoproperty.TwoPropertySubjectNote;
import com.housedevinci.shredding.autoconfigure.blindindexsubjectcolumn.unmapped.UnmappedSubjectNote;
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
 * Design addendum 3, change 8 (§3.8a): the startup half of S-20. {@code @BlindIndex(subjectColumn =
 * ...)} is resolved to a property through the entity's own column mapping, by the same method and
 * under the same rules as {@code tenantColumn} - one probe per refusal branch, plus the camel-case
 * configuration that must still boot. Before change 8, every one of these applications started and
 * wrote an index whose {@code subjectColumn} nobody had ever looked at.
 */
@Testcontainers
class CipherProbeBlindIndexSubjectColumnStartupTest {

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
  @EntityScan(basePackageClasses = CamelSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = CamelSubjectNote.class)
  static class CamelApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = UnmappedSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = UnmappedSubjectNote.class)
  static class UnmappedApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TwoPropertySubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = TwoPropertySubjectNote.class)
  static class TwoPropertyApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = NonStringSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = NonStringSubjectNote.class)
  static class NonStringApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = EmbeddedSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = EmbeddedSubjectNote.class)
  static class EmbeddedApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = IdentifierSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = IdentifierSubjectNote.class)
  static class IdentifierApp {}

  /** The ordinary correct configuration: a column name over a camel-case property. It must boot. */
  @Test
  void probe_a_subject_column_over_a_camel_case_property_starts_up() {
    assertThat(startup(CamelApp.class)).isEqualTo("STARTED");
  }

  /** {@code subjectColumn} given the property name instead of the column name. */
  @Test
  void probe_a_subject_column_naming_a_property_is_refused() {
    String outcome = startup(UnmappedApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("UnmappedSubjectNote")
        .contains("emailIndex")
        .contains("customerref")
        .contains("column name, not a property name");
  }

  /** Two properties over one column: no single value to compare the subject with. */
  @Test
  void probe_a_subject_column_mapped_by_two_properties_is_refused() {
    String outcome = startup(TwoPropertyApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("TwoPropertySubjectNote")
        .contains("customerRef")
        .contains("customerRefReadOnly");
  }

  /** A subject column that is not a {@code String} cannot be compared with a {@code SubjectId}. */
  @Test
  void probe_a_non_string_subject_column_is_refused() {
    String outcome = startup(NonStringApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("NonStringSubjectNote").contains("java.lang.Long");
  }

  /** A subject column mapped only inside an {@code @Embeddable} is not in the state array. */
  @Test
  void probe_a_subject_column_inside_an_embeddable_is_refused() {
    String outcome = startup(EmbeddedApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("EmbeddedSubjectNote").contains("@Embeddable");
  }

  /**
   * §3.8a's decision, made visible: the identifier as {@code subjectColumn} is refused, and the
   * message says what to do instead rather than leaving the developer to infer it.
   */
  @Test
  void probe_the_identifier_as_subject_column_is_refused_with_its_reason() {
    String outcome = startup(IdentifierApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("IdentifierSubjectNote")
        .contains("identifier")
        .contains("state array");
  }

  private String startup(Class<?> app) {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(app)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("subjectcolumn-master-key-32-byte"),
                "shredding.erasure-log.hmac-secret=" + b64("subjectcolumn-chain-secret-32byt"),
                "shredding.blind-index.hmac-secret=" + b64("subjectcolumn-index-secret-32byt"),
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
