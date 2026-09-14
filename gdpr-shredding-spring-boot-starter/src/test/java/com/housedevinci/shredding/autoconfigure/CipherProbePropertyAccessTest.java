package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.propaccess.PropWidget;
import com.housedevinci.shredding.autoconfigure.propaccess.PropWidgetRepository;
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
 * The sixth pass. {@code @Access(AccessType.PROPERTY)} moves the mapping to the getters and JPA
 * then ignores the annotations on the fields - the {@code @Convert} among them. The startup scan
 * reads {@code @Shredded} and {@code @Convert} off the <em>field</em> and accepts the mapping; the
 * C-19 reverse check walks the metamodel for attributes whose resolved converter is a {@code
 * ShreddedConverter} and finds none, because under property access there is none. The application
 * starts with a {@code @Shredded} column that is a plain varchar and no converter on it.
 *
 * <p>What saves it is the post-hoc header check (item 14): the first insert writes plaintext, the
 * read-back cannot decode it and the flush aborts with {@code SHRED-FORMAT-001}, so nothing is
 * committed in the clear. That is fail-closed but it is discovered on the first write in
 * production, with a message about the {@code SH1} magic that names neither the field nor the
 * mapping - where every other mapping this module cannot protect (composite id,
 * {@code @SecondaryTable} split, {@code byte[]} without {@code @Immutable}, {@code @NaturalId},
 * {@code OptimisticLockType.ALL}) is refused at startup, naming the field.
 */
@Testcontainers
class CipherProbePropertyAccessTest {

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
  @EntityScan(basePackageClasses = PropWidget.class)
  @EnableJpaRepositories(basePackageClasses = PropWidgetRepository.class)
  static class PropApp {}

  /**
   * The mapping must be refused at boot, naming the field, the same as every other mapping whose
   * shredded column this module cannot actually protect.
   */
  @Test
  void probe_a_property_access_shredded_field_is_refused_at_startup() {
    String outcome = startup();
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("PropWidget").contains("name");
  }

  private String startup() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(PropApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("propaccess-master-key-32-bytes!!"),
                "shredding.erasure-log.hmac-secret=" + b64("propaccess-chain-secret-32bytes!"),
                "shredding.blind-index.hmac-secret=" + b64("propaccess-index-secret-32bytes!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("PROPERTY-ACCESS -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println("PROPERTY-ACCESS -> " + outcome);
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
