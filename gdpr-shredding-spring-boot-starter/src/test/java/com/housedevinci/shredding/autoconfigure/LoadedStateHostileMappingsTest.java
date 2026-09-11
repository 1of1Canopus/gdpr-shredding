package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.hostile.alllock.AllColumnLock;
import com.housedevinci.shredding.autoconfigure.hostile.embeddedid.EmbeddedIdRow;
import com.housedevinci.shredding.autoconfigure.hostile.naturalid.NaturalIdRow;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Design §2 rows 13 and 14, finding items 7 and 10 (decision D4). {@code onPostLoad} installs the
 * verified plaintext into the entity <em>and</em> into the persistence context's loaded state, and
 * a handful of Hibernate mappings make that unsound. Each is refused at startup, naming what to
 * change, rather than discovered as a row that can never be updated or a natural id that never
 * resolves.
 *
 * <p>Every check is read off the <em>runtime persister</em>, not off the annotation:
 * {@code @SelectBeforeUpdate} does not exist as an annotation in Hibernate 7 at all, and optimistic
 * locking and natural ids can both arrive through {@code orm.xml} or a mapped superclass. One test
 * per mapping, each with its own context, because a context that refuses to start cannot be shared.
 */
@Testcontainers
class LoadedStateHostileMappingsTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @Test
  void an_all_column_optimistic_lock_is_refused_at_startup() {
    String outcome = startup(AllColumnLockApp.class);

    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("AllColumnLock").contains("optimistic locking");
  }

  @Test
  void a_shredded_natural_id_is_refused_at_startup() {
    String outcome = startup(NaturalIdApp.class);

    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("NaturalIdRow").contains("natural id");
  }

  /** finding item 7: single-column, so C-38's column count check waves it through. */
  @Test
  void a_single_column_embedded_id_is_refused_at_startup() {
    String outcome = startup(EmbeddedIdApp.class);

    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("EmbeddedIdRow").contains("not a basic value");
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = AllColumnLock.class)
  static class AllColumnLockApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = NaturalIdRow.class)
  static class NaturalIdApp {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = EmbeddedIdRow.class)
  static class EmbeddedIdApp {}

  private String startup(Class<?> app) {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(app)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("hostile-master-key-32-bytes-long"),
                "shredding.erasure-log.hmac-secret=" + b64("hostile-chain-secret-32-bytes-x!"),
                "shredding.blind-index.hmac-secret=" + b64("hostile-index-secret-32-bytes-x!"),
                // Nothing but the entity under test: this module's test sources declare several
                // repositories with colliding bean names, and none of them is what is being probed.
                "spring.data.jpa.repositories.enabled=false",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("HOSTILE " + app.getSimpleName() + " -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println("HOSTILE " + app.getSimpleName() + " -> " + outcome);
      return outcome;
    }
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
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
