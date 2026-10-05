package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Release-candidate review 0.2.0, pass 2 (PR 21): the RC-5 fix refuses a negative backup retention
 * but has no upper bound. A positive retention the proof of erasure cannot date boots cleanly and
 * then refuses every erasure, with no code naming the property.
 */
@Testcontainers
class CipherProbeRc020Pass2Test {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class PlainApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  private final ListAppender<ILoggingEvent> events = new ListAppender<>();

  private void capture() {
    events.start();
    ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
        .addAppender(events);
  }

  @AfterEach
  void detach() {
    ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
        .detachAppender(events);
  }

  /**
   * RC-9, first half. {@code PT9000000000000H} binds (it fits a {@code Duration}) and is not
   * negative, so startup accepts it; {@code erasedAt + retention} is past {@code Instant.MAX}, so
   * every erasure throws an uncoded {@code DateTimeException} before its first statement.
   */
  @Test
  void probe_backup_retention_past_instant_max_boots_and_every_erasure_fails_uncoded() {
    assertRefusedAtStartup("shredding.erasure.backup-retention=PT9000000000000H");
  }

  /**
   * RC-9, second half. {@code PT3000000000H} (about 342,000 years) is a valid {@code Instant} but
   * past PostgreSQL's {@code timestamptz} range (year 294276), so the record's {@code
   * backup_clear_at} cannot be stored: every erasure rolls back and is reported as a key-store
   * outage.
   */
  @Test
  void probe_backup_retention_past_the_database_range_boots_and_erasure_reports_key_store_outage() {
    assertRefusedAtStartup("shredding.erasure.backup-retention=PT3000000000H");
  }

  private void assertRefusedAtStartup(String property) {
    Throwable thrown =
        catchThrowable(
            () -> {
              try (var ctx = builder(null).run(args(property))) {
                persistNote(ctx);
                var result =
                    ctx.getBean(ErasureService.class)
                        .erase(
                            new ErasureRequest(
                                TenantId.of("org-b"), SubjectId.of("rc5"), "dpo", "art 17"));
                throw new AssertionError(
                    "booted and erased, backups clear "
                        + java.time.Duration.between(
                            result.records().get(0).timestamp(), result.completeInBackupsAt())
                        + " after the erasure");
              } catch (RuntimeException | AssertionError e) {
                System.out.println("CIPHER-RC9 " + property + " -> " + chain(e));
                throw e;
              }
            });
    // Secure outcome: startup refuses the property as SHRED-CONFIG-001, naming it.
    assertThat(thrown).isNotNull();
    assertThat(chain(thrown))
        .contains("[SHRED-CONFIG-001]")
        .contains("shredding.erasure.backup-retention");
  }

  private static String chain(Throwable t) {
    StringBuilder all = new StringBuilder();
    for (Throwable c = t; c != null && c.getCause() != c; c = c.getCause()) {
      all.append(c).append(" | ");
    }
    return all.toString();
  }

  // ---------------------------------------------------------------------------------------------

  private static void persistNote(org.springframework.context.ConfigurableApplicationContext ctx) {
    var em = ctx.getBean(jakarta.persistence.EntityManagerFactory.class).createEntityManager();
    try {
      em.getTransaction().begin();
      em.persist(new B2Note("rc5", "org-b", "a@b.test"));
      em.getTransaction().commit();
    } finally {
      em.close();
    }
  }

  private static String rootMessage(Throwable t) {
    StringBuilder all = new StringBuilder();
    for (Throwable c = t; c != null && c.getCause() != c; c = c.getCause()) {
      all.append(c.getMessage()).append(" | ");
    }
    return all.toString();
  }

  private SpringApplicationBuilder builder(String unused) {
    return new SpringApplicationBuilder(PlainApp.class)
        .web(WebApplicationType.NONE)
        .listeners(
            (org.springframework.context.ApplicationListener<
                    org.springframework.boot.context.event.ApplicationPreparedEvent>)
                e -> capture());
  }

  private static List<String> base() {
    return new ArrayList<>(
        List.of(
            "shredding.master-key=" + b64("rc-startup-probe-master-key-32-b"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("rc-startup-probe-chain-secret-32"),
            "shredding.blind-index.hmac-secret=" + b64("rc-startup-probe-index-secret-32"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect"));
  }

  private static String[] args(String... extra) {
    List<String> all = base();
    for (String e : extra) {
      String key = e.substring(0, e.indexOf('=') + 1);
      all.removeIf(a -> a.startsWith(key));
    }
    all.addAll(List.of(extra));
    return all.stream().map(a -> "--" + a).toArray(String[]::new);
  }

  private static String[] argsWithout(String key, String... extra) {
    List<String> all = base();
    all.removeIf(a -> a.startsWith(key + "="));
    all.addAll(List.of(extra));
    return Stream.of(all.toArray(String[]::new)).map(a -> "--" + a).toArray(String[]::new);
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
