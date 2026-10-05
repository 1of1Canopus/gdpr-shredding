package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureResult;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
 * Release-candidate whole-module pass, 0.2.0, lead 5: every weaker mode is an explicit property
 * that WARNs at every startup, and a property that would make the proof of erasure state something
 * false is refused.
 */
@Testcontainers
class CipherProbeRc020StartupTest {

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
   * Confirmation, not a finding: each weaker mode, switched on alone on top of the harness's two
   * jdbc modes, prints a WARN naming its property. Run twice per mode to show "every startup".
   */
  @ParameterizedTest
  @CsvSource({
    "shredding.dev-mode=true, shredding.dev-mode=true",
    "shredding.allow-second-level-cache=true, shredding.allow-second-level-cache=true",
    "shredding.erased-value.policy=null, shredding.erased-value.policy=null",
    "shredding.jdbc.initialize-schema=true, shredding.jdbc.initialize-schema=true",
    "shredding.jdbc.allow-privileged-runtime-role=true,"
        + " shredding.jdbc.allow-privileged-runtime-role=true",
  })
  void rc_each_weaker_mode_warns_at_every_startup(String property, String expected) {
    for (int boot = 0; boot < 2; boot++) {
      events.list.clear();
      try (var ctx = builder(property).run(args(property))) {
        assertThat(warnsContaining(expected)).describedAs("boot %d, %s", boot, property).isTrue();
      }
    }
  }

  @Test
  void rc_unkeyed_erasure_log_warns_at_every_startup() {
    String[] extra = {
      "shredding.erasure-log.unkeyed=true",
      "shredding.subject-pseudonym.pepper=" + b64("rc-startup-probe-pepper-32-bytes")
    };
    for (int boot = 0; boot < 2; boot++) {
      events.list.clear();
      try (var ctx = builder(null).run(argsWithout("shredding.erasure-log.hmac-secret", extra))) {
        assertThat(warnsContaining("shredding.erasure-log.unkeyed=true")).isTrue();
      }
    }
  }

  /**
   * RC-0.2.0-5. {@code shredding.erasure.backup-retention} is the one number the proof of erasure
   * prints as "complete in backups on". A negative value boots without a word and every erasure
   * record then states that backups were clear before the erasure happened.
   */
  @Test
  void probe_negative_backup_retention_boots_and_records_backups_clear_before_the_erasure() {
    Throwable thrown =
        catchThrowable(
            () -> {
              try (var ctx = builder(null).run(args("shredding.erasure.backup-retention=-30d"))) {
                persistNote(ctx);
                ErasureResult result =
                    ctx.getBean(ErasureService.class)
                        .erase(
                            new ErasureRequest(
                                TenantId.of("org-b"), SubjectId.of("rc5"), "dpo", "art 17"));
                System.out.println(
                    "CIPHER-RC backup retention: erasedAt="
                        + result.records().get(0).timestamp()
                        + " backupsClearAt="
                        + result.completeInBackupsAt());
                assertThat(result.completeInBackupsAt())
                    .describedAs("the proof's backup date must not precede the erasure")
                    .isAfterOrEqualTo(result.records().get(0).timestamp());
              }
            });
    // Secure outcome: startup refuses the property, naming it.
    assertThat(thrown).isNotNull();
    assertThat(String.valueOf(rootMessage(thrown))).contains("shredding.erasure.backup-retention");
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

  private boolean warnsContaining(String text) {
    return events.list.stream()
        .anyMatch(e -> e.getLevel() == Level.WARN && e.getFormattedMessage().contains(text));
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
