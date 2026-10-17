package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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
 * Security review, PR 41 pass 1 (C-PR-1d fix). Starter side.
 *
 * <p>C-PR41-1: with shredding.jdbc.initialize-schema=false and
 * shredding.jdbc.allow-privileged-runtime-role=true, a privileged login role boots. Before PR 41
 * the starter WARN named the property; after it, core's WARN names the role and legs only, and no
 * starter line names the property that let the role through, nor that setting it back to false (the
 * default) makes the same start refuse.
 */
@Testcontainers
class CipherProbePr41Test {

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

  @AfterEach
  void detach() {
    root().detachAppender(events);
  }

  @Test
  void probe_privileged_mode_startup_never_names_the_property_that_allows_it() {
    // Boot 0 creates the schema (initialize-schema=true), so later boots verify only.
    try (var ctx = builder().run(args(true, true))) {
      assertThat(ctx.isActive()).isTrue();
    }
    // Control: strict mode with the same privileged login refuses, so the property is what lets
    // the next boots through.
    Throwable refused = catchThrowable(() -> builder().run(args(false, false)).close());
    assertThat(String.valueOf(refused))
        .contains("is a superuser")
        .contains("is not one this module");

    for (int boot = 1; boot <= 2; boot++) {
      events.list.clear();
      try (var ctx = builder().run(args(false, true))) {
        List<String> warns =
            events.list.stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("shredding:"))
                .toList();
        assertThat(warns)
            .describedAs("precondition, boot %d: core WARN for the privileged role", boot)
            .anyMatch(m -> m.contains("is privileged over the shredding objects"));
        assertThat(warns)
            .describedAs(
                "C-PR41-1, boot %d: no WARN names shredding.jdbc.allow-privileged-runtime-role",
                boot)
            .anyMatch(m -> m.contains("shredding.jdbc.allow-privileged-runtime-role=true"));
        assertThat(
                warns.stream().filter(m -> m.contains("is privileged over the shredding")).count())
            .describedAs("the core line must not be duplicated by the starter line")
            .isEqualTo(1);
      }
    }
  }

  private static ch.qos.logback.classic.Logger root() {
    return (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
  }

  private SpringApplicationBuilder builder() {
    return new SpringApplicationBuilder(PlainApp.class)
        .web(WebApplicationType.NONE)
        .listeners(
            (org.springframework.context.ApplicationListener<
                    org.springframework.boot.context.event.ApplicationPreparedEvent>)
                e -> {
                  events.start();
                  root().addAppender(events);
                });
  }

  private static String[] args(boolean initialize, boolean allowPrivileged) {
    List<String> all =
        new ArrayList<>(
            List.of(
                "shredding.master-key=" + b64("pr41-startup-probe-master-key-32"),
                "shredding.jdbc.initialize-schema=" + initialize,
                "shredding.jdbc.allow-privileged-runtime-role=" + allowPrivileged,
                "shredding.erasure-log.hmac-secret=" + b64("pr41-startup-probe-chain-secre32"),
                "shredding.blind-index.hmac-secret=" + b64("pr41-startup-probe-index-secre32"),
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword(),
                "spring.data.jpa.repositories.enabled=false",
                "spring.jpa.hibernate.ddl-auto=update",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect"));
    return all.stream().map(a -> "--" + a).toArray(String[]::new);
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
