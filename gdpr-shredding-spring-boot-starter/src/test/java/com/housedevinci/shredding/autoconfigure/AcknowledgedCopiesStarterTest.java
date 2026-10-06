package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.application.PostErasureHook;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
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
 * {@code shredding.jdbc.acknowledged-copies} at startup (audit-table coverage design, sections 3c
 * and 4h): every refusal an entry or the hook list can cause stops the context, with lazy
 * initialisation on as well as off, because a binding checked only when the {@code ErasureService}
 * bean is first used would let an application serve requests on a configuration that can never
 * erase correctly.
 */
@Testcontainers
class AcknowledgedCopiesStarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static PostErasureHook hook(String name) {
    return new PostErasureHook() {
      @Override
      public String name() {
        return name;
      }

      @Override
      public void afterErasure(TenantId tenant, SubjectId subject) {}
    };
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  static class OneHookApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    @Bean
    PostErasureHook scrubber() {
      return hook("scrubber");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  static class TwoHooksOneNameApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    @Bean
    PostErasureHook first() {
      return hook("purge");
    }

    @Bean
    PostErasureHook second() {
      return hook("purge");
    }
  }

  @Test
  void y11_duplicate_hook_names_refuse_startup() {
    for (String lazy : new String[] {"false", "true"}) {
      ShreddingException refusal =
          refusal(TwoHooksOneNameApp.class, "spring.main.lazy-initialization=" + lazy);
      assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
      assertThat(refusal.getMessage())
          .isEqualTo(
              "shredding: two post-erasure hooks are named purge. Hook names identify the step in"
                  + " the erasure trail and must be unique; rename one.");
    }
  }

  @Test
  void a4_entry_without_registered_hook_refuses_startup() {
    for (String lazy : new String[] {"false", "true"}) {
      ShreddingException refusal =
          refusal(
              OneHookApp.class,
              "spring.main.lazy-initialization=" + lazy,
              "shredding.jdbc.acknowledged-copies[0].kind=replication-slot",
              "shredding.jdbc.acknowledged-copies[0].name=cdc",
              "shredding.jdbc.acknowledged-copies[0].cleared-by=historyIndexScrubber");
      assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
      assertThat(refusal.getMessage())
          .isEqualTo(
              "shredding: shredding.jdbc.acknowledged-copies[0] has cleared-by=historyIndexScrubber,"
                  + " and no PostErasureHook has that name. An acknowledged copy needs the hook that"
                  + " clears it, or every erasure would be recorded COMPLETE over it.");
    }
  }

  @Test
  void entry_naming_a_missing_trigger_refuses_startup() {
    ShreddingException refusal =
        refusal(
            OneHookApp.class,
            "shredding.jdbc.acknowledged-copies[0].kind=trigger",
            "shredding.jdbc.acknowledged-copies[0].schema=public",
            "shredding.jdbc.acknowledged-copies[0].table=owned_note",
            "shredding.jdbc.acknowledged-copies[0].name=Owned_Note_Audit",
            "shredding.jdbc.acknowledged-copies[0].cleared-by=scrubber");
    assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
    assertThat(refusal.getMessage())
        .isEqualTo(
            "shredding: shredding.jdbc.acknowledged-copies[0] names trigger"
                + " \"public\".\"owned_note\".\"Owned_Note_Audit\", which does not exist. Names are"
                + " compared exactly as pg_catalog stores them (unquoted SQL names are stored in"
                + " lower case). Remove the entry or correct it.");
  }

  @Test
  void malformed_entry_refuses_startup_by_its_index() {
    ShreddingException refusal =
        refusal(
            OneHookApp.class,
            "shredding.jdbc.acknowledged-copies[0].kind=publication",
            "shredding.jdbc.acknowledged-copies[0].table=owned_note",
            "shredding.jdbc.acknowledged-copies[0].name=pub",
            "shredding.jdbc.acknowledged-copies[0].cleared-by=scrubber");
    assertThat(refusal.code()).isEqualTo(ErrorCodes.CONFIG);
    assertThat(refusal.getMessage())
        .isEqualTo(
            "shredding: shredding.jdbc.acknowledged-copies[0] has kind=publication and sets table;"
                + " schema and table belong to kind=trigger only.");
  }

  private static ShreddingException refusal(Class<?> app, String... extra) {
    Throwable thrown =
        catchThrowable(
            () ->
                new SpringApplicationBuilder(app)
                    .web(WebApplicationType.NONE)
                    .properties(
                        Stream.concat(
                                Stream.of(
                                    "shredding.master-key="
                                        + b64("ack-starter-master-key-32-bytes!"),
                                    "shredding.jdbc.initialize-schema=true",
                                    "shredding.jdbc.allow-privileged-runtime-role=true",
                                    "shredding.erasure-log.hmac-secret="
                                        + b64("ack-starter-chain-secret-32-byte"),
                                    "shredding.blind-index.hmac-secret="
                                        + b64("ack-starter-index-secret-32-byte"),
                                    "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                                    "spring.datasource.username=" + POSTGRES.getUsername(),
                                    "spring.datasource.password=" + POSTGRES.getPassword(),
                                    "spring.data.jpa.repositories.enabled=false",
                                    "spring.jpa.hibernate.ddl-auto=create-drop",
                                    "spring.jpa.properties.hibernate.default_schema=public",
                                    "spring.jpa.properties.hibernate.dialect="
                                        + "org.hibernate.dialect.PostgreSQLDialect"),
                                Stream.of(extra))
                            .toArray(String[]::new))
                    .run()
                    .close());
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s;
      }
    }
    throw new AssertionError("no ShreddingException in the cause chain", thrown);
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
