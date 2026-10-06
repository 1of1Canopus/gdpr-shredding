package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Base64;
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
 * The statistics check at startup (audit-table coverage design, section 3b): a schema Hibernate's
 * {@code ddl-auto} creates leaves every column at the default statistics target, so a
 * {@code @BlindIndex} column refuses the context with {@code SHRED-SCHEMA-010}, naming the
 * attribute; the documented step 3a admits it. The container deliberately does not install the
 * test-only statistics-off event trigger every other fixture uses.
 */
@Testcontainers
class PlannerStatisticsStarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
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

  @Test
  void a_ddl_auto_schema_refuses_startup_naming_the_blind_index_attribute_then_step_3a_admits()
      throws Exception {
    Throwable thrown = catchThrowable(() -> builder("create").run().close());

    ShreddingException refusal = shredding(thrown);
    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal)
        .hasMessageStartingWith(
            "shredding: PostgreSQL keeps, or will keep, planner statistics on the blind-index"
                + " column public.b2_note.email_idx (@BlindIndex B2Note.emailIndex): its statistics"
                + " target is -1 (the default), so the next ANALYZE samples it.")
        .hasMessageContaining(
            "ALTER TABLE public.b2_note ALTER COLUMN email_idx TYPE bytea USING email_idx;");

    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute("SET lock_timeout = '5s'");
      st.execute("ALTER TABLE public.b2_note ALTER COLUMN email_idx SET STATISTICS 0");
      st.execute("ALTER TABLE public.b2_note ALTER COLUMN email_idx TYPE bytea USING email_idx");
    }
    try (var ctx = builder("none").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
    }
  }

  private SpringApplicationBuilder builder(String ddlAuto) {
    return new SpringApplicationBuilder(PlainApp.class)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("stats-starter-master-key-32-byte"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("stats-starter-chain-secret-32-by"),
            "shredding.blind-index.hmac-secret=" + b64("stats-starter-index-secret-32-by"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=" + ddlAuto,
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
  }

  private static ShreddingException shredding(Throwable thrown) {
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
