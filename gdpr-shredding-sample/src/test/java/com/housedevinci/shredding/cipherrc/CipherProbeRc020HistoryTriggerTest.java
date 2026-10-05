package com.housedevinci.shredding.cipherrc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.autoconfigure.ShreddingEventListener;
import com.housedevinci.shredding.cipherrc.hist.RcHistNote;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
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
 * Release-candidate whole-module pass, 0.2.0, lead 1 at the database level: the audit-table pattern
 * without Envers. A row-level {@code AFTER UPDATE} trigger that copies {@code OLD} into a history
 * table is the common shape in regulated schemas. The erasure's own blind-index {@code UPDATE}
 * fires it, so the erasure itself writes the erased subject's pre-erasure index into the history
 * table, after which it records {@code COMPLETE}. Admission reads the relation, its descendants and
 * its columns, never its triggers, so nothing at startup or at erasure time says so.
 *
 * <p>The property asserted: a trigger that fires on the erasure's {@code UPDATE} of a blind-indexed
 * table is named in a startup WARN by mapping admission (the module cannot know where the trigger
 * copies data, so it must at least say that it exists).
 */
@Testcontainers
class CipherProbeRc020HistoryTriggerTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcHistNote.class)
  static class HistApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /**
   * Split per the design review's ruling 1 (audit-table coverage, 2026-10-05): with no
   * acknowledgement, the history trigger refuses startup with {@code SHRED-SCHEMA-010} naming the
   * trigger. The second half, an acknowledged trigger that WARNs at every boot and is never
   * recorded as an unqualified {@code COMPLETE}, needs the acknowledgement list, which is PR 1b.
   */
  @Test
  void probe_history_trigger_without_acknowledgement_refuses_startup() throws SQLException {
    sql(
        "CREATE TABLE public.rc_hist_note (id bigint PRIMARY KEY, owner_id text NOT NULL,"
            + " tenant_id text NOT NULL, email bytea, email_idx bytea)",
        "CREATE TABLE public.rc_hist_note_history (LIKE public.rc_hist_note,"
            + " changed_at timestamptz NOT NULL DEFAULT now())",
        "CREATE FUNCTION public.rc_hist_note_copy() RETURNS trigger LANGUAGE plpgsql AS $$"
            + " BEGIN INSERT INTO public.rc_hist_note_history (id, owner_id, tenant_id, email,"
            + " email_idx) VALUES (OLD.id, OLD.owner_id, OLD.tenant_id, OLD.email, OLD.email_idx);"
            + " RETURN NULL; END $$",
        "CREATE TRIGGER rc_hist_note_audit AFTER UPDATE ON public.rc_hist_note"
            + " FOR EACH ROW EXECUTE FUNCTION public.rc_hist_note_copy()");

    Throwable thrown =
        catchThrowable(
            () ->
                new SpringApplicationBuilder(HistApp.class)
                    .web(WebApplicationType.NONE)
                    .run(args())
                    .close());

    ShreddingException refusal = null;
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        refusal = s;
        break;
      }
    }
    assertThat(refusal).describedAs("refusal cause: %s", thrown).isNotNull();
    System.out.println("CIPHER-RC history trigger refusal: " + refusal.getMessage());
    assertThat(refusal.code()).isEqualTo("SHRED-SCHEMA-010");
    assertThat(refusal.getMessage()).contains("rc_hist_note_audit");
  }

  private static String[] args() {
    return java.util.stream.Stream.of(
            "shredding.master-key=" + b64("rc-histtr-probe-master-key-32-by"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("rc-histtr-probe-chain-secret-32b"),
            "shredding.blind-index.hmac-secret=" + b64("rc-histtr-probe-index-secret-32b"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=none",
            "spring.jpa.properties.hibernate.default_schema=public",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
            "spring.autoconfigure.exclude="
                + "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration")
        .map(a -> "--" + a)
        .toArray(String[]::new);
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static void sql(String... statements) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
  }
}
