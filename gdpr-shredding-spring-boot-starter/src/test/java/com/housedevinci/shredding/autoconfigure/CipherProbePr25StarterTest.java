package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
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
 * Security review, pass 1 of feat/audit-table-coverage (PR 25). C-25-2: design row 10 refuses a
 * leftover Envers audit table "named by Envers' default (or configured prefix/suffix ...)" when
 * Envers is off. With hibernate.integration.envers.enabled=false the starter hands the catalogue
 * leg only the default signatures, so an audit table written under a configured suffix and
 * revision-field name (both still in the application's configuration) is neither named nor
 * recognised by shape.
 */
@Testcontainers
class CipherProbePr25StarterTest {

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
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.copies.enversidx.EnvIdxNote.class)
  static class EnvIdxApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @BeforeEach
  void emptySchema() throws SQLException {
    exec("DROP SCHEMA public CASCADE", "CREATE SCHEMA public");
  }

  @Test
  void probe_envers_off_leftover_audit_table_with_configured_suffix_and_revision_field_is_admitted()
      throws SQLException {
    // Written by an earlier run with Envers on and this same configuration.
    exec(
        "CREATE TABLE public.env_idx_note_log (id bigint, rev_id integer, revtype smallint,"
            + " email_idx bytea, PRIMARY KEY (id, rev_id))",
        "INSERT INTO public.env_idx_note_log VALUES (1, 1, 0, '\\x0102')");

    Throwable thrown =
        catchThrowable(
            () ->
                builder(
                        "spring.jpa.properties.hibernate.integration.envers.enabled=false",
                        "spring.jpa.properties.org.hibernate.envers.audit_table_suffix=_log",
                        "spring.jpa.properties.org.hibernate.envers.revision_field_name=rev_id")
                    .run()
                    .close());

    ShreddingException refusal = null;
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        refusal = s;
        break;
      }
    }
    assertThat(refusal)
        .describedAs("Envers off, audit table env_idx_note_log with email_idx left behind")
        .isNotNull();
    assertThat(refusal.code()).isEqualTo(ErrorCodes.BLIND_INDEX_COPIED);
    assertThat(refusal).hasMessageContaining("public.env_idx_note_log");
  }

  /**
   * C-25-3: a 0.1.1 installation with Envers meets several successive refusals (an audited
   * ciphertext SHRED-CONFIG-001, an audited index SHRED-SCHEMA-010 from the mapping, the listener
   * order SHRED-CONFIG-001, then the catalogue SHRED-SCHEMA-010 for the column its audit table
   * still holds, together with the statistics). The upgrade guide must name that sequence so the
   * operator plans one window, not four.
   */
  @Test
  void probe_upgrade_guide_names_the_envers_refusal_sequence() throws java.io.IOException {
    String guide =
        java.nio.file.Files.readString(java.nio.file.Path.of("..", "docs", "upgrading-0.2.0.md"));
    boolean named = false;
    for (String paragraph : guide.split("\\R\\s*\\R")) {
      if (paragraph.contains("Envers")
          && paragraph.contains("SHRED-CONFIG-001")
          && paragraph.contains("SHRED-SCHEMA-010")
          && paragraph.contains("_aud")) {
        named = true;
      }
    }
    assertThat(named)
        .describedAs("a paragraph of docs/upgrading-0.2.0.md giving the Envers refusal sequence")
        .isTrue();
  }

  private SpringApplicationBuilder builder(String... extra) {
    return new SpringApplicationBuilder(EnvIdxApp.class)
        .web(WebApplicationType.NONE)
        .properties(
            Stream.concat(
                    Stream.of(
                        "shredding.master-key=" + b64("copy-mapping-master-key-32-bytes"),
                        "shredding.jdbc.initialize-schema=true",
                        "shredding.jdbc.allow-privileged-runtime-role=true",
                        "shredding.erasure-log.hmac-secret="
                            + b64("copy-mapping-chain-secret-32-byte"),
                        "shredding.blind-index.hmac-secret="
                            + b64("copy-mapping-index-secret-32-byte"),
                        "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "spring.datasource.username=" + POSTGRES.getUsername(),
                        "spring.datasource.password=" + POSTGRES.getPassword(),
                        "spring.data.jpa.repositories.enabled=false",
                        "spring.jpa.hibernate.ddl-auto=create-drop",
                        "spring.jpa.properties.hibernate.dialect="
                            + "org.hibernate.dialect.PostgreSQLDialect"),
                    Stream.of(extra))
                .toArray(String[]::new));
  }

  private static void exec(String... sql) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    }
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
