package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

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
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, pass 2 of feat/audit-table-coverage (PR 25): the C-25-2 fix feeds Envers' naming
 * settings, as configured, into TableRef's lowercase-identifier rule. An unquoted mixed-case
 * org.hibernate.envers.default_schema is a valid setting (PostgreSQL folds it), and the documented
 * composition must boot with it; so must a 61-character table, whose Envers audit name PostgreSQL
 * truncates to 63 bytes.
 */
@Testcontainers
class CipherProbePr25Pass2StarterTest {

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
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.enversok.EnvOkNote.class)
  static class EnvIdxApp {
    @Bean
    HibernatePropertiesCustomizer enversFirst() {
      return props ->
          props.put(
              org.hibernate.jpa.boot.spi.JpaSettings.INTEGRATOR_PROVIDER,
              (org.hibernate.jpa.boot.spi.IntegratorProvider)
                  () ->
                      java.util.List.of(
                          new com.housedevinci.shredding.autoconfigure.copies.enversok
                              .EnversFirstIntegrator()));
    }

    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @BeforeEach
  void emptySchema() throws SQLException {
    exec(
        "DROP SCHEMA IF EXISTS audit CASCADE",
        "DROP SCHEMA public CASCADE",
        "CREATE SCHEMA public");
  }

  @Test
  void probe_documented_envers_composition_with_unquoted_mixed_case_default_schema_boots() {
    Throwable thrown =
        catchThrowable(
            () ->
                builder(
                        EnvIdxApp.class,
                        "spring.jpa.properties.hibernate.envers.autoRegisterListeners=false",
                        "spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true",
                        "spring.jpa.properties.org.hibernate.envers.default_schema=Audit")
                    .run()
                    .close());
    assertThat(thrown).describedAs("boot of the documented composition").isNull();
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.copies.p2long.LongNote.class)
  static class LongApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /** No Envers anywhere in the mapping: a 60-character table name, legal in PostgreSQL. */
  @Test
  void probe_sixty_character_table_without_envers_boots() {
    Throwable thrown =
        catchThrowable(
            () ->
                builder(
                        LongApp.class,
                        "spring.jpa.properties.hibernate.integration.envers.enabled=false")
                    .run()
                    .close());
    assertThat(thrown).describedAs("boot of a plain entity on a 60-character table").isNull();
  }

  private SpringApplicationBuilder builder(Class<?> app, String... extra) {
    return new SpringApplicationBuilder(app)
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
