package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.JdbcKeyProvider;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review, PR 38 (C-PR-1) pass 1, 2026-10-16. Spring paths the PR does not test, tried to
 * see whether the identity check refuses a legitimate setup or passes a hostile one. Both are
 * characterisations (green on c09f9b4); neither is a finding.
 *
 * <ol>
 *   <li>{@code @Lazy} on the context's DataSource bean definition: the gate's injection forces the
 *       creation, so the gate and an application store taking the bean by type hold the same
 *       object. Starts, writes to the verified database.
 *   <li>{@code @Lazy} on the injection point of an application store that uses the deprecated
 *       constructor: Spring injects a lazy-resolution proxy, a different object, so the store
 *       refuses with SHRED-SCHEMA-011. Strict, and the message names the remedy (the constructor
 *       without a DataSource). Accepted as designed (the P15 rule: a wrapper is refused).
 * </ol>
 */
@Testcontainers
@SuppressWarnings("removal")
class CipherProbePr38StarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @BeforeAll
  static void schema() {
    JdbcSupport.initializeSchema(
        new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
  }

  @AfterEach
  void clearRuntime() {
    ShreddingRuntime.clear();
  }

  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class Base {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  static class LazyPoolBeanApp extends Base {
    @Bean
    @Lazy
    DataSource dataSource(DataSourceProperties properties) {
      return properties.initializeDataSourceBuilder().build();
    }

    @Bean
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate,
        DataSource byType,
        MasterKey masterKey,
        RandomSource random,
        Clock clock) {
      return new JdbcKeyProvider(byType, gate.schema(), masterKey, random, clock);
    }
  }

  static class LazyInjectionPointApp extends Base {
    @Bean
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate,
        @Lazy DataSource lazyRef,
        MasterKey masterKey,
        RandomSource random,
        Clock clock) {
      return new JdbcKeyProvider(lazyRef, gate.schema(), masterKey, random, clock);
    }
  }

  @Test
  void lazy_datasource_bean_definition_starts_and_writes_to_the_verified_database()
      throws SQLException {
    long before = keyRows();
    try (var ctx = builder(LazyPoolBeanApp.class).run()) {
      ctx.getBean(KeyProvider.class)
          .currentForWrite(TenantId.of("cz1"), SubjectId.of("s-" + System.nanoTime()));
    }
    assertThat(keyRows()).isEqualTo(before + 1);
  }

  @Test
  void lazy_injection_point_on_the_deprecated_constructor_is_refused_with_011() {
    Throwable thrown =
        catchThrowable(
            () -> {
              try (var ignored = builder(LazyInjectionPointApp.class).run()) {
                // started: the assertion below fails
              }
            });
    var codes = new ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        codes.add(s.code());
      }
    }
    assertThat(codes).contains("SHRED-SCHEMA-011");
  }

  private static long keyRows() throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var s = c.createStatement();
        var rs = s.executeQuery("SELECT count(*) FROM public.shredding_data_key")) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static SpringApplicationBuilder builder(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("probe-pr38-master-key-32-bytes!!"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("probe-pr38-chain-secret-32-byte!"),
            "shredding.blind-index.hmac-secret=" + b64("probe-pr38-index-secret-32-byte!"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
