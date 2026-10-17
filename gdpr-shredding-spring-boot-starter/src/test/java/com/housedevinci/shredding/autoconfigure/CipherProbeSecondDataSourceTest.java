package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.BlindIndexResidual;
import com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore;
import com.housedevinci.shredding.adapter.jdbc.JdbcKeyProvider;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Security review probe for C-PR-1 (2026-10-12), moved into the suite by the builder. An
 * application's own JDBC store, built from {@code gate.schema()} on a DataSource the gate never
 * read, must refuse startup with {@code SHRED-SCHEMA-011}. Red on 0.2.0 for both stores: the
 * context started and the store wrote to the unguarded database. The code is a literal on purpose,
 * so this file compiles against 0.2.0 too.
 */
@Testcontainers
@SuppressWarnings("removal")
class CipherProbeSecondDataSourceTest {

  private static final String STORE_DATASOURCE_UNVERIFIED = "SHRED-SCHEMA-011";

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static String otherUrl() {
    return POSTGRES.getJdbcUrl().replace("/" + POSTGRES.getDatabaseName(), "/unguarded");
  }

  static DriverManagerDataSource other() {
    return new DriverManagerDataSource(otherUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  @BeforeAll
  static void secondDatabase() throws Exception {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var s = c.createStatement()) {
      s.execute("CREATE DATABASE unguarded");
    }
    // The other database has the tables, so a store that is not refused can write there.
    JdbcSupport.initializeSchema(other());
  }

  @AfterEach
  void clearRuntime() {
    ShreddingRuntime.clear();
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class App {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    /** Application's own key store on a DataSource the gate never read. */
    @Bean
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate, MasterKey masterKey, RandomSource random, Clock clock) {
      return new JdbcKeyProvider(other(), gate.schema(), masterKey, random, clock);
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class ErasureStoreApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    /** Application's own erasure store on a DataSource the gate never read. */
    @Bean
    JdbcErasureStore shreddingErasureStore(ShreddingSchemaGate gate, ErasureChain chain) {
      BlindIndexResidual none = (c, column, tenant, subject) -> 0L;
      return new JdbcErasureStore(other(), gate.schema(), chain, List.of(), none);
    }
  }

  @Test
  void probe_own_key_provider_on_a_second_datasource_starts_unverified() {
    assertRefusedWithCode(App.class);
  }

  @Test
  void probe_own_erasure_store_on_a_second_datasource_starts_unverified() {
    assertRefusedWithCode(ErasureStoreApp.class);
  }

  private static void assertRefusedWithCode(Class<?> app) {
    Throwable thrown =
        catchThrowable(
            () -> {
              try (var ctx = builder(app).run()) {
                System.out.println("CIPHER-DS started; the gate verified another database");
              }
            });
    assertThat(thrown)
        .describedAs(
            "a JDBC store on a DataSource the schema gate never verified must refuse startup")
        .isNotNull();
    assertThat(codesInChain(thrown)).contains(STORE_DATASOURCE_UNVERIFIED);
  }

  private static List<String> codesInChain(Throwable thrown) {
    var codes = new java.util.ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        codes.add(s.code());
      }
    }
    return codes;
  }

  private static SpringApplicationBuilder builder(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
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
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
