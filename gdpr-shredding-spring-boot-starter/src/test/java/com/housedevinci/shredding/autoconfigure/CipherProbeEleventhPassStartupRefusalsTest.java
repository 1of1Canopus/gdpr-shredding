package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNote;
import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNoteRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The eleventh pass, E-1 and E-2: both close as a startup refusal (design addendum 4, §4.5 and
 * §4.2). Promoted from {@code src/test-pending} once the fixes made them green.
 */
@Testcontainers
class CipherProbeEleventhPassStartupRefusalsTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  static class Tenant {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = AutoQuoteNote.class)
  @EnableJpaRepositories(basePackageClasses = AutoQuoteNoteRepository.class)
  static class KeywordApp extends Tenant {}

  /**
   * E-2. {@code @Column(name = "user")}, unquoted, on a physical column created as {@code "user"}.
   * The round trip holds - {@code user} parses unquoted and renders {@code user} - so startup
   * accepts it, and the erasure then interpolates a bare {@code user} into an unqualified {@code
   * WHERE}, where PostgreSQL reads it as CURRENT_USER. The independent read-back catches the miss,
   * so nothing is lost - but every erasure of this entity refuses for ever, blaming "a trigger, a
   * rule, a rewriting view", and the mapping that caused it is never named. The design stop's
   * property says startup refuses, naming the mapping.
   */
  @Test
  void probe_an_unquoted_reserved_word_column_is_refused_at_startup_naming_the_mapping()
      throws Exception {
    sql(
        "create table if not exists autoquote_note (id bigserial primary key,"
            + " \"user\" varchar(255) not null, tenant_id varchar(255) not null,"
            + " email bytea, email_idx bytea)");
    String outcome;
    try (var ctx =
        builder(KeywordApp.class).properties("spring.jpa.hibernate.ddl-auto=none").run()) {
      outcome = "STARTED";
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + code(e);
    }
    assertThat(outcome)
        .describedAs(
            "an unquoted column whose name PostgreSQL reserves cannot be addressed in an"
                + " unqualified WHERE, and is not refused at startup")
        .startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("AutoQuoteNote").contains("user");
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.eleventhpass.sharedtable.DupA.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.eleventhpass.sharedtable.DupA.class)
  static class SharedTableDecoyApp extends Tenant {

    /**
     * Both indexes are mis-addressed the same way the read-back independence probe does it: the
     * tenant column stands in the subject position, so neither UPDATE matches a row and neither
     * same-text read-back disagrees with it. Only the Hibernate-rendered residual can catch it -
     * and there is only one of those left for the two columns.
     */
    @Bean
    com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore shreddingErasureStore(
        DataSource dataSource,
        com.housedevinci.shredding.domain.ErasureChain chain,
        ShreddedModel model,
        jakarta.persistence.EntityManagerFactory entityManagerFactory) {
      com.housedevinci.shredding.adapter.jdbc.JdbcSupport.initializeSchema(dataSource);
      var decoys =
          model.blindIndexColumns().stream()
              .map(
                  c ->
                      new com.housedevinci.shredding.domain.BlindIndexColumn(
                          c.table(),
                          c.column(),
                          c.tenantColumn(),
                          c.tenantColumn(),
                          c.tenantProperty(),
                          c.subjectProperty()))
              .toList();
      return new com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore(
          dataSource,
          chain,
          decoys,
          new HibernateBlindIndexResidual(
              entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class),
              model));
    }
  }

  /**
   * {@code HibernateBlindIndexResidual} keyed its residuals on (table, index column) alone. Two
   * entities mapped to one table that index the same column collided in one {@code LinkedHashMap}:
   * the second {@code put} overwrote the first and {@code Map.copyOf} said nothing. The erasure
   * would then have verified one of the two blind indexes with the <em>other</em> entity's query -
   * the S-22 net, silently pointed at the wrong subject column. The fix (E-1): the constructor now
   * refuses at startup, naming both entities, the shared table and the shared column, rather than
   * keeping only one of the two independent read-backs.
   */
  @Test
  void probe_two_entities_on_one_table_do_not_share_one_independent_read_back() throws Exception {
    ddl(
        "create table if not exists dup_note (id bigserial primary key,"
            + " owner_a varchar(255) not null, owner_b varchar(255) not null,"
            + " tenant_id varchar(255) not null, email bytea, email_idx bytea)");
    String outcome;
    try (var ctx =
        builder(SharedTableDecoyApp.class).properties("spring.jpa.hibernate.ddl-auto=none").run()) {
      outcome = "STARTED";
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + code(e);
    }
    assertThat(outcome)
        .describedAs(
            "two entities on one table sharing a blind-index column must not silently share one"
                + " independent read-back")
        .startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("DupA")
        .contains("DupB")
        .contains("dup_note")
        .contains("email_idx");
  }

  private static void ddl(String statement) throws java.sql.SQLException {
    sql(statement);
  }

  private static void sql(String statement) throws java.sql.SQLException {
    try (var c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private SpringApplicationBuilder builder(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("eleventh-master-key-32-bytes!!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("eleventh-chain-secret-32-bytes!!"),
            "shredding.blind-index.hmac-secret=" + b64("eleventh-index-secret-32-bytes!!"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
  }

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code() + ": " + s.getMessage();
      }
    }
    return thrown.getClass().getSimpleName() + ": " + thrown.getMessage();
  }
}
