package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
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
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, twelfth pass: the surfaces the eleventh pass's two fixes left open.
 *
 * <ul>
 *   <li>E-1 was verified through a test that supplies its own {@code JdbcErasureStore} bean, so the
 *       refusal it pins is one the <em>test</em> constructs. The first probe here asks the same
 *       question of the module's own auto-configuration, with no bean overridden.
 *   <li>E-2 added a refusal. Nothing pins the other half - that a reserved word the mapping
 *       <em>quotes</em> still boots and still erases. The tenth pass's probe on the same entity
 *       returns early and passes if startup refuses, so an over-refusal would have been green.
 *   <li>The {@code @SecondaryTable} refusal exists for the {@code @Shredded} column and for both
 *       index axes, and for no third thing: the {@code @BlindIndex} column itself.
 * </ul>
 */
@Testcontainers
class CipherProbeTwelfthPassTest {

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
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.eleventhpass.sharedtable.DupA.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.eleventhpass.sharedtable.DupA.class)
  static class SharedTableApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNote.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNoteRepository.class)
  static class QuotedKeywordApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.twelfthpass.singletable.SingleBase.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.twelfthpass.singletable.SingleBase.class)
  static class SingleTableApp extends Tenant {}

  /**
   * The inheritance limit and E-1's new refusal describe the same mapping from two sides: a
   * SINGLE_TABLE hierarchy is two entity names over one table, and the root's one
   * {@code @BlindIndex} field is scanned once per entity name. Whichever refusal wins the race, the
   * message a developer sees must name inheritance - E-1's text tells them to stop mapping two
   * entities onto one table, which is not something a subclass can stop doing.
   */
  @Test
  void probe_a_single_table_hierarchy_is_refused_by_its_real_reason() {
    String outcome;
    try (var ctx = builder(SingleTableApp.class).run()) {
      outcome = "STARTED";
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + code(e);
    }
    assertThat(outcome).startsWith("STARTUP-REFUSED");
    assertThat(outcome)
        .describedAs("a SINGLE_TABLE hierarchy must be refused by the inheritance limit")
        .containsIgnoringCase("inherit");
  }

  /**
   * E-1 under the module's own wiring. {@code HibernateBlindIndexResidual} is constructed by {@code
   * ShreddingAutoConfiguration#shreddingErasureStore}, an eager singleton, so the collision must be
   * refused during refresh and not on the first erasure of a running application.
   */
  @Test
  void probe_two_entities_on_one_table_are_refused_by_the_module_s_own_wiring() throws Exception {
    sql(
        "create table if not exists dup_note (id bigserial primary key,"
            + " owner_a varchar(255) not null, owner_b varchar(255) not null,"
            + " tenant_id varchar(255) not null, email bytea, email_idx bytea)");
    String outcome;
    try (var ctx =
        builder(SharedTableApp.class).properties("spring.jpa.hibernate.ddl-auto=none").run()) {
      outcome = "STARTED";
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + code(e);
    }
    assertThat(outcome)
        .describedAs(
            "the collision refusal must belong to the auto-configuration, not to a test that"
                + " builds HibernateBlindIndexResidual itself")
        .startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("DupA").contains("DupB").contains("email_idx");
  }

  /**
   * The other half of E-2. {@code KeywordNote} maps {@code @Column(name = "\"user\"")} - the
   * reserved word, quoted, which is the shape the refusal tells developers to write. It must boot,
   * and the erasure must clear the index. Unlike the tenth pass's probe on this entity, a startup
   * refusal here is a failure, not an accepted alternative.
   */
  @Test
  void probe_a_reserved_word_column_the_mapping_quotes_still_boots_and_erases() {
    ConfigurableApplicationContext context = null;
    try {
      context = builder(QuotedKeywordApp.class).run();
    } catch (RuntimeException startupFailure) {
      throw new AssertionError(
          "the reserved-word refusal tells developers to quote the column in the mapping; this"
              + " mapping does exactly that and startup refused it anyway: "
              + code(startupFailure),
          startupFailure);
    }
    try (var ctx = context) {
      var notes =
          ctx.getBean(
              com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNoteRepository
                  .class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "twelfth-kw-" + System.nanoTime();
      notes.saveAndFlush(
          new com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNote(
              owner, "org-a", "victim@example.test"));

      assertThat(indexes(ctx, "keyword_note", "\"user\"", owner)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "keyword_note", "\"user\"", owner)).isZero();
    }
  }

  private long indexes(ConfigurableApplicationContext ctx, String table, String column, String v) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from "
                    + table
                    + " where "
                    + column
                    + " = ? and email_idx is not"
                    + " null")) {
      ps.setString(1, v);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
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
            "shredding.master-key=" + b64("twelfth-master-key-32-bytes!!!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("twelfth-chain-secret-32-bytes!!!"),
            "shredding.blind-index.hmac-secret=" + b64("twelfth-index-secret-32-bytes!!!"),
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
