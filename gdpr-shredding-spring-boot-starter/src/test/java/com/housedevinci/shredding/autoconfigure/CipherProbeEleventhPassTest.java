package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNote;
import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNoteRepository;
import com.housedevinci.shredding.autoconfigure.eleventhpass.oddname.OddNameNote;
import com.housedevinci.shredding.autoconfigure.eleventhpass.oddname.OddNameNoteRepository;
import com.housedevinci.shredding.autoconfigure.eleventhpass.writetx.WriteOnlyTxNote;
import com.housedevinci.shredding.autoconfigure.eleventhpass.writetx.WriteOnlyTxNoteRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
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

/** The eleventh pass: the surfaces design addendum 4 left open. */
@Testcontainers
class CipherProbeEleventhPassTest {

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

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = WriteOnlyTxNote.class)
  @EnableJpaRepositories(basePackageClasses = WriteOnlyTxNoteRepository.class)
  static class WriteOnlyTxApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OddNameNote.class)
  @EnableJpaRepositories(basePackageClasses = OddNameNoteRepository.class)
  static class OddNameApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class OwnedApp extends Tenant {}

  /**
   * The original S-22 attack, in the one shape that survives addendum 4: the physical column is
   * created quoted-lower-case ("user" == user), so the mapping can name it <em>unquoted</em>, and
   * PostgreSQL parses an unqualified bare {@code user} as CURRENT_USER rather than as that column.
   * Hibernate's own SQL is alias-qualified and unaffected; this module's is not.
   *
   * <p>Hibernate cannot <em>write</em> such a column at all - an INSERT column list is a ColId
   * position, where a reserved word is a syntax error - so the row and its index are written the
   * only way they can exist: by the system that owns the legacy table. The erasure must not report
   * a completion it did not perform.
   */
  @Test
  void probe_an_unquoted_reserved_word_subject_column_never_reports_a_completion_it_did_not_do()
      throws Exception {
    ddl(
        "create table if not exists autoquote_note (id bigserial primary key,"
            + " \"user\" varchar(255) not null, tenant_id varchar(255) not null,"
            + " email bytea, email_idx bytea)");
    String victim = "kw11-" + System.nanoTime();
    sql(
        "insert into autoquote_note (\"user\", tenant_id, email, email_idx) values ('"
            + victim
            + "', 'org-a', null, '\\x0102')");
    ConfigurableApplicationContext context = null;
    try {
      // hibernate.auto_quote_keyword is left at its default (false), so @Column(name = "user")
      // reaches the mapping unquoted.
      context = builder(KeywordApp.class).properties("spring.jpa.hibernate.ddl-auto=none").run();
    } catch (RuntimeException startupFailure) {
      assertThat(code(startupFailure))
          .describedAs("refusing this mapping at startup is a fine answer")
          .isNotBlank();
      return;
    }
    try (var ctx = context) {
      var erasures = ctx.getBean(ErasureService.class);
      assertThat(keywordIndexes(ctx, victim)).isEqualTo(1);

      String outcome;
      try {
        erasures.erase(
            new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));
        outcome = "COMPLETED";
      } catch (RuntimeException e) {
        outcome = code(e);
      }

      assertThat(outcome + " | index rows left: " + keywordIndexes(ctx, victim))
          .describedAs("a completion that left the blind index in place is S-22 again")
          .doesNotStartWith("COMPLETED | index rows left: 1");
    }
  }

  /**
   * Change 4's predicate reads {@code getCustomWriteExpression()} as well as the read one. A
   * transformer that only rewrites the write leaves the read plain, so a predicate built on the
   * read alone lets it through - and the column then stores upper(value) while the erasure binds
   * the value as given.
   */
  @Test
  void probe_a_write_only_column_transformer_is_refused_at_startup() {
    assertThat(startup(WriteOnlyTxApp.class))
        .startsWith("STARTUP-REFUSED SHRED-CONFIG-001")
        .contains("WriteOnlyTxNote")
        .contains("@ColumnTransformer");
  }

  /**
   * A leading underscore and a dollar sign are legal unquoted PostgreSQL identifiers and are two of
   * the shapes Hibernate's IdentifierHelper quotes beyond the mapping. Whatever the mapping says,
   * the erasure must address the same column Hibernate does.
   */
  @Test
  void probe_underscore_and_dollar_column_names_are_addressed_as_the_mapping_addresses_them()
      throws Exception {
    ddl(
        "create table if not exists oddname_note (id bigserial primary key,"
            + " _owner varchar(255) not null, t$x varchar(255) not null,"
            + " email bytea, email_idx bytea)");
    try (var ctx =
        builder(OddNameApp.class).properties("spring.jpa.hibernate.ddl-auto=none").run()) {
      var notes = ctx.getBean(OddNameNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "odd-" + System.nanoTime();
      notes.saveAndFlush(new OddNameNote(victim, "org-a", "victim@example.test"));
      assertThat(oddIndexes(ctx, victim)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(oddIndexes(ctx, victim)).isZero();
    }
  }

  /**
   * The other side of change 10. A row committed for <em>another</em> subject while the erasure is
   * held open must not refuse this erasure: a residual that counted rows rather than this subject's
   * rows would turn any concurrent traffic into a refusal, and a control that fires on ordinary
   * load is a control that gets switched off.
   */
  @Test
  void probe_a_concurrent_insert_for_another_subject_does_not_refuse_the_erasure()
      throws Exception {
    try (var ctx = start(OwnedApp.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "conc-victim-" + System.nanoTime();
      String bystander = "conc-other-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));
      sql(
          "create or replace function shredding_probe_slow11() returns trigger as $$ begin"
              + " perform pg_sleep(2); return null; end; $$ language plpgsql");
      sql(
          "create trigger shredding_probe_slow11_trg after update on owned_note"
              + " for each row execute function shredding_probe_slow11()");
      try {
        var erasure =
            CompletableFuture.supplyAsync(
                () -> {
                  try {
                    erasures.erase(
                        new ErasureRequest(
                            TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));
                    return "COMPLETED";
                  } catch (ShreddingException e) {
                    return e.code();
                  }
                });
        Thread.sleep(700);
        sql(
            "insert into owned_note (owner_id, tenant_id, email, email_idx) values ('"
                + bystander
                + "', 'org-a', null, '\\x0102')");

        assertThat(erasure.get())
            .describedAs("another subject's concurrent row refused this subject's erasure")
            .isEqualTo("COMPLETED");
        assertThat(indexes(ctx, victim)).isZero();
        assertThat(indexes(ctx, bystander))
            .describedAs("the bystander's index was cleared by someone else's erasure")
            .isEqualTo(1);
      } finally {
        sql("drop trigger if exists shredding_probe_slow11_trg on owned_note");
      }
    }
  }

  // ---------------------------------------------------------------- helpers

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

  private static long keywordIndexes(ConfigurableApplicationContext ctx, String owner) {
    return count(
        ctx,
        "select count(*) from autoquote_note where \"user\" = ? and email_idx is not null",
        owner);
  }

  private static long oddIndexes(ConfigurableApplicationContext ctx, String owner) {
    return count(
        ctx, "select count(*) from oddname_note where _owner = ? and email_idx is not null", owner);
  }

  private static long indexes(ConfigurableApplicationContext ctx, String owner) {
    return count(
        ctx, "select count(*) from owned_note where owner_id = ? and email_idx is not null", owner);
  }

  private static long keys(ConfigurableApplicationContext ctx, String subject) {
    return count(
        ctx,
        "select count(*) from shredding_data_key where tenant = 'org-a' and subject = ?",
        subject);
  }

  private static long count(ConfigurableApplicationContext ctx, String query, String parameter) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps = c.prepareStatement(query)) {
      ps.setString(1, parameter);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
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

  private ConfigurableApplicationContext start(Class<?> app) {
    return builder(app).run();
  }

  private String startup(Class<?> app) {
    try (var ctx = builder(app).run()) {
      return "STARTED";
    } catch (RuntimeException e) {
      return "STARTUP-REFUSED " + code(e);
    }
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
