package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.autoconfigure.columnid.assocsubject.AssocSubjectNote;
import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNote;
import com.housedevinci.shredding.autoconfigure.columnid.autoquote.AutoQuoteNoteRepository;
import com.housedevinci.shredding.autoconfigure.columnid.caseonly.CaseOnlyNote;
import com.housedevinci.shredding.autoconfigure.columnid.dot.DotNote;
import com.housedevinci.shredding.autoconfigure.columnid.dot.DotNoteRepository;
import com.housedevinci.shredding.autoconfigure.columnid.formula.FormulaNote;
import com.housedevinci.shredding.autoconfigure.columnid.quotedmixed.QuotedOwnerNote;
import com.housedevinci.shredding.autoconfigure.columnid.quotedmixed.QuotedOwnerNoteRepository;
import com.housedevinci.shredding.autoconfigure.columnid.transformerindex.TransformerIndexNote;
import com.housedevinci.shredding.autoconfigure.columnid.transformersubject.TransformerSubjectNote;
import com.housedevinci.shredding.autoconfigure.columnid.upper.UpperOwnerNote;
import com.housedevinci.shredding.autoconfigure.columnid.upper.UpperOwnerNoteRepository;
import com.housedevinci.shredding.autoconfigure.composite.Ticket;
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
 * Design addendum 4: one probe per path by which a column identifier reaches a statement, written
 * before the hook (the framework integration rule). The property under test throughout: <em>every
 * identifier this module interpolates addresses the column Hibernate's mapping addresses, or
 * startup refuses naming the mapping.</em>
 */
@Testcontainers
class CipherProbeColumnIdentityTest {

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
  @EntityScan(basePackageClasses = QuotedOwnerNote.class)
  @EnableJpaRepositories(basePackageClasses = QuotedOwnerNoteRepository.class)
  static class QuotedMixedApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = UpperOwnerNote.class)
  @EnableJpaRepositories(basePackageClasses = UpperOwnerNoteRepository.class)
  static class UpperApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = CaseOnlyNote.class)
  @EnableJpaRepositories(basePackageClasses = CaseOnlyNote.class)
  static class CaseOnlyApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = FormulaNote.class)
  @EnableJpaRepositories(basePackageClasses = FormulaNote.class)
  static class FormulaApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TransformerSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = TransformerSubjectNote.class)
  static class TransformerSubjectApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TransformerIndexNote.class)
  @EnableJpaRepositories(basePackageClasses = TransformerIndexNote.class)
  static class TransformerIndexApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = AssocSubjectNote.class)
  @EnableJpaRepositories(basePackageClasses = AssocSubjectNote.class)
  static class AssocApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = DotNote.class)
  @EnableJpaRepositories(basePackageClasses = DotNoteRepository.class)
  static class DotApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Ticket.class)
  @EnableJpaRepositories(basePackageClasses = Ticket.class)
  static class CompositeIdApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class OwnedApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = AutoQuoteNote.class)
  @EnableJpaRepositories(basePackageClasses = AutoQuoteNoteRepository.class)
  static class AutoQuoteApp extends Tenant {}

  // ---------------------------------------------------------------- change 2

  /**
   * Change 2. {@code @Column(name = "\"Owner\"")} is quoted by the mapping, so the erasure must
   * quote it too. A legacy, unmapped, lower-case {@code owner} column sits beside it in the table
   * and carries a <em>different</em> subject's label: if the module folds the name and drops the
   * quotes it addresses that column instead, clearing a bystander's index and missing the victim's.
   */
  @Test
  void probe_a_quoted_mixed_case_column_boots_and_is_addressed_quoted() throws Exception {
    ddl(
        "create table if not exists quotedmixed_note (id bigserial primary key,"
            + " \"Owner\" varchar(255) not null, owner varchar(255),"
            + " tenant_id varchar(255) not null, email bytea, email_idx bytea)");
    try (var ctx = start(QuotedMixedApp.class)) {
      var notes = ctx.getBean(QuotedOwnerNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "qm-victim-" + System.nanoTime();
      String bystander = "qm-bystander-" + System.nanoTime();
      notes.saveAndFlush(new QuotedOwnerNote(victim, "org-a", "victim@example.test"));
      notes.saveAndFlush(new QuotedOwnerNote(bystander, "org-a", "bystander@example.test"));
      // The legacy column carries the victim's identifier for the *bystander*'s row.
      update(ctx, "update quotedmixed_note set owner = ? where \"Owner\" = ?", victim, bystander);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "quotedmixed_note", "\"Owner\"", victim))
          .describedAs("the victim's index survived")
          .isZero();
      assertThat(indexes(ctx, "quotedmixed_note", "\"Owner\"", bystander))
          .describedAs("a bystander's index was cleared through the folded, unquoted name")
          .isEqualTo(1);
    }
  }

  /**
   * Change 2, the other way round. {@code @Column(name = "OWNER_ID")} is <em>unquoted</em>, so
   * PostgreSQL folded the physical column to {@code owner_id}. A module that blanket-quotes every
   * column renders {@code "OWNER_ID"} and addresses a decoy column of that exact name, which this
   * table also has: the erasure then clears nothing the mapping knows about.
   */
  @Test
  void probe_an_unquoted_upper_case_column_is_addressed_folded() throws Exception {
    ddl(
        "create table if not exists upper_note (id bigserial primary key,"
            + " owner_id varchar(255) not null, \"OWNER_ID\" varchar(255),"
            + " tenant_id varchar(255) not null, email bytea, email_idx bytea)");
    try (var ctx =
        builder(UpperApp.class)
            // Spring Boot's default physical naming strategy lower-cases every explicit
            // @Column(name = ...), which would hide the case this probe exists for. Hibernate's own
            // standard strategy keeps the name as written - unquoted and upper case - which is what
            // a large share of legacy mappings and every JPA-portable one look like.
            .properties(
                "spring.jpa.hibernate.naming.physical-strategy="
                    + "org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl")
            .run()) {
      var notes = ctx.getBean(UpperOwnerNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "up-" + System.nanoTime();
      notes.saveAndFlush(new UpperOwnerNote(victim, "org-a", "victim@example.test"));
      update(ctx, "update upper_note set \"OWNER_ID\" = ? where owner_id = ?", "decoy", victim);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "upper_note", "owner_id", victim)).isZero();
    }
  }

  // ---------------------------------------------------------------- change 7

  /** Change 7: the lookup key is case-sensitive against the mapping, and the message says which. */
  @Test
  void probe_a_column_lookup_key_differing_only_by_case_is_refused_naming_the_case_only_match() {
    String outcome = startup(CaseOnlyApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("CaseOnlyNote")
        .contains("OWNER_ID")
        .contains("owner_id")
        .contains("case-sensitive")
        .contains("only by case");
  }

  // ---------------------------------------------------------------- change 3

  /**
   * Change 3: {@code @Formula("owner_id")} is a plain identifier, so a shape test on the text lets
   * it through. The refusal is on {@code isFormula()}, which is a flag.
   */
  @Test
  void probe_a_formula_column_is_refused_by_its_flag() {
    String outcome = startup(FormulaApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("FormulaNote").containsIgnoringCase("formula");
  }

  // ---------------------------------------------------------------- change 4

  /**
   * Change 4: a {@code @ColumnTransformer} mis-addresses by value what S-22 mis-addressed by name.
   */
  @Test
  void probe_a_column_transformer_on_the_subject_column_is_refused_at_startup() {
    String subject = startup(TransformerSubjectApp.class);
    assertThat(subject).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(subject).contains("TransformerSubjectNote").contains("@ColumnTransformer");

    String index = startup(TransformerIndexApp.class);
    assertThat(index).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(index).contains("TransformerIndexNote").contains("@ColumnTransformer");
  }

  // ---------------------------------------------------------------- change 6

  /** Change 6: an association is refused as an association, not as an unknown column. */
  @Test
  void probe_a_join_column_named_as_the_subject_column_is_refused_as_an_association() {
    String outcome = startup(AssocApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome)
        .contains("AssocSubjectNote")
        .containsIgnoringCase("association")
        .doesNotContain("no property of");
  }

  /** Change 6, the identifier half: the composite id is refused by its real reason. */
  @Test
  void probe_a_composite_identifier_is_refused_by_its_real_reason() {
    String outcome = startup(CompositeIdApp.class);
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("Ticket").containsIgnoringCase("composite");
  }

  // ---------------------------------------------------------------- change 1

  /** Change 1: the refusal of a quote character belongs on the parsed text, not on the fragment. */
  @Test
  void probe_a_column_name_containing_a_quote_character_is_refused() {
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> ColumnRefs.parse("\"Ow\"\"ner\"", "a probe"))
        .describedAs("a quote character inside the parsed name is refused, never escaped")
        .isInstanceOf(ShreddingException.class)
        .hasMessageContaining("double-quote");
    assertThat(ColumnRefs.parse("\"Owner\"", "a probe").sql()).isEqualTo("\"Owner\"");
    assertThat(ColumnRefs.parse("owner_id", "a probe").sql()).isEqualTo("owner_id");
  }

  /** A quoted name containing a dot is one identifier, not a qualified pair. */
  @Test
  void probe_a_quoted_column_whose_name_contains_a_dot_is_addressed_whole() throws Exception {
    ddl(
        "create table if not exists dot_note (id bigserial primary key,"
            + " \"a.b\" varchar(255) not null, tenant_id varchar(255) not null,"
            + " email bytea, email_idx bytea)");
    try (var ctx = start(DotApp.class)) {
      var notes = ctx.getBean(DotNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "dot-" + System.nanoTime();
      notes.saveAndFlush(new DotNote(victim, "org-a", "victim@example.test"));

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "dot_note", "\"a.b\"", victim)).isZero();
    }
  }

  // ---------------------------------------------------------------- change 12

  /** Change 12: {@code globally_quoted_identifiers} is decided here, not at the first erasure. */
  @Test
  void probe_globally_quoted_identifiers_boots_or_is_refused_by_its_real_reason() {
    ConfigurableApplicationContext context = null;
    try {
      context =
          builder(OwnedApp.class)
              .properties("spring.jpa.properties.hibernate.globally_quoted_identifiers=true")
              .run();
    } catch (RuntimeException startupFailure) {
      String message = code(startupFailure);
      assertThat(message)
          .describedAs("refusing is a fine answer; it has to name the setting")
          .contains("globally_quoted_identifiers");
      return;
    }
    try (var ctx = context) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "gq-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "owned_note", "owner_id", victim)).isZero();
    }
  }

  /**
   * Revision correction 1. Two shapes the {@code IdentifierHelper}'s {@code normalizeQuoting} would
   * quote beyond what the mapping says: an unquoted reserved word under {@code
   * hibernate.auto_quote_keyword}, and every column under {@code globally_quoted_identifiers}
   * paired with {@code globally_quoted_identifiers_skip_column_definitions}, which leaves the
   * expressions unquoted at boot. Both must boot and address the right column.
   */
  @Test
  void probe_an_auto_quoted_column_boots_and_round_trips() {
    try (var ctx =
        builder(AutoQuoteApp.class)
            .properties("spring.jpa.properties.hibernate.auto_quote_keyword=true")
            .run()) {
      var notes = ctx.getBean(AutoQuoteNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "aq-" + System.nanoTime();
      notes.saveAndFlush(new AutoQuoteNote(victim, "org-a", "victim@example.test"));

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "autoquote_note", "\"user\"", victim)).isZero();
    }

    try (var ctx =
        builder(OwnedApp.class)
            .properties(
                "spring.jpa.properties.hibernate.globally_quoted_identifiers=true",
                "spring.jpa.properties.hibernate.globally_quoted_identifiers_skip_column_definitions=true")
            .run()) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "skip-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, "owned_note", "owner_id", victim)).isZero();
    }
  }

  // ---------------------------------------------------------------- helpers

  private static void ddl(String statement) throws java.sql.SQLException {
    try (var c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private static void update(ConfigurableApplicationContext ctx, String sql, String a, String b) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps = c.prepareStatement(sql)) {
      ps.setString(1, a);
      ps.setString(2, b);
      ps.executeUpdate();
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long indexes(
      ConfigurableApplicationContext ctx, String table, String column, String value) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from "
                    + table
                    + " where "
                    + column
                    + " = ? and email_idx is not null")) {
      ps.setString(1, value);
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
            "shredding.master-key=" + b64("columnid-master-key-32-bytes!!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("columnid-chain-secret-32-bytes!!"),
            "shredding.blind-index.hmac-secret=" + b64("columnid-index-secret-32-bytes!!"),
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
