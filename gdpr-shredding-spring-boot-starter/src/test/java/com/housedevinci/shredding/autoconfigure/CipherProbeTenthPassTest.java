package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.tenthpass.collision.CollisionNote;
import com.housedevinci.shredding.autoconfigure.tenthpass.collision.CollisionNoteRepository;
import com.housedevinci.shredding.autoconfigure.tenthpass.joined.JoinedChild;
import com.housedevinci.shredding.autoconfigure.tenthpass.joined.JoinedChildRepository;
import com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNote;
import com.housedevinci.shredding.autoconfigure.tenthpass.keyword.KeywordNoteRepository;
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
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, tenth pass: the surfaces change 9 made live, promoted out of {@code src/test-pending}
 * once design addendum 4 closed S-22 and S-24. Every method here is green by its own assertions - a
 * real erasure, or a startup refusal this module names - not by the escape hatch it was written
 * with.
 */
@Testcontainers
class CipherProbeTenthPassTest {

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

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = JoinedChild.class)
  @EnableJpaRepositories(basePackageClasses = JoinedChildRepository.class)
  static class JoinedApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = KeywordNote.class)
  @EnableJpaRepositories(basePackageClasses = KeywordNoteRepository.class)
  static class KeywordApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = CollisionNote.class)
  @EnableJpaRepositories(basePackageClasses = CollisionNoteRepository.class)
  static class CollisionApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /**
   * The second face of the same statement. {@code ShreddedModel.unquote} lowercases before it
   * compares, so a quoted {@code "Owner"} satisfies {@code subjectColumn="owner"} - and the erasure
   * then interpolates {@code owner} unquoted, which in PostgreSQL is the *other* column of that
   * name. The erasure matches on a column that has nothing to do with the subject: it clears
   * whatever rows happen to hold the label, and misses the ones it was asked for.
   */
  @Test
  void probe_a_case_folded_subject_column_does_not_address_a_different_column() {
    ShreddingException refusal = null;
    ConfigurableApplicationContext context = null;
    try {
      context = start(CollisionApp.class);
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
      assertThat(refusal).isNotNull();
      return;
    }
    try (var ctx = context) {
      var notes = ctx.getBean(CollisionNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "col-" + System.nanoTime();
      String other = "other-" + System.nanoTime();
      // victim's row: subject in "Owner", an unrelated label in owner
      notes.saveAndFlush(new CollisionNote(owner, other, "org-a", "victim@example.test"));
      // a bystander whose *label* happens to equal the victim's subject id
      notes.saveAndFlush(new CollisionNote(other, owner, "org-a", "bystander@example.test"));

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(collisionIndexes(ctx, "\"Owner\"", owner))
          .describedAs(
              "the victim's own index survived (outcome=%s, cleared=%d)",
              result.outcome(), result.blindIndexColumnsCleared())
          .isZero();
      assertThat(collisionIndexes(ctx, "\"Owner\"", other))
          .describedAs("a bystander's index was cleared by someone else's erasure")
          .isEqualTo(1);
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository.class)
  static class DefaultSchemaApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /**
   * S-21 verification in the shape an enterprise deployment actually has: no {@code @Table(schema)}
   * anywhere, the schema named once by {@code hibernate.default_schema=app3}, and a decoy table of
   * the same name sitting in {@code public}, which is on the connection's search_path while {@code
   * app3} is not. The ninth-pass probe only exercised {@code default_schema=public}, where
   * qualified and unqualified address the same table and the bug is invisible.
   */
  @Test
  void probe_a_default_schema_deployment_addresses_its_own_table_and_not_the_decoy()
      throws Exception {
    try (var c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute("create schema if not exists app3");
      st.execute(
          "create table if not exists public.owned_note (id bigserial primary key,"
              + " owner_id varchar(255) not null, tenant_id varchar(255) not null,"
              + " email bytea, email_idx bytea)");
    }
    try (var ctx =
        new SpringApplicationBuilder(DefaultSchemaApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("tenthpass-master-key-32-bytes!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("tenthpass-chain-secret-32-bytes!"),
                "shredding.blind-index.hmac-secret=" + b64("tenthpass-index-secret-32-bytes!"),
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword(),
                "spring.jpa.hibernate.ddl-auto=update",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
                "spring.jpa.properties.hibernate.default_schema=app3")
            .run()) {
      var dataSource = ctx.getBean(DataSource.class);
      String owner = "ds-" + System.nanoTime();
      try (var c = dataSource.getConnection();
          var ps =
              c.prepareStatement(
                  "insert into public.owned_note (owner_id, tenant_id, email, email_idx)"
                      + " values (?, 'org-a', null, ?)")) {
        ps.setString(1, owner);
        ps.setBytes(2, new byte[] {9, 9, 9, 9});
        ps.executeUpdate();
      }
      var notes =
          ctx.getBean(
              com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      notes.saveAndFlush(
          new com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote(
              owner, "org-a", "victim@example.test"));

      assertThat(count(dataSource, "app3.owned_note", owner)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(count(dataSource, "app3.owned_note", owner)).isZero();
      assertThat(count(dataSource, "public.owned_note", owner))
          .describedAs("the decoy in public is another table's data and must be untouched")
          .isEqualTo(1);
    } finally {
      try (var c =
              java.sql.DriverManager.getConnection(
                  POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
          var st = c.createStatement()) {
        st.execute("drop table if exists public.owned_note");
      }
    }
  }

  private static long count(DataSource ds, String table, String owner)
      throws java.sql.SQLException {
    try (var c = ds.getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from "
                    + table
                    + " where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    }
  }

  private long collisionIndexes(ConfigurableApplicationContext ctx, String column, String value) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from collision_note where "
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

  /**
   * JdbcErasureStore interpolates column(), subjectColumn() and tenantColumn() UNQUOTED, while
   * every statement the starter builds quotes them. A subject column named {@code user} is a
   * PostgreSQL reserved word that is also a valid scalar expression, so {@code WHERE user = ?}
   * parses, compares the connection's role name against the subject, and matches nothing. The
   * UPDATE clears no row - and verifyCleared's two read-backs are built from the same unquoted
   * text, so they agree with it. Key destroyed, ciphertext destroyed, record COMPLETE, and the HMAC
   * of the erased plaintext still sitting in the table as a correlator: S-20's failure reached
   * through the quoting, not through the binding.
   */
  @Test
  void probe_a_reserved_word_column_quoted_by_the_mapping_is_cleared() {
    ShreddingException refusal = null;
    ConfigurableApplicationContext context = null;
    try {
      context = start(KeywordApp.class);
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
      assertThat(refusal)
          .describedAs("refusing this mapping at startup is a fine answer; a raw failure is not")
          .isNotNull();
      return;
    }
    try (var ctx = context) {
      var notes = ctx.getBean(KeywordNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "kw-" + System.nanoTime();
      notes.saveAndFlush(new KeywordNote(owner, "org-a", "victim@example.test"));

      assertThat(keywordIndexes(ctx, owner)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(keywordIndexes(ctx, owner))
          .describedAs(
              "the blind index of an erased subject survived the erasure, which returned"
                  + " outcome=%s and cleared=%d without throwing",
              result.outcome(), result.blindIndexColumnsCleared())
          .isZero();
      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.tenthpass.quotedcol.QuotedColNote.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.tenthpass.quotedcol.QuotedColNoteRepository
              .class)
  static class QuotedColApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /**
   * The third face: {@code ShreddedModel.columnName(Field)} returns the raw text of
   * {@code @Column(name = ...)}, quotes and all, and the starter's own {@code quote()} then doubles
   * them - so a {@code @Shredded} column the mapping quotes is addressed as the identifier {@code
   * "Email"} with the quote characters in the name. Startup must refuse that mapping, not boot and
   * fail on whichever row is written first.
   */
  @Test
  void probe_a_quoted_shredded_column_is_settled_at_startup_not_at_the_first_write() {
    ShreddingException refusal = null;
    ConfigurableApplicationContext context = null;
    try {
      context = start(QuotedColApp.class);
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
    }
    if (context == null) {
      assertThat(refusal)
          .describedAs("refused at startup, but not with this module's own typed error")
          .isNotNull();
      return;
    }
    try (var ctx = context) {
      var notes =
          ctx.getBean(
              com.housedevinci.shredding.autoconfigure.tenthpass.quotedcol.QuotedColNoteRepository
                  .class);
      String owner = "q-" + System.nanoTime();
      org.assertj.core.api.Assertions.assertThatCode(
              () ->
                  notes.saveAndFlush(
                      new com.housedevinci.shredding.autoconfigure.tenthpass.quotedcol
                          .QuotedColNote(owner, "org-a", "victim@example.test")))
          .describedAs(
              "the module booted on a mapping whose @Shredded column it cannot address, and"
                  + " discovered it on the first row instead of at startup")
          .doesNotThrowAnyException();
    }
  }

  private long keywordIndexes(ConfigurableApplicationContext ctx, String owner) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from keyword_note where \"user\" = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * The @SecondaryTable refusal (change 9, §3.9c) is newly live, so the first question was whether
   * it false-positives on a JOINED hierarchy. It does not - something earlier does. The root and
   * the subclass are both entities and {@code allFields} walks the superclass, so the one converter
   * on the root's field is checked twice, against two entity names, and no pair satisfies both:
   * {@code (JoinedBase, email)} is refused for JoinedChild and {@code (JoinedChild, email)} is
   * refused for JoinedBase (verified both ways). {@code @Shredded} is therefore unusable anywhere
   * in an entity inheritance hierarchy, under every strategy - and the module says so nowhere, and
   * refuses it with a message telling the developer to correct a converter pair that cannot be
   * corrected. Refuse it by its real reason, and write the limit down.
   */
  @Test
  void probe_a_shredded_field_in_an_inheritance_hierarchy_is_refused_by_its_real_reason() {
    ShreddingException refusal = null;
    ConfigurableApplicationContext context = null;
    try {
      context = start(JoinedApp.class);
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
    }
    if (refusal != null) {
      assertThat(refusal.getMessage())
          .describedAs(
              "startup refused a JOINED hierarchy, which is a fine answer - but the message names"
                  + " the converter's entity/field pair, which is the one thing the developer"
                  + " cannot fix here. It must name inheritance")
          .containsIgnoringCase("inherit");
      return;
    }
    try (var ctx = context) {
      var notes = ctx.getBean(JoinedChildRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "joined-" + System.nanoTime();
      notes.saveAndFlush(new JoinedChild(owner, "org-a", "victim@example.test", "n"));

      assertThat(indexes(ctx, owner)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, owner)).isZero();
    }
  }

  private long indexes(ConfigurableApplicationContext ctx, String owner) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from joined_base where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private ConfigurableApplicationContext start(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("tenthpass-master-key-32-bytes!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("tenthpass-chain-secret-32-bytes!"),
            "shredding.blind-index.hmac-secret=" + b64("tenthpass-index-secret-32-bytes!"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect")
        .run();
  }

  private static ShreddingException shreddingCause(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s;
      }
    }
    return null;
  }
}
