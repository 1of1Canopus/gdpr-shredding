package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.ninthpass.elements.TaggedNote;
import com.housedevinci.shredding.autoconfigure.ninthpass.schema.SchemaNote;
import com.housedevinci.shredding.autoconfigure.ninthpass.schema.SchemaNoteRepository;
import com.housedevinci.shredding.autoconfigure.ninthpass.twoindex.TwoIndexNote;
import com.housedevinci.shredding.autoconfigure.ninthpass.twoindex.TwoIndexNoteRepository;
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
 * Cipher, ninth pass. Three surfaces addendum 3 opened or left open: two blind indexes on one
 * entity, an index table in a schema of its own (the K1 lesson - an unqualified identifier resolves
 * against {@code search_path}), and an {@code @ElementCollection} whose element carries the
 * {@code @Shredded} value and its index.
 */
@Testcontainers
class CipherProbeNinthPassBlindIndexTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TwoIndexNote.class)
  @EnableJpaRepositories(basePackageClasses = TwoIndexNoteRepository.class)
  static class TwoIndexApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = SchemaNote.class)
  @EnableJpaRepositories(basePackageClasses = SchemaNoteRepository.class)
  static class SchemaApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote.class)
  @EnableJpaRepositories(
      basePackageClasses = com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository.class)
  static class SchemaDefaultApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = TaggedNote.class)
  @EnableJpaRepositories(basePackageClasses = TaggedNote.class)
  static class ElementsApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /** Both indexes are written under the row's tenant, and one erasure destroys both. */
  @Test
  void probe_two_blind_indexes_on_one_entity_are_both_erased() {
    try (var context = start(TwoIndexApp.class)) {
      var notes = context.getBean(TwoIndexNoteRepository.class);
      var erasures = context.getBean(ErasureService.class);
      String owner = "two-" + System.nanoTime();
      notes.saveAndFlush(new TwoIndexNote(owner, "org-a", "victim@example.test", "+33100000000"));

      assertThat(countTwoIndexes(context, owner)).isEqualTo(2);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(2);
      assertThat(countTwoIndexes(context, owner)).isZero();
    }
  }

  /**
   * The index table is in schema {@code app2}. Either the module refuses the mapping at startup,
   * naming the schema, or the erasure destroys the index - what it may not do is boot, write an
   * index and then report an erasure that an unqualified {@code UPDATE} never reached.
   */
  @Test
  void probe_a_blind_index_in_another_schema_is_erased_or_refused_at_startup() {
    ConfigurableApplicationContext context;
    try {
      context = start(SchemaApp.class);
    } catch (RuntimeException startupFailure) {
      ShreddingException refusal = shreddingCause(startupFailure);
      assertThat(refusal)
          .describedAs("startup failed, but not with this module's own typed refusal")
          .isNotNull();
      assertThat(refusal.getMessage()).contains("app2");
      return;
    }
    try (var ctx = context) {
      var notes = ctx.getBean(SchemaNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "schema-" + System.nanoTime();
      notes.saveAndFlush(new SchemaNote(owner, "org-a", "victim@example.test"));

      assertThat(countIndexes(ctx, "app2.schema_note", owner)).isEqualTo(1);

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(countIndexes(ctx, "app2.schema_note", owner)).isZero();
    }
  }

  /**
   * An {@code @ElementCollection} element carrying a {@code @Shredded} value and its
   * {@code @BlindIndex}: the forward scan never sees either annotation and the index would live in
   * the collection table, which no {@code BlindIndexColumn} names. Refused at startup, naming the
   * path, is the only safe outcome.
   */
  @Test
  void probe_a_blind_index_inside_an_element_collection_is_refused_at_startup() {
    ShreddingException refusal = null;
    try (var ignored = start(ElementsApp.class)) {
      // fall through: it started
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
    }
    assertThat(refusal)
        .describedAs("a @Shredded value and its blind index inside an element collection must be"
            + " refused at startup with this module's own typed error")
        .isNotNull();
    assertThat(refusal.getMessage()).contains("tags");
  }

  /**
   * The same shape reached by configuration rather than by annotation: a deployment that sets
   * {@code hibernate.default_schema}, which is how most enterprise deployments name their schema.
   * Every entity's containing table expression is then qualified, and {@code @BlindIndex} refuses
   * at startup - for a mapping that has no secondary table anywhere, with a message that says it
   * has one.
   */
  @Test
  void probe_a_default_schema_is_supported_or_refused_by_its_real_reason() {
    ShreddingException refusal = null;
    try (var ignored =
        new SpringApplicationBuilder(SchemaDefaultApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("ninthpass-master-key-32-bytes!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("ninthpass-chain-secret-32-bytes!"),
                "shredding.blind-index.hmac-secret=" + b64("ninthpass-index-secret-32-bytes!"),
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword(),
                "spring.jpa.hibernate.ddl-auto=update",
                "spring.jpa.properties.hibernate.default_schema=public")
            .run()) {
      // it started
    } catch (RuntimeException startupFailure) {
      refusal = shreddingCause(startupFailure);
    }
    if (refusal == null) {
      return; // the module addresses the qualified table: nothing to report
    }
    assertThat(refusal.getMessage())
        .describedAs(
            "hibernate.default_schema is how most deployments name their schema, and it makes"
                + " every @BlindIndex mapping refuse. Refusing is fail-closed and acceptable; the"
                + " diagnosis is not, because there is no secondary table anywhere in this mapping"
                + " and the real reason is that this module interpolates the entity's table"
                + " unqualified, so what its statements hit is decided by search_path")
        .doesNotContain("secondary table");
    assertThat(refusal.getMessage()).contains("search_path");
  }

  private ConfigurableApplicationContext start(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("ninthpass-master-key-32-bytes!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("ninthpass-chain-secret-32-bytes!"),
            "shredding.blind-index.hmac-secret=" + b64("ninthpass-index-secret-32-bytes!"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true")
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

  private long countTwoIndexes(ConfigurableApplicationContext context, String owner) {
    try (var c = context.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select coalesce(sum((case when email_idx is not null then 1 else 0 end)"
                    + " + (case when phone_idx is not null then 1 else 0 end)), 0)"
                    + " from two_index_note where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private long countIndexes(ConfigurableApplicationContext context, String table, String owner) {
    try (var c = context.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from "
                    + table
                    + " where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
