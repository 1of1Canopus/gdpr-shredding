package com.housedevinci.shredding.cipherrc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureResult;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.ShreddingEventListener;
import com.housedevinci.shredding.cipherrc.aud1.RcAuditedNote;
import com.housedevinci.shredding.cipherrc.aud2.RcAuditedIndexNote;
import com.housedevinci.shredding.cipherrc.aud3.RcComposedNote;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Release-candidate whole-module pass, 0.2.0, lead 1: Hibernate Envers on a {@code @Shredded}
 * entity that carries a {@code @BlindIndex}.
 *
 * <p>Envers mirrors every audited column into {@code <table>_aud}, the blind-index column included.
 * No erasure statement, no admission target and neither read-back addresses that table, so an
 * erasure records {@code COMPLETE} while the erased subject's index survives, queryable with the
 * application's own index secret. The module's own text says an index that survives an erasure
 * "keeps the erased subject searchable and linkable for ever, which defeats the product".
 *
 * <p>The property that must hold: after an erasure recorded {@code COMPLETE}, no relation the
 * application's own Hibernate mapping created holds the erased subject's blind index. Either the
 * context refuses to start, naming Envers and the blind-index column, or the erasure reaches the
 * audit table too.
 */
@Testcontainers
class CipherProbeRc020EnversTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static class Tenant {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcAuditedNote.class)
  static class AuditedApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcAuditedIndexNote.class)
  static class AuditedIndexApp extends Tenant {}

  /**
   * The composition the listener-order refusal points at ("see shreddingHibernateCustomizer for how
   * to compose instead of displacing it"): the application provides Envers' own integrator through
   * {@code hibernate.integrator_provider}, ordered before this module's customizer, which composes
   * it first and itself last. Envers' own auto-registration is off ({@code
   * hibernate.envers.autoRegisterListeners=false}), its documented manual mode.
   */
  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcComposedNote.class)
  static class ComposedApp extends Tenant {
    @Bean
    @org.springframework.core.annotation.Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE)
    org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer enversFirst() {
      return props ->
          props.put(
              org.hibernate.jpa.boot.spi.JpaSettings.INTEGRATOR_PROVIDER,
              (org.hibernate.jpa.boot.spi.IntegratorProvider)
                  () ->
                      java.util.List.of(
                          new com.housedevinci.shredding.cipherrc.aud3.EnversFirstIntegrator()));
    }
  }

  /**
   * RC-0.2.0-1. Envers composed the way the module's own refusal suggests, ciphertext
   * {@code @NotAudited}, blind index audited. If the context starts, the erasure records {@code
   * COMPLETE} and the audit table keeps the erased subject's blind index.
   */
  @Test
  void probe_envers_composed_as_advised_keeps_the_erased_subjects_blind_index() {
    assertIndexGoneFromAudit(
        ComposedApp.class,
        "rc_composed_note",
        RcComposedNote::new,
        "--spring.jpa.properties.hibernate.envers.autoRegisterListeners=false");
  }

  /**
   * RC-0.2.0-2. The whole entity audited: Envers maps {@code RcAuditedNote_AUD.email} with the
   * module's converter, and startup refuses (fail closed, good). The message blames a class-level
   * {@code @Convert}, an orm.xml mapping or an embeddable - none of which the application has - and
   * never names Envers or the blind index. The remedy a developer then reaches for is
   * {@code @NotAudited} on the ciphertext field, which is the shape of the next probe.
   */
  @Test
  void probe_envers_audited_shredded_entity_is_refused_with_a_message_naming_other_causes() {
    Throwable thrown = catchThrowable(() -> builder(AuditedApp.class).run(args()).close());
    assertThat(thrown).isNotNull();
    ShreddingException refusal = shreddingCause(thrown);
    assertThat(refusal).isNotNull();
    System.out.println("CIPHER-RC envers refusal: " + refusal.getMessage());
    assertThat(refusal.getMessage())
        .describedAs("the refusal must name Envers / @Audited as the cause, and the blind index")
        .containsIgnoringCase("envers");
  }

  /**
   * RC-0.2.0-1. Ciphertext {@code @NotAudited}, blind index audited (the default for a plain
   * column). Startup admits it; the erasure records {@code COMPLETE}; the audit table keeps the
   * erased subject's blind index, which the application's own index secret still matches.
   */
  /**
   * RC-0.2.0-2 (second shape). Ciphertext {@code @NotAudited}, blind index audited, default
   * composition: startup refuses on listener order. Fail closed; the probe asserts the refusal
   * names Envers and the blind-index column rather than pointing the developer at a composition.
   */
  @Test
  void probe_envers_audited_blind_index_is_refused_without_naming_the_index() {
    assertIndexGoneFromAudit(
        AuditedIndexApp.class, "rc_audited_index_note", RcAuditedIndexNote::new);
  }

  interface NoteFactory {
    Object create(Long id, String owner, String tenant, String email);
  }

  private void assertIndexGoneFromAudit(
      Class<?> app, String table, NoteFactory note, String... extra) {
    ConfigurableApplicationContext ctx;
    try {
      ctx =
          builder(app)
              .run(
                  java.util.stream.Stream.concat(
                          java.util.Arrays.stream(args()), java.util.Arrays.stream(extra))
                      .toArray(String[]::new));
    } catch (RuntimeException refused) {
      // Secure by refusal: startup names Envers and the audited blind-index column.
      ShreddingException refusal = shreddingCause(refused);
      assertThat(refusal).describedAs("refusal cause: %s", refused).isNotNull();
      System.out.println("CIPHER-RC envers " + table + " refusal: " + refusal.getMessage());
      assertThat(refusal.getMessage()).containsIgnoringCase("envers").contains("email_idx");
      return;
    }
    try (ctx) {
      persist(ctx.getBean(EntityManagerFactory.class), note.create(1L, "s1", "org-b", "a@b.test"));
      assertThat(count("SELECT count(*) FROM public." + table + " WHERE email_idx IS NOT NULL"))
          .isEqualTo(1);
      long audBefore =
          count(
              "SELECT count(*) FROM public."
                  + table
                  + "_aud WHERE owner_id = 's1' AND email_idx IS NOT NULL");
      ErasureResult result =
          ctx.getBean(ErasureService.class)
              .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("s1"), "dpo", "art 17"));
      long audAfter =
          count(
              "SELECT count(*) FROM public."
                  + table
                  + "_aud WHERE owner_id = 's1' AND email_idx IS NOT NULL");
      System.out.println(
          "CIPHER-RC envers "
              + table
              + ": outcome="
              + result.outcome()
              + " main-table index left="
              + count("SELECT count(*) FROM public." + table + " WHERE email_idx IS NOT NULL")
              + " aud rows with index before="
              + audBefore
              + " after="
              + audAfter);
      assertThat(result.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
      assertThat(audAfter)
          .as(
              "blind-index copies of the erased subject left in the Envers audit table after a"
                  + " COMPLETE erasure")
          .isZero();
    }
  }

  private static ShreddingException shreddingCause(Throwable t) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      if (c instanceof ShreddingException se) {
        return se;
      }
      if (c.getCause() == c) {
        break;
      }
    }
    return null;
  }

  private SpringApplicationBuilder builder(Class<?> app) {
    return new SpringApplicationBuilder(app).web(WebApplicationType.NONE);
  }

  /**
   * Command-line arguments, not default properties: the sample's own application.yml binds the
   * secrets from the environment and would otherwise win.
   */
  private static String[] args() {
    return java.util.stream.Stream.of(
            "shredding.master-key=" + b64("rc-envers-probe-master-key-32-by"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("rc-envers-probe-chain-secret-32b"),
            "shredding.blind-index.hmac-secret=" + b64("rc-envers-probe-index-secret-32b"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.properties.hibernate.default_schema=public",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
            "spring.autoconfigure.exclude="
                + "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration")
        .map(a -> "--" + a)
        .toArray(String[]::new);
  }

  private static void persist(EntityManagerFactory emf, Object entity) {
    var em = emf.createEntityManager();
    try {
      em.getTransaction().begin();
      em.persist(entity);
      em.getTransaction().commit();
    } finally {
      em.close();
    }
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static long count(String statement) {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement();
        ResultSet rs = st.executeQuery(statement)) {
      return rs.next() ? rs.getLong(1) : -1L;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
