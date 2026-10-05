package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.admission.joined.B2JoinedLeaf;
import com.housedevinci.shredding.autoconfigure.admission.joinedpk.B2PkLeaf;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.autoconfigure.admission.single.B2SingleLeaf;
import com.housedevinci.shredding.autoconfigure.cipherprobe19.tpc.C19TpcLeaf;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Mapping admission at startup (name-resolution design, addendum section A.5): the bean's
 * lifecycle, what it refuses and what it only warns about, and the treatment of JPA inheritance the
 * addendum states - the check addresses the one table the module's statements address, the entity's
 * own mapped table, and nothing else.
 */
@Testcontainers
class CipherProbePr19StarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static class Tenant {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class PlainApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2JoinedLeaf.class)
  static class JoinedApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2PkLeaf.class)
  static class JoinedPkApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2SingleLeaf.class)
  static class SingleApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = C19TpcLeaf.class)
  static class TpcApp extends Tenant {}

  private final ListAppender<ILoggingEvent> warnings = new ListAppender<>();

  /**
   * Attached once the context's logging system is initialised: Spring Boot resets logback the first
   * time a context starts in a JVM, which would drop an appender attached before it.
   */
  private void captureWarnings() {
    warnings.start();
    ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(MappingAdmissionCheck.class))
        .addAppender(warnings);
  }

  @AfterEach
  void reset() throws SQLException {
    ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(MappingAdmissionCheck.class))
        .detachAppender(warnings);
    sql(
        "DO $$ BEGIN"
            + " IF EXISTS (SELECT 1 FROM pg_views WHERE schemaname = 'public'"
            + " AND viewname = 'b2_note') THEN DROP VIEW public.b2_note; END IF; END $$",
        "DROP TABLE IF EXISTS public.b2_note CASCADE",
        "DROP TABLE IF EXISTS public.b2_note_base CASCADE");
  }

  /**
   * Deviation 4 of PR 19: TABLE_PER_CLASS is the one inheritance strategy the PR leaves untested.
   * The leaf declares its own shredded and blind-indexed columns; its rows live only in its own
   * table, which is the one table the erasure and admission must address.
   */
  @Test
  void probe_a_table_per_class_leaf_is_checked_on_its_own_table_and_erases() {
    try (var ctx = builder(TpcApp.class, "create-drop").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      assertThat(ctx.getBean(ShreddedModel.class).admissionTargets())
          .singleElement()
          .satisfies(t -> assertThat(t.table().toString()).isEqualTo("public.c19_tpc_leaf"));
      persist(
          ctx.getBean(EntityManagerFactory.class), new C19TpcLeaf(7L, "tpc1", "org-b", "a@b.test"));
      assertThat(count("SELECT count(*) FROM public.c19_tpc_leaf WHERE email_idx IS NOT NULL"))
          .isEqualTo(1);
      ctx.getBean(ErasureService.class)
          .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("tpc1"), "dpo", "art 17"));
      assertThat(count("SELECT count(*) FROM public.c19_tpc_leaf WHERE email_idx IS NOT NULL"))
          .isZero();
      // The polymorphic root query is a UNION over both tables; the residue is nowhere.
      assertThat(count("SELECT count(*) FROM public.c19_tpc_root")).isZero();
    }
  }

  // ---------------------------------------------------------------------------------------------

  private SpringApplicationBuilder builder(Class<?> app, String ddlAuto) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .listeners(
            (org.springframework.context.ApplicationListener<
                    org.springframework.boot.context.event.ApplicationPreparedEvent>)
                e -> captureWarnings())
        .properties(
            "shredding.master-key=" + b64("b2-admission-master-key-32-bytes"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("b2-admission-chain-secret-32-byt"),
            "shredding.blind-index.hmac-secret=" + b64("b2-admission-index-secret-32-byt"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=" + ddlAuto,
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
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

  private static void sql(String... statements) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      for (String s : statements) {
        st.execute(s);
      }
    }
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

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in " + thrown, thrown);
  }

  private static String message(Throwable thrown) {
    var out = new ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      out.add(String.valueOf(t.getMessage()));
    }
    return String.join(" | ", out);
  }
}
