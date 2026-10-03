package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.cipherpr18restricted.Pr18RestrictedNote;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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
 * Security review, PR 18 (feat/read-back-bracket), first pass, starter side. RED on f3fc861.
 *
 * <p>Copy the test and its fixture package ({@code cipherpr18restricted}) into
 * gdpr-shredding-spring-boot-starter/src/test/java/com/housedevinci/shredding/autoconfigure/.
 */
@Testcontainers
class CipherProbePr18StarterTest {

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
  @EntityScan(basePackageClasses = Pr18RestrictedNote.class)
  static class RestrictedApp extends Tenant {}

  /**
   * C-18-2. A {@code @SQLRestriction} (and an auto-enabled {@code @Filter}) is SQL text the
   * application wrote into its mapping, and Hibernate renders it into the independent read-back -
   * so it now runs inside the window. A restriction that calls an application function or names a
   * relation unqualified resolves everywhere the application runs it and nowhere inside the window:
   * every erasure of that entity fails with 42883/42P01. SECURITY-NOTES' list of "what a SELECT can
   * still run inside the window" names RLS policy functions and view functions, and the upgrade
   * page repeats it; neither names the mapping's own SQL fragments, which are the commoner case.
   *
   * <p>Measured here: the erasure is refused loudly and rolled back whole (the data key is still
   * there) - that half is the fail-closed property and must stay. RED on the documentation half.
   */
  @Test
  void probe_a_mapping_restriction_rendered_into_the_window_is_documented_and_fails_closed()
      throws Exception {
    sql(
        "CREATE OR REPLACE FUNCTION public.pr18_visible(pg_catalog.varchar) RETURNS boolean"
            + " AS $$ SELECT true $$ LANGUAGE sql");
    String outcome =
        bootAndErase(
            RestrictedApp.class,
            emf -> {
              persist(
                  emf, new Pr18RestrictedNote("restricted-victim", "org-b", "victim@example.test"));
              return "restricted-victim";
            });
    assertThat(outcome)
        .describedAs("loud, and the whole erasure rolled back: the key is still there")
        .startsWith("ERASURE-FAILED")
        .contains("pr18_visible")
        .contains("KEY-PRESENT 1");

    for (String doc : List.of("SECURITY-NOTES.md", "docs/upgrading-0.2.0.md")) {
      assertThat(Files.readString(moduleRoot().resolve(doc), StandardCharsets.UTF_8))
          .describedAs(
              doc
                  + " names the mapping's own SQL fragments among what runs inside the window: "
                  + outcome)
          .contains("@SQLRestriction")
          .contains("@Filter");
    }
  }

  // ---------------------------------------------------------------------------------------------

  private String bootAndErase(Class<?> app, Function<EntityManagerFactory, String> fixture) {
    var sqlLog = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger("org.hibernate.SQL");
    var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    sqlLog.addAppender(appender);
    Level before = sqlLog.getLevel();
    sqlLog.setLevel(Level.DEBUG);
    try (ConfigurableApplicationContext ctx = builder(app).run()) {
      String owner = fixture.apply(ctx.getBean(EntityManagerFactory.class));
      appender.list.clear();
      try {
        ctx.getBean(ErasureService.class)
            .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));
        return "STARTED-AND-ERASED";
      } catch (RuntimeException e) {
        String rendered =
            appender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.contains("count("))
                .findFirst()
                .orElse("<no count statement logged>");
        System.out.println("CIPHER-PR18 rendered read-back: " + rendered);
        return "ERASURE-FAILED "
            + chain(e)
            + " KEY-PRESENT "
            + count(
                "SELECT pg_catalog.count(*) FROM public.shredding_data_key WHERE subject = '"
                    + owner
                    + "'");
      }
    } catch (RuntimeException e) {
      return "STARTUP-REFUSED " + code(e);
    } finally {
      sqlLog.detachAppender(appender);
      sqlLog.setLevel(before);
    }
  }

  private SpringApplicationBuilder builder(Class<?> app) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(
            "shredding.master-key=" + b64("pr18-review-master-key-32-bytes!"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("pr18-review-chain-secret-32-byte"),
            "shredding.blind-index.hmac-secret=" + b64("pr18-review-index-secret-32-byte"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=create-drop",
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

  private static Path moduleRoot() {
    Path here = Path.of("").toAbsolutePath();
    return Files.exists(here.resolve("SECURITY-NOTES.md")) ? here : here.getParent();
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static void sql(String statement) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute(statement);
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
      return -1L;
    }
  }

  private static String chain(Throwable thrown) {
    var sb = new StringBuilder();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      sb.append(t.getClass().getSimpleName()).append(": ").append(t.getMessage()).append(" | ");
    }
    return sb.toString();
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
