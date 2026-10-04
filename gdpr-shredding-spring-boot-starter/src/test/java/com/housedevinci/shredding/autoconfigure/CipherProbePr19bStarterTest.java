package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.cipherprobe19b.idsubject.C19bOwner;
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
import java.util.UUID;
import org.junit.jupiter.api.Test;
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
 * Second pass of the PR 19 review, startup leg: the admission targets the startup check builds must
 * carry clause C-i for the tenant and subject columns even when one of them is also the entity's
 * identifier column.
 */
@Testcontainers
class CipherProbePr19bStarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = C19bOwner.class)
  static class OwnerApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  private void captureWarnings() {}

  /**
   * C-19-7 (LOW). The subject column is the uuid identifier column, reached through a read-only
   * String property mapped over it. The startup target lists the identifier first (COMPARED, role
   * identifier) and the subject's {@code addOnce} drops the same ref with the same use, so C-i
   * never sees it: startup is green. The erasure leg builds its targets from the blind indexes
   * alone, so there the column is the subject and C-i refuses every erasure. Startup and erasure
   * must agree: the context must refuse to start with C-i.
   */
  @Test
  void probe_a_subject_column_that_is_also_the_identifier_skips_c_i_at_startup() {
    Throwable started = null;
    try (var ctx = builder(OwnerApp.class, "create-drop").run()) {
      System.out.println(
          "CIPHER-B2 startup targets: " + ctx.getBean(ShreddedModel.class).admissionTargets());
      UUID id = UUID.fromString("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11");
      persist(ctx.getBean(EntityManagerFactory.class), new C19bOwner(id, "org-b", "a@b.test"));
      Throwable erased =
          catchThrowable(
              () ->
                  ctx.getBean(ErasureService.class)
                      .erase(
                          new ErasureRequest(
                              TenantId.of("org-b"), SubjectId.of(id.toString()), "dpo", "art 17")));
      System.out.println("CIPHER-B2 erasure: " + (erased == null ? "ok" : message(erased)));
      System.out.println(
          "CIPHER-B2 residue: "
              + count("SELECT count(*) FROM public.c19b_owner WHERE email_idx IS NOT NULL"));
    } catch (RuntimeException e) {
      started = e;
    }
    assertThat(started).describedAs("startup must refuse what every erasure refuses").isNotNull();
    assertThat(code(started)).isEqualTo("SHRED-SCHEMA-009");
    assertThat(message(started)).contains("public.c19b_owner.id is of type uuid");
  }

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
