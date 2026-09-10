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
 * Cipher, twelfth pass: the one finding. RED against 13535d8. Run with {@code ./mvnw
 * -Pprobes-pending test}; promote into {@code src/test} when it is green.
 */
@Testcontainers
class CipherProbeTwelfthPassPendingTest {

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
          com.housedevinci.shredding.autoconfigure.twelfthpass.secondaryidx.SecondaryIdxNote.class)
  @EnableJpaRepositories(
      basePackageClasses =
          com.housedevinci.shredding.autoconfigure.twelfthpass.secondaryidx.SecondaryIdxNote.class)
  static class SecondaryIndexApp extends Tenant {}

  /**
   * The {@code @BlindIndex} column's own table is never compared with the entity's primary table.
   * {@code resolveIndexColumns} takes the table from {@code primaryTable(persister)} and the column
   * from the field's mapping, so a field mapped by {@code @Column(table = "...")} onto a
   * {@code @SecondaryTable} yields a {@link com.housedevinci.shredding.domain.BlindIndexColumn}
   * that names a column of one table and the name of another. Both other axes refuse this at
   * startup, naming the mapping; this one must too.
   */
  @Test
  void probe_a_blind_index_column_on_a_secondary_table_is_refused_at_startup() {
    ConfigurableApplicationContext context = null;
    String startup;
    try {
      context = builder(SecondaryIndexApp.class).run();
      startup = "STARTED";
    } catch (RuntimeException e) {
      startup = "STARTUP-REFUSED " + code(e);
    }
    if (context == null) {
      assertThat(startup).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
      assertThat(startup).contains("SecondaryIdxNote").contains("secidx_note_ext");
      return;
    }
    String erasure;
    try (var ctx = context) {
      var notes =
          ctx.getBean(
              com.housedevinci.shredding.autoconfigure.twelfthpass.secondaryidx
                  .SecondaryIdxNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String owner = "secidx-" + System.nanoTime();
      notes.saveAndFlush(
          new com.housedevinci.shredding.autoconfigure.twelfthpass.secondaryidx.SecondaryIdxNote(
              owner, "org-a", "victim@example.test"));
      try {
        var result =
            erasures.erase(
                new ErasureRequest(TenantId.of("org-a"), SubjectId.of(owner), "dpo", "art 17"));
        erasure =
            "COMPLETED outcome="
                + result.outcome()
                + " cleared="
                + result.blindIndexColumnsCleared()
                + " residual="
                + indexes(ctx, "secidx_note_ext", "id", owner);
      } catch (RuntimeException e) {
        erasure = "ERASURE-FAILED " + code(e);
      }
      // What the failure cost: if the transaction rolled back, the subject's key is still there
      // and the ciphertext still decrypts - the erasure is impossible, not half-done. This is the
      // difference between LOW and HIGH, so it is asserted rather than assumed.
      var still =
          notes.findAll().stream()
              .filter(n -> owner.equals(n.getOwnerId()))
              .findFirst()
              .orElse(null);
      erasure =
          erasure
              + " | row still readable after the failure: "
              + (still != null && still.getEmail() != null);
    }
    throw new AssertionError(
        "a @BlindIndex column mapped onto a @SecondaryTable booted; the erasure then said: "
            + erasure);
  }

  private long indexes(ConfigurableApplicationContext ctx, String table, String column, String v) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from " + table + " where " + column + " = ? and email_idx is not"
                    + " null")) {
      ps.setString(1, v);
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
