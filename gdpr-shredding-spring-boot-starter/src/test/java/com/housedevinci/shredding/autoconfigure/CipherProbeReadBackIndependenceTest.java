package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
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

/**
 * Design addendum 4, §4.5: the erasure's own read-back has to be <em>independent</em> of the text
 * the erasure was built from, and has to run on the erasure's own connection, in its own
 * transaction, on a session that cannot flush and never commits.
 */
@Testcontainers
class CipherProbeReadBackIndependenceTest {

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
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class App {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /**
   * The decoy. The erasure's {@code UPDATE} is given a subject column that matches nothing, so it
   * clears no row and its own same-text read-back agrees with it. Only a residual Hibernate renders
   * from the mapping sees the row that is still there. This is the probe that fails the moment the
   * residual is ever rebuilt from the erasure's own text.
   */
  @Test
  void probe_a_mis_addressed_erasure_is_caught_by_the_hibernate_rendered_residual() {
    try (var ctx = start(DecoyApp.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "decoy-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));
      long recordsBefore = count(ctx, "select count(*) from shredding_erasure");

      assertThatThrownBy(
              () ->
                  erasures.erase(
                      new ErasureRequest(
                          TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17")))
          .isInstanceOf(ShreddingException.class)
          .extracting(t -> ((ShreddingException) t).code())
          .isEqualTo(ErrorCodes.ERASURE_INDEX_RESIDUAL);

      assertThat(keys(ctx, victim)).describedAs("the key was destroyed anyway").isEqualTo(1);
      assertThat(count(ctx, "select count(*) from shredding_erasure"))
          .describedAs("a record was appended for an erasure that did not happen")
          .isEqualTo(recordsBefore);
      assertThat(indexes(ctx, victim))
          .describedAs("the index is still there, which is why this refused")
          .isEqualTo(1);
    }
  }

  /**
   * Change 8. {@code AND email_idx IS NOT NULL} makes the {@code UPDATE}'s row count a subset of
   * the subject's rows, so a nullable index is an ordinary, correct erasure - not a mismatch to
   * refuse.
   */
  @Test
  void probe_a_partially_null_index_erases_without_refusing() {
    try (var ctx = start(App.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "partial-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));
      // A second row for the same subject whose index was never populated - a nullable field, a
      // row written before the index column existed, a retry after a partial failure.
      execute(
          ctx,
          "insert into owned_note (owner_id, tenant_id, email, email_idx) values ('"
              + victim
              + "', 'org-a', null, null)");

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, victim)).isZero();
    }
  }

  /**
   * Change 9. The check runs on the erasure's own connection. A pool of one proves it: a second
   * connection cannot be had, and this transaction already holds the advisory lock and the {@code
   * SELECT ... FOR UPDATE} rows, so asking for one deadlocks rather than merely queues.
   */
  @Test
  void probe_the_independence_check_takes_no_second_connection() throws Exception {
    try (var ctx =
        builder(App.class)
            .properties(
                "spring.datasource.hikari.maximum-pool-size=1",
                "spring.datasource.hikari.connection-timeout=3000")
            .run()) {
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "pool1-" + System.nanoTime();
      // The row is written outside the pool on purpose. The write path legitimately holds
      // Hibernate's connection and asks the key store for a second one, so a pool of one is not a
      // shape an application ever runs writes under; what this probe pins is the *erasure*, which
      // takes exactly one connection and must not ask for another to verify itself.
      sql(
          "insert into owned_note (owner_id, tenant_id, email, email_idx) values ('"
              + victim
              + "', 'org-a', null, '\\x0102')");

      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(indexes(ctx, victim)).isZero();
    }
  }

  /**
   * Change 9, the other half. A stateful auto-flushing session would flush pending entity state at
   * the query and write a blind index back <em>after</em> the clear. The session the check uses
   * cannot flush at all, and it is not the caller's session in any case.
   */
  @Test
  void probe_the_independence_check_cannot_flush_pending_writes() {
    try (var ctx = start(App.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      var emf = ctx.getBean(EntityManagerFactory.class);
      String victim = "flush-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));

      var em = emf.createEntityManager();
      try {
        em.getTransaction().begin();
        // Dirty with an unflushed insert for the very subject being erased.
        em.persist(new OwnedNote(victim, "org-a", "second@example.test"));

        var result =
            erasures.erase(
                new ErasureRequest(TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17"));

        assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
        assertThat(indexes(ctx, victim))
            .describedAs("the pending insert was flushed by the residual check, after the clear")
            .isZero();
      } finally {
        em.getTransaction().rollback();
        em.close();
      }
    }
  }

  /**
   * Change 10, stated as intent. A row committed for the subject after the {@code UPDATE}'s
   * snapshot - here by a second connection while an {@code AFTER UPDATE} trigger holds the erasure
   * inside its statement - carries a live index for a subject whose key is about to be destroyed.
   * That refuses the erasure. It is not a race to retry away.
   */
  @Test
  void probe_a_row_inserted_for_the_subject_after_the_clear_refuses_the_erasure() throws Exception {
    try (var ctx = start(App.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "late-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));
      sql(
          "create or replace function shredding_probe_slow() returns trigger as $$ begin"
              + " perform pg_sleep(2); return null; end; $$ language plpgsql");
      sql(
          "create trigger shredding_probe_slow_trg after update on owned_note"
              + " for each row execute function shredding_probe_slow()");
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
        // Committed on its own connection, after the UPDATE's snapshot.
        sql(
            "insert into owned_note (owner_id, tenant_id, email, email_idx) values ('"
                + victim
                + "', 'org-a', null, '\\x0102')");

        assertThat(erasure.get()).isEqualTo(ErrorCodes.ERASURE_INDEX_RESIDUAL);
        assertThat(keys(ctx, victim)).describedAs("the key was destroyed anyway").isEqualTo(1);
      } finally {
        sql("drop trigger if exists shredding_probe_slow_trg on owned_note");
      }
    }
  }

  /**
   * Revision review, hazard (a). The stateless session must never begin or commit a transaction on
   * the erasure's connection: doing so would commit a half-done erasure - index cleared, key
   * destroyed, no record appended. Proven by failing the append afterwards and showing the clear
   * did not survive.
   */
  @Test
  void probe_the_independence_check_never_commits_the_erasures_transaction() throws Exception {
    try (var ctx = start(App.class)) {
      var notes = ctx.getBean(OwnedNoteRepository.class);
      var erasures = ctx.getBean(ErasureService.class);
      String victim = "nocommit-" + System.nanoTime();
      notes.saveAndFlush(new OwnedNote(victim, "org-a", "victim@example.test"));
      sql(
          "create or replace function shredding_probe_refuse() returns trigger as $$ begin"
              + " raise exception 'probe: the append fails after the residual check'; end;"
              + " $$ language plpgsql");
      sql(
          "create trigger shredding_probe_refuse_trg before insert on shredding_erasure"
              + " for each row execute function shredding_probe_refuse()");
      try {
        assertThatThrownBy(
                () ->
                    erasures.erase(
                        new ErasureRequest(
                            TenantId.of("org-a"), SubjectId.of(victim), "dpo", "art 17")))
            .isInstanceOf(RuntimeException.class);

        assertThat(indexes(ctx, victim))
            .describedAs(
                "the clear survived a rolled-back erasure, so something committed the erasure's"
                    + " own connection before the record was appended")
            .isEqualTo(1);
        assertThat(keys(ctx, victim)).isEqualTo(1);
      } finally {
        sql("drop trigger if exists shredding_probe_refuse_trg on shredding_erasure");
      }
    }
  }

  // ---------------------------------------------------------------- helpers

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class DecoyApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    /**
     * The erasure's own statements are built from a subject column that matches nothing. The
     * residual is not: it is rendered by Hibernate from the mapping.
     */
    @Bean
    com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore shreddingErasureStore(
        DataSource dataSource,
        com.housedevinci.shredding.domain.ErasureChain chain,
        ShreddedModel model,
        jakarta.persistence.EntityManagerFactory entityManagerFactory) {
      com.housedevinci.shredding.adapter.jdbc.JdbcSupport.initializeSchema(dataSource);
      var decoys =
          model.blindIndexColumns().stream()
              .map(CipherProbeReadBackIndependenceTest::decoy)
              .toList();
      return new com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore(
          dataSource,
          chain,
          decoys,
          new HibernateBlindIndexResidual(
              entityManagerFactory.unwrap(org.hibernate.engine.spi.SessionFactoryImplementor.class),
              model));
    }
  }

  private static com.housedevinci.shredding.domain.BlindIndexColumn decoy(
      com.housedevinci.shredding.domain.BlindIndexColumn column) {
    return new com.housedevinci.shredding.domain.BlindIndexColumn(
        column.table(),
        column.column(),
        // tenant_id in the subject position: a valid, mapped column that never holds a subject id,
        // so the UPDATE matches nothing and its same-text read-back agrees.
        column.tenantColumn(),
        column.tenantColumn(),
        column.tenantProperty(),
        column.subjectProperty());
  }

  private static void sql(String statement) throws java.sql.SQLException {
    try (var c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement()) {
      st.execute(statement);
    }
  }

  private static void execute(ConfigurableApplicationContext ctx, String statement) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var st = c.createStatement()) {
      st.execute(statement);
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long count(ConfigurableApplicationContext ctx, String query) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var st = c.createStatement();
        var rs = st.executeQuery(query)) {
      return rs.next() ? rs.getLong(1) : 0L;
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long indexes(ConfigurableApplicationContext ctx, String owner) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from owned_note where owner_id = ? and email_idx is not null")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        return rs.next() ? rs.getLong(1) : 0L;
      }
    } catch (java.sql.SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long keys(ConfigurableApplicationContext ctx, String subject) {
    try (var c = ctx.getBean(DataSource.class).getConnection();
        var ps =
            c.prepareStatement(
                "select count(*) from shredding_data_key where tenant = 'org-a' and subject = ?")) {
      ps.setString(1, subject);
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
            "shredding.master-key=" + b64("readback-master-key-32-bytes!!!!"),
            "shredding.erasure-log.hmac-secret=" + b64("readback-chain-secret-32-bytes!!"),
            "shredding.blind-index.hmac-secret=" + b64("readback-index-secret-32-bytes!!"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
  }

  private ConfigurableApplicationContext start(Class<?> app) {
    return builder(app).run();
  }
}
