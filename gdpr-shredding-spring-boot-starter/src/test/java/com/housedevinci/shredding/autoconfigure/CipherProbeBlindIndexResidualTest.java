package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.Note;
import com.housedevinci.shredding.autoconfigure.blindindexambient.NoteRepository;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Design addendum 3, change 5 (applied §3.5): verify inside the erasure transaction rather than
 * assume.
 *
 * <p>The {@code UPDATE} that nulls a blind-index column reports a row count. A row count is what
 * this module asked the database to do, not evidence of what the table now holds: between the
 * startup scan and this transaction the column can gain a trigger, a rule or a rewriting view. Here
 * a {@code BEFORE UPDATE} trigger puts the index straight back - the erasure clears one row, reads
 * it back inside its own transaction, finds it populated, and refuses. Nothing is recorded, the key
 * is not destroyed, and the DPO gets an error instead of a proof of an erasure that did not happen.
 */
@SpringBootTest(classes = CipherProbeBlindIndexResidualTest.ResidualApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeBlindIndexResidualTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Note.class)
  @EnableJpaRepositories(basePackageClasses = NoteRepository.class)
  static class ResidualApp {
    @org.springframework.context.annotation.Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @Autowired OwnedNoteRepository ownedNotes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;

  @AfterEach
  void dropTrigger() throws Exception {
    execute("DROP TRIGGER IF EXISTS shredding_probe_keep_idx ON owned_note");
  }

  @Test
  void probe_an_erasure_that_finds_an_index_still_populated_is_refused_not_recorded()
      throws Exception {
    String owner = "residual-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    execute(
        "CREATE OR REPLACE FUNCTION shredding_probe_keep_idx() RETURNS trigger AS $$ BEGIN"
            + " NEW.email_idx := OLD.email_idx; RETURN NEW; END; $$ LANGUAGE plpgsql");
    execute(
        "CREATE TRIGGER shredding_probe_keep_idx BEFORE UPDATE ON owned_note FOR EACH ROW EXECUTE"
            + " FUNCTION shredding_probe_keep_idx()");
    long recordsBefore = count("SELECT count(*) FROM shredding_erasure");

    ShreddingException refusal =
        refusalOf(
            () ->
                erasures.erase(
                    new ErasureRequest(
                        TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.ERASURE_INDEX_RESIDUAL);
    assertThat(refusal.getMessage()).contains("owned_note").contains("email_idx");
    assertThat(count("SELECT count(*) FROM shredding_erasure"))
        .describedAs("no erasure record claims a completion that did not happen")
        .isEqualTo(recordsBefore);
    assertThat(count("SELECT count(*) FROM shredding_data_key WHERE subject = '" + owner + "'"))
        .describedAs("the whole transaction rolled back, key destruction included")
        .isEqualTo(1);
  }

  /**
   * Change 5's second half. The same subject identifier under a different tenant value is
   * <b>not</b> a refusal - refusing would let one tenant's data block another tenant's erasure -
   * but it is the only place anyone ever sees it, so it is a WARN carrying the count. When the two
   * rows are the same person (a row moved between tenants by a bulk update outside Hibernate,
   * change 7) this line is the whole warning system.
   */
  @Test
  void probe_an_index_under_another_tenant_value_for_the_same_subject_warns_and_does_not_refuse()
      throws Exception {
    String owner = "shared-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-c", "victim@example.test"));
    var warnings = captureWarnings();
    try {
      var result =
          erasures.erase(
              new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
      assertThat(
              warnings.list.stream()
                  .map(ILoggingEvent::getFormattedMessage)
                  .filter(m -> m.contains("under other tenant values"))
                  .toList())
          .describedAs("the leftover under org-c is reported, with its count")
          .isNotEmpty();
      assertThat(
              count(
                  "SELECT count(*) FROM owned_note WHERE owner_id = '"
                      + owner
                      + "' AND email_idx IS NOT NULL"))
          .describedAs("the other tenant's row is untouched: this erasure was not asked for it")
          .isEqualTo(1);
    } finally {
      releaseWarnings(warnings);
    }
  }

  private static ListAppender<ILoggingEvent> captureWarnings() {
    var logger =
        (ch.qos.logback.classic.Logger)
            LoggerFactory.getLogger(com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore.class);
    var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void releaseWarnings(ListAppender<ILoggingEvent> appender) {
    var logger =
        (ch.qos.logback.classic.Logger)
            LoggerFactory.getLogger(com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore.class);
    logger.detachAppender(appender);
    appender.stop();
  }

  private static ShreddingException refusalOf(Runnable erasure) {
    try {
      erasure.run();
    } catch (RuntimeException thrown) {
      for (Throwable t = thrown; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          return s;
        }
      }
      throw new AssertionError("the erasure failed, but not with a ShreddingException", thrown);
    }
    throw new AssertionError("the erasure was not refused");
  }

  private void execute(String sql) throws Exception {
    try (var c = dataSource.getConnection();
        var st = c.createStatement()) {
      st.execute(sql);
    }
  }

  private long count(String sql) throws Exception {
    try (var c = dataSource.getConnection();
        var st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getLong(1) : 0L;
    }
  }
}
