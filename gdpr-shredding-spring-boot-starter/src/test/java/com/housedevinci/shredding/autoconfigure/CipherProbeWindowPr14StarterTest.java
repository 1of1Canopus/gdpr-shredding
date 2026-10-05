package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNote;
import com.housedevinci.shredding.autoconfigure.blindindexambient.OwnedNoteRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * PR B1 at the only place the statement under test is rendered by the framework for real: a live
 * Hibernate mapping, on a hostile {@code search_path}, through {@code ErasureService}.
 *
 * <p>{@code OwnedNote}'s subject and tenant columns are {@code varchar(255)} - which is what
 * Hibernate maps a {@code String} to - and the HQL read-back of {@code HibernateBlindIndexResidual}
 * renders {@code where e.ownerId = :subject and e.tenantId = :tenant and e.emailIndex is not null}.
 * An {@code =(varchar, varchar)} in a schema ahead of {@code pg_catalog} is an exact-type match for
 * both comparisons and is selected whatever the path order (N-1), so this is the leg a role that
 * owns one schema can make answer zero. Nothing in the text is the module's to qualify: Hibernate
 * renders it, and HQL has no spelling for {@code OPERATOR(pg_catalog.=)} or {@code
 * pg_catalog.count(*)}.
 *
 * <p><b>The hostile path, spelled out.</b> {@code pg_catalog} is implicitly <em>first</em> on a
 * {@code search_path} that does not name it, so the stock {@code "$user", public} is not hostile:
 * the attack needs {@code pg_catalog} demoted by being named late. Every pooled connection is
 * initialised with {@code SET search_path = public, pg_catalog} - a connection-init SQL rather than
 * an {@code ALTER ROLE}, so no pool has to be rebuilt.
 *
 * <p>The first two cases are RED on {@code d1289db}. The third is the one the window must
 * <em>not</em> break, and it is the test that forbids revision 1's transaction-wide pin: it is
 * green on {@code d1289db} and green after, and red only under mutation 9 (widen the window from
 * the statement to the transaction).
 */
@SpringBootTest(classes = CipherProbeWindowPr14StarterTest.WindowApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeWindowPr14StarterTest {

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
    registry.add("shredding.jdbc.initialize-schema", () -> "true");
    registry.add("shredding.jdbc.allow-privileged-runtime-role", () -> "true");
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    registry.add("spring.jpa.properties.hibernate.default_schema", () -> "public");
    registry.add(
        "spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
    registry.add(
        "spring.datasource.hikari.connection-init-sql",
        () -> "SET search_path = public, pg_catalog");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = OwnedNote.class)
  @EnableJpaRepositories(basePackageClasses = OwnedNoteRepository.class)
  static class WindowApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  @Autowired OwnedNoteRepository ownedNotes;
  @Autowired ErasureService erasures;
  @Autowired DataSource dataSource;

  @AfterEach
  void removeTheFixture() {
    execute(
        "DROP TRIGGER IF EXISTS shredding_probe_keep_idx ON public.owned_note",
        "DROP TRIGGER IF EXISTS shredding_probe_audit ON public.owned_note",
        "DROP OPERATOR IF EXISTS public.= (pg_catalog.varchar, pg_catalog.varchar)");
  }

  /**
   * N15 against the real rendering. A {@code BEFORE UPDATE} trigger puts the index straight back,
   * so one row still holds an HMAC of the erased plaintext after the erasure's {@code UPDATE} and
   * both read-backs must refuse. Only the framework-rendered one says "read back through the
   * entity's own mapping", so the assertion on the message is the assertion that the leg answered
   * truthfully: with the shadow in place and no window, it answers 0 and the refusal that is left
   * is the module's own qualified same-text count, with a different message.
   */
  @Test
  void probe_a_shadowed_varchar_equality_cannot_make_the_hql_read_back_answer_zero() {
    String owner = "window-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    execute(
        "CREATE OR REPLACE FUNCTION public.shredding_probe_keep_idx() RETURNS trigger AS $$ BEGIN"
            + " NEW.email_idx := OLD.email_idx; RETURN NEW; END; $$ LANGUAGE plpgsql",
        "CREATE TRIGGER shredding_probe_keep_idx BEFORE UPDATE ON public.owned_note"
            + " FOR EACH ROW EXECUTE FUNCTION public.shredding_probe_keep_idx()");
    shadowVarcharEquality();

    ShreddingException refusal =
        refusalOf(
            () ->
                erasures.erase(
                    new ErasureRequest(
                        TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17")));

    assertThat(refusal.code()).isEqualTo(ErrorCodes.ERASURE_INDEX_RESIDUAL);
    assertThat(refusal.getMessage())
        .describedAs(
            "the leg Hibernate renders is the one that has to refuse here; it is the only one that"
                + " does not share an identifier with the statements the erasure built")
        .contains("read back through the entity's own mapping");
    assertThat(
            count(
                "SELECT pg_catalog.count(*) FROM public.shredding_data_key"
                    + " WHERE (subject OPERATOR(pg_catalog.=) '"
                    + owner
                    + "')"))
        .describedAs(
            "the whole transaction rolled back, key destruction included. The operator is"
                + " qualified here because the shadow this case installs is still on the path:"
                + " a bare `=` in the assertion would answer 0 and the test would read a rollback"
                + " that did not happen")
        .isEqualTo(1);
  }

  /**
   * The cross-tenant WARN count. It runs outside any window since C-18-6: every name in it is
   * {@code pg_catalog}'s and its relation is two-part. It was once the one statement this module
   * built with a name qualification could not reach, {@code IS DISTINCT FROM}, the type's own
   * {@code =} behind a grammar keyword; C-A-6 removed that spelling.
   *
   * <p><b>What this case can and cannot show, measured here rather than assumed.</b> The wrong
   * answer T3c measured (2 where the truth is 1) is <em>not</em> reachable end to end, and that is
   * a fact about this statement and not about the shadow: the count's third conjunct is {@code
   * &lt;index&gt; IS NOT NULL}, and the only row a shadowed {@code IS DISTINCT FROM} would wrongly
   * admit is the row this erasure has just cleared - so it is excluded anyway. A fixture that keeps
   * the index populated to get around that makes the erasure refuse before the WARN runs. The
   * statement's exposure is therefore the accuracy of a log line, and it is measured directly, at
   * the SQL level with the parameter typed both ways, by {@code
   * CipherProbeWindowPr14Test#probe_the_cross_tenant_shape_is_only_correct_inside_the_window}.
   *
   * <p>What this case holds is the other half: the count must report only the rows under other
   * tenants and must not change the erasure's behaviour. It is red if the count is lost, counts the
   * wrong rows, or re-points the connection it was handed.
   */
  @Test
  void probe_the_cross_tenant_warn_counts_only_the_rows_under_other_tenants() {
    String owner = "shared-window-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-c", "victim@example.test"));
    shadowVarcharEquality();
    var warnings = captureWarnings();
    try {
      erasures.erase(
          new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

      assertThat(
              warnings.list.stream()
                  .map(ILoggingEvent::getFormattedMessage)
                  .filter(m -> m.contains("under other tenant values"))
                  .toList())
          .describedAs(
              "one leftover, under org-c, reported with its count - with the shadow installed, the"
                  + " window open around the count, and the erasure itself unaffected by either")
          .hasSize(1)
          .allSatisfy(m -> assertThat(m).contains(" 1 blind index value"));
    } finally {
      releaseWarnings(warnings);
    }
  }

  /**
   * N21, and the reason the window is one statement wide rather than one transaction wide (T15b vs
   * T17). An application {@code AFTER UPDATE} trigger whose body names a relation unqualified is an
   * ordinary application; revision 1's transaction-wide pin made the erasure fail on it, which is a
   * configuration this module has no business breaking. The erasure's own {@code UPDATE} runs
   * outside the window, on the arrived path, with every name in it qualified by the module itself;
   * the framework-rendered {@code SELECT} inside the window fires no trigger.
   */
  @Test
  void probe_an_application_trigger_with_an_unqualified_body_still_fires_on_the_erasure() {
    String owner = "trigger-window-" + System.nanoTime();
    ownedNotes.saveAndFlush(new OwnedNote(owner, "org-b", "victim@example.test"));
    execute(
        "CREATE TABLE IF NOT EXISTS public.probe_audit_log (note_id bigint)",
        "CREATE OR REPLACE FUNCTION public.shredding_probe_audit() RETURNS trigger AS $$ BEGIN"
            + " INSERT INTO probe_audit_log (note_id) VALUES (NEW.id); RETURN NEW; END;"
            + " $$ LANGUAGE plpgsql",
        "CREATE TRIGGER shredding_probe_audit AFTER UPDATE ON public.owned_note"
            + " FOR EACH ROW EXECUTE FUNCTION public.shredding_probe_audit()");

    var result =
        erasures.erase(
            new ErasureRequest(TenantId.of("org-b"), SubjectId.of(owner), "dpo", "art 17"));

    assertThat(result.blindIndexColumnsCleared()).isEqualTo(1);
    assertThat(count("SELECT count(*) FROM public.probe_audit_log"))
        .describedAs(
            "the application's trigger resolved `probe_audit_log` on the path the transaction"
                + " arrived with. A window around the whole transaction would have failed it with"
                + " `relation \"probe_audit_log\" does not exist` and refused the erasure")
        .isEqualTo(1);
  }

  /**
   * An {@code =(varchar, varchar)} in {@code public}, which the connection-init {@code search_path}
   * puts ahead of {@code pg_catalog}. Every argument type is spelled {@code pg_catalog.varchar}:
   * the design's fixture note (E7b) is that a shadow declared on a bare type name while the role
   * owns a domain of that name is created on the domain and shadows nothing.
   */
  private void shadowVarcharEquality() {
    execute(
        "CREATE OR REPLACE FUNCTION public.always_false(pg_catalog.varchar, pg_catalog.varchar)"
            + " RETURNS boolean AS $$ SELECT false $$ LANGUAGE sql",
        "DROP OPERATOR IF EXISTS public.= (pg_catalog.varchar, pg_catalog.varchar)",
        "CREATE OPERATOR public.= (LEFTARG = pg_catalog.varchar,"
            + " RIGHTARG = pg_catalog.varchar, FUNCTION = public.always_false)");
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

  private long count(String sql) {
    try (Connection c = dataSource.getConnection();
        Statement st = c.createStatement();
        ResultSet rs = st.executeQuery(sql)) {
      return rs.next() ? rs.getLong(1) : 0L;
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private void execute(String... sql) {
    try (Connection c = dataSource.getConnection();
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }
}
