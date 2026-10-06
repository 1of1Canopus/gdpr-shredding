package com.housedevinci.shredding.cipherrc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureResult;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.application.PostErasureHook;
import com.housedevinci.shredding.autoconfigure.ShreddingEventListener;
import com.housedevinci.shredding.cipherrc.hist.RcHistNote;
import com.housedevinci.shredding.domain.ErasureOutcome;
import com.housedevinci.shredding.domain.HookOutcome;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Release-candidate whole-module pass, 0.2.0, lead 1 at the database level: the audit-table pattern
 * without Envers. A row-level {@code AFTER UPDATE} trigger that copies {@code OLD} into a history
 * table is the common shape in regulated schemas. The erasure's own blind-index {@code UPDATE}
 * fires it, so the erasure itself writes the erased subject's pre-erasure index into the history
 * table, after which it records {@code COMPLETE}. Admission reads the relation, its descendants and
 * its columns, never its triggers, so nothing at startup or at erasure time says so.
 *
 * <p>The property asserted: a trigger that fires on the erasure's {@code UPDATE} of a blind-indexed
 * table is named in a startup WARN by mapping admission (the module cannot know where the trigger
 * copies data, so it must at least say that it exists).
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class CipherProbeRc020HistoryTriggerTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcHistNote.class)
  static class HistApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /** The clearing hook of the acknowledged case; it fails until the test lets it succeed. */
  static final AtomicBoolean SCRUBBER_FAILS = new AtomicBoolean(true);

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = RcHistNote.class)
  static class AcknowledgedHistApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }

    @Bean
    PostErasureHook historyIndexScrubber() {
      return new PostErasureHook() {
        @Override
        public String name() {
          return "historyIndexScrubber";
        }

        @Override
        public void afterErasure(TenantId tenant, SubjectId subject) {
          if (SCRUBBER_FAILS.get()) {
            throw new IllegalStateException("history store unreachable");
          }
          try {
            sql(
                "UPDATE public.rc_hist_note_trail SET email_idx = NULL WHERE owner_id = '"
                    + subject.value()
                    + "'");
          } catch (SQLException e) {
            throw new IllegalStateException(e);
          }
        }
      };
    }
  }

  /**
   * The second half of ruling 1, with the C3 assertion as the design's probe adjustment states it
   * (audit-table coverage design, section 3c): the same history trigger, acknowledged with the hook
   * that clears it. Startup WARNs naming the trigger at each of two boots; the erasure's first
   * record is {@code PARTIAL} with a pending outcome naming the trigger; with the hook failing the
   * last record is {@code PARTIAL} naming it; once the hook succeeds the retry is {@code COMPLETE}
   * with an outcome naming it; and the same entry without {@code cleared-by} refuses startup.
   *
   * <p>The history table is {@code rc_hist_note_trail}, not {@code rc_hist_note_history}: the
   * second is the name Hibernate gives a {@code @Temporal} history table and is refused as a stale
   * history table by name, which is not acknowledgeable and not what this case is about.
   */
  @Test
  void probe_acknowledged_history_trigger_warns_and_is_not_recorded_complete(CapturedOutput output)
      throws Exception {
    sql(
        "DROP TABLE IF EXISTS public.rc_hist_note, public.rc_hist_note_history,"
            + " public.rc_hist_note_trail CASCADE",
        "DROP FUNCTION IF EXISTS public.rc_hist_note_copy() CASCADE",
        "CREATE TABLE public.rc_hist_note (id bigint PRIMARY KEY, owner_id text NOT NULL,"
            + " tenant_id text NOT NULL, email bytea, email_idx bytea)",
        "ALTER TABLE public.rc_hist_note ALTER COLUMN email_idx SET STATISTICS 0",
        "CREATE TABLE public.rc_hist_note_trail (id bigint, owner_id text, tenant_id text,"
            + " email bytea, email_idx bytea, changed_at timestamptz NOT NULL DEFAULT now())",
        "CREATE FUNCTION public.rc_hist_note_copy() RETURNS trigger LANGUAGE plpgsql AS $$"
            + " BEGIN INSERT INTO public.rc_hist_note_trail (id, owner_id, tenant_id, email,"
            + " email_idx) VALUES (OLD.id, OLD.owner_id, OLD.tenant_id, OLD.email, OLD.email_idx);"
            + " RETURN NULL; END $$",
        "CREATE TRIGGER rc_hist_note_audit AFTER UPDATE ON public.rc_hist_note"
            + " FOR EACH ROW EXECUTE FUNCTION public.rc_hist_note_copy()");
    String[] entry = {
      "shredding.jdbc.acknowledged-copies[0].kind=trigger",
      "shredding.jdbc.acknowledged-copies[0].schema=public",
      "shredding.jdbc.acknowledged-copies[0].table=rc_hist_note",
      "shredding.jdbc.acknowledged-copies[0].name=rc_hist_note_audit"
    };
    String[] withHook =
        Stream.concat(
                Stream.of(entry),
                Stream.of("shredding.jdbc.acknowledged-copies[0].cleared-by=historyIndexScrubber"))
            .toArray(String[]::new);
    String object = "trigger \"public\".\"rc_hist_note\".\"rc_hist_note_audit\"";

    // Boot 1: WARN, then one erasure with the clearing hook failing, then a retry once it works.
    try (ConfigurableApplicationContext ctx = boot(AcknowledgedHistApp.class, withHook)) {
      assertThat(acknowledgementWarnings(output.getAll()))
          .describedAs("the acknowledged trigger is named at startup, with its hook")
          .hasSize(1)
          .allSatisfy(w -> assertThat(w).contains(object).contains("historyIndexScrubber"));

      persist(ctx.getBean(EntityManagerFactory.class), new RcHistNote(1L, "s1", "org-b", "a@b"));
      SCRUBBER_FAILS.set(true);
      ErasureResult first =
          ctx.getBean(ErasureService.class)
              .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("s1"), "dpo", "art 17"));
      System.out.println("CIPHER-RC acknowledged history trigger, first: " + first.records());

      assertThat(first.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
      assertThat(first.records().get(0).outcome()).isEqualTo(ErasureOutcome.PARTIAL);
      assertThat(first.records().get(0).hookOutcomes())
          .containsExactly(
              new HookOutcome("historyIndexScrubber", false, "pending; clears " + object));
      var last = first.records().get(first.records().size() - 1);
      assertThat(last.outcome()).isEqualTo(ErasureOutcome.PARTIAL);
      assertThat(last.hookOutcomes())
          .singleElement()
          .satisfies(
              o -> {
                assertThat(o.hook()).isEqualTo("historyIndexScrubber");
                assertThat(o.succeeded()).isFalse();
                assertThat(o.detail()).contains("leaves " + object);
              });
      assertThat(
              count("SELECT count(*) FROM public.rc_hist_note_trail WHERE email_idx IS NOT NULL"))
          .describedAs("the erasure's own UPDATE fired the trigger, so the copy exists")
          .isPositive();

      SCRUBBER_FAILS.set(false);
      ErasureResult retry =
          ctx.getBean(ErasureService.class)
              .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("s1"), "dpo", "art 17"));
      System.out.println("CIPHER-RC acknowledged history trigger, retry: " + retry.records());
      assertThat(retry.outcome()).isEqualTo(ErasureOutcome.COMPLETE);
      assertThat(retry.records().get(retry.records().size() - 1).hookOutcomes())
          .containsExactly(new HookOutcome("historyIndexScrubber", true, "clears " + object));
      assertThat(
              count("SELECT count(*) FROM public.rc_hist_note_trail WHERE email_idx IS NOT NULL"))
          .isZero();
    }

    // Boot 2: the WARN again, at every startup.
    try (ConfigurableApplicationContext ctx = boot(AcknowledgedHistApp.class, withHook)) {
      assertThat(acknowledgementWarnings(output.getAll())).hasSize(2);
    }

    // Boot 3: the same entry with no cleared-by refuses startup.
    Throwable thrown = catchThrowable(() -> boot(AcknowledgedHistApp.class, entry).close());
    ShreddingException refusal = null;
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        refusal = s;
        break;
      }
    }
    assertThat(refusal).describedAs("refusal cause: %s", thrown).isNotNull();
    assertThat(refusal.code()).isEqualTo("SHRED-CONFIG-001");
    assertThat(refusal.getMessage()).contains("shredding.jdbc.acknowledged-copies[0]");
  }

  private static ConfigurableApplicationContext boot(Class<?> app, String[] extra) {
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .run(
            Stream.concat(Stream.of(args()), Stream.of(extra).map(a -> "--" + a))
                .toArray(String[]::new));
  }

  private static List<String> acknowledgementWarnings(String output) {
    return output
        .lines()
        .filter(l -> l.contains("WARN"))
        .filter(l -> l.contains("rc_hist_note_audit") && l.contains("acknowledged-copies[0]"))
        .toList();
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

  private static long count(String query) throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var st = c.createStatement();
        var rs = st.executeQuery(query)) {
      return rs.next() ? rs.getLong(1) : 0L;
    }
  }

  /**
   * Split per the design review's ruling 1 (audit-table coverage, 2026-10-05): with no
   * acknowledgement, the history trigger refuses startup with {@code SHRED-SCHEMA-010} naming the
   * trigger. The second half is {@link
   * #probe_acknowledged_history_trigger_warns_and_is_not_recorded_complete}.
   */
  @Test
  void probe_history_trigger_without_acknowledgement_refuses_startup() throws SQLException {
    sql(
        "DROP TABLE IF EXISTS public.rc_hist_note, public.rc_hist_note_history,"
            + " public.rc_hist_note_trail CASCADE",
        "DROP FUNCTION IF EXISTS public.rc_hist_note_copy() CASCADE",
        "CREATE TABLE public.rc_hist_note (id bigint PRIMARY KEY, owner_id text NOT NULL,"
            + " tenant_id text NOT NULL, email bytea, email_idx bytea)",
        "CREATE TABLE public.rc_hist_note_history (LIKE public.rc_hist_note,"
            + " changed_at timestamptz NOT NULL DEFAULT now())",
        "CREATE FUNCTION public.rc_hist_note_copy() RETURNS trigger LANGUAGE plpgsql AS $$"
            + " BEGIN INSERT INTO public.rc_hist_note_history (id, owner_id, tenant_id, email,"
            + " email_idx) VALUES (OLD.id, OLD.owner_id, OLD.tenant_id, OLD.email, OLD.email_idx);"
            + " RETURN NULL; END $$",
        "CREATE TRIGGER rc_hist_note_audit AFTER UPDATE ON public.rc_hist_note"
            + " FOR EACH ROW EXECUTE FUNCTION public.rc_hist_note_copy()");

    Throwable thrown =
        catchThrowable(
            () ->
                new SpringApplicationBuilder(HistApp.class)
                    .web(WebApplicationType.NONE)
                    .run(args())
                    .close());

    ShreddingException refusal = null;
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        refusal = s;
        break;
      }
    }
    assertThat(refusal).describedAs("refusal cause: %s", thrown).isNotNull();
    System.out.println("CIPHER-RC history trigger refusal: " + refusal.getMessage());
    assertThat(refusal.code()).isEqualTo("SHRED-SCHEMA-010");
    assertThat(refusal.getMessage()).contains("rc_hist_note_audit");
  }

  private static String[] args() {
    return java.util.stream.Stream.of(
            "shredding.master-key=" + b64("rc-histtr-probe-master-key-32-by"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("rc-histtr-probe-chain-secret-32b"),
            "shredding.blind-index.hmac-secret=" + b64("rc-histtr-probe-index-secret-32b"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=none",
            "spring.jpa.properties.hibernate.default_schema=public",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect",
            "spring.autoconfigure.exclude="
                + "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration")
        .map(a -> "--" + a)
        .toArray(String[]::new);
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
}
