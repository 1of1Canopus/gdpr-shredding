package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.application.ErasureRequest;
import com.housedevinci.shredding.application.ErasureService;
import com.housedevinci.shredding.autoconfigure.admission.joined.B2JoinedLeaf;
import com.housedevinci.shredding.autoconfigure.admission.joinedpk.B2PkLeaf;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.autoconfigure.admission.single.B2SingleLeaf;
import com.housedevinci.shredding.domain.ErrorCodes;
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
class MappingAdmissionStarterTest {

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

  /** N28, startup half: the check runs once per entity and admits the plain mapping. */
  @Test
  void the_plain_mapping_is_checked_at_startup_and_erases() {
    try (var ctx = builder(PlainApp.class, "create-drop").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      persist(ctx.getBean(EntityManagerFactory.class), new B2Note("n28", "org-b", "a@b.test"));
      ctx.getBean(ErasureService.class)
          .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("n28"), "dpo", "art 17"));
      assertThat(count("SELECT count(*) FROM public.b2_note WHERE email_idx IS NOT NULL")).isZero();
    }
    assertThat(warnings.list).isEmpty();
  }

  /** N30: absent at startup is a WARN naming the entity, the table and the remedy. */
  @Test
  void a_table_absent_at_startup_warns_and_boots_and_the_erasure_refuses() {
    try (var ctx = builder(PlainApp.class, "none").run()) {
      assertThat(warnings.list)
          .singleElement()
          .satisfies(
              e -> {
                assertThat(e.getLevel()).isEqualTo(Level.WARN);
                assertThat(e.getFormattedMessage())
                    .contains("B2Note")
                    .contains("public.b2_note")
                    .contains("does not exist")
                    .contains(ErrorCodes.MAPPING_INADMISSIBLE);
              });
      Throwable thrown =
          catchThrowable(
              () ->
                  ctx.getBean(ErasureService.class)
                      .erase(
                          new ErasureRequest(
                              TenantId.of("org-b"), SubjectId.of("n30"), "dpo", "art 17")));
      assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    }
  }

  /** Present and inadmissible fails startup, naming the entity and the catalogue fact. */
  @Test
  void a_hiding_view_under_the_mapping_refuses_startup() throws SQLException {
    sql(
        "CREATE TABLE public.b2_note_base (id bigserial PRIMARY KEY, owner_id varchar(255),"
            + " tenant_id varchar(255), email bytea, email_idx bytea)",
        "CREATE VIEW public.b2_note AS SELECT * FROM public.b2_note_base"
            + " WHERE (owner_id <> 'hidden')");
    Throwable thrown = catchThrowable(() -> builder(PlainApp.class, "none").run().close());
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(message(thrown)).contains("@Shredded entity B2Note").contains("is a view");
  }

  /** A citext tenant column under a String property: C-b at startup, naming the column. */
  @Test
  void a_citext_tenant_column_refuses_startup() throws SQLException {
    sql(
        "CREATE EXTENSION IF NOT EXISTS citext",
        "CREATE TABLE public.b2_note (id bigserial PRIMARY KEY, owner_id varchar(255),"
            + " tenant_id public.citext, email bytea, email_idx bytea)");
    Throwable thrown = catchThrowable(() -> builder(PlainApp.class, "none").run().close());
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(message(thrown))
        .contains("tenant column public.b2_note.tenant_id")
        .contains("citext");
  }

  /** C-i (security review C-19-3): a uuid tenant column refuses startup, naming the column. */
  @Test
  void a_uuid_tenant_column_refuses_startup_and_says_ids_are_stored_as_text() throws SQLException {
    sql(
        "CREATE TABLE public.b2_note (id bigserial PRIMARY KEY, owner_id varchar(255),"
            + " tenant_id uuid, email bytea, email_idx bytea)");
    Throwable thrown = catchThrowable(() -> builder(PlainApp.class, "none").run().close());
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(message(thrown))
        .contains("tenant column public.b2_note.tenant_id")
        .contains("uuid")
        .contains("stored in a text column");
  }

  /**
   * D-8(a)'s reason, for this bean: lazy initialisation does not move the check to request time.
   */
  @Test
  void lazy_initialisation_does_not_defer_the_check() throws SQLException {
    sql(
        "CREATE TABLE public.b2_note_base (id bigserial PRIMARY KEY, owner_id varchar(255),"
            + " tenant_id varchar(255), email bytea, email_idx bytea)",
        "CREATE VIEW public.b2_note AS SELECT * FROM public.b2_note_base");
    Throwable thrown =
        catchThrowable(
            () ->
                builder(PlainApp.class, "none")
                    .properties("spring.main.lazy-initialization=true")
                    .run()
                    .close());
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
  }

  /**
   * {@code @DependsOnDatabaseInitialization}: with {@code defer-datasource-initialization} the
   * {@code spring.sql.init} script runs after the EntityManagerFactory, and the check must still
   * see the table it creates rather than warn that it is absent.
   */
  @Test
  void a_deferred_sql_init_script_runs_before_the_check() {
    try (var ctx =
        builder(PlainApp.class, "none")
            .properties(
                "spring.sql.init.mode=always",
                "spring.sql.init.schema-locations=classpath:admission/b2-schema.sql",
                "spring.jpa.defer-datasource-initialization=true")
            .run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
    }
    assertThat(warnings.list).describedAs("the table existed when it was checked").isEmpty();
  }

  /**
   * JPA inheritance, JOINED, finding C-18-1's shape: the root's table names no schema. The module
   * addresses the leaf's own table only, which is what admission checks; the root table is reached
   * by no module statement, and by Hibernate's read-back only if a future Hibernate stops pruning
   * the join, which fails closed inside the window. It boots and erases.
   */
  @Test
  void a_joined_leaf_is_checked_on_its_own_table_and_erases() {
    try (var ctx = builder(JoinedApp.class, "create-drop").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      persist(ctx.getBean(EntityManagerFactory.class), new B2JoinedLeaf("j1", "org-b", "a@b.test"));
      ctx.getBean(ErasureService.class)
          .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("j1"), "dpo", "art 17"));
      assertThat(count("SELECT count(*) FROM public.b2_joined_leaf WHERE email_idx IS NOT NULL"))
          .isZero();
    }
  }

  /**
   * A JOINED leaf whose key column is renamed with {@code @PrimaryKeyJoinColumn}: Hibernate's
   * identifier mapping for the leaf names the leaf's own key column, which is the column the write
   * path's statements and the admission check address. Measured, not assumed: an earlier reading of
   * the design expected the root's column here.
   */
  @Test
  void a_joined_leaf_with_a_renamed_key_column_is_checked_on_its_own_key_column() {
    try (var ctx = builder(JoinedPkApp.class, "create-drop").run()) {
      assertThat(ctx.getBean(ShreddedModel.class).idColumn("B2PkLeaf").text()).isEqualTo("leaf_id");
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      persist(ctx.getBean(EntityManagerFactory.class), new B2PkLeaf("pk1", "org-b", "a@b.test"));
      ctx.getBean(ErasureService.class)
          .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("pk1"), "dpo", "art 17"));
      assertThat(count("SELECT count(*) FROM public.b2_pk_leaf WHERE email_idx IS NOT NULL"))
          .isZero();
    }
  }

  /**
   * Addendum A.12 point 5: the identifier column is checked too, at startup, because the write
   * path's rebind, re-read and verification compare it with OPERATOR(pg_catalog.=).
   */
  @Test
  void a_citext_identifier_column_refuses_startup_naming_the_identifier() throws SQLException {
    sql(
        "CREATE EXTENSION IF NOT EXISTS citext",
        "CREATE TABLE public.b2_note (id public.citext PRIMARY KEY, owner_id varchar(255),"
            + " tenant_id varchar(255), email bytea, email_idx bytea)");
    Throwable thrown = catchThrowable(() -> builder(PlainApp.class, "none").run().close());
    assertThat(code(thrown)).isEqualTo(ErrorCodes.MAPPING_INADMISSIBLE);
    assertThat(message(thrown)).contains("identifier column public.b2_note.id").contains("citext");
  }

  /** SINGLE_TABLE: the subclass's columns live in the root's table, which is the one checked. */
  @Test
  void a_single_table_subclass_is_checked_on_the_shared_table_and_erases() {
    try (var ctx = builder(SingleApp.class, "create-drop").run()) {
      assertThat(ctx.getBean(MappingAdmissionCheck.class).checked()).isEqualTo(1);
      persist(
          ctx.getBean(EntityManagerFactory.class), new B2SingleLeaf("st1", "org-b", "a@b.test"));
      ctx.getBean(ErasureService.class)
          .erase(new ErasureRequest(TenantId.of("org-b"), SubjectId.of("st1"), "dpo", "art 17"));
      assertThat(count("SELECT count(*) FROM public.b2_single WHERE email_idx IS NOT NULL"))
          .isZero();
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
