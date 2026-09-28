package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.autoconfigure.gate.GateNote;
import com.housedevinci.shredding.autoconfigure.gate.GateNoteRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * The starter half of design §7: the paths that only exist once Spring is wiring the beans. The
 * catalogue legs themselves are tested without Spring in {@code SchemaVerificationTest}; what is
 * here is the wiring that decides whether those legs ever run, and against which {@code
 * DataSource}.
 *
 * <p>Note what the properties say in each test. This class is the only one in the starter's test
 * tree that runs on the shipped defaults; every other class sets {@code
 * shredding.jdbc.initialize-schema=true} because it drives one container with one role and is about
 * converters, not about roles.
 */
@Testcontainers
class CipherProbeSchemaGateTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static final String OWNER = "gate_owner";
  private static final String APP = "gate_app";

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static boolean rolesCreated;

  @BeforeEach
  void resetDatabase() throws SQLException {
    ShreddingRuntime.clear();
    if (!rolesCreated) {
      su(
          "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw' NOSUPERUSER",
          "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw' NOSUPERUSER");
      rolesCreated = true;
    }
    // DROP OWNED BY also revokes every grant made to the role, which is what makes each test start
    // from the same posture rather than inheriting the previous one's GRANTs.
    su(
        "DROP OWNED BY " + APP,
        "DROP OWNED BY " + OWNER,
        "DROP SCHEMA IF EXISTS public CASCADE",
        "CREATE SCHEMA public",
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "REVOKE ALL ON DATABASE " + POSTGRES.getDatabaseName() + " FROM " + APP,
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC",
        "GRANT CONNECT ON DATABASE " + POSTGRES.getDatabaseName() + " TO " + APP);
  }

  @AfterEach
  void clearRuntime() {
    ShreddingRuntime.clear();
  }

  // ------------------------------------------------------------------ T1, T2

  @Test
  void t1_on_the_shipped_defaults_an_empty_database_refuses_the_context_and_creates_nothing()
      throws SQLException {
    grantUsage();
    long before = relationCount();

    String outcome = start(PlainApp.class);

    assertThat(outcome).startsWith("REFUSED " + ErrorCodes.SCHEMA_ABSENT);
    assertThat(outcome)
        .contains("shredding.jdbc.initialize-schema")
        .contains("docs/upgrading-0.2.0.md");
    assertThat(relationCount())
        .describedAs("a refused context must leave the database exactly as it found it")
        .isEqualTo(before);
  }

  @Test
  void t2_the_documented_two_role_posture_boots_and_neither_warning_fires() throws SQLException {
    ownerAppliesSchemaAndGrants();

    var log = new CapturingAppender();
    try (var ctx = log.armed(builder(PlainApp.class)).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).schema().name()).isEqualTo("public");
      assertThat(ctx.getBean(ShreddingSchemaGate.class).verdict().runtimeRoleIsUnprivileged())
          .isTrue();

      // The adapters were built from the gate, on the gate's DataSource, and they work.
      ctx.getBean(KeyProvider.class).currentForWrite(TenantId.of("t1"), SubjectId.of("s1"));
      assertThat(count("public.shredding_data_key")).isEqualTo(1);
    } finally {
      log.detach();
    }
    assertThat(log.warnings())
        .describedAs("the hardened posture warns about nothing")
        .noneMatch(line -> line.contains("shredding.jdbc."));
    assertThat(log.infos()).anyMatch(line -> line.contains("schema verified in schema public"));
  }

  // ------------------------------------------------------------- T13, T14, T15

  @Test
  void t13_allow_privileged_runtime_role_boots_and_warns_at_every_startup() throws SQLException {
    ownerAppliesSchemaAndGrants();

    var log = new CapturingAppender();
    try (var ctx =
        log.armed(builder(PlainApp.class, "shredding.jdbc.allow-privileged-runtime-role=true"))
            .run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class)).isNotNull();
    } finally {
      log.detach();
    }
    // Booted as the owner, which is every leg at once.
    assertThat(log.warnings()).isEmpty();

    var ownerLog = new CapturingAppender();
    try (var ctx =
        ownerLog
            .armed(
                ownerBuilder(PlainApp.class, "shredding.jdbc.allow-privileged-runtime-role=true"))
            .run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).verdict().runtimeRoleIsUnprivileged())
          .isFalse();
    } finally {
      ownerLog.detach();
    }
    assertThat(ownerLog.warnings())
        .anyMatch(
            line ->
                line.contains("shredding.jdbc.allow-privileged-runtime-role=true")
                    && line.contains("owns table shredding_erasure")
                    && line.contains("advisory in this configuration"));
    assertThat(ownerLog.infos())
        .describedAs("the INFO line must not claim the role clause it did not earn")
        .anyMatch(line -> line.contains("schema verified") && !line.contains("owns none of the 9"));
  }

  @Test
  void t14_creation_mode_creates_verifies_warns_and_is_idempotent_across_two_boots() {
    var first = new CapturingAppender();
    try (var ctx =
        first.armed(ownerBuilder(PlainApp.class, "shredding.jdbc.initialize-schema=true")).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).schema().name()).isEqualTo("public");
    } finally {
      first.detach();
    }
    assertThat(first.warnings())
        .describedAs("the DDL warning names the property and the supported path")
        .anyMatch(
            line ->
                line.contains("shredding.jdbc.initialize-schema=true")
                    && line.contains("DISABLE TRIGGER")
                    && line.contains("docs/upgrading-0.2.0.md"));
    assertThat(first.warnings())
        .describedAs("both weaker modes are in force, so both are said out loud")
        .anyMatch(line -> line.contains("privileged over the shredding objects"));
    assertThat(triggerStates()).containsOnly("A");

    var second = new CapturingAppender();
    try (var ctx =
        second.armed(ownerBuilder(PlainApp.class, "shredding.jdbc.initialize-schema=true")).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class)).isNotNull();
    } finally {
      second.detach();
    }
    assertThat(second.warnings())
        .describedAs("every startup, not the first")
        .anyMatch(line -> line.contains("shredding.jdbc.initialize-schema=true"));
  }

  @Test
  void t15_creation_mode_as_a_non_owner_is_006_and_never_a_raw_permission_denied()
      throws SQLException {
    grantUsage();
    String outcome = start(PlainApp.class, "shredding.jdbc.initialize-schema=true");
    assertThat(outcome).startsWith("REFUSED " + ErrorCodes.SCHEMA_CREATION_FAILED);
    assertThat(outcome).contains("apply the script once with a privileged role");
    assertThat(outcome).doesNotContain("permission denied for schema");
  }

  // ------------------------------------------------------------- T33, T34, T18

  @Test
  void t33_lazy_initialization_cannot_defer_the_gate_to_the_first_erasure() throws SQLException {
    grantUsage();
    String outcome = start(PlainApp.class, "spring.main.lazy-initialization=true");
    assertThat(outcome)
        .describedAs("a boot-time control a property can move to request time is not one")
        .startsWith("REFUSED " + ErrorCodes.SCHEMA_ABSENT);
  }

  @Test
  void t34_lazy_initialization_with_user_supplied_adapters_still_refuses() throws SQLException {
    grantUsage();
    String outcome = start(UserSuppliedAdaptersApp.class, "spring.main.lazy-initialization=true");
    assertThat(outcome)
        .describedAs(
            "both adapters are @ConditionalOnMissingBean, so an application that supplies them"
                + " removes the only ordering edge that would otherwise pull the gate in")
        .startsWith("REFUSED " + ErrorCodes.SCHEMA_ABSENT);
  }

  @Test
  void t18_one_gate_serves_both_adapters_and_neither_is_built_without_it() throws SQLException {
    ownerAppliesSchemaAndGrants();
    try (var ctx = builder(PlainApp.class).run()) {
      assertThat(ctx.getBeanNamesForType(ShreddingSchemaGate.class)).hasSize(1);
      var gate = ctx.getBean(ShreddingSchemaGate.class);
      assertThat(ctx.getBean(KeyProvider.class)).isNotNull();
      assertThat(ctx.getBean(JdbcErasureStore.class)).isNotNull();
      assertThat(gate.dataSource()).isSameAs(ctx.getBean(DataSource.class));
    }
  }

  // ------------------------------------------------------------------ T35

  @Test
  void t35_with_two_datasource_beans_the_verified_one_is_the_one_written_to() throws SQLException {
    ownerAppliesSchemaAndGrants();
    su("DROP DATABASE IF EXISTS decoy", "CREATE DATABASE decoy OWNER " + OWNER);
    try (var ctx = builder(TwoDataSourceApp.class).run()) {
      var gate = ctx.getBean(ShreddingSchemaGate.class);
      assertThat(gate.dataSource()).isSameAs(ctx.getBean("primaryDataSource"));

      ctx.getBean(KeyProvider.class).currentForWrite(TenantId.of("t1"), SubjectId.of("s1"));
      assertThat(count("public.shredding_data_key"))
          .describedAs("the write went to the database that was verified")
          .isEqualTo(1);

      // And nothing early in the lifecycle reached the database before the gate did.
      assertThat(ctx.getBean(ShreddingReadBracketCustomizer.class)).isNotNull();
    } finally {
      su("DROP DATABASE IF EXISTS decoy WITH (FORCE)");
    }
  }

  // ------------------------------------------------------------------ T19

  @Test
  void t19_only_one_starter_class_may_reach_the_schema_step() throws java.io.IOException {
    var offenders = new ArrayList<String>();
    var root = java.nio.file.Path.of("src/main/java");
    try (var files = java.nio.file.Files.walk(root)) {
      for (java.nio.file.Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
        String source = java.nio.file.Files.readString(file);
        if (source.contains("JdbcSupport.initializeSchema")
            || source.contains("JdbcSupport.initializeAndVerifySchema")) {
          offenders.add(file.getFileName().toString());
        }
      }
    }
    assertThat(offenders)
        .describedAs("DDL has exactly one door in this starter, and it is the gate")
        .containsExactly("ShreddingSchemaGate.java");
  }

  // ------------------------------------------------------------------ fixtures

  static class Tenant {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("t1");
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = GateNote.class)
  @EnableJpaRepositories(basePackageClasses = GateNoteRepository.class)
  static class PlainApp extends Tenant {}

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = GateNote.class)
  @EnableJpaRepositories(basePackageClasses = GateNoteRepository.class)
  static class UserSuppliedAdaptersApp extends Tenant {

    @Bean
    KeyProvider shreddingKeyProvider(ShreddingSchemaGate gate) {
      return new com.housedevinci.shredding.adapter.jdbc.JdbcKeyProvider(
          gate.dataSource(),
          gate.schema(),
          MasterKey.fromBytes(new byte[32]),
          RandomSource.secure(),
          Clock.systemUTC());
    }
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = GateNote.class)
  @EnableJpaRepositories(basePackageClasses = GateNoteRepository.class)
  static class TwoDataSourceApp extends Tenant {

    /** The one the application is configured for, and the one the gate must verify and use. */
    @Bean
    @Primary
    DataSource primaryDataSource(DataSourceProperties properties) {
      return properties.initializeDataSourceBuilder().build();
    }

    /** A second, perfectly healthy DataSource pointing at a different database entirely. */
    @Bean
    DataSource decoyDataSource() {
      var builder = new DataSourceProperties();
      builder.setUrl(POSTGRES.getJdbcUrl().replaceFirst("/[^/?]+($|\\?)", "/decoy$1"));
      builder.setUsername(OWNER);
      builder.setPassword("pw");
      return builder.initializeDataSourceBuilder().build();
    }
  }

  private SpringApplicationBuilder builder(Class<?> app, String... extra) {
    return builderAs(app, APP, extra);
  }

  private SpringApplicationBuilder ownerBuilder(Class<?> app, String... extra) {
    return builderAs(app, OWNER, extra);
  }

  private SpringApplicationBuilder builderAs(Class<?> app, String user, String... extra) {
    var properties =
        new ArrayList<>(
            List.of(
                "shredding.master-key=" + b64("gate-master-key-32-bytes!!!!!!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("gate-chain-secret-32-bytes!!!!!!"),
                "shredding.blind-index.hmac-secret=" + b64("gate-index-secret-32-bytes!!!!!!"),
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + user,
                "spring.datasource.password=pw",
                "spring.jpa.hibernate.ddl-auto=none",
                "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect"));
    properties.addAll(List.of(extra));
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(properties.toArray(String[]::new));
  }

  private String start(Class<?> app, String... extra) {
    return start(builder(app, extra));
  }

  private String start(SpringApplicationBuilder builder) {
    try (var ignored = builder.run()) {
      return "STARTED";
    } catch (RuntimeException e) {
      for (Throwable t = e; t != null; t = t.getCause()) {
        if (t instanceof ShreddingException s) {
          return "REFUSED " + s.code() + " " + s.getMessage();
        }
      }
      return "REFUSED " + e;
    }
  }

  // ------------------------------------------------------------------ database

  private void grantUsage() throws SQLException {
    ownerSql("GRANT USAGE ON SCHEMA public TO " + APP);
  }

  private void ownerAppliesSchemaAndGrants() throws SQLException {
    JdbcSupport.initializeSchema(ownerDataSource());
    ownerSql(
        "GRANT USAGE ON SCHEMA public TO " + APP,
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO " + APP,
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erased_subject TO " + APP,
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO " + APP,
        "GRANT SELECT, INSERT ON shredding_erasure TO " + APP,
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO " + APP,
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO " + APP,
        "CREATE TABLE gate_note (id bigserial PRIMARY KEY, tenant_id varchar(255) NOT NULL,"
            + " subject_id varchar(255) NOT NULL, body bytea)",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON gate_note TO " + APP,
        "GRANT USAGE, SELECT ON SEQUENCE gate_note_id_seq TO " + APP);
  }

  private static DataSource ownerDataSource() {
    var properties = new DataSourceProperties();
    properties.setUrl(POSTGRES.getJdbcUrl());
    properties.setUsername(OWNER);
    properties.setPassword("pw");
    return properties.initializeDataSourceBuilder().build();
  }

  private static void su(String... sql) throws SQLException {
    run(POSTGRES.getUsername(), POSTGRES.getPassword(), sql);
  }

  private static void ownerSql(String... sql) throws SQLException {
    run(OWNER, "pw", sql);
  }

  private static void run(String user, String password, String... sql) throws SQLException {
    try (Connection c =
            java.sql.DriverManager.getConnection(POSTGRES.getJdbcUrl(), user, password);
        Statement st = c.createStatement()) {
      for (String one : sql) {
        st.execute(one);
      }
    }
  }

  private static long scalar(String sql) {
    try (Connection c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        var rs = st.executeQuery(sql)) {
      rs.next();
      return rs.getLong(1);
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
  }

  private static long count(String relation) {
    return scalar("SELECT count(*) FROM " + relation);
  }

  private static long relationCount() {
    return scalar("SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace");
  }

  private static List<String> triggerStates() {
    var out = new ArrayList<String>();
    try (Connection c =
            java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Statement st = c.createStatement();
        var rs =
            st.executeQuery(
                "SELECT t.tgenabled FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid"
                    + " WHERE r.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal")) {
      while (rs.next()) {
        out.add(rs.getString(1));
      }
    } catch (SQLException e) {
      throw new IllegalStateException(e);
    }
    return out;
  }

  /**
   * Captures what an operator would actually read in the boot log.
   *
   * <p>Attached on {@code ApplicationPreparedEvent}, not in the constructor: Spring Boot
   * re-initialises the logging system during environment preparation and discards appenders
   * registered before that, so a capture set up earlier records nothing and the test passes for the
   * wrong reason. {@code ApplicationPreparedEvent} fires after logging is up and before any bean,
   * including the gate, is created.
   */
  private static final class CapturingAppender {

    private final List<String> lines = java.util.Collections.synchronizedList(new ArrayList<>());
    private final ch.qos.logback.classic.Logger logger =
        (ch.qos.logback.classic.Logger)
            org.slf4j.LoggerFactory.getLogger("com.housedevinci.shredding");
    private final ch.qos.logback.core.AppenderBase<ch.qos.logback.classic.spi.ILoggingEvent>
        appender =
            new ch.qos.logback.core.AppenderBase<>() {
              @Override
              protected void append(ch.qos.logback.classic.spi.ILoggingEvent event) {
                lines.add(event.getLevel() + "|" + event.getFormattedMessage());
              }
            };

    SpringApplicationBuilder armed(SpringApplicationBuilder builder) {
      return builder.listeners(
          (org.springframework.context.ApplicationListener<
                  org.springframework.boot.context.event.ApplicationPreparedEvent>)
              event -> {
                appender.setContext(logger.getLoggerContext());
                appender.start();
                logger.setLevel(ch.qos.logback.classic.Level.INFO);
                logger.addAppender(appender);
              });
    }

    void detach() {
      logger.detachAppender(appender);
      appender.stop();
    }

    List<String> warnings() {
      return lines.stream().filter(l -> l.startsWith("WARN|")).toList();
    }

    List<String> infos() {
      return lines.stream().filter(l -> l.startsWith("INFO|")).toList();
    }
  }
}
