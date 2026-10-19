package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1c through the starter's default beans (L22, L23): a pool that logs in as the owner and runs
 * {@code SET ROLE shredding_app} in Hikari's {@code connection-init-sql} refuses to start, and with
 * {@code allow-privileged-runtime-role=true} it starts with a WARN that names the login-role legs
 * and says that any statement can {@code RESET ROLE}.
 */
@Testcontainers
class LoginRoleStarterTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static final String OWNER = "shred_owner";
  static final String APP = "shredding_app";

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class PlainApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  private final ListAppender<ILoggingEvent> events = new ListAppender<>();

  @BeforeAll
  static void twoRoles() throws SQLException {
    exec(
        as(POSTGRES.getUsername(), POSTGRES.getPassword()),
        "CREATE ROLE " + OWNER + " LOGIN PASSWORD 'pw'",
        "CREATE ROLE " + APP + " LOGIN PASSWORD 'pw'",
        "GRANT " + APP + " TO " + OWNER,
        "ALTER SCHEMA public OWNER TO " + OWNER,
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        "REVOKE TEMPORARY ON DATABASE " + POSTGRES.getDatabaseName() + " FROM PUBLIC");
    DataSource owner = as(OWNER, "pw");
    JdbcSupport.initializeSchema(owner);
    exec(
        owner,
        "GRANT USAGE ON SCHEMA public TO shredding_app",
        "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO shredding_app",
        "GRANT UPDATE (encryption_count) ON shredding_data_key TO shredding_app",
        "GRANT SELECT, INSERT ON shredding_erased_subject TO shredding_app",
        "GRANT UPDATE (erased_at) ON shredding_erased_subject TO shredding_app",
        "GRANT SELECT, INSERT ON shredding_erasure TO shredding_app",
        "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO shredding_app",
        "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO shredding_app");
  }

  @AfterEach
  void detach() {
    root().detachAppender(events);
    ShreddingRuntime.clear();
  }

  @Test
  void default_beans_with_owner_login_and_init_sql_refuse_to_start() {
    Throwable refused = catchThrowable(() -> builder().run(args(false)).close());

    var chain = new StringBuilder();
    for (Throwable t = refused; t != null; t = t.getCause()) {
      chain.append(t.getMessage()).append('\n');
    }
    Throwable root = refused;
    while (root.getCause() != null) {
      root = root.getCause();
    }
    assertThat(root).isInstanceOf(com.housedevinci.shredding.domain.ShreddingException.class);
    assertThat(((com.housedevinci.shredding.domain.ShreddingException) root).code())
        .isEqualTo("SHRED-SCHEMA-004");
    assertThat(chain.toString())
        .contains("as role " + APP + " (login role " + OWNER + ")")
        .contains("login role " + OWNER + " owns, or is a member of the owner of, table");
  }

  @Test
  void allow_privileged_runtime_role_warns_with_the_login_role_legs() {
    try (var ctx = builder().run(args(true))) {
      List<String> warns =
          events.list.stream()
              .filter(e -> e.getLevel() == Level.WARN)
              .map(ILoggingEvent::getFormattedMessage)
              .filter(m -> m.contains("is privileged over the shredding objects"))
              .toList();
      assertThat(warns).hasSize(1);
      assertThat(warns.getFirst())
          .contains("login role " + OWNER + " owns, or is a member of the owner of, table")
          .contains(
              "The pool logs in as "
                  + OWNER
                  + ": any statement on this pool can RESET ROLE back to that login role.");
    }
  }

  private static ch.qos.logback.classic.Logger root() {
    return (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
  }

  private SpringApplicationBuilder builder() {
    return new SpringApplicationBuilder(PlainApp.class)
        .web(WebApplicationType.NONE)
        .listeners(
            (org.springframework.context.ApplicationListener<
                    org.springframework.boot.context.event.ApplicationPreparedEvent>)
                e -> {
                  events.start();
                  root().addAppender(events);
                });
  }

  private static String[] args(boolean allowPrivileged) {
    return List.of(
            "shredding.master-key=" + b64("c1c-starter-test-master-key-32by"),
            "shredding.jdbc.initialize-schema=false",
            "shredding.jdbc.allow-privileged-runtime-role=" + allowPrivileged,
            "shredding.erasure-log.hmac-secret=" + b64("c1c-starter-test-chain-secret-32"),
            "shredding.blind-index.hmac-secret=" + b64("c1c-starter-test-index-secret-32"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + OWNER,
            "spring.datasource.password=pw",
            "spring.datasource.hikari.connection-init-sql=SET ROLE " + APP,
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect")
        .stream()
        .map(a -> "--" + a)
        .toArray(String[]::new);
  }

  private static DataSource as(String user, String password) {
    return new DriverManagerDataSource(POSTGRES.getJdbcUrl(), user, password);
  }

  private static void exec(DataSource ds, String... sql) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      for (String each : sql) {
        s.execute(each);
      }
    }
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
