package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.SQLException;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * {@code shredding.jdbc.accepted-third-party-extensions} (C-PR45-3, rule R5b (ii)), bound as the
 * starter binds it and passed by the schema gate to core. Absent is empty, and empty refuses a
 * native function of an extension the pinned image does not ship.
 */
class AcceptedThirdPartyExtensionsTest {

  private static final PostgreSQLContainer<?> PG =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  private static HikariDataSource app;

  @BeforeAll
  static void start() throws SQLException {
    PG.start();
    String ext = "/usr/local/share/postgresql/extension/";
    PG.copyFileToContainer(
        Transferable.of("default_version = '1.0'\nrelocatable = true\n"), ext + "tp.control");
    PG.copyFileToContainer(
        Transferable.of(
            "CREATE FUNCTION tp_similarity(text, text) RETURNS real"
                + " AS '$libdir/pg_trgm', 'similarity' LANGUAGE c STRICT;\n"),
        ext + "tp--1.0.sql");
    try (var su = pool(PG.getUsername(), PG.getPassword())) {
      exec(
          su,
          "CREATE ROLE tpx_owner LOGIN PASSWORD 'pw' NOSUPERUSER",
          "CREATE ROLE tpx_app LOGIN PASSWORD 'pw' NOSUPERUSER",
          "ALTER SCHEMA public OWNER TO tpx_owner",
          "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
          "REVOKE TEMPORARY ON DATABASE " + PG.getDatabaseName() + " FROM PUBLIC",
          "CREATE EXTENSION tp");
    }
    try (var owner = pool("tpx_owner", "pw")) {
      JdbcSupport.initializeSchema(owner);
      exec(
          owner,
          "GRANT USAGE ON SCHEMA public TO tpx_app",
          "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO tpx_app",
          "GRANT UPDATE (encryption_count) ON shredding_data_key TO tpx_app",
          "GRANT SELECT, INSERT ON shredding_erased_subject TO tpx_app",
          "GRANT UPDATE (erased_at) ON shredding_erased_subject TO tpx_app",
          "GRANT SELECT, INSERT ON shredding_erasure TO tpx_app",
          "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO tpx_app",
          "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO tpx_app");
    }
    app = pool("tpx_app", "pw");
  }

  @AfterAll
  static void stop() {
    if (app != null) {
      app.close();
    }
    PG.stop();
  }

  private static HikariDataSource pool(String user, String password) {
    var config = new HikariConfig();
    config.setJdbcUrl(PG.getJdbcUrl());
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(2);
    return new HikariDataSource(config);
  }

  private static void exec(DataSource ds, String... sql) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      for (String each : sql) {
        s.execute(each);
      }
    }
  }

  private static ShreddingProperties bind(Map<String, String> values) {
    return new Binder(new MapConfigurationPropertySource(values))
        .bindOrCreate("shredding", ShreddingProperties.class);
  }

  @Test
  void absent_accepted_list_binds_an_empty_array_and_refuses() {
    var properties = bind(Map.of());
    assertThat(properties.getJdbc().getAcceptedThirdPartyExtensions()).isEmpty();
    assertThatThrownBy(() -> new ShreddingSchemaGate(app, properties))
        .isInstanceOfSatisfying(
            ShreddingException.class,
            e -> assertThat(e.code()).isEqualTo(ErrorCodes.RUNTIME_ROLE_PRIVILEGED))
        .hasMessageContaining("native code of third-party extension tp")
        .hasMessageContaining("shredding.jdbc.accepted-third-party-extensions");
  }

  @Test
  void an_accepted_entry_is_trimmed_and_starts() {
    var properties = bind(Map.of("shredding.jdbc.accepted-third-party-extensions", " tp "));
    assertThatCode(() -> new ShreddingSchemaGate(app, properties)).doesNotThrowAnyException();
  }

  @Test
  void a_blank_entry_refuses_to_start() {
    var properties =
        bind(
            Map.of(
                "shredding.jdbc.accepted-third-party-extensions[0]", "tp",
                "shredding.jdbc.accepted-third-party-extensions[1]", " "));
    assertThatThrownBy(() -> new ShreddingSchemaGate(app, properties))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG))
        .hasMessageContaining("is blank");
  }

  @Test
  void a_manifest_name_refuses_to_start_whatever_its_case() {
    var properties = bind(Map.of("shredding.jdbc.accepted-third-party-extensions", "tp,AdminPack"));
    assertThatThrownBy(() -> new ShreddingSchemaGate(app, properties))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG))
        .hasMessageContaining("AdminPack");
  }
}
