package com.housedevinci.shredding.adapter.jdbc;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1b test fixture, test tree only: one PostgreSQL cluster in the documented two-role posture
 * (an owner applies the schema, the runtime role holds only the grants of SECURITY-NOTES "Database
 * roles"), in any number of databases. The same script on two clusters gives two look-alike
 * installations: same database name, same roles, same {@code public} oid.
 */
final class TwoRoleCluster {

  static final String IMAGE =
      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777";

  static final String IMAGE_17 =
      "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";

  /** The pinned image of {@code major}. */
  static String image(int major) {
    return switch (major) {
      case 16 -> IMAGE;
      case 17 -> IMAGE_17;
      default -> throw new IllegalArgumentException("no pinned image for PostgreSQL " + major);
    };
  }

  /**
   * A container of {@code image} with nothing added (no init script), limited to 512 MB and two
   * CPUs: the generator of the pinned files reads the image as it ships.
   */
  static PostgreSQLContainer<?> pristine(String image) {
    return new PostgreSQLContainer<>(
            DockerImageName.parse(image).asCompatibleSubstituteFor("postgres"))
        .withCreateContainerCmdModifier(
            cmd -> cmd.getHostConfig().withMemory(512L * 1024 * 1024).withNanoCPUs(2_000_000_000L))
        .withStartupTimeout(java.time.Duration.ofMinutes(2));
  }

  /**
   * As {@link #container()}, on the pinned image of {@code major}, limited as {@link #pristine}.
   */
  static PostgreSQLContainer<?> container(int major) {
    return pristine(image(major)).withInitScript("shredding-test/statistics-off.sql");
  }

  static final String OWNER = "shred_owner";
  static final String APP = "shredding_app";
  static final String PASSWORD = "pw";

  static final List<String> GRANT_BLOCK =
      List.of(
          "GRANT USAGE ON SCHEMA public TO shredding_app",
          "GRANT SELECT, INSERT, DELETE ON shredding_data_key TO shredding_app",
          "GRANT UPDATE (encryption_count) ON shredding_data_key TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erased_subject TO shredding_app",
          "GRANT UPDATE (erased_at) ON shredding_erased_subject TO shredding_app",
          "GRANT SELECT, INSERT ON shredding_erasure TO shredding_app",
          "GRANT SELECT, INSERT, UPDATE ON shredding_erasure_anchor TO shredding_app",
          "GRANT USAGE ON SEQUENCE shredding_erasure_seq_seq TO shredding_app");

  private TwoRoleCluster() {}

  static PostgreSQLContainer<?> container() {
    return new PostgreSQLContainer<>(
            DockerImageName.parse(IMAGE).asCompatibleSubstituteFor("postgres"))
        .withInitScript("shredding-test/statistics-off.sql")
        .withStartupTimeout(java.time.Duration.ofMinutes(2));
  }

  /** Creates the two roles once per cluster. */
  static void roles(PostgreSQLContainer<?> pg) throws SQLException {
    try (var su = pool(pg, pg.getUsername(), pg.getPassword(), pg.getDatabaseName())) {
      exec(
          su,
          "CREATE ROLE " + OWNER + " LOGIN PASSWORD '" + PASSWORD + "' NOSUPERUSER",
          "CREATE ROLE " + APP + " LOGIN PASSWORD '" + PASSWORD + "' NOSUPERUSER");
    }
  }

  /**
   * Prepares {@code database} (created when it is not the container's own): {@code public} owned by
   * the owner, the schema applied by the owner, the grant block, no TEMPORARY for anyone.
   */
  static void install(PostgreSQLContainer<?> pg, String database) throws SQLException {
    if (!database.equals(pg.getDatabaseName())) {
      try (var su = pool(pg, pg.getUsername(), pg.getPassword(), pg.getDatabaseName())) {
        exec(su, "CREATE DATABASE " + database);
      }
    }
    try (var su = pool(pg, pg.getUsername(), pg.getPassword(), database)) {
      exec(
          su,
          // Owned by the owner, but never dropped: public keeps oid 2200 in every database and
          // every cluster, so a test that moves between them changes only what it means to.
          "ALTER SCHEMA public OWNER TO " + OWNER,
          "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
          "REVOKE ALL ON DATABASE " + database + " FROM " + APP,
          "REVOKE TEMPORARY ON DATABASE " + database + " FROM PUBLIC",
          "GRANT CONNECT ON DATABASE " + database + " TO " + APP);
    }
    try (var owner = pool(pg, OWNER, PASSWORD, database)) {
      JdbcSupport.initializeSchema(owner);
      exec(owner, GRANT_BLOCK.toArray(String[]::new));
    }
  }

  static String url(PostgreSQLContainer<?> pg, String database) {
    return "jdbc:postgresql://"
        + pg.getHost()
        + ":"
        + pg.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT)
        + "/"
        + database;
  }

  static HikariDataSource pool(
      PostgreSQLContainer<?> pg, String user, String password, String database) {
    var config = new HikariConfig();
    config.setJdbcUrl(url(pg, database));
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(3);
    config.setMinimumIdle(0);
    return new HikariDataSource(config);
  }

  /**
   * C-PR-1c: a pool whose every new connection runs {@code initSql} first, as HikariCP's {@code
   * connectionInitSql} does. Statements are separated by semicolons and run in one simple query.
   */
  static HikariDataSource pool(
      PostgreSQLContainer<?> pg, String user, String password, String database, String initSql) {
    var config = new HikariConfig();
    config.setJdbcUrl(url(pg, database));
    config.setUsername(user);
    config.setPassword(password);
    config.setMaximumPoolSize(1);
    config.setMinimumIdle(0);
    config.setConnectionInitSql(initSql);
    return new HikariDataSource(config);
  }

  static HikariDataSource app(PostgreSQLContainer<?> pg, String database) {
    return pool(pg, APP, PASSWORD, database);
  }

  static HikariDataSource superuser(PostgreSQLContainer<?> pg, String database) {
    return pool(pg, pg.getUsername(), pg.getPassword(), database);
  }

  static void exec(DataSource ds, String... sql) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement()) {
      for (String each : sql) {
        s.execute(each);
      }
    }
  }

  static long rows(DataSource ds, String table) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery("SELECT count(*) FROM public." + table)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  static String scalar(DataSource ds, String sql) throws SQLException {
    try (var c = ds.getConnection();
        var s = c.createStatement();
        var rs = s.executeQuery(sql)) {
      rs.next();
      return rs.getString(1);
    }
  }

  /** The probe's ten-line application delegate. Not a Spring class: no class name sees it. */
  static final class Swappable implements DataSource {
    final AtomicReference<DataSource> target;

    Swappable(DataSource initial) {
      this.target = new AtomicReference<>(initial);
    }

    @Override
    public Connection getConnection() throws SQLException {
      return target.get().getConnection();
    }

    @Override
    public Connection getConnection(String u, String p) throws SQLException {
      return target.get().getConnection(u, p);
    }

    @Override
    public PrintWriter getLogWriter() {
      return null;
    }

    @Override
    public void setLogWriter(PrintWriter out) {}

    @Override
    public void setLoginTimeout(int seconds) {}

    @Override
    public int getLoginTimeout() {
      return 0;
    }

    @Override
    public Logger getParentLogger() {
      return Logger.getGlobal();
    }

    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
      throw new SQLException("not a wrapper");
    }

    @Override
    public boolean isWrapperFor(Class<?> iface) {
      return false;
    }
  }
}
