package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.config.CustomScopeConfigurer;
import org.springframework.beans.factory.config.InstantiationAwareBeanPostProcessor;
import org.springframework.beans.factory.config.Scope;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.jdbc.datasource.TransactionAwareDataSourceProxy;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1b, the paths of the design page that need Spring to wire them: a routing pool (M1), a
 * refresh-scoped pool (M2), Spring's {@code DelegatingDataSource} retargeted (M3), Hikari
 * credentials changed through its management bean (M10), Spring's lazy and transaction-aware
 * proxies as the context DataSource (M13), and the starter's own boot read after the gate (M14).
 * Core's {@code DatabaseIdentityCheckTest} covers the paths without Spring.
 *
 * <p>The container role owns both databases, so every context runs with {@code
 * initialize-schema=true} and {@code allow-privileged-runtime-role=true}; this class is about which
 * database a connection reaches. The {@code unguarded} database holds the module tables, so a store
 * that were not refused could write there; each refusal asserts it did not.
 */
@Testcontainers
class MovingTargetStarterTest {

  static final String CODE = "SHRED-SCHEMA-012";

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
              DockerImageName.parse(
                      "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
                  .asCompatibleSubstituteFor("postgres"))
          .withInitScript("shredding-test/statistics-off.sql")
          .withStartupTimeout(java.time.Duration.ofMinutes(2));

  static String unguardedUrl() {
    return POSTGRES.getJdbcUrl().replace("/" + POSTGRES.getDatabaseName(), "/unguarded");
  }

  static DataSource verified() {
    return new DriverManagerDataSource(
        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  static DataSource unguarded() {
    return new DriverManagerDataSource(
        unguardedUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  @BeforeAll
  static void secondDatabase() throws SQLException {
    try (var c = verified().getConnection();
        var s = c.createStatement()) {
      s.execute("CREATE DATABASE unguarded");
      s.execute("CREATE ROLE intruder LOGIN SUPERUSER PASSWORD 'intruder-pw'");
    }
    JdbcSupport.initializeSchema(unguarded());
    JdbcSupport.initializeSchema(verified());
  }

  @AfterEach
  void clearRuntime() {
    ShreddingRuntime.clear();
    Router.KEY.set("verified");
  }

  // ------------------------------------------------------------------ M1

  @Test
  void routing_datasource_switching_target_refuses_the_write_and_keeps_the_verified_route_working()
      throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    long unguardedBefore = keyRows(unguardedUrl());
    try (var ctx = builder(RoutingApp.class).run()) {
      KeyProvider keys = ctx.getBean(KeyProvider.class);
      Router.KEY.set("other");
      assertRefused(catchThrowable(() -> keys.currentForWrite(TenantId.of("m1"), subject())));
      assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);

      Router.KEY.set("verified");
      keys.currentForWrite(TenantId.of("m1"), subject());
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
  }

  // ------------------------------------------------------------------ M2

  @Test
  void refreshed_datasource_with_a_new_url_refuses() throws SQLException {
    long unguardedBefore = keyRows(unguardedUrl());
    RefreshApp.URL.set(POSTGRES.getJdbcUrl());
    try (var ctx = builder(RefreshApp.class).run()) {
      KeyProvider keys = ctx.getBean(KeyProvider.class);
      keys.currentForWrite(TenantId.of("m2"), subject());

      // What a configuration refresh does: the URL changes and the scoped target is rebuilt.
      RefreshApp.URL.set(unguardedUrl());
      RefreshApp.SCOPE.refresh();

      assertRefused(catchThrowable(() -> keys.currentForWrite(TenantId.of("m2"), subject())));
      assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
      RefreshApp.URL.set(POSTGRES.getJdbcUrl());
      RefreshApp.SCOPE.refresh();
    }
  }

  // ------------------------------------------------------------------ M3

  @Test
  void delegating_datasource_set_target_after_startup_refuses() throws SQLException {
    long unguardedBefore = keyRows(unguardedUrl());
    try (var ctx = builder(DelegatingApp.class).run()) {
      KeyProvider keys = ctx.getBean(KeyProvider.class);
      var delegating = ctx.getBean(DelegatingDataSource.class);
      delegating.setTargetDataSource(unguarded());

      assertRefused(catchThrowable(() -> keys.currentForWrite(TenantId.of("m3"), subject())));
      assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
      delegating.setTargetDataSource(verified());
    }
  }

  // ------------------------------------------------------------------ M10

  /**
   * Hikari applies credentials changed through its management bean to the connections it opens
   * next. New connections then log in as another role, and {@code session_user} differs from the
   * verified one.
   */
  @Test
  void hikari_credentials_changed_through_the_mxbean_refuse_or_are_recorded_unreachable()
      throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    try (var ctx = builder(HikariApp.class).run()) {
      KeyProvider keys = ctx.getBean(KeyProvider.class);
      var hikari = ctx.getBean(HikariDataSource.class);
      // Let the pool finish its first fill: a connection whose creation began before the
      // credentials change logs in with the old ones, and under a loaded suite it can arrive
      // after the eviction below (seen once in a full verify, C-PR-1c build).
      long deadline = System.nanoTime() + java.time.Duration.ofSeconds(20).toNanos();
      while (hikari.getHikariPoolMXBean().getTotalConnections() < hikari.getMinimumIdle()
          && System.nanoTime() < deadline) {
        java.util.concurrent.locks.LockSupport.parkNanos(20_000_000L);
      }
      hikari.getHikariConfigMXBean().setUsername("intruder");
      hikari.getHikariConfigMXBean().setPassword("intruder-pw");
      hikari.getHikariPoolMXBean().softEvictConnections();
      // Precondition: the path is reachable, new connections log in as the other role.
      try (var c = hikari.getConnection();
          var s = c.createStatement();
          var rs = s.executeQuery("SELECT session_user")) {
        rs.next();
        assertThat(rs.getString(1)).isEqualTo("intruder");
      }

      Throwable thrown = catchThrowable(() -> keys.currentForWrite(TenantId.of("m10"), subject()));

      assertRefused(thrown);
      assertThat(thrown.getMessage()).contains("login role").contains("\"intruder\"");
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore);
  }

  // ------------------------------------------------------------------ M13

  @Test
  void lazy_connection_proxy_as_context_datasource_starts_and_writes() throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    try (var ctx = builder(LazyProxyApp.class).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).dataSource())
          .isInstanceOf(LazyConnectionDataSourceProxy.class);
      ctx.getBean(KeyProvider.class).currentForWrite(TenantId.of("m13"), subject());
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
  }

  @Test
  void transaction_aware_proxy_as_context_datasource_starts_and_writes() throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    try (var ctx = builder(TransactionAwareApp.class).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).dataSource())
          .isInstanceOf(TransactionAwareDataSourceProxy.class);
      ctx.getBean(KeyProvider.class).currentForWrite(TenantId.of("m13t"), subject());
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
  }

  // ------------------------------------------------------------------ M14

  @Test
  void mapping_admission_check_refuses_a_moved_target_at_boot() {
    Throwable thrown = catchThrowable(() -> builder(MovedBeforeAdmissionApp.class).run().close());

    assertThat(thrown).isNotNull();
    BeanCreationException failed = null;
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof BeanCreationException b) {
        failed = b;
      }
    }
    assertThat(failed).isNotNull();
    assertThat(failed.getBeanName()).isEqualTo("shreddingMappingAdmission");
    assertThat(codesInChain(thrown)).contains(CODE);
    MovedBeforeAdmissionApp.MOVING.target.set(verified());
  }

  // ------------------------------------------------------------------ applications

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class BaseApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  static final class Router extends AbstractRoutingDataSource {
    static final AtomicReference<String> KEY = new AtomicReference<>("verified");

    Router() {
      setTargetDataSources(Map.of("verified", verified(), "other", unguarded()));
      setDefaultTargetDataSource(verified());
    }

    @Override
    protected Object determineCurrentLookupKey() {
      return KEY.get();
    }
  }

  static class RoutingApp extends BaseApp {
    @Bean
    DataSource dataSource() {
      return new Router();
    }
  }

  /**
   * A minimal refresh scope: what a configuration refresh does to a scoped bean, no Spring Cloud.
   */
  static final class RefreshScope implements Scope {
    private final Map<String, Object> beans = new ConcurrentHashMap<>();

    @Override
    public Object get(String name, ObjectFactory<?> factory) {
      return beans.computeIfAbsent(name, n -> factory.getObject());
    }

    @Override
    public Object remove(String name) {
      return beans.remove(name);
    }

    @Override
    public void registerDestructionCallback(String name, Runnable callback) {}

    @Override
    public Object resolveContextualObject(String key) {
      return null;
    }

    @Override
    public String getConversationId() {
      return "refresh";
    }

    void refresh() {
      beans.clear();
    }
  }

  static class RefreshApp extends BaseApp {
    static final AtomicReference<String> URL = new AtomicReference<>();
    static final RefreshScope SCOPE = new RefreshScope();

    @Bean
    static CustomScopeConfigurer refreshScope() {
      var configurer = new CustomScopeConfigurer();
      configurer.addScope("refresh", SCOPE);
      return configurer;
    }

    @Bean
    @org.springframework.context.annotation.Scope(
        value = "refresh",
        proxyMode = ScopedProxyMode.INTERFACES)
    DataSource dataSource() {
      return new DriverManagerDataSource(URL.get(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
  }

  static class DelegatingApp extends BaseApp {
    @Bean
    DelegatingDataSource dataSource() {
      return new DelegatingDataSource(verified());
    }
  }

  static class HikariApp extends BaseApp {}

  static class LazyProxyApp extends BaseApp {
    @Bean
    DataSource dataSource(DataSourceProperties properties) {
      return new LazyConnectionDataSourceProxy(properties.initializeDataSourceBuilder().build());
    }
  }

  static class TransactionAwareApp extends BaseApp {
    @Bean
    DataSource dataSource(DataSourceProperties properties) {
      return new TransactionAwareDataSourceProxy(properties.initializeDataSourceBuilder().build());
    }
  }

  /** Moves the target in the instant before the starter's mapping admission bean is created. */
  static class MovedBeforeAdmissionApp extends BaseApp {
    static final Moving MOVING = new Moving();

    @Bean
    DataSource dataSource() {
      MOVING.target.set(verified());
      return MOVING;
    }

    @Bean
    static InstantiationAwareBeanPostProcessor moveBeforeAdmission() {
      return new InstantiationAwareBeanPostProcessor() {
        @Override
        public Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) {
          if ("shreddingMappingAdmission".equals(beanName)) {
            MOVING.target.set(unguarded());
          }
          return null;
        }
      };
    }
  }

  /** The ten-line application delegate. */
  static final class Moving extends DelegatingDataSource {
    final AtomicReference<DataSource> target = new AtomicReference<>();

    @Override
    public DataSource getTargetDataSource() {
      return target.get();
    }

    @Override
    public void afterPropertiesSet() {}
  }

  // ------------------------------------------------------------------ helpers

  private static void assertRefused(Throwable thrown) {
    assertThat(thrown).isInstanceOf(ShreddingException.class);
    assertThat(((ShreddingException) thrown).code()).isEqualTo(CODE);
  }

  private static List<String> codesInChain(Throwable thrown) {
    var codes = new ArrayList<String>();
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        codes.add(s.code());
      }
    }
    return codes;
  }

  private static SubjectId subject() {
    return SubjectId.of("s-" + System.nanoTime());
  }

  private static long keyRows(String url) throws SQLException {
    try (var c = DriverManager.getConnection(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        var s = c.createStatement();
        var rs = s.executeQuery("SELECT count(*) FROM public.shredding_data_key")) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static SpringApplicationBuilder builder(Class<?> app) {
    var properties =
        List.of(
            "shredding.master-key=" + b64("moving-target-master-key-32-byte"),
            "shredding.jdbc.initialize-schema=true",
            "shredding.jdbc.allow-privileged-runtime-role=true",
            "shredding.erasure-log.hmac-secret=" + b64("moving-target-chain-secret-32-by"),
            "shredding.blind-index.hmac-secret=" + b64("moving-target-index-secret-32-by"),
            "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
            "spring.datasource.username=" + POSTGRES.getUsername(),
            "spring.datasource.password=" + POSTGRES.getPassword(),
            "spring.data.jpa.repositories.enabled=false",
            "spring.jpa.hibernate.ddl-auto=update",
            "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect");
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(properties.toArray(String[]::new));
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }
}
