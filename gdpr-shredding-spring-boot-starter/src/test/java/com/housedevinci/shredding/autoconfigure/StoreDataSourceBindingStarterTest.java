package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.housedevinci.shredding.adapter.jdbc.BlindIndexResidual;
import com.housedevinci.shredding.adapter.jdbc.JdbcErasureStore;
import com.housedevinci.shredding.adapter.jdbc.JdbcKeyProvider;
import com.housedevinci.shredding.adapter.jdbc.JdbcSupport;
import com.housedevinci.shredding.application.KeyProvider;
import com.housedevinci.shredding.autoconfigure.admission.plain.B2Note;
import com.housedevinci.shredding.domain.ErasureChain;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.MasterKey;
import com.housedevinci.shredding.domain.RandomSource;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.domain.SubjectId;
import com.housedevinci.shredding.domain.TenantId;
import com.housedevinci.shredding.jpa.ShreddingRuntime;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-PR-1, the paths of the design page that only exist once Spring wires the beans: an application
 * store bean on a second DataSource bean (P1), a post-processor that replaces the store (P5), wraps
 * it (P6) or wraps the pool (P8), lazy stores (P9) and a child context (P10). Core's {@code
 * VerifiedDataSourceBindingTest} covers the paths that need no container.
 *
 * <p>One container role owns both databases, so every context runs with {@code
 * initialize-schema=true} and {@code allow-privileged-runtime-role=true}; this class is about which
 * DataSource is written to, not about roles. The {@code unguarded} database has the module tables,
 * so a store that were not refused could write there; each refusal asserts it did not.
 */
@Testcontainers
@SuppressWarnings("removal")
class StoreDataSourceBindingStarterTest {

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

  static DataSource unguarded() {
    return new DriverManagerDataSource(
        unguardedUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
  }

  @BeforeAll
  static void secondDatabase() throws SQLException {
    try (var c =
            DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        var s = c.createStatement()) {
      s.execute("CREATE DATABASE unguarded");
    }
    JdbcSupport.initializeSchema(unguarded());
    // The verified database too, so row counts before the first context are well defined.
    JdbcSupport.initializeSchema(
        new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
  }

  @AfterEach
  void clearRuntime() {
    ShreddingRuntime.clear();
  }

  // ------------------------------------------------------------------ P1

  @Test
  void application_key_provider_on_a_second_datasource_bean_refuses_startup() throws SQLException {
    assertStartupRefused(SecondPoolKeyProviderApp.class);
  }

  @Test
  void application_erasure_store_on_a_second_datasource_bean_refuses_startup() throws SQLException {
    assertStartupRefused(SecondPoolErasureStoreApp.class);
  }

  // ------------------------------------------------------------------ P5

  @Test
  void post_processor_replacing_the_store_with_one_on_another_pool_refuses_startup()
      throws SQLException {
    assertStartupRefused(ReplacingPostProcessorApp.class);
  }

  // ------------------------------------------------------------------ P6

  @Test
  void post_processor_wrapping_the_store_in_a_proxy_starts_and_writes_to_the_verified_database()
      throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    long unguardedBefore = keyRows(unguardedUrl());
    try (var ctx = builder(WrappingStorePostProcessorApp.class).run()) {
      KeyProvider keys = ctx.getBean(KeyProvider.class);
      assertThat(Proxy.isProxyClass(keys.getClass())).isTrue();
      keys.currentForWrite(TenantId.of("p6"), SubjectId.of("s-" + System.nanoTime()));
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
    assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
  }

  // ------------------------------------------------------------------ P8

  @Test
  void post_processor_wrapping_the_pool_bean_starts_and_store_uses_the_wrapped_pool()
      throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    try (var ctx = builder(WrappingPoolPostProcessorApp.class).run()) {
      DataSource gatePool = ctx.getBean(ShreddingSchemaGate.class).dataSource();
      assertThat(gatePool).isInstanceOf(CountingDataSource.class);
      var counting = (CountingDataSource) gatePool;
      int before = counting.connections.get();
      ctx.getBean(KeyProvider.class)
          .currentForWrite(TenantId.of("p8"), SubjectId.of("s-" + System.nanoTime()));
      assertThat(counting.connections.get())
          .describedAs("the store writes through the wrapper the gate verified through")
          .isGreaterThan(before);
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
  }

  @Test
  void
      context_datasource_bean_that_is_a_lazy_connection_proxy_starts_and_writes_to_the_verified_database()
          throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    long unguardedBefore = keyRows(unguardedUrl());
    try (var ctx = builder(LazyProxyPoolApp.class).run()) {
      assertThat(ctx.getBean(ShreddingSchemaGate.class).dataSource())
          .isInstanceOf(LazyConnectionDataSourceProxy.class);
      ctx.getBean(KeyProvider.class)
          .currentForWrite(TenantId.of("p8l"), SubjectId.of("s-" + System.nanoTime()));
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
    assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
  }

  // ------------------------------------------------------------------ P9

  /**
   * Measured on this branch: in both variants an eager bean that depends on the key store creates
   * it during startup, so the refusal lands at startup, earlier than the design page expected
   * ("first use"). The body still asks for the store and writes, so if a later change made it truly
   * lazy, the refusal would have to come at that first use, before the write.
   */
  @Test
  void lazy_store_on_another_pool_refuses_at_creation_and_writes_nothing() throws SQLException {
    long unguardedBefore = keyRows(unguardedUrl());
    // @Lazy on the application's own bean, and the whole context lazy.
    for (var run :
        List.of(
            builder(LazySecondPoolKeyProviderApp.class),
            builder(SecondPoolKeyProviderApp.class, "spring.main.lazy-initialization=true"))) {
      Throwable thrown =
          catchThrowable(
              () -> {
                try (var ctx = run.run()) {
                  // Started: the store is created on first use, and refuses there.
                  ctx.getBean(KeyProvider.class)
                      .currentForWrite(TenantId.of("p9"), SubjectId.of("s1"));
                }
              });
      assertThat(codesInChain(thrown)).contains(ErrorCodes.STORE_DATASOURCE_UNVERIFIED);
    }
    assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
  }

  // ------------------------------------------------------------------ P10

  @Test
  void child_context_store_on_another_pool_is_refused() throws SQLException {
    long unguardedBefore = keyRows(unguardedUrl());
    try (var parent = builder(DefaultApp.class).run()) {
      var child = new AnnotationConfigApplicationContext();
      child.setParent(parent);
      child.register(ChildStoreConfig.class);
      Throwable thrown = catchThrowable(child::refresh);
      child.close();
      assertThat(codesInChain(thrown)).contains(ErrorCodes.STORE_DATASOURCE_UNVERIFIED);
    }
    assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedBefore);
  }

  // ------------------------------------------------------------------ regression, compatibility

  @Test
  void default_stores_still_start_and_log_schema_verified() throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    var log = new CapturingAppender();
    try (var ctx = log.armed(builder(DefaultApp.class)).run()) {
      assertThat(ctx.getBean(KeyProvider.class)).isInstanceOf(JdbcKeyProvider.class);
      assertThat(ctx.getBean(JdbcErasureStore.class)).isNotNull();
      ctx.getBean(KeyProvider.class)
          .currentForWrite(TenantId.of("d1"), SubjectId.of("s-" + System.nanoTime()));
    } finally {
      log.detach();
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
    assertThat(log.lines).anyMatch(l -> l.startsWith("INFO|") && l.contains("schema verified"));
  }

  @Test
  void own_store_bean_on_the_deprecated_constructor_with_the_gates_pool_still_starts()
      throws SQLException {
    long verifiedBefore = keyRows(POSTGRES.getJdbcUrl());
    try (var ctx = builder(DeprecatedFormWithGatePoolApp.class).run()) {
      ctx.getBean(KeyProvider.class)
          .currentForWrite(TenantId.of("c1"), SubjectId.of("s-" + System.nanoTime()));
    }
    assertThat(keyRows(POSTGRES.getJdbcUrl())).isEqualTo(verifiedBefore + 1);
  }

  // ------------------------------------------------------------------ applications

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = B2Note.class)
  static class DefaultApp {
    @Bean
    ShreddingEventListener.TenantSupplier tenantSupplier() {
      return () -> TenantId.of("org-a");
    }
  }

  /** The context's own DataSource, plus a second one for the application's store. */
  static class TwoPools extends DefaultApp {
    @Bean
    @Primary
    DataSource dataSource(DataSourceProperties properties) {
      return properties.initializeDataSourceBuilder().build();
    }

    @Bean
    DataSource unguardedDataSource() {
      return unguarded();
    }
  }

  static class SecondPoolKeyProviderApp extends TwoPools {
    @Bean
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate,
        @org.springframework.beans.factory.annotation.Qualifier("unguardedDataSource")
            DataSource second,
        MasterKey masterKey,
        RandomSource random,
        Clock clock) {
      return new JdbcKeyProvider(second, gate.schema(), masterKey, random, clock);
    }
  }

  static class LazySecondPoolKeyProviderApp extends TwoPools {
    @Bean
    @Lazy
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate,
        @org.springframework.beans.factory.annotation.Qualifier("unguardedDataSource")
            DataSource second,
        MasterKey masterKey,
        RandomSource random,
        Clock clock) {
      return new JdbcKeyProvider(second, gate.schema(), masterKey, random, clock);
    }
  }

  static class SecondPoolErasureStoreApp extends TwoPools {
    @Bean
    JdbcErasureStore shreddingErasureStore(
        ShreddingSchemaGate gate,
        @org.springframework.beans.factory.annotation.Qualifier("unguardedDataSource")
            DataSource second,
        ErasureChain chain) {
      BlindIndexResidual none = (c, column, tenant, subject) -> 0L;
      return new JdbcErasureStore(second, gate.schema(), chain, List.of(), none);
    }
  }

  static class ReplacingPostProcessorApp extends DefaultApp {
    @Bean
    static BeanPostProcessor replaceKeyProvider(
        ObjectProvider<ShreddingSchemaGate> gate,
        ObjectProvider<MasterKey> masterKey,
        ObjectProvider<RandomSource> random) {
      return new BeanPostProcessor() {
        @Override
        public Object postProcessAfterInitialization(Object bean, String name) {
          if (bean instanceof JdbcKeyProvider) {
            return new JdbcKeyProvider(
                unguarded(),
                gate.getObject().schema(),
                masterKey.getObject(),
                random.getObject(),
                Clock.systemUTC());
          }
          return bean;
        }
      };
    }
  }

  static class WrappingStorePostProcessorApp extends DefaultApp {
    @Bean
    static BeanPostProcessor wrapKeyProvider() {
      return new BeanPostProcessor() {
        @Override
        public Object postProcessAfterInitialization(Object bean, String name) {
          if (bean instanceof JdbcKeyProvider target) {
            return Proxy.newProxyInstance(
                KeyProvider.class.getClassLoader(),
                new Class<?>[] {KeyProvider.class},
                (proxy, method, args) -> {
                  try {
                    return method.invoke(target, args);
                  } catch (InvocationTargetException e) {
                    throw e.getCause();
                  }
                });
          }
          return bean;
        }
      };
    }
  }

  static class WrappingPoolPostProcessorApp extends DefaultApp {
    @Bean
    static BeanPostProcessor wrapPool() {
      return new BeanPostProcessor() {
        @Override
        public Object postProcessAfterInitialization(Object bean, String name) {
          if (bean instanceof DataSource ds && !(bean instanceof CountingDataSource)) {
            return new CountingDataSource(ds);
          }
          return bean;
        }
      };
    }
  }

  static class LazyProxyPoolApp extends DefaultApp {
    @Bean
    DataSource dataSource(DataSourceProperties properties) {
      return new LazyConnectionDataSourceProxy(properties.initializeDataSourceBuilder().build());
    }
  }

  static class DeprecatedFormWithGatePoolApp extends DefaultApp {
    @Bean
    KeyProvider shreddingKeyProvider(
        ShreddingSchemaGate gate, MasterKey masterKey, RandomSource random, Clock clock) {
      return new JdbcKeyProvider(gate.dataSource(), gate.schema(), masterKey, random, clock);
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class ChildStoreConfig {
    @Bean
    KeyProvider childKeyProvider(ShreddingSchemaGate gate, MasterKey masterKey) {
      return new JdbcKeyProvider(
          unguarded(), gate.schema(), masterKey, RandomSource.secure(), Clock.systemUTC());
    }
  }

  /** A pool wrapper that keeps its target, and counts connections taken through it. */
  static final class CountingDataSource extends DelegatingDataSource {
    final AtomicInteger connections = new AtomicInteger();

    CountingDataSource(DataSource target) {
      super(target);
    }

    @Override
    public Connection getConnection() throws SQLException {
      connections.incrementAndGet();
      return super.getConnection();
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
      connections.incrementAndGet();
      return super.getConnection(username, password);
    }
  }

  // ------------------------------------------------------------------ helpers

  private static void assertStartupRefused(Class<?> app) throws SQLException {
    long unguardedKeys = keyRows(unguardedUrl());
    long unguardedLog = rows(unguardedUrl(), "shredding_erasure");
    Throwable thrown =
        catchThrowable(
            () -> {
              try (ConfigurableApplicationContext ignored = builder(app).run()) {
                // started: the assertion below fails
              }
            });
    assertThat(thrown).describedAs("the context must refuse to start").isNotNull();
    assertThat(codesInChain(thrown)).contains(ErrorCodes.STORE_DATASOURCE_UNVERIFIED);
    assertThat(keyRows(unguardedUrl())).isEqualTo(unguardedKeys);
    assertThat(rows(unguardedUrl(), "shredding_erasure")).isEqualTo(unguardedLog);
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

  private static long keyRows(String url) throws SQLException {
    return rows(url, "shredding_data_key");
  }

  private static long rows(String url, String table) throws SQLException {
    try (var c = DriverManager.getConnection(url, POSTGRES.getUsername(), POSTGRES.getPassword());
        var s = c.createStatement();
        var rs = s.executeQuery("SELECT count(*) FROM public." + table)) {
      rs.next();
      return rs.getLong(1);
    }
  }

  private static SpringApplicationBuilder builder(Class<?> app, String... extra) {
    var properties =
        new ArrayList<>(
            List.of(
                "shredding.master-key=" + b64("binding-test-master-key-32-bytes"),
                "shredding.jdbc.initialize-schema=true",
                "shredding.jdbc.allow-privileged-runtime-role=true",
                "shredding.erasure-log.hmac-secret=" + b64("binding-test-chain-secret-32-byt"),
                "shredding.blind-index.hmac-secret=" + b64("binding-test-index-secret-32-byt"),
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword(),
                "spring.data.jpa.repositories.enabled=false",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.dialect="
                    + "org.hibernate.dialect.PostgreSQLDialect"));
    properties.addAll(List.of(extra));
    return new SpringApplicationBuilder(app)
        .web(WebApplicationType.NONE)
        .properties(properties.toArray(String[]::new));
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static final class CapturingAppender {

    final List<String> lines = java.util.Collections.synchronizedList(new ArrayList<>());
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
  }
}
