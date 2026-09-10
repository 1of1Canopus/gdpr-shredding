package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ShreddingException;
import com.housedevinci.shredding.jpa.Placeholders;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.hibernate.boot.Metadata;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.PostLoadEvent;
import org.hibernate.event.spi.PostLoadEventListener;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.jpa.boot.spi.IntegratorProvider;
import org.hibernate.jpa.boot.spi.JpaSettings;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher sixth pass, design item 8. {@code ShreddingIntegrator} prepends its {@code POST_LOAD}
 * listener so no {@code @PostLoad} callback ever sees the placeholder, and {@code
 * ShreddingAutoConfiguration.shreddingHibernateCustomizer} installs that integrator with an
 * unconditional {@code properties.put(JpaSettings.INTEGRATOR_PROVIDER, ...)}.
 *
 * <p>Two things nothing in the module checks. First, {@code INTEGRATOR_PROVIDER} is a single
 * property: a second {@code HibernatePropertiesCustomizer} - a library that ships its own
 * integrator, or an application that adds one - overwrites the value instead of adding to it, and
 * whichever customizer Spring happens to apply last decides whether this module's listener is
 * registered at all. Second, even when both are registered, "prepended" is only "first" until
 * another integrator prepends after ours, and the verifier stops being the first thing to see the
 * loaded row.
 *
 * <p>Measured on this branch: the auto-configuration's customizer is the one Spring applies last,
 * so the module's own integrator survives and the <em>other</em> library's is silently discarded -
 * an application's own auditing or security integrator among them. The reverse ordering, an
 * integrator discovered through {@code META-INF/services} (which Hibernate registers after the
 * provided ones) prepending {@code POST_LOAD} after this module, is not reproduced here: it needs a
 * service file on the module's whole test classpath. It is the same missing check.
 */
@Testcontainers
class CipherProbeSecondIntegratorTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  static final List<String> OBSERVED = new java.util.concurrent.CopyOnWriteArrayList<>();

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class SecondIntegratorApp {

    /** What another starter on the classpath looks like. Applied after this module's. */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    HibernatePropertiesCustomizer otherLibraryIntegrator() {
      return properties ->
          properties.put(
              JpaSettings.INTEGRATOR_PROVIDER,
              (IntegratorProvider) () -> List.of(new NosyIntegrator()));
    }
  }

  /** Prepends its own {@code POST_LOAD} listener, exactly the way this module does. */
  static final class NosyIntegrator implements Integrator {
    @Override
    public void integrate(
        Metadata metadata,
        org.hibernate.boot.spi.BootstrapContext bootstrapContext,
        SessionFactoryImplementor sessionFactory) {
      EventListenerRegistry registry =
          sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
      registry.prependListeners(EventType.POST_LOAD, (PostLoadEventListener) NosyIntegrator::look);
    }

    private static void look(PostLoadEvent event) {
      if (event.getEntity() instanceof Widget widget) {
        String seen = String.valueOf(nameOf(widget));
        OBSERVED.add(seen);
      }
    }

    private static Object nameOf(Widget widget) {
      try {
        var field = Widget.class.getDeclaredField("name");
        field.setAccessible(true);
        return field.get(widget);
      } catch (ReflectiveOperationException e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public void disintegrate(
        SessionFactoryImplementor sessionFactory,
        org.hibernate.service.spi.SessionFactoryServiceRegistry serviceRegistry) {}
  }

  /**
   * Nothing outside this module may observe the placeholder, and a read must still work. If this
   * module's listener cannot be guaranteed to be first, or cannot be guaranteed to be registered at
   * all, that has to be detected after the {@code SessionFactory} is built and refused - not left
   * to whichever customizer Spring applies last.
   */
  @Test
  void probe_a_second_integrator_cannot_displace_the_verifier() {
    OBSERVED.clear();
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(SecondIntegratorApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("secondintegrator-master-key-32!!"),
                "shredding.erasure-log.hmac-secret=" + b64("secondintegrator-chain-secret32!"),
                "shredding.blind-index.hmac-secret=" + b64("secondintegrator-index-secret32!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());

    String outcome;
    try (var ctx = builder.run()) {
      var widgets = ctx.getBean(WidgetRepository.class);
      var transactions =
          ctx.getBean(org.springframework.transaction.support.TransactionTemplate.class);
      var entityManager = ctx.getBean(jakarta.persistence.EntityManager.class);
      String owner = "second-integrator-" + System.nanoTime();
      Long id = transactions.execute(s -> widgets.save(new Widget(owner, "NOSY-SECRET")).getId());
      outcome =
          transactions.execute(
              s -> {
                entityManager.clear();
                try {
                  return "READ " + widgets.findById(id).orElseThrow().getName();
                } catch (RuntimeException e) {
                  return "REFUSED " + codeOf(e);
                }
              });
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + codeOf(e);
    }
    System.out.println("SECOND INTEGRATOR -> " + outcome + "; observed " + OBSERVED);

    // Measured: our customizer is the one Spring applies last, so the other library's provider is
    // the one that loses - its integrator never runs, silently. Both halves are asserted, because
    // the fix has to be "compose the providers, then check after the SessionFactory is built that
    // this module's listener is registered and is first on POST_LOAD" - not "hope we win the race".
    assertThat(OBSERVED).as("the other library's integrator never ran at all").isNotEmpty();
    // S-10 (Cipher seventh pass): describe() is now a fixed literal, not the real per-JVM token -
    // the property this asserts is about the real token never leaking, so it compares against
    // Placeholders.STRING itself, not describe()'s rendering of it.
    assertThat(OBSERVED).noneMatch(seen -> seen.equals(Placeholders.STRING));
    assertThat(outcome).doesNotStartWith("REFUSED");
  }

  private static String codeOf(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code() + ": " + s.getMessage();
      }
    }
    return thrown.getClass().getSimpleName() + ": " + thrown.getMessage();
  }
}
