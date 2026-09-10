package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.hibernate.boot.Metadata;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.event.spi.FlushEvent;
import org.hibernate.event.spi.FlushEventListener;
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
 * Cipher, seventh and eighth pass. S-11: an accepted residual, ruled on and written up in {@code
 * SECURITY-NOTES.md} beside the startup listener check and in {@code
 * ShreddingStartupCheck.REGISTERED_TYPES}'s own javadoc.
 *
 * <p>{@code ShreddingStartupCheck} proves that this module's own listener is registered on all
 * eight event types it registers for, in the position it registered for. It cannot prove that the
 * listeners Hibernate itself seeded are still there, because this module composes its integrator
 * last on purpose: an integrator composed earlier can call {@code registry.setListeners(type, ...)}
 * and replace a group's prior contents - Hibernate's own {@code DefaultFlushEventListener} among
 * them - before this module ever registers, and our listener is then added to the emptied group and
 * measures as correctly positioned, because position is measured against what remains.
 *
 * <p>This is not this module's own control failing: what the attack removes is Hibernate's own
 * seeded listener, never ours. Our listener is registered after the wipe and its presence - and its
 * position, last on {@code FLUSH} - is exactly what {@code refuseIfVerifierNotRegisteredFirst}
 * proves, on all eight types. The application starts, and it should: no control this module makes
 * is disabled by an earlier integrator wiping Hibernate's own default, and the startup check
 * correctly reports that this module's own listener is where it needs to be.
 */
@Testcontainers
class CipherProbeEarlierIntegratorWipesHibernateDefaultsTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = Widget.class)
  @EnableJpaRepositories(basePackageClasses = WidgetRepository.class)
  static class DisplacingApp {
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    HibernatePropertiesCustomizer otherLibraryIntegrator() {
      return properties ->
          properties.put(
              JpaSettings.INTEGRATOR_PROVIDER,
              (IntegratorProvider) () -> List.of(new DisplacingIntegrator()));
    }
  }

  /** Takes over {@code FLUSH} wholesale, the way any library owning its own flush concern might. */
  static final class DisplacingIntegrator implements Integrator {
    @Override
    public void integrate(
        Metadata metadata,
        org.hibernate.boot.spi.BootstrapContext bootstrapContext,
        SessionFactoryImplementor sessionFactory) {
      EventListenerRegistry registry =
          sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
      registry.setListeners(EventType.FLUSH, (FlushEventListener) DisplacingIntegrator::ignore);
    }

    private static void ignore(FlushEvent event) {}

    @Override
    public void disintegrate(
        SessionFactoryImplementor sessionFactory,
        org.hibernate.service.spi.SessionFactoryServiceRegistry serviceRegistry) {}
  }

  @Test
  void our_listener_is_still_present_and_last_on_flush_after_an_earlier_integrator_wipes_it() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(DisplacingApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("displaced-master-key-32-bytes!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("displaced-chain-secret-32-byte!!"),
                "shredding.blind-index.hmac-secret=" + b64("displaced-index-secret-32-byte!!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());

    // The application starts: DisplacingIntegrator wiped Hibernate's own seeded FLUSH listener,
    // not this module's - ours is composed last and registers into the (now emptied) group
    // afterwards, so it is still present and still last, which is what the startup check proves.
    try (var ctx = builder.run()) {
      var sessionFactory =
          ctx.getBean(jakarta.persistence.EntityManagerFactory.class)
              .unwrap(SessionFactoryImplementor.class);
      EventListenerRegistry registry =
          sessionFactory.getServiceRegistry().getService(EventListenerRegistry.class);
      var flushListeners = new java.util.ArrayList<FlushEventListener>();
      registry.getEventListenerGroup(EventType.FLUSH).listeners().forEach(flushListeners::add);

      assertThat(flushListeners)
          .describedAs("Hibernate's own seeded FLUSH listener was wiped by DisplacingIntegrator")
          .noneMatch(l -> l.getClass().getSimpleName().contains("DefaultFlushEventListener"));
      assertThat(flushListeners.get(flushListeners.size() - 1))
          .describedAs("this module's own listener is still last on FLUSH")
          .isInstanceOf(ShreddingEventListener.class);
    }
  }
}
