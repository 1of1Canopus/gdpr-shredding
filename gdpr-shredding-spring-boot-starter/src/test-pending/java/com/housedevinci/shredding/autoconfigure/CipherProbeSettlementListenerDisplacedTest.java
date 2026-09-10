package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.fixture.Widget;
import com.housedevinci.shredding.autoconfigure.fixture.WidgetRepository;
import com.housedevinci.shredding.domain.ShreddingException;
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
 * Cipher, seventh pass (e2c2bdd). S-6's post-boot self-check
 * ({@code ShreddingStartupCheck.refuseIfVerifierNotRegisteredFirst}) closes "the composition
 * actually reached Hibernate" for five of the seven event types {@code ShreddingIntegrator}
 * registers, and closes "still in the position it was registered in" for exactly one.
 *
 * <ul>
 *   <li>{@code FLUSH}, {@code AUTO_FLUSH} and {@code POST_DELETE} are not checked at all. Those
 *       three are S-1's settlement machinery: the first settlement point and the discharge of a row
 *       deleted in the same flush.
 *   <li>{@code PRE_INSERT} and {@code PRE_UPDATE} are checked for presence but not for being first,
 *       though the integrator prepends them precisely so "the scope is pushed before anything else
 *       can trigger a bind"; {@code POST_INSERT} and {@code POST_UPDATE} are checked for presence
 *       but not for being last, though the integrator appends them precisely so the post-hoc check
 *       "sees what actually reached the database, after every other listener has had its turn".
 * </ul>
 *
 * <p>A self-check that verifies some of what it registered is not a self-check; it is the same
 * "best effort, not a proof" S-6 was raised to remove, moved one level in. This probe displaces the
 * one listener that costs the most - {@code FLUSH} - with another library's {@code
 * setListeners(...)}, which is an ordinary {@code EventListenerRegistry} call, and the application
 * starts without a word. The fix is to check every type the integrator touches, at the position it
 * registered for.
 */
@Testcontainers
class CipherProbeSettlementListenerDisplacedTest {

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
  void probe_a_displaced_settlement_listener_is_not_detected_after_boot() {
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

    String outcome;
    try (var ctx = builder.run()) {
      outcome = "STARTED";
    } catch (RuntimeException e) {
      outcome = "STARTUP-REFUSED " + codeOf(e);
    }
    System.out.println("DISPLACED FLUSH LISTENER -> " + outcome);

    assertThat(outcome).startsWith("STARTUP-REFUSED");
  }

  private static String codeOf(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    return thrown.getClass().getSimpleName();
  }
}
