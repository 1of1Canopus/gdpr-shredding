package com.housedevinci.shredding.autoconfigure;

import com.housedevinci.shredding.application.ErasureChainVerifier;
import com.housedevinci.shredding.application.KeyProvider;
import java.util.Set;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;

/**
 * Actuator wiring: the master key is removed from {@code /env} and {@code /configprops}
 * <em>explicitly</em> (control 5), and the key store's reachability is reported.
 */
@AutoConfiguration(after = ShreddingAutoConfiguration.class)
@ConditionalOnClass({SanitizingFunction.class, HealthIndicator.class})
public class ShreddingActuatorAutoConfiguration {

  /**
   * Every property of this module that holds key material, by name.
   *
   * <p>Boot's default sanitiser happens to catch names containing "key" and "secret" today. That is
   * a heuristic about English words, not a security control, and one rename upstream turns a master
   * key into a public endpoint. This function names them.
   */
  static final Set<String> SECRET_PROPERTIES =
      Set.of(
          "shredding.master-key",
          "shredding.erasure-log.hmac-secret",
          "shredding.blind-index.hmac-secret");

  private static final Set<String> SECRET_NAMES =
      SECRET_PROPERTIES.stream()
          .map(ShreddingActuatorAutoConfiguration::squash)
          .collect(java.util.stream.Collectors.toUnmodifiableSet());

  private static String squash(String name) {
    return name.toLowerCase(java.util.Locale.ROOT)
        .replace(".", "")
        .replace("-", "")
        .replace("_", "");
  }

  @Bean
  public SanitizingFunction shreddingSanitizingFunction() {
    return (SanitizableData data) -> {
      String key = data.getKey();
      if (key == null) {
        return data;
      }
      // Separators are stripped, so the canonical name, the relaxed name and the environment
      // variable form (SHREDDING_MASTER_KEY) are all the same string here. The actuator's env
      // endpoint reports whichever form the property source used.
      String normalised = squash(key);
      if (SECRET_NAMES.contains(normalised)
          || normalised.startsWith(squash("shredding.erasure-log.hmac-keys"))) {
        return data.withValue("******");
      }
      return data;
    };
  }

  @Bean
  @ConditionalOnMissingBean(name = "shreddingHealthIndicator")
  public HealthIndicator shreddingHealthIndicator(
      KeyProvider keyProvider, ErasureChainVerifier verifier) {
    return () -> {
      if (!keyProvider.healthy()) {
        // A key store that is down is an outage, not an erasure: the readiness probe must say so
        // rather than let the application serve sentinels (control 16).
        return Health.down().withDetail("keyStore", "unreachable").build();
      }
      var report = verifier.verify();
      Health.Builder builder = report.intact() ? Health.up() : Health.down();
      return builder
          .withDetail("keyStore", "reachable")
          .withDetail("erasureLog", report.status().name())
          .withDetail("erasureRecords", report.verified())
          .build();
    };
  }
}
