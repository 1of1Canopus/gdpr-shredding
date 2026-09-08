package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.endpoint.SanitizableData;

/** Cipher probe: the master key is out of the actuator by name, not by luck (control 5). */
class CipherProbeActuatorTest {

  private final org.springframework.boot.actuate.endpoint.SanitizingFunction function =
      new ShreddingActuatorAutoConfiguration().shreddingSanitizingFunction();

  /**
   * Boot's default sanitiser catches names that happen to contain "key" or "secret". That is a
   * heuristic about English words, and one property rename upstream would publish the master key on
   * an HTTP endpoint. This module names the properties it will not show.
   */
  @Test
  void probe_master_key_appears_in_actuator_env() {
    assertThat(sanitize("shredding.master-key", "AAAA")).isEqualTo("******");
    assertThat(sanitize("SHREDDING_MASTER_KEY", "AAAA")).isEqualTo("******");
    assertThat(sanitize("shredding.erasure-log.hmac-secret", "AAAA")).isEqualTo("******");
    assertThat(sanitize("shredding.erasure-log.hmac-keys.k1", "AAAA")).isEqualTo("******");
    assertThat(sanitize("shredding.blind-index.hmac-secret", "AAAA")).isEqualTo("******");
  }

  @Test
  void a_harmless_property_is_left_alone() {
    assertThat(sanitize("shredding.data-key-cache.ttl", "60s")).isEqualTo("60s");
    assertThat(sanitize("shredding.erased-value.policy", "sentinel")).isEqualTo("sentinel");
  }

  private Object sanitize(String key, String value) {
    return function.apply(new SanitizableData(null, key, value)).getValue();
  }
}
