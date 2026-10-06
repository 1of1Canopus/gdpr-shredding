package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/** RC-5 at the core boundary: a negative backup retention is refused, zero stays legal. */
class ErasureServiceRetentionTest {

  private static ErasureService service(Duration retention) {
    return new ErasureService(
        null_store(),
        new DataKeyCache(Duration.ofSeconds(60), 10, Clock.systemUTC()),
        new Pseudonymiser("rc5-retention-secret-32-bytes!!!!".getBytes(StandardCharsets.UTF_8)),
        List.of(),
        retention,
        Clock.systemUTC(),
        1,
        1);
  }

  private static ErasureStore null_store() {
    return (ErasureStore)
        java.lang.reflect.Proxy.newProxyInstance(
            ErasureStore.class.getClassLoader(),
            new Class<?>[] {ErasureStore.class},
            (proxy, method, args) -> {
              // The constructor reads the acknowledged copies (audit-table coverage, 3c.2); this
              // store has none, as the port's default says. Every other call is refused.
              if ("acknowledgedCopies".equals(method.getName())) {
                return List.of();
              }
              throw new UnsupportedOperationException();
            });
  }

  @Test
  void a_negative_retention_is_refused_naming_the_property() {
    assertThatThrownBy(() -> service(Duration.ofDays(-30)))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertCode(e, "shredding.erasure.backup-retention"));
  }

  @Test
  void zero_is_legal() {
    assertThatCode(() -> service(Duration.ZERO)).doesNotThrowAnyException();
  }

  private static void assertCode(ShreddingException e, String property) {
    org.assertj.core.api.Assertions.assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG);
    org.assertj.core.api.Assertions.assertThat(e.getMessage()).contains(property);
  }
}
