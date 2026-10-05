package com.housedevinci.shredding.application;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.Pseudonymiser;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Release-candidate review 0.2.0, pass 2 (PR 21), RC-9 at the core boundary: the constructor
 * refuses a negative retention but accepts one that cannot be dated. {@code erase} computes {@code
 * now + retention} before its first statement, so Long.MAX_VALUE seconds throws an uncoded
 * DateTimeException on every erasure, and PT3000000000H yields a backup_clear_at PostgreSQL's
 * timestamptz cannot store.
 */
class CipherProbeRc020Pass2RetentionTest {

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
              throw new UnsupportedOperationException();
            });
  }

  @Test
  void probe_a_retention_past_instant_max_is_accepted_by_the_core_constructor() {
    assertThatThrownBy(() -> service(Duration.ofSeconds(Long.MAX_VALUE)))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertCode(e, "shredding.erasure.backup-retention"));
  }

  @Test
  void probe_a_retention_past_the_database_range_is_accepted_by_the_core_constructor() {
    assertThatThrownBy(() -> service(Duration.ofHours(3_000_000_000L)))
        .isInstanceOfSatisfying(
            ShreddingException.class, e -> assertCode(e, "shredding.erasure.backup-retention"));
  }

  private static void assertCode(ShreddingException e, String property) {
    org.assertj.core.api.Assertions.assertThat(e.code()).isEqualTo(ErrorCodes.CONFIG);
    org.assertj.core.api.Assertions.assertThat(e.getMessage()).contains(property);
  }
}
