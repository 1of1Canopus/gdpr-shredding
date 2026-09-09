package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.housedevinci.shredding.autoconfigure.brokenconvert.Ledger;
import com.housedevinci.shredding.autoconfigure.brokenconvert.LedgerRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * C-19: {@code ShreddedModel.scan}'s reverse metamodel check. Kept as its own, self-booted context
 * (rather than a {@code @SpringBootTest} class field) because the whole point of the fix is that a
 * context containing {@code Ledger} must never finish starting - sharing a context with any other
 * test would take that test down too. See {@code Ledger}'s javadoc.
 */
@Testcontainers
class CipherProbeReverseScanTest {

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
  @EntityScan(basePackageClasses = Ledger.class)
  @EnableJpaRepositories(basePackageClasses = LedgerRepository.class)
  static class LedgerOnlyApp {}

  @Test
  void a_class_level_convert_column_with_no_shredded_annotation_fails_startup() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(LedgerOnlyApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("reverse-scan-master-key-32-bytes"),
                "shredding.erasure-log.hmac-secret=" + b64("reverse-scan-chain-secret-32bytes"),
                "shredding.blind-index.hmac-secret=" + b64("reverse-scan-index-secret-32bytes"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());

    assertThatThrownBy(builder::run)
        .satisfies(
            t -> {
              String code = shreddingCode(t);
              assertThat(code).isEqualTo(ErrorCodes.CONFIG);
              assertThat(t).hasMessageContaining("Ledger.secret").hasMessageContaining("Convert");
            });
  }

  private static String shreddingCode(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code();
      }
    }
    throw new AssertionError("no ShreddingException in the chain", thrown);
  }
}
