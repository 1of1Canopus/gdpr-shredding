package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.propseq.PropSeqWidget;
import com.housedevinci.shredding.autoconfigure.propseq.PropSeqWidgetRepository;
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
 * Cipher sixth pass, design item 14's insert half - QUESTIONS #25; renamed per S-12 (Cipher seventh
 * pass) to what this class actually asserts.
 *
 * <p>This probe originally demonstrated S-1 (a batched {@code INSERT} silently skipping the
 * insert-side post-hoc header check) through {@code PropSeqWidget}, an
 * {@code @Access(AccessType.PROPERTY)} shredded mapping: the one shape whose column Hibernate wrote
 * with no converter applied at all, which is what let a batched write commit plaintext without a
 * fixture needing to fight Hibernate's own snapshot machinery.
 *
 * <p>{@code PropSeqWidget} is also exactly S-5's shape - {@code @Shredded} declared on the field,
 * {@code @Convert} never applied because Hibernate reads property-access mappings off the getters -
 * and S-5's fix refuses that mapping at startup, naming the entity and the field, the same
 * treatment every other mapping this module cannot protect gets (composite id,
 * {@code @SecondaryTable} split, {@code byte[]} without {@code @Immutable}). Once S-5 lands, this
 * fixture's {@code @SpringBootTest} context can no longer come up at all - refused before a single
 * row is ever written, batched or not - so what this class asserts today, and the reason for its
 * name, is the startup refusal of a property-access mapping <em>under batching configuration</em>
 * specifically (the original S-1 fixture's own {@code hibernate.jdbc.batch_size} / {@code
 * order_inserts} properties, kept so a future batching-specific regression in the startup scan
 * still has a fixture to catch it on) - not S-1's batched-write property itself, which this file no
 * longer tests. It is in the same shape as {@code CipherProbeCompositeIdTest} (C-38) and {@code
 * CipherProbePropertyAccessTest} (S-5's own probe, on a different fixture, without batching).
 *
 * <p>S-1's property - no row of a {@code @Shredded} entity commits whose stored header is not bound
 * to the scope it was written under, at any {@code hibernate.jdbc.batch_size} - is independently
 * carried in the default build by {@code BatchedWriteVerificationTest}'s seventeen probes (see that
 * class's own javadoc), none of which needs a mapping S-5 refuses to demonstrate it.
 */
@Testcontainers
class CipherProbePropertyAccessSequenceTest {

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
  @EntityScan(basePackageClasses = PropSeqWidget.class)
  @EnableJpaRepositories(basePackageClasses = PropSeqWidgetRepository.class)
  static class PropSeqApp {}

  /**
   * The mapping this probe used to write batched rows through is refused at boot, naming the entity
   * and the field - not left to be discovered by a batched write committing plaintext.
   */
  @Test
  void probe_a_property_access_mapping_under_batching_is_refused_at_startup() {
    String outcome = startup();
    assertThat(outcome).startsWith("STARTUP-REFUSED SHRED-CONFIG-001");
    assertThat(outcome).contains("PropSeqWidget").contains("name");
  }

  private String startup() {
    SpringApplicationBuilder builder =
        new SpringApplicationBuilder(PropSeqApp.class)
            .web(WebApplicationType.NONE)
            .properties(
                "shredding.master-key=" + b64("propseq-master-key-32-bytes!!!!!"),
                "shredding.erasure-log.hmac-secret=" + b64("propseq-chain-secret-32-bytes!!!"),
                "shredding.blind-index.hmac-secret=" + b64("propseq-index-secret-32-bytes!!!"),
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "spring.jpa.properties.hibernate.jdbc.batch_size=10",
                "spring.jpa.properties.hibernate.order_inserts=true",
                "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "spring.datasource.username=" + POSTGRES.getUsername(),
                "spring.datasource.password=" + POSTGRES.getPassword());
    try (var ctx = builder.run()) {
      System.out.println("PROPSEQ BATCHED -> STARTED (nothing refused it)");
      return "STARTED";
    } catch (RuntimeException e) {
      String outcome = "STARTUP-REFUSED " + code(e);
      System.out.println("PROPSEQ BATCHED -> " + outcome);
      return outcome;
    }
  }

  private static String code(Throwable thrown) {
    for (Throwable t = thrown; t != null; t = t.getCause()) {
      if (t instanceof ShreddingException s) {
        return s.code() + ": " + s.getMessage();
      }
    }
    return thrown.getClass().getSimpleName() + ": " + thrown.getMessage();
  }
}
