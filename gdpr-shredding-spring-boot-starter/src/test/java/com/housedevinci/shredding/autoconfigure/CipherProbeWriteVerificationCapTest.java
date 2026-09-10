package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.batch.BatchWidget;
import com.housedevinci.shredding.autoconfigure.batch.BatchWidgetRepository;
import com.housedevinci.shredding.domain.ErrorCodes;
import com.housedevinci.shredding.domain.ShreddingException;
import jakarta.persistence.EntityManagerFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * QUESTIONS #26, Cipher's ruling on the seventh pass (2026-09-10, accepted with a number).
 *
 * <p>Settlement discharges the write-verification ledger at the end of every flush, so an ordinary
 * {@code @Transactional} write never holds more than one flush worth of debt. {@code
 * StatelessSession} fires no flush event at all, so a stateless import that stays inside one
 * transaction for its whole run keeps accumulating debts - each one a subject and a tenant - until
 * {@code beforeCompletion}, unboundedly: "it degrades until the JVM dies" is not a bound, and an
 * OOM heap dump of the ledger is personal data.
 *
 * <p>{@code shredding.write-verification.max-outstanding} (default 50 000) is the hard cap: a debt
 * that would exceed it is refused with {@code SHRED-UNVERIFIED-WRITE}, naming the property and the
 * remedy (a transaction per chunk), rather than left to grow without bound. It refuses; it never
 * degrades.
 */
@SpringBootTest(classes = CipherProbeWriteVerificationCapTest.CapApp.class)
@Testcontainers
@DirtiesContext
class CipherProbeWriteVerificationCapTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("write-verif-cap-master-key-32byt"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("write-verif-cap-chain-secret-32b"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("write-verif-cap-index-secret-32b"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
    // A small cap so the probe does not need to actually insert fifty thousand rows to reach it.
    registry.add("shredding.write-verification.max-outstanding", () -> "3");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = BatchWidget.class)
  @EnableJpaRepositories(basePackageClasses = BatchWidgetRepository.class)
  static class CapApp {}

  @Autowired EntityManagerFactory entityManagerFactory;
  @Autowired BatchWidgetRepository widgets;

  @Test
  void a_stateless_import_past_the_cap_is_refused_rather_than_accumulated() {
    String owner = "cap-" + System.nanoTime();
    var sessionFactory = entityManagerFactory.unwrap(org.hibernate.SessionFactory.class);

    String outcome;
    try (var stateless = sessionFactory.openStatelessSession()) {
      var tx = stateless.beginTransaction();
      try {
        List<BatchWidget> rows = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
          rows.add(new BatchWidget(owner, "row-" + i));
        }
        // insertMultiple fires PostInsert - and so WriteVerification.owe - once per row, inside the
        // loop, before its own batch executes: the cap is crossed on the fourth row, well before
        // the whole list is even done inserting.
        stateless.insertMultiple(rows);
        tx.commit();
        outcome = "COMMITTED";
      } catch (RuntimeException e) {
        outcome = "REFUSED " + codeOf(e);
        tx.rollback();
      }
    }

    assertThat(outcome).isEqualTo("REFUSED " + ErrorCodes.UNVERIFIED_WRITE);
    // Never degraded: the ledger did not silently keep every one of the ten rows' debts.
    assertThat(widgets.findByOwnerId(owner)).hasSizeLessThan(10);
  }

  private static String codeOf(Throwable t) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      if (c instanceof ShreddingException e) {
        return e.code();
      }
    }
    return t.getClass().getSimpleName();
  }
}
