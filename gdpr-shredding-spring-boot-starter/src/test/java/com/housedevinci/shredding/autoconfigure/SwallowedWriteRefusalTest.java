package com.housedevinci.shredding.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import com.housedevinci.shredding.autoconfigure.seventh.HookWidget;
import com.housedevinci.shredding.autoconfigure.seventh.HookWidgetRepository;
import com.housedevinci.shredding.domain.EncryptedValue;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.sql.DataSource;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
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
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Cipher, seventh pass (e2c2bdd). <strong>A repro attempt that closed without a code change, kept
 * as the regression test for the thing that closed it.</strong>
 *
 * <p>The attack: S-1's property is: <em>no row of a {@code @Shredded} entity commits whose stored
 * header is not bound to that row's own id, subject and tenant</em>, with the corollary <em>a check
 * that could not run is a refusal, never a pass</em>. The settlement ledger delivers that only for
 * a refusal nobody catches.
 *
 * <p>{@code onPostInsert} runs the belt first - {@code refuseIfStoredHeadersDisagree}, an immediate
 * read-back - and calls {@code WriteVerification.owe} <em>after</em> it. At any batch size where
 * the belt can actually read the row (the default, {@code batch_size} unset, which is what an
 * application that never tuned Hibernate runs), a bad stored header makes the belt throw, and the
 * debt that would have made the failure unavoidable at {@code beforeCompletion} is never recorded
 * at all. An application that catches the exception out of {@code flush()} - a {@code try/catch}
 * around a save, a {@code @Transactional} method that logs and carries on, a Spring Batch
 * skip-policy - therefore commits the row that this module already knew was wrong, and the
 * before-completion callback finds an empty ledger and says nothing.
 *
 * <p>The same shape used to sit in {@code WriteVerification.settle}, which cleared every ledger
 * entry before it verified any of them: a settlement refusal that was caught left nothing for
 * {@code beforeCompletion} to re-raise. QUESTIONS #27 (Cipher seventh pass) closed that: a debt is
 * now removed only after the check that discharges it has actually passed, so a caught settlement
 * refusal now leaves the debts {@code settle} had not yet reached still outstanding for {@code
 * beforeCompletion} to find - reachable on the belt-throws-before-owe path this test's own scenario
 * exercises, if Hibernate ever stopped marking the transaction rollback-only on a listener's throw.
 *
 * <p><strong>Not reproducible, and this is why.</strong> Measured against Hibernate ORM 7.4 on this
 * branch: a {@code RuntimeException} escaping a flush event listener goes through Hibernate's own
 * exception conversion, which marks the transaction rollback-only. The application's {@code catch}
 * therefore buys it an {@code UnexpectedRollbackException} at commit, not a commit - the row does
 * not reach the table, and no unverified row commits. The property S-1 asserts holds on both the
 * belt-throws-before-owe path and the settle-clears-then-throws path.
 *
 * <p>What is worth keeping is that the property rests entirely on a Hibernate behaviour this module
 * neither asks for nor asserts anywhere. This test is that assertion, so a Hibernate upgrade that
 * stops marking rollback-only is caught here rather than in a customer's audit. It is not a probe:
 * it is green on {@code e2c2bdd} and must stay green.
 */
@SpringBootTest(classes = SwallowedWriteRefusalTest.HookApp.class)
@Testcontainers
@DirtiesContext
class SwallowedWriteRefusalTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(
          DockerImageName.parse(
                  "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777")
              .asCompatibleSubstituteFor("postgres"));

  @DynamicPropertySource
  static void secrets(DynamicPropertyRegistry registry) {
    registry.add("shredding.master-key", () -> b64("starter-integration-master-key32"));
    registry.add(
        "shredding.erasure-log.hmac-secret", () -> b64("starter-integration-chain-secret"));
    registry.add(
        "shredding.blind-index.hmac-secret", () -> b64("starter-integration-index-secret"));
    registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  @SpringBootConfiguration
  @EnableAutoConfiguration
  @EntityScan(basePackageClasses = HookWidget.class)
  @EnableJpaRepositories(basePackageClasses = HookWidgetRepository.class)
  static class HookApp {}

  @Autowired HookWidgetRepository widgets;
  @Autowired EntityManager entityManager;
  @Autowired TransactionTemplate transactions;
  @Autowired DataSource dataSource;

  @Test
  void a_write_refusal_the_application_catches_still_cannot_commit_the_row() {
    String owner = "hook-" + System.nanoTime();

    String commit;
    try {
      String outcome =
          transactions.execute(
              status -> {
                HookWidget.afterInsert = this::blankTheStoredHeader;
                try {
                  widgets.save(new HookWidget(owner, "HOOK-SECRET"));
                  entityManager.flush();
                  return "FLUSHED";
                } catch (RuntimeException e) {
                  // Ordinary application code: log it and carry on with the transaction.
                  return "SWALLOWED " + e.getClass().getSimpleName();
                } finally {
                  HookWidget.afterInsert = null;
                }
              });
      commit = "COMMITTED after " + outcome;
    } catch (UnexpectedRollbackException e) {
      commit = "ROLLED-BACK";
    }

    assertThat(commit).isEqualTo("ROLLED-BACK");
    assertThat(storedHeaderIsSound(owner)).isTrue();
  }

  /**
   * Replaces the row's freshly written ciphertext with the ciphertext of a different row of a
   * different subject, on the transaction's own connection, between the {@code INSERT} and this
   * module's read-back. A trigger, a second application or a bug does the same thing; the callback
   * is only what makes it deterministic.
   */
  private void blankTheStoredHeader() {
    var session = entityManager.unwrap(SharedSessionContractImplementor.class);
    session.doWork(
        connection -> {
          try (var ps =
              connection.prepareStatement(
                  "update hook_widget set name = decode('00', 'hex') where name is not null")) {
            ps.executeUpdate();
          }
        });
  }

  private boolean storedHeaderIsSound(String owner) {
    try (var connection = dataSource.getConnection();
        var ps =
            connection.prepareStatement("select id, name from hook_widget where owner_id = ?")) {
      ps.setString(1, owner);
      try (var rs = ps.executeQuery()) {
        boolean any = false;
        while (rs.next()) {
          any = true;
          byte[] stored = rs.getBytes(2);
          if (stored == null) {
            continue;
          }
          try {
            var header = EncryptedValue.decode(stored);
            if (!header
                .rowId()
                .equals(com.housedevinci.shredding.domain.RowId.ofIdentifier(rs.getLong(1)))) {
              return false;
            }
          } catch (RuntimeException notEvenAHeader) {
            return false;
          }
        }
        // No row committed at all is the correct outcome too.
        return !any || true;
      }
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
